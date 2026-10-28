# Blocking sites

The verified core proves that every loop terminates provided each effect
call returns ([liveness scope](liveness-scope.md)). Whether a blocking call
returns is a property of the kernel and cannot be proved from inside the
process. What this page does instead is make the assumption auditable: every
call in the runtime's production code that can block its thread is listed
with what unblocks it, how long it can hold the thread, the test that
exercises the unblock, and the one kernel fact each row still rests on.
`scripts/check_blocking_sites.py` scans the runtime for these calls and fails
CI when the set differs from the list in the script or when a site's function
has no row here, so a new blocking call cannot appear without a row.

Test modules, test files, and test support are out of scope, as is the
`hypgate scan` command's output stream. Mutex acquisition is not listed: no
lock is held across a blocking call except the DNS pool's receiver lock, noted
in its row, and poisoned locks fail closed ([runtime ownership](runtime-ownership.md)).

## Accept thread

| Site | Blocks on | Unblocked by | Bound | Test | Kernel assumption |
|------|-----------|--------------|-------|------|-------------------|
| `server.rs` `Effects::accept` | `accept(2)` on the listener | Any incoming connection, or the loopback connect that `Shutdown::trigger` makes after setting the flag (`wake_accept`) | None while serving, by design; one connect after the trigger | Every server test ends with `trigger` then join; `sigterm_drains_and_exits_cleanly_with_a_complete_log` | A connect to the listener's own address completes the blocked accept; the backlog has room because the accept is idle |
| `server.rs` `wake_accept` | `connect_timeout` to the listener | The listener accepting, or the timeout | 1 s | Same | `connect_timeout` returns at its timeout |
| `server/connections.rs` `ConnectionSlots::wait_drained`, `server/workers.rs` `WorkerSlots::wait_drained` | Condition variable with timeout | A lease returning its credit, `close`, or the window end | The drain window (10 s), then the cancel window (10 s) | `drain_waits_for_the_last_connection_thread`, `shutdown_closes_shared_worker_admission_before_waiting_for_existing_work`, `shutdown_aborts_stalled_response_after_drain_and_releases_request` | `wait_timeout` returns at the timeout |

## Connection threads

| Site | Blocks on | Unblocked by | Bound | Test | Kernel assumption |
|------|-----------|--------------|-------|------|-------------------|
| `net.rs` `Io::perform` | Every raw read, write, and flush on the client and upstream sockets | Data, EOF, the socket timeout the verified deadline driver arms to the remaining budget, or `Cancel` shutting the socket down | The exchange deadline | `a_read_that_outlives_the_deadline_times_out_without_data`, `cancel_shuts_registered_sockets_and_those_registered_later`, `tls_trickles_release_every_request_slot_by_the_deadline` | `SO_RCVTIMEO` and `SO_SNDTIMEO` are honored; `shutdown(2)` fails a blocked operation on that socket |
| `net.rs` `Tls::handshake` | `complete_io` over the timed socket, repeated while handshaking | Each step's socket operation (row above); the outer deadline check between steps | The exchange deadline | `tls_handshake_and_application_record_trickles_expire`, `cancelling_a_trickled_handshake_does_not_report_timeout`, `shutdown_during_a_stalled_handshake_cancels_it_after_the_drain_and_recovers_credit` | As above; rustls finishes each step in finite CPU time |
| `transport.rs` `open_socket` | `connect_timeout` per resolved address | Connection, refusal, or the timeout; each address gets the deadline's remaining budget | The exchange deadline | None for an unreachable address; `deadline_drops_connection_and_releases_admission` covers the deadline after connect | `connect_timeout` returns at its timeout |
| `credited_job.rs` `Pending::wait` | `recv_timeout` for a DNS reply | The lookup's reply or the deadline; a departed requester leaves the lookup's credit with the worker | The exchange deadline | `departed_lookups_keep_credit_until_blocking_work_finishes` | `recv_timeout` returns at the timeout |
| `server.rs` `ClientWatch::start` | `peek` on a clone of the client socket, and 5 ms or 20 ms sleeps between polls | Data, EOF, an error, or `finish` shutting the socket down; the sleeps end on their own | One poll slice after `finish` | `client_disconnect_during_response_cancels_and_releases_request`, `clean_client_close_before_headers_waits_for_deadline` | `shutdown(2)` wakes a blocked `peek` |
| `server.rs` `ClientWatch::finish` | Joining the watcher | The watcher's next loop turn after the flag and the socket shutdown | One poll slice plus the peek return | Same | None beyond the row above |
| `disk_log.rs` `AuditLog::append`, `disk_log/queue.rs` `Queue::enqueue` | `recv_timeout` for the sync acknowledgment; `wait_timeout` for a free queue slot | The worker's completion or slot release, or the log deadline (one deadline covers both waits) | The log deadline | `slot_wait_is_bounded_by_the_deadline_and_poisons_health`, `blocked_disk_times_out_without_spawning_replacements`, `stalled_log_under_load_preserves_health_deadlines_and_mode_policy` | Both timeouts fire |

## Audit worker thread

| Site | Blocks on | Unblocked by | Bound | Test | Kernel assumption |
|------|-----------|--------------|-------|------|-------------------|
| `disk_log/queue.rs` `Queue::recv` | Condition variable, no timeout | `enqueue` notifying, or `close` | None: this is the idle wait, by design | `dropping_final_logger_handle_wakes_and_releases_idle_worker`, `closing_wakes_waiting_callers_without_constructing_their_jobs` | A notify wakes the waiter |
| `disk_log.rs` `DurableWrite::sync`, `disk_log/rotation.rs` `SegmentIo::sync`, `SegmentIo::seal`, `create_segment` | `fsync` of the log segment or its directory | The storage stack | None. Callers stop waiting at the log deadline (row above) and `DiskLog::shutdown` abandons the worker after its window; the worker is never replaced | `shutdown_deadline_does_not_wait_for_stuck_sync_or_replace_worker`, `shutdown_with_blocked_disk_returns_error_without_replacement_or_replay`, `write_and_sync_failures_never_acknowledge_and_poison_future_appends` | `fsync` eventually returns; until it does, one thread and its slot are gone ([storage contract](storage-crash-contract.md)) |
| `disk_log.rs` `DiskLog::shutdown` | Joining the worker; 1 ms sleeps while polling `is_finished` | The worker exiting after `close`, or the shutdown window | The shutdown window (2 s); join only after `is_finished` | `shutdown_closes_all_clones_drains_admitted_jobs_and_joins`, `shutdown_deadline_does_not_wait_for_stuck_sync_or_replace_worker` | None beyond the rows above |

## DNS pool threads

| Site | Blocks on | Unblocked by | Bound | Test | Kernel assumption |
|------|-----------|--------------|-------|------|-------------------|
| `credited_job.rs` `JobPool::new` | `recv` on the job channel, holding the receiver lock; the other idle workers block on that lock | A submitted job, or the pool's sender dropping when the transport is dropped | None: the idle wait, by design | `panicked_lookup_returns_credit_without_losing_the_pool_worker` | A send or a sender drop wakes the receiver |
| `transport/resolver.rs` `Resolver::resolve` | `getaddrinfo` | The system resolver, under its own `resolv.conf` timeouts and attempts | None in this process. The requester stops waiting at its deadline and the worker keeps the lookup's credit; the pool of four never grows | `departed_lookups_keep_credit_until_blocking_work_finishes` | `getaddrinfo` eventually returns; until it does, one of four workers and one of 32 lookup slots are gone |

## Shipper thread

| Site | Blocks on | Unblocked by | Bound | Test | Kernel assumption |
|------|-----------|--------------|-------|------|-------------------|
| `shipping/lookup.rs` `Lookup::resolve` | `recv_timeout` for the lookup thread's answer | The answer, or the request deadline; a lookup thread still busy from an earlier request fails the submission at once instead of waiting | The request deadline | `a_stalled_lookup_times_out_and_later_requests_fail_fast_until_it_returns` | `recv_timeout` returns at the timeout |
| `shipping/client.rs` `open_socket` (connect) | `connect_timeout` per address, at most 16 | Connection, refusal, or the timeout | The request deadline | `cloud_client_classifies_handshake_and_record_trickles_as_timeouts` covers the deadline after connect | `connect_timeout` returns at its timeout |
| The shipper's reads and writes | `Io::perform` and `Tls::handshake` above | As above | The request deadline | `cloud_client_classifies_handshake_and_record_trickles_as_timeouts`, `shutdown_returns_within_its_window_while_the_server_hangs` | As above |
| `shipping.rs` `Engine::wait` | `sleep` in slices of at most 100 ms, checking the stop flag between slices | Time, or the stop flag at the next slice | 100 ms past the stop flag | `shutdown_returns_within_its_window_while_the_server_hangs`, `ships_many_exchanges_in_bounded_batches_with_drain_mode` | `sleep` returns |
| `shipping/state.rs` `write_private` | `fsync` of a state file and its directory | The storage stack | None; `Shipper::shutdown` abandons the thread after its window | None for a stuck sync | `fsync` eventually returns |
| `shipping/state.rs` `read_bounded`, `disk_log.rs` `Source::read_exact` | Reads of the state files and the audit log | The filesystem; the size is checked first or bounded by the record | By the file size on a regular local file | `scanner_io_error_at_every_record_byte_preserves_prefix_and_stops_reading` covers errors, not stalls | A regular file on local storage: a FIFO or a stalled network mount blocks the thread |
| `shipping.rs` `Shipper::shutdown` | `recv_timeout` for the finished signal, then join | The thread finishing its current step after the stop flag, or the window | The shutdown window; join only after the signal | `shutdown_returns_within_its_window_while_the_server_hangs` | `recv_timeout` returns at the timeout |

## Shipper lookup thread

| Site | Blocks on | Unblocked by | Bound | Test | Kernel assumption |
|------|-----------|--------------|-------|------|-------------------|
| `shipping/lookup.rs` `Lookup::with` | `recv` on the request channel | A submitted request, or the client dropping its sender | None: the idle wait, by design | `a_stalled_lookup_times_out_and_later_requests_fail_fast_until_it_returns` | A send or a sender drop wakes the receiver |
| `shipping/lookup.rs` `Lookup::new` | `getaddrinfo` | The system resolver, under its own `resolv.conf` timeouts and attempts | None in this process. The requester stops waiting at its deadline; one further request is buffered and a departed requester's buffered request is skipped; the thread is never replaced | Same | `getaddrinfo` eventually returns; until it does, the shipper's requests fail fast with `Resolve` and are retried on the machine's schedule |

## Signal thread and startup

| Site | Blocks on | Unblocked by | Bound | Test | Kernel assumption |
|------|-----------|--------------|-------|------|-------------------|
| `signal.rs` `on_termination` | `read` on the socket pair | The signal handler's one-byte write on SIGTERM or SIGINT | None: it waits for the signal for the life of the process and is never joined | `sigterm_drains_and_exits_cleanly_with_a_complete_log` | The async-signal-safe write reaches the pair |
| `main.rs` `bounded_file` | Reading the configuration and secret files at startup, capped in size | The filesystem | By the cap on a regular file | Startup of every CLI test | A regular file: a FIFO at that path blocks startup |

## What this leaves

Three facts carry everything above: socket timeouts and `shutdown(2)` work
as documented, condition variable and channel timeouts fire, and the
scheduler runs a woken thread. Two calls have no unblock mechanism at all,
`fsync` and `getaddrinfo`; the gateway bounds their effect by having callers
stop waiting at a deadline and by never replacing the blocked thread, so a
stall costs a fixed slot rather than the process: a DNS worker, or the
shipper's lookup thread, whose stall turns the shipper's requests into fast
`Resolve` failures retried on the machine's schedule rather than a hang.
