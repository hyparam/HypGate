# End-to-end audit: authorization through network and disk effects

This audit follows one request through the production source at `8102eba`,
from the inbound socket to the exact upstream TCP/TLS/HTTP calls and the exact
audit-file write/sync calls, then through every failure exit and graceful
shutdown. Each step names the code, states whether the step is **proved**
(a Verus contract in `gateway-core`), **tested** (a runtime test exercises it),
or **assumed** (trusted code or an external contract), and names the evidence.
It is a source-level traceability record made by reading the code, not an
independent review or a mechanized proof of the async runtime. Line numbers
refer to the audited commit.

Milestone 6 ownership refactor: the historical `WorkerTask` and `ConnectionTask`
wrappers below now share private `server/leased_task.rs::LeasedTask`. It starts a
verified `TaskCredit`, explicitly destroys the future before reporting cleanup
complete, and retains unit output. Both lease types consume credits through
verified gates that refuse release while running or cleaning. Tests cover
deterministic never-polled destruction and wrapper-cleanup panics, in addition
to cancellation, task panic, and shutdown. A wrapper-cleanup panic strands the
credit and closes worker admission. These checked transitions do not mechanize
the destructor correspondence or independent cleanup tails assumed by this audit.

DNS/TLS follow-up: both pools now use `credited_job::CreditedJob` and `Reply`.
Queued/running work and unread replies keep their own verified credit. The
transport calls `Reply::adopt` before TCP use or HTTP handshake; the target
request's actual registry and stream supply the verified `handoff_to` check.
Only a live admitted target enables background release. Dropped replies destroy
their result first. The historical effect sites below remain the same, but pool
release now includes this checked lifecycle/handoff gate. Destructor/channel
correspondence and the full cross-category composition are still explicit joins.

Disk follow-up: `disk_worker::DiskWorker` now owns the queue-to-active transfer,
write/sync/commit sequence, and session/generation-checked release. The runtime
queue uses its `take` while locked; the worker uses `run`, consuming `deliver`,
then `release`. The actual file effects are isolated in `disk_log::Storage`,
and consuming oneshot delivery in `disk_log::Completion`. Those adapter contracts
remain trusted; the sequencing, exact frame binding, active credit, and Q+1 bound
are checked. See [audit-buffer ownership](audit-buffer-lifetimes.md).

Related records: the [proof index](proof-index.md) lists every contract, the
[adapter audit](adapter-audit.md) records milestone 2 bindings, the
[storage contract](storage-crash-contract.md) and [shutdown proof](shutdown-proof.md)
cover disk and termination, and the [resource composition](resource-composition.md)
covers memory. This document composes them along one request path and lists
what still has no theorem.

## Every external effect site in production source

A grep of the non-test runtime source for socket, file, thread, process, and
environment operations finds only these sites. Code under `#[cfg(test)]` and in
`tests/` directories is excluded. `gateway-core` performs no I/O and forbids
`unsafe`; neither crate contains `assume`, `external_body`, or `unsafe`.

| Effect | Production site | What must already hold when it runs |
| --- | --- | --- |
| Listen on loopback | `main.rs:30` | Address checked loopback at `main.rs:21`; configuration and audit log already created |
| Read root policy, routes, and secrets | `main.rs:23-25` | Startup only; bounded file reads, secrets from environment through `GatewayConfig::from_json` |
| Accept inbound connection | `server.rs:231` | Connection credit from the verified connection registry, `server.rs:233-234` |
| Spawn request worker | `workers.rs:26` via `server.rs:76` | Worker credit from the verified drain registry, `server.rs:67` |
| DNS lookup | `transport/resolver.rs:59` | Called only from `HttpsTransport::run` with a `PreparedRequest` borrowed, `transport.rs:68` |
| Upstream TCP connect | `transport.rs:69` | Same owner; addresses come only from the configured destination host/port |
| Upstream TLS handshake | `transport.rs:73`, polled on `handshake.rs:31` threads | `ServerName` built from the configured destination host, `transport.rs:66` |
| Upstream HTTP request, including the provider credential header | `transport.rs:95` | Request head built only by `http_boundary::prepare`, `http_boundary.rs:134-149` |
| Response bytes to the client | `server.rs:189-206` through the bounded HTTP channel into Hyper | Head sent once by `Output::start`; body bytes come only from `copy_body` |
| Create audit file, write/sync header, sync parent directory | `disk_log.rs:64-76` | Startup only; `create_new`, mode 0600, path chosen by the operator |
| Audit record write and sync | `disk_log.rs:97` | One worker thread (`disk_log.rs:91`); frame came through the verified queue reservation |
| Read audit file for recovery | `disk_log.rs:248-267` | Read-only; never truncates, appends, or replays |
| Dedicated threads | `disk_log.rs:91` (1), `handshake.rs:31` (4), `resolver.rs:39` (4) | Fixed counts at construction; never replaced after a timeout |

No other `connect`, `send_request`, `write_all`, `sync_all`, `spawn`, or file-open
call exists in production runtime source. This enumeration is review evidence
for complete mediation. Rust visibility and ownership stop safe code outside
these modules from reaching the effects without the tokens below; they do not
stop a future edit inside `transport.rs` or `disk_log.rs` from adding a bypass,
so this table must be rechecked when those modules change.

## Mediation tokens and who can construct them

| Token | Only constructor | Private evidence it carries |
| --- | --- | --- |
| `policy::Authenticated` | `Policy::authenticate`, `policy.rs:186` | Proved: digest equals some identity in a valid policy |
| `policy::AuthorizedRequest` | `Authenticated::authorize`, `policy.rs:220` | Proved: route belongs to that tenant and selector, request ID nonzero, route is `allowed` by root grants, credential owner equals tenant |
| `owned_stream::OwnedStream` | `OwnedStream::claim`, `owned_stream.rs:60` | Proved: stream owner equals the authority's request ID, slot owned by the registry, strict flag recorded, empty initial body |
| `admission::Request` | `Admission::admit`, `admission.rs:73` | Trusted Rust pairing the above; lease retires the stream under the registry lock on drop |
| `config::RoutedRequest` | `GatewayConfig::admit`, `config.rs:160` | Trusted pairing; destination URI and credential chosen by the proved `ResolvedRoute::resolve` from the authority's route indices |
| `http_boundary::PreparedRequest` | `http_boundary::prepare`, `http_boundary.rs:118` | Trusted: upstream head with configured Host, configured credential, filtered client headers |

None of these has a public field, public constructor, `Clone`, or deserializer.
Five compile-fail doctests in `owned_stream.rs` check that raw stream creation
and raw claim/release do not compile outside the core. `HttpsTransport::exchange`
takes a `PreparedRequest` by value and no destination or credential parameter;
`RoutedRequest::credential_header` is `pub(crate)`. Tested:
`tokens_cannot_switch_to_another_policy`, `tickets_from_independent_registries_are_rejected`,
`outstanding_ticket_cannot_advance_replacement_request`.

## Trace of one successful request

Status key: P proved, T tested, A assumed.

| Step | Code | Status | Evidence and scope |
| --- | --- | --- | --- |
| 1. Accept and connection credit | `serve` loop, `server.rs:226-245`; `ConnectionSlots` over `ResourceAdmission` | P/T/A | Acquire/release contracts proved. Excess sockets closed, Hyper limits (100 headers, 32 KiB head, bounded read frames, 10 s header timeout, connection deadline) are trusted Hyper behavior. T: `incomplete_connections_expire_without_workers_and_capacity_recovers`, `serve_invocations_share_connection_credit_and_reject_limit_changes`, `inbound_wire_head_and_header_count_limits_apply_before_health_dispatch`. |
| 2. Health endpoints need no credit | `server.rs:44-66` | T | `/metrics`, `/healthz`, `/readyz` answered before worker admission. Readiness fails on poisoned/closed registries and on unhealthy strict logging. T: `poisoned_admission_is_unready_and_fail_closed_in_both_logging_modes`, `poisoned_worker_registry_is_unready_and_fail_closed_in_both_modes`. |
| 3. Worker credit before any request allocation | `server.rs:67-70`, `workers.rs:61-67` | P/T | `DrainRegistry::acquire` proved exact occupancy and refusal when full or closed. 503 without a lease. T: `worker_budget_covers_cleanup_without_consuming_request_slots`, `concurrent_workers_hold_credit_until_task_cleanup`. |
| 4. Worker future owned before its lease | `WorkerTask`, `workers.rs:17-27`; cancellation select, `server.rs:77-79` | T/A | Future destroyed before credit returned, including never-polled futures. A: Tokio cancellation and Rust drop order. T: `task_captures_drop_before_worker_credit_on_every_exit`. |
| 5. Metadata boundary | `prepare_request_parts` → `prepare`, `http_boundary.rs:118-150` | T | POST only; head size recheck; selector strictly `/routes/<decimal>`; exactly one well-formed bearer; allowlisted request headers copied by value; `content-encoding`, `upgrade`, `trailer` rejected. Client `Authorization` is not on the allowlist and cannot reach upstream. T: `malformed_authentication_never_issues_a_prepared_request`, `caller_cannot_select_an_arbitrary_url_path_or_method`, `connection_nominations_are_stripped_but_cannot_suppress_root_credentials`, `invalid_and_oversized_headers_do_not_leak_admission_slots`. |
| 6. Authentication | `GatewayConfig::admit`, `config.rs:160-163`: SHA-256 of the token, then `Policy::authenticate` | A/P | SHA-256 and token provisioning assumed. Proved: success iff the digest equals an identity digest in a valid policy; digest comparison scans every byte but has no constant-time theorem. |
| 7. Request slot | `Admission::admit`, `admission.rs:75-81` | P/T | `ResourceAdmission::acquire` proved: occupancy plus one, distinct live IDs, refusal when full. Any later early return drops the lease and releases the key. T: `authorization_failures_return_capacity_and_drop_reclaims_it`, `concurrent_handlers_share_one_capacity_registry`. |
| 8. Authorization | `Authenticated::authorize`, `admission.rs:83` | P | Proved: the returned token's route has the authenticated tenant and requested selector, nonzero request ID, and is in the root grants with a credential owned by that tenant. Candidate routes cannot enlarge grants (`Policy::validate`). T: `candidate_configuration_cannot_expand_root_grants`, `untrusted_configuration_cannot_change_destinations_or_ownership`. |
| 9. Stream bound to slot and authority | `OwnedStream::claim`, `admission.rs:88` | P | Proved: stream owner equals the token's request ID, capacity equals the configured chunk, strict flag recorded, one creation per key. |
| 10. Destination and credential binding | `config.rs:164-165` call `ResolvedRoute::resolve` over `destinations`/`credentials` | P/A | Proved to select the entries at the granted route's indices and to hand them out only for the bound authority. Index-to-URI and index-to-secret mapping is trusted but immutable after startup; `destination()` (`config.rs:72-102`) admits only `https://`, ASCII DNS or bracketed IPv6 host, numeric port, no userinfo, query, or percent escapes. T: `native_provider_endpoints_keep_their_own_credentials`, `malformed_or_ambiguous_destinations_are_rejected`. |
| 11. Upstream head | `http_boundary.rs:138-149` | T | Host from the configured authority; credential header from `credential_header`; `accept-encoding: identity`; URI is the configured destination. T: `fixed_destination_and_credentials_replace_host_and_client_secrets`. |
| 12. Strict pre-check | `server.rs:92-96` | T | If strict logging is already unhealthy, 503 before any DNS, TCP, or TLS work. T: `strict_log_failure_prevents_even_upstream_connection`. |
| 13. Exchange deadline and ownership | `HttpsTransport::exchange`, `transport.rs:51-58` | T/A | `PreparedRequest` lives outside the timed future, so network futures drop before the slot can release. A: Tokio timer. T: `deadline_drops_connection_and_releases_admission`, `canceling_tls_handshake_drops_socket_and_returns_owned_request_credit`. |
| 14. Name resolution | `transport.rs:63-68`, `resolver.rs` | T/A | Host and port read only from the prepared destination. Four threads, 32 credits, at most 64 addresses; saturation fails the exchange. A: system resolver, no IP-range policy (not an SSRF theorem). T: resolver tests in `transport/resolver.rs`. |
| 15. TCP and TLS | `transport.rs:69-76` | A/T | rustls with webpki roots verifies the configured host name; early data off, certificate decompression off, 64 KiB application buffer, 256-entry session cache. The handshake polls on the bounded pool with its own credit. A: rustls, webpki, PKI. T: `tls_exchange_preserves_native_payloads_and_scoped_credentials`, `untrusted_certificate_is_rejected_before_http_credentials_are_sent`, `trusted_certificate_with_large_wrong_purpose_list_is_rejected_before_upload`, `oversized_handshake_is_rejected_from_its_length_before_upload`. |
| 16. HTTP/1 client connection | `transport.rs:78-87` | A/T | Same parser limits as inbound; URI rewritten to origin-form path of the configured destination. Connection future polled inline in `select!`, never spawned; no redirect following, pooling, or retry. T: `redirects_are_returned_without_opening_a_second_connection`, `upstream_wire_head_and_header_count_limits_cover_status_line`. |
| 17. Upload copy | `copy_body(Upload)`, `transfer.rs:48-83` | P/T | Per chunk: `read_next` (proved: at most one retained chunk across stream and read buffer), then `audit_current`, then write tickets. T: `multichunk_partial_writes_follow_durable_logs_and_preserve_bytes`, `real_async_backpressure_preserves_fragmented_sse_bytes`. |
| 18. Audit record construction | `Request::audit_current`, `admission.rs:145-179`, calling `StreamChunk::audit_record` | P | Proved: header tenant equals the authority's tenant, request equals both the authority's and the stream's owner, chunk equals the current chunk, payload length and bytes equal the current body, stream neither closed nor failed. Caller headers never enter the record. |
| 19. Queue reservation and encoding | `DiskLog::append` → `Queue::enqueue`, `disk_log.rs:189-217`, `queue.rs:42-75` | P/T/A | Health check, payload limit, nonzero request. A full queue parks the caller on a fair semaphore (one permit per free slot) until the worker pops a job; the append deadline covers the wait and poisons health on expiry. `FrameQueue::reserve`/`encode_reserved`/`finish_reserved` proved: slot reserved before encoding, payload limit enforced, FIFO order and completion pairing preserved, permanent closure. Encoding permit is single use. A: Tokio's semaphore hands permits in arrival order and returns a canceled waiter's place. T: `production_enqueue_preserves_pairing_waits_while_full_and_refuses_closed_before_encoding`, `closing_wakes_waiting_callers_without_constructing_their_jobs`, `dropped_waiter_leaves_no_reservation_and_later_callers_proceed`, `full_queue_parks_excess_work_before_allocation_and_serves_it_in_order`, `slot_wait_is_bounded_by_the_deadline_and_poisons_health`. |
| 20. Durable write | Worker loop, `disk_log.rs:94-106` | P/A | `AuditJournal::begin`, then `write_all`, then `sync_all`, then `commit_frame`. Proved: a receipt exists only if the commit matched the ticket, the frame length, and a non-failed journal; the acknowledged history is the prior history plus exactly this frame; `durable_commit_without_sync` mutation fails. A: syscalls report truth, storage preserves synced bytes ([storage contract](storage-crash-contract.md)). T: `strict_transfer_and_real_disk_records_have_identical_payloads`, `actual_file_acknowledgments_are_readable_and_existing_files_are_not_overwritten`, `kill_after_ack_preserves_the_acknowledged_record`. |
| 21. Receipt delivery and acknowledgment | oneshot to `audit_current`, then `OwnedStream::acknowledge_receipt` | P/T | Proved: acknowledgment succeeds iff the receipt's record equals the canonical encoding of this exact header and body plus checksum; then durable offset equals body length and nothing else in the stream changes. T: `mismatched_durable_receipts_never_authorize_forwarding`, `durable_receipt_matches_exact_metadata_and_payload`. |
| 22. Write tickets | `prepare`/`pending_bytes`/`complete`, `transfer.rs:72-79` | P/T | Proved: `prepare` in strict mode offers only durable-covered bytes; `pending_bytes` is the exact unsent slice; `complete` requires a matching owner and generation and advances by the accepted count; completed history is an unchanged ordered prefix of input. T: `zero_error_and_flush_failures_close_without_replay`, `spare_vector_capacity_cannot_escape_the_retained_chunk_budget`. |
| 23. Body channel to Hyper | `http_body::channel`, `http_body.rs:53-115`, with the verified `Mailbox` | P/A | Accepted count means queued in the one-slot mailbox, not peer receipt. Proved: mailbox never overwrites, drains after sender closure. A: Hyper framing and socket send. |
| 24. Response head | `prepare_response_parts`, `http_boundary.rs:160-178`; `Output::start`, `server.rs:192-194` | T | 1xx rejected; response allowlist excludes `set-cookie`, `location`, and credentials; a hop-by-hop nominated `content-encoding` rejects the response. Head sent exactly once to `worker_response`. T: `upstream_response_cannot_forward_credentials_cookies_or_redirect_location`, `unsolicited_protocol_switch_is_rejected_before_client_headers`, `interim_response_does_not_replace_final_status_or_payload`. |
| 25. Download copy | `copy_body(Download)`, `transport.rs:100-102` | P/T | Same stream, same log, direction 1, same proved gates as steps 17 to 22. `output.finish` drains the application queue. T: `full_gateway_streams_before_upstream_eof_and_logs_exact_bytes`, `concurrent_tenants_keep_credentials_bodies_and_audit_records_isolated`. |
| 26. Clean EOF only on success | `server.rs:100-103`; `GatewayBody::poll_frame`, `server.rs:174-180` | T | Only `Ok` from `exchange` calls `output.shutdown`, the sole path that enqueues the clean end marker. `Ready(None)` releases the abort guard so the worker finishes accounting. T: `truncated_response_is_never_reported_as_success`, `bodyless_http_statuses_finish_worker_accounting`. |
| 27. Release | Worker future drops `PreparedRequest` → `Lease::drop`, `admission.rs:31-44`; then `WorkerLease::drop`, `workers.rs:30-39`; then `ConnectionLease::drop` | P/T | `OwnedStream::retire` proved to release exactly its live slot under the lock; `DrainRegistry::release` proved. A panic during the reservation-to-stream transfer strands the slot rather than releasing it. T: `strict_logging_and_cancellation_keep_the_lease_until_drop`, `unwinding_releases_owned_request`, `aborting_server_drops_connections_and_recovers_worker_credit_across_restarts`. |

Across this trace, no byte reaches the provider without passing step 8 and no
body byte is submitted in strict mode without passing step 21. These are two
chains of proved steps joined by trusted Rust ownership, not one theorem.

## Failure exits

Each row states what the client sees, whether any upstream effect occurred,
what the audit log holds, and how the slot is released.

| Failure | Detected at | Client | Upstream | Audit | Release and evidence |
| --- | --- | --- | --- | --- | --- |
| Bad method, URI, headers, or bearer syntax | Step 5 | 400/401/405/431, no body | None | Nothing | No request slot was taken; worker credit returns with the task. T: `malformed_authentication_never_issues_a_prepared_request`, `invalid_and_oversized_headers_do_not_leak_admission_slots`. |
| Unknown token or no grant for the selector | Steps 6, 8 | 401 | None | Nothing | P: no `AuthorizedRequest` exists. Lease dropped at `admission.rs:83`. T: `authorization_failures_return_capacity_and_drop_reclaims_it`, `authentication_and_tenant_scoped_dispatch`. |
| Request slots full | Step 7 | 503 | None | Nothing | P: `acquire` refuses when full. T: `repeated_overload_preserves_active_streams_health_and_reusable_capacity`, `sustained_overload_preserves_active_streams_and_health`. |
| Worker credits full | Step 3 | 503 | None | Nothing | P: `DrainRegistry::acquire`. T: `worker_budget_covers_cleanup_without_consuming_request_slots`. |
| Poisoned admission or worker registry | Steps 2, 3, 7 | 503 and `/readyz` 503, both modes | None | Nothing | Poison is never recovered; capacity stays stranded. T: `poisoned_admission_is_unready_and_fail_closed_in_both_logging_modes`, `poisoned_worker_registry_is_unready_and_fail_closed_in_both_modes`, `poisoned_connection_registry_never_reissues_credit`. |
| Strict logging already unhealthy | Step 12 | 503 | None, no DNS/TCP/TLS | Nothing | T: `strict_log_failure_prevents_even_upstream_connection`. Not counted as an audit gap. |
| DNS, TCP, or TLS failure, or pool saturation | Steps 14, 15 | 502 | TCP may have opened; TLS fails before any HTTP byte, so no credential sent | Nothing | Network futures drop inside `exchange` before the slot. T: `untrusted_certificate_is_rejected_before_http_credentials_are_sent`, `canceling_tls_handshake_drops_socket_and_returns_owned_request_credit`. |
| Logger append fails or times out during a body | Step 19/20, `audit_current` `Err` path | Strict: 502 if before head, else body aborted (HTTP framing error, never clean EOF). Availability: stream continues | Strict: no further bytes submitted. Availability: forwarding continues | Strict: acknowledged prefix only. Availability: later appends skipped for this request; gap counter incremented once at first failure (`server.rs:155-164`) | P: `fail_log` closes a strict stream and only marks an availability stream; `prepare` cannot offer undurable bytes in strict mode. Logger health goes false; the worker is never replaced. T: `logger_failure_is_closed_in_strict_mode_and_reported_in_availability_mode`, `availability_log_failure_preserves_stream_and_reports_gap`, `blocked_disk_times_out_without_spawning_replacements`, `stalled_log_under_load_preserves_health_deadlines_and_mode_policy`. |
| Write or sync syscall fails | Step 20 | As above | As above | P: `Journal::fail` prevents any later acknowledgment; receipt is `None` | Health false. T: `write_and_sync_failures_never_acknowledge_and_poison_future_appends`, `filesystem_full_preserves_acknowledged_prefix_and_fails_closed`, `filesystem_read_only_refuses_logger_startup`. |
| Receipt does not match the current record | Step 21 | Stream closed, exchange fails | No further bytes | The durable record exists but authorizes nothing | P: `acknowledge_receipt` returns false and leaves the stream unchanged. T: `mismatched_durable_receipts_never_authorize_forwarding`. |
| Upstream connection error or truncated body after head | Step 25 | Head already sent; body aborted by dropping the writer, never clean EOF | Exchange ended | Prefix logged | T: `truncated_response_is_never_reported_as_success`, `truncated_generation_is_an_error_and_still_reports_audit_gap`. |
| Exchange deadline (300 s) | Step 13 | 504 before head, else body aborted | Connection dropped | Prefix logged | T: `deadline_drops_connection_and_releases_admission`. |
| Client disconnects before head | Hyper drops the response future → `AbortOnDrop` | Nothing | Worker aborted; upstream socket closed | Prefix logged; a queued frame may become durable but unsent | P: `cancel` closes the stream so no new ticket is issued. T: `client_disconnect_before_headers_cancels_request_and_upstream_socket`, `worker_body_drop_aborts_pending_request`. |
| Client disconnects during body | Body dropped → `AbortOnDrop` | Nothing further | Same | Same | T: `client_disconnect_cancels_stalled_provider_and_releases_request`. |
| Cancellation while an append is pending | `Pending` drop in `audit_current` | As above | None | Frame stays owned by the queue; worker still writes it; result discarded | T: `canceled_audit_cannot_authorize_or_reuse_the_chunk`, `canceling_append_callers_does_not_release_queued_or_active_frame_credit`, `worker_panic_marks_health_failed_even_after_append_caller_is_canceled`. |
| Bodyless 204/304 with a body, or worker failure | `worker_response`, `server.rs:132-143` | 502 | Exchange ended | Prefix logged | T: `bodyless_status_rejects_payload_or_missing_completion`. |
| Gateway process killed | Any | Truncated body, HTTP framing error | Provider may have executed; no replay | Acknowledged prefix recoverable; restart uses a new file and session | T: `killed_gateway_truncates_response_preserves_audit_prefix_and_does_not_replay`, `kill_during_following_appends_preserves_the_acknowledged_prefix`, `proxy_gateway_process_failover_without_replay`. |

In every row the client never receives a clean HTTP EOF for an incomplete
generation, no row contains a retry or replay path, and authorization is never
re-evaluated more permissively. Strict mode may have opened the connection and
sent the request head before a body-logging failure; that is documented, not a
defect.

## Shutdown

`serve` (`server.rs:218-261`) after SIGINT/SIGTERM or a listener error:

| Step | Code | Status | Evidence |
| --- | --- | --- | --- |
| Stop accepting | `drop(listener)`, `server.rs:248` | T | Listening socket closes while workers continue. |
| Permanently close worker admission across all listeners | `WorkerSlots::close`, `workers.rs:49-54` | P/T | `DrainRegistry::close` proved: outstanding keys preserved, no reopening, later acquire fails. Close and acquire share one mutex. T: `shutdown_closes_shared_worker_admission_before_waiting_for_existing_work`. |
| Ten-second drain of connection tasks, then abort and join | `server.rs:251-254` | T/A | A: Tokio abort/join terminate under finite polls and destructors. T: `shutdown_drains_active_response_without_truncation`, `shutdown_aborts_stalled_response_after_drain_and_releases_request`. |
| Same deadline for all tracked workers, else cancel token | `server.rs:255-258`; worker `select! { biased; cancel }`, `server.rs:77-79` | P/T/A | Each canceled worker drops its operation, then `WorkerTask` drops the future before the lease, then `release`. `drain_trace_rank` proved: each release lowers the finite rank, no new admission. T: `shutdown_cancels_stalled_workers_owned_by_another_listener`. |
| Logger close, drain, join with a two-second window | `DiskLog::shutdown`, `disk_log.rs:119-146` | P/T/A | `FixedQueue::close` proved: pending frames preserved and drained in order. A stuck syscall returns `TimedOut`; the worker is never replaced and may finish its write later. T: `shutdown_closes_all_clones_drains_admitted_jobs_and_joins`, `shutdown_deadline_does_not_wait_for_stuck_sync_or_replace_worker`, `shutdown_with_blocked_disk_returns_error_without_replacement_or_replay`. |

The [shutdown proof](shutdown-proof.md) states the scheduler, timer, mutex,
and destructor assumptions. Ten plus two seconds are cooperative windows, not a
process-exit bound. Restart requires a fresh `Gateway`, transport, logger, and
log path; nothing is resumed from the previous process.

## Advertised guarantees traced to this path

| README property | Steps that carry it | Proved part | Trusted joins |
| --- | --- | --- | --- |
| Authorization and fail-closed security | 5, 6, 8, 11, 12, 16; failure rows 1 to 6 | Token issuance, grant membership, tenant/credential ownership | SHA-256, header parsing, that `exchange` is the only dispatch (effect-site table) |
| Tenant and credential isolation | 8, 9, 10, 11, 18, 21, 27 | Credential owner equals tenant; audit header tenant/request bound to authority and stream owner; ticket owner/generation checks; distinct live IDs | Index-to-secret mapping, Hyper header serialization |
| Routing and configuration confinement | 8, 10, 14, 15, 16 | `Policy::validate`, `allowed`, origin accessor | URI parser, DNS, TLS name check, no IP-range policy |
| Byte integrity and ordering | 17, 22, 23, 25 | Completed history is an ordered prefix of input; one outstanding write; stale completions rejected | Writer reports the true accepted count; Hyper delivers queued frames |
| Strict audit-before-forwarding | 18 to 22 | Receipt only after commit after sync; receipt matched to exact record; `prepare` bounded by durable offset | Syscall truth, storage contract, single worker, oneshot pairing |
| Crash-safe recovery | 20; process-kill rows | Acknowledged prefix survives a stable prefix; ordered reconstruction under read/checksum contracts | Filesystem and hardware persistence, SHA-256 |
| Cancellation and no replay | Failure rows for disconnect, cancellation, deadline, process kill | `cancel` blocks new tickets while completing issued writes | Tokio cancellation reaches the future; no retry code exists (effect-site table); external proxy retries disabled |
| Resource bounds and safe release | 1, 3, 7, 9, 14, 15, 19, 27 | Registry occupancy, drain rank, queue slots, mailbox slot, per-request chunk bound | Drop order, allocator, dependency allocations ([resource composition](resource-composition.md)) |
| Logging-mode separation | 12, failure row for logger failure | `fail_log` mode-specific transition; same authorization path in both modes | No formal noninterference between modes |
| Honest completion and conditional progress | 26, failure rows, shutdown | Non-refusal postconditions, permanent closure, finite rank | Scheduler fairness, finite polls, timers |

## What this audit does not establish

- There is no single mechanized theorem over the async runtime. The proved
  steps are synchronous transitions; the joins between them are Rust ownership,
  mutex discipline, and drop order, checked by reading and by tests.
- SHA-256, rustls, webpki, DNS, Hyper, Tokio, the allocator, the kernel, and the
  filesystem are trusted. Origin confinement is not an IP-range or SSRF theorem.
- Acceptance into the HTTP channel is not peer receipt, and a logged request is
  not evidence the provider executed or finished it.
- The storage contract excludes power loss, device lies, and malicious rewriting.
- Bodies are logged verbatim; nothing here is a secrecy property for body
  contents, and timing is not constant.
- Availability mode shares the authorization path with strict mode but has no
  formal noninterference proof.
- Test evidence is finite: observed no-replay windows and drain times are not
  universal bounds.
- This is a self-audit against the source at `8102eba`. Independent review has
  not been performed. The effect-site and token tables must be rechecked when
  `transport.rs`, `disk_log.rs`, `http_boundary.rs`, `admission.rs`, or
  `config.rs` change.

## Reproduction

At the audited commit, `cargo test --workspace --locked` passed on macOS arm64
(2026-10-23). The effect-site table comes from this search, which must list only
the sites named above outside `#[cfg(test)]` modules and `tests/` directories:

```sh
grep -rn --include='*.rs' -E 'TcpStream::connect|send_request|\.handshake\(|connect_with|OpenOptions|File::open|File::create|write_all|\.sync\(|sync_all|TcpListener::bind|tokio::spawn|thread::Builder|std::thread::spawn|process::exit|std::env::var' crates/gateway-runtime/src
grep -rn --include='*.rs' -E 'unsafe|assume\(|external_body' crates/gateway-core/src crates/gateway-runtime/src
```

Proofs and deliberate defects are checked by the commands in the
[README](../README.md); CI runs them with the pinned toolchain.


## Milestone 6 HTTP ownership follow-up

The production reader now stores `ReadBuffer`, whose checked transitions retain
the full copied payload charge through partial consumption and return exact read
ranges. Production mailbox receiver destruction now uses
`Mailbox::close_receiver_charged`: clearing the mailbox transfers both the exact
pending item and its charge to `Cleanup`. Extracting it for destruction preserves
the charge; the adapter reports completion only after its destructor returns.
A panic skips that report and the enclosing leased task's completion report.
These changes strengthen the HTTP steps above without changing the historical
line references. Rust destructor behavior, mutex serialization, and the mapping
from HTTP owners to admitted worker/connection slots remain explicit trusted or
unfinished composition joins. Dequeued frames handed to Hyper remain in the
separate dependency allocation account.


## Milestone 6 journal-session follow-up

`Journal` and `AuditJournal` now take the file session explicitly. Checked
transitions preserve that identity; append tickets cannot be substituted across
distinct sessions even when their offsets match. A successful `commit_frame`
issues a receipt carrying that journal's identity. `DiskWorker::run` checks the
worker/job session against the journal before write or sync; mismatch fails the
journal without a storage effect or receipt. Production uses the same random
file-header session for the journal and worker. Session uniqueness and the real
file correspondence remain trusted. The subsequent request-side change adds `JournalBinding`, privately owned by
`Request` and established before its first append. It refuses a different logger
identity on later calls before any append. Stream receipt acceptance now checks
that binding as well as the exact existing record, and invalid receipts cancel
both strict and availability requests. `DiskLog` and `ObservedLog` expose the
actual file session; test loggers must also explicitly implement identity.
The initial logger selection and file correspondence remain trusted. The
end-to-end theorem connecting authorization, concrete destination/credentials,
receipt acceptance, and exact write submission is still unfinished.


## Milestone 6 authorized-write follow-up

Production `Request` now uses `submission::AuthorizedWrite` in prepare, byte
access, and completion. Issuance checks authority/request ownership. Byte access
checks the token against the request, tenant, selector, origin index, and
credential index, then returns the exact live stream-ticket range. The checked
contract also establishes root-policy permission and the strict-mode durable
ceiling. Runtime cross-admission pointer checks remain in place. The existing
transfer driver still borrows those bytes into its single write call and reports
the actual accepted count; cancellation closes access without erasing issued
completion accounting. This does not yet compose concrete URL/secret resolution,
the AsyncWrite target, and journal receipt provenance into the required final
upstream mediation theorem. Those remaining joins stay explicit in milestone 6.


## Milestone 6 receipt-to-write composition follow-up

`OwnedStream::valid` now includes exact receipt evidence for the current chunk.
A successful receipt acknowledgment records the issuing session, tenant, and
direction plus an erased snapshot of the actual `DurableFrame`. The invariant
binds that snapshot to the current owner, chunk, and exact payload. Every body
replacement/discard clears evidence; ticket preparation and partial completion
preserve it. The snapshot adds no runtime payload allocation or retained receipt.
Production `AuthorizedWrite::bytes` checks the current journal designation and
jointly proves policy permission, the exact pending range, and strict-mode
coverage by that valid session-bound receipt. Same-byte later chunks cannot reuse
prior evidence. Availability permits missing audit evidence but retains the same
request/tenant/route/credential checks. Concrete transport direction, URL/secret
resolution and actual writer correspondence still need the remaining mediation
work; this is not yet closure of milestone 6.


## Milestone 6 concrete route and transfer-direction follow-up

Production configuration now calls `ResolvedRoute::resolve` instead of indexing
destination/credential tables in unverified Rust. Its postcondition binds the
actual selected values to the authorized route; both getters recheck request and
route identity. The configuration/secret parser and the meaning of these opaque
values remain trusted. `PreparedRequest` fields are private. Before DNS, TCP, or
TLS, the transport calls `take_upstream`, which checks the configured URI, method,
Host, and credential, converts only the configured path/query to origin form,
and moves the HTTP request once. Socket/TLS naming derives from the immutable
configured destination. HTTP header serialization remains a trusted adapter join.
The upload driver passes Upload to logging, ticket preparation, and byte access;
the response driver passes Download. Strict write access now requires exact
receipt direction, and tickets reject opposite-direction use in either mode.
Tests exercise mismatched metadata, repeated dispatch, strict direction mismatch,
and correct response-direction partial writes. These replace the corresponding
historical transport/configuration joins above, without claiming a proof of
Hyper/TLS/DNS or peer delivery. One explicit composition between the resolved
dispatch owner and the body-write capability remains in milestone 6.


## Milestone 6 final upstream mediation audit

The current production chain is now explicit:

| Boundary | Checked fact / actual adapter binding |
| --- | --- |
| Configuration to resolved dispatch | `ResolvedRoute::resolve` selects the actual immutable destination and credential by the authorized indices, with root-policy permission. `RoutedRequest` privately pairs that owner with the admitted request. |
| Resolved dispatch to HTTP/TLS | `PreparedRequest::take_upstream` validates configured URI, Host, credential, and method before connection effects; transport derives the socket/TLS host from the same configured destination and sends the origin-form request once. These metadata and I/O bindings are trusted Rust, covered by configuration, HTTP boundary, and real TLS exchange tests. |
| Resolved dispatch to every body range | Both production transport directions call `PreparedRequest::copy_body`, forwarding the same `RoutedRequest` owner into `copy_body_bound`. Its resolved `BodyBinding` calls `Request::routed_bytes`, which checks admission identity and invokes `ResolvedRoute::write_bytes`. |
| Core composition | Successful `write_bytes` establishes matching resolved/write/request authority, allowed route/credential, direction, live ticket, and exact pending slice. Strict mode additionally establishes a valid current-chunk receipt with exact tenant/request/chunk/direction/payload and the designated journal session. Availability omits receipt evidence while retaining route/authority/direction checks. |
| Submission and completion | `copy_body_bound` borrows the returned slice into its one `writer.write` call, then accounts the returned count using the same ticket. Upload uses the provider body channel mapped into this request; download uses the response sink. Cancellation blocks further byte access without erasing issued completion accounting. |

This closes the milestone's upstream mediation row under the explicit adapter
assumptions: trusted configuration and secret provisioning, initial logger
selection and unique file-session identity, Rust private ownership/borrows,
truthful async I/O/count/destructor reports, and Hyper/TLS/DNS/OS behavior. The
proof covers body submission, not peer receipt or physical power-loss durability.
The generic public `copy_body` helper deliberately supports embedders with their
own writer mapping; the production HTTPS path always uses the resolved binding.
Tests cover wrong resolved request/route, foreign session, mismatched direction,
exact partial ranges, stale tickets, strict unaudited rejection, availability,
metadata substitution, and real TLS transport. At this checkpoint 237 Verus
checks, the locked workspace suite and six compile-fail doctests pass, and all
208 mutations are rejected. The resource/HTTP ownership composition rows remain
open; closing this row does not claim a whole-runtime memory or scheduling proof.


## Milestone 6 HTTP output-frame follow-up

`Writer::poll_write` now constructs the actual queued payload through
`OutputFrame::copy_prefix` and reports that frame's checked length. The verified
constructor bounds and detaches the exact visible prefix, including when a
caller supplies an oversized frame limit. Construction stays inside the mailbox
callback after its liveness/capacity check. `ChannelBody` consumes the frame's
exact vector into `Bytes`; it introduces no second payload copy. Dependency
retention and destructor probes use a separate test-only message variant so their
custom backing owners remain observable. The production type has only bounded
frames and End. These checks strengthen per-owner sizes, but do not establish
the remaining global HTTP owner count or cross-owner lifecycle composition.


## Milestone 6 HTTP mailbox-byte follow-up

Production mailbox items now use `HttpMessage` from the verified core, including
its exact consuming payload extraction. Its queued-byte and closed-mailbox-plus-
cleanup theorems bound the actual message projection, not a caller-supplied byte
count. End has zero payload; Data owns a bounded OutputFrame. Extraction retains
the cleanup charge until reported completed destruction. The runtime adapter's
mutex, wakers, destruction, and Hyper handoff correspondence remain trusted.
The global HTTP owner-count mapping and cross-owner lifecycle theorem remain
unfinished; these per-mailbox results do not close either remaining milestone row.
