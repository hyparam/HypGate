# Operational limits

Every fixed or configurable limit in the runnable gateway, the behavior when a
caller or peer reaches it, and the evidence behind that behavior. Values are
those compiled into the `loggate` executable or accepted by its configuration
as of 2026-10-24; library callers may choose others within the stated ranges.
"Proved" means a Verus contract covers the count or transition; "tested" means a
workspace or opt-in test exercises the limit; "measured" points at the
[benchmarks](benchmarks.md). None of these limits is a measured memory or latency
bound; see the [resource composition](resource-composition.md) for the
requested-allocation accounting that follows from them.

## Configuration

| Limit | Value | Reached | Evidence |
| --- | --- | --- | --- |
| Request slots (`limits.requests`) | 1 to 65,536; documented example 16 | Admission returns 503 before any upstream connection; readiness stays 200; a released slot is reusable. Slots above the audit queue depth add waiting per frame, not failures. | Proved acquire/release/occupancy; `repeated_overload_preserves_active_streams_health_and_reusable_capacity`, `sustained_overload_preserves_active_streams_and_health`; measured. |
| Chunk size (`limits.chunk_bytes`) | 1 byte to 1 MiB; example 16 KiB; `requests × chunk_bytes` at most 128 MiB | Larger configurations are rejected at startup. The chunk size bounds every core stream chunk and every audit record payload. | `validate_limits` proved; configuration tests. |
| Root policy and candidate route files | 1 MiB each | Startup fails with "invalid configuration". | `config.rs` tests. |
| Destination URL | 8,192 bytes, `https://` only, no query, host at most 253 bytes | Rejected at startup; routing never uses caller URLs. | Configuration confinement proved and tested. |
| Provider credential | 1 to 8,192 printable ASCII bytes from the named environment variable | Startup fails with "missing credential"; the credential never appears in logs. | `check_deployment.sh`; secret-header tests. |
| Gateway token | 1 to 512 bytes; SHA-256 digest compared | Longer or missing tokens are 401 without capacity use. | `authorization_failures_return_capacity_and_drop_reclaims_it`. |
| Logging mode | `strict` or `availability` | Strict refuses forwarding without a durable acknowledgment; availability forwards and counts a gap. | Mode transitions proved; `strict_failed_log`, `availability_failed_log`, `stalled_log_under_load_preserves_health_deadlines_and_mode_policy`. |

## Inbound connections and HTTP

| Limit | Value | Reached | Evidence |
| --- | --- | --- | --- |
| Inbound connection slots | 128 per `Gateway` (library range 1 to 65,536; shared by every listener) | Excess connections are accepted and closed without a worker; canceled connections keep their slot until cleanup finishes. | Proved registry; `incomplete_connections_expire_without_workers_and_capacity_recovers`, `serve_invocations_share_connection_credit_and_reject_limit_changes`. |
| Head read deadline | 10 s | Connection closed before dispatch with no response; no worker or request slot is used. | `incomplete_connections_expire_without_workers_and_capacity_recovers`. |
| Inbound head size and field count | 32 KiB on the wire, 100 fields, one request per connection; the verified parser's limits | 431 before health or route dispatch for a head over either limit, 400 for a malformed head or ambiguous framing; duplicate security-relevant headers are 400. | `inbound_wire_head_and_header_count_limits_apply_before_health_dispatch`. |
| Body read | 32 KiB per socket read into the body reader's one buffer, 16 KiB application mailbox | A slow reader bounds read-ahead to that buffer; chunk sizes are not limited by it. | Verified chunked decoder and framing; mailbox occupancy proved. |
| Connection deadline | 310 s (library range up to 3,600 s) | Connection aborted and its slot released; a truncated body is reported as an error, never a clean end. | `incomplete_connections_expire_without_workers_and_capacity_recovers`, `client_disconnect_before_headers_cancels_request_and_upstream_socket`. |
| Worker slots | Equal to the request limit | 503 "workers unavailable" when exhausted; permanently closed by shutdown. | Drain registry proved; `worker_budget_covers_cleanup_without_consuming_request_slots`. |

## Upstream transport

| Limit | Value | Reached | Evidence |
| --- | --- | --- | --- |
| Exchange deadline | 300 s from dispatch, including DNS wait | 504 before response headers; aborted body after them. Admission is released and nothing is replayed. | Verified `deadline::run`; `tls_trickles_release_every_request_slot_by_the_deadline`, `deadline_drops_connection_and_releases_admission`. |
| DNS lookups | 4 dedicated threads, 32 queued/running lookups or unadopted replies per transport, 64 addresses per answer | The exchange fails with 502 without queuing another lookup; extra addresses are rejected without draining; a stuck lookup keeps its credit and does not block shutdown. | `address_results_are_detached_and_reject_excess_without_draining_iterator`, `departed_lookups_keep_credit_until_blocking_work_finishes`, `panicked_lookup_returns_credit_without_losing_the_pool_worker`. |
| TLS handshake | On the connection thread, under the exchange deadline | Every underlying socket operation uses the remaining exchange budget; expiry gives 504 before headers. TLS computation and OS scheduling are not preempted by this mechanism. | `untrusted_certificate_is_rejected_before_http_credentials_are_sent`, `tls_handshake_and_application_record_trickles_expire`. |
| TLS buffers and session cache | 64 KiB application buffer, 256 cached sessions | Oversized handshake messages fail before any upload; the cache evicts rather than grows. | `oversized_handshake_is_rejected_from_its_length_before_upload`, `tls_session_cache_bounds_servers_and_tickets_without_disabling_resumption`. |
| Upstream head size and field count | 32 KiB, 100 fields, including the status line | 502 before any response headers are forwarded. | `upstream_wire_head_and_header_count_limits_cover_status_line`. |
| Bodyless upstream statuses | 204 and 304 | Any body bytes are a 502; completion is still required. | `bodyless_status_refuses_payload_and_an_unfinished_stream_is_truncated`. |

## Audit log

| Limit | Value | Reached | Evidence |
| --- | --- | --- | --- |
| Queued records | 16 (library range 1 to 1,024) | A full queue parks the append, in arrival order, until the worker frees a slot; nothing is reserved, allocated, or encoded while waiting, and a canceled waiter leaves no reservation. The acknowledgment deadline covers the wait, so if no slot frees in time the append fails and health closes exactly as for a late acknowledgment (strict: 502 before headers or an aborted body, then readiness 503; availability: one gap). Each request has at most one append outstanding, so at most `limits.requests` appends ever wait. No worker is replaced. | FIFO and reservation proved; `production_enqueue_preserves_pairing_waits_while_full_and_refuses_closed_before_encoding`, `full_queue_parks_excess_work_before_allocation_and_serves_it_in_order`, `slot_wait_is_bounded_by_the_deadline_and_poisons_health`; measured by `queue_contention` and the sweep at 32 concurrent requests. |
| Record payload | The larger of `chunk_bytes` and 8,210 bytes; hard maximum 1 MiB | Larger records cannot be constructed. Body chunks are at most `chunk_bytes`; the request-start record is 18 bytes plus the destination, the response head 10 bytes, the completion 25 bytes. A library logger whose limit is below a metadata payload refuses that append without poisoning health (`failed_start_record_refuses_in_strict_mode_and_forwards_with_one_gap_in_availability_mode`). | Framing and codec proofs; `metadata_records_roundtrip_through_disk_and_scanner`. |
| Recorded destination | 1 to 8,192 bytes, the configured text | Bounded by the destination limit above, so the executable never exceeds it. | Codec proof; `request_start_roundtrips_within_destination_bounds`. |
| Synced-record rate | Storage dependent: about 125 to 210 records of 16 KiB per second on the benchmark laptop, about 1,800 on the Ubuntu CI runner's virtual disk | Every record is written and synced by one disk worker in both modes while the log is healthy, so sustained payload throughput is the synced-record rate times `chunk_bytes`, and each forwarded frame waits behind one synced write per concurrent stream. | Measured: concurrency sweep, long streams, and 1 MiB uploads in the [benchmarks](benchmarks.md#broader-workloads). |
| Acknowledgment deadline | 2 s (library range up to 300 s), measured from the append call and including any wait for a queue slot | Health closes permanently. Strict: a request whose start record expires gets 503 with no upstream connection; one whose body or response-head append expires gets 502 before headers or an aborted body; later requests are refused with 503 at dispatch, and readiness becomes 503. Availability: gap counter increments once per request. | `stalled_log_under_load_preserves_health_deadlines_and_mode_policy`. |
| Storage faults | Full or read-only filesystem, process death, abrupt guest power cut | Acknowledged prefix survives; scan reports a complete, incomplete, or corrupt tail without modifying the file. | `filesystem_full_preserves_acknowledged_prefix_and_fails_closed`, `filesystem_read_only_refuses_logger_startup`, crash tests on Linux ext4; six [QEMU guest power-cut trials](storage-crash-contract.md#guest-power-cut-experiment). Host/device power loss remains unvalidated. |
| Log file reuse | Never | Startup refuses an existing path and leaves it unchanged. | `check_deployment.sh`. |

## Cloud shipping (optional)

| Limit | Value | Reached | Evidence |
| --- | --- | --- | --- |
| Shipping server | One `https://` URL, same validation as destinations | Rejected at startup; the shipper has no other destination. | `shipping_section_is_optional_and_validated`. |
| Operator token | 1 to 512 visible ASCII bytes from the named environment variable | Startup fails with "missing token"; the token never appears in state files, logs, or rows. | Executable test; `ships_exchanges_once_with_stable_ids_and_resumes_from_checkpoint`. |
| Open exchanges and pending rows (`max_open_exchanges`) | 1 to 65,536; default 64 | The oldest open exchange is evicted as `incomplete`; a full row queue pauses reading until a batch resolves. | Assembler bound proved; drain-mode test. |
| Retained bytes per exchange (`max_exchange_bytes`) | 4 KiB to 16 MiB; default 1 MiB | Further body bytes are counted and dropped; the rows say `truncated`. | Prefix bound proved; `assembler_interleaves_requests_and_truncates_at_the_cap`. |
| Batch | 5,000 rows, 4 MiB, whole exchanges only | The batch is sent and the next one starts; an exchange that fits no batch is poisoned. | `BatchBuilder` proved; drain-mode test. |
| Request deadline and reply | 30 s, 64 KiB reply | Counted as a transport failure and retried after 2, 4, 6 s, then 30 to 300 s. | `transport_delay` proved; shutdown-under-hang test. |
| Throttling | `Retry-After` clamped to 1 to 300 s, else 30/60/120/300 s | The same batch is retried under the same id. | `throttle_delay` proved; recovery test. |
| Poison | 400, 413, 415, 422 | Multi-exchange batches are retried one exchange at a time; the isolated exchange is skipped and counted in `loggate_shipping_poisoned_batches_total`. | Recovery test. |
| Enrollment | Credential renewed inside 24 h of expiry or once after a 401; re-enrolled after a rejected refresh; `service_token_revoked` / `service_account_disabled` stop the shipper permanently | `loggate_shipping_stopped 1`; nothing else changes. | `Enrollment` proved; recovery test. |
| Shutdown window | 2 s after request workers and the logger | A thread inside a request is left to finish; no replacement. | `shutdown_returns_within_its_window_while_the_server_hangs`. |

## Shutdown

| Limit | Value | Reached | Evidence |
| --- | --- | --- | --- |
| Drain window | 10 s after SIGTERM or SIGINT | Remaining connections are aborted and remaining workers canceled through the shared token; admission stays closed. | Permanent closure and rank proved; `shutdown_with_blocked_disk_returns_error_without_replacement_or_replay`; [shutdown proof](shutdown-proof.md). |
| Logger join window | 2 s after workers stop | `serve` returns an error; the blocked worker is never replaced and a running syscall is not interrupted. | Same tests. |

## Measured behavior at and below these limits

The [benchmarks](benchmarks.md) report throughput, first-byte and completion
latency, client-observed inter-frame gaps, and gateway-only resident memory for
both logging modes at concurrency one through 32, with paced 4 MiB and 32 MiB
streams, 1 MiB uploads, 128 requests at 32 concurrent against the 16-record audit
queue (all complete in both modes, with the frame gap doubling while appends wait
for slots), permanent logging failure, a blocked disk worker, ten minutes of
admission overload per mode, and 100-wave memory soaks. Those numbers are
single-machine observations. No release performance threshold has been set,
and no table above turns a logical limit into a memory, CPU, or latency guarantee.
