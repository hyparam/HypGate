# Operational limits

Every fixed or configurable limit in the runnable gateway, the behavior when a
caller or peer reaches it, and the evidence behind that behavior. Values are
those compiled into the `soundgate` executable or accepted by its configuration
at commit `553ba36`; library callers may choose others within the stated ranges.
"Proved" means a Verus contract covers the count or transition; "tested" means a
workspace or opt-in test exercises the limit; "measured" points at the
[benchmarks](benchmarks.md). None of these limits is a measured memory or latency
bound; see the [resource composition](resource-composition.md) for the
requested-allocation accounting that follows from them.

## Configuration

| Limit | Value | Reached | Evidence |
| --- | --- | --- | --- |
| Request slots (`limits.requests`) | 1 to 65,536; documented example 16, matching the audit queue depth | Admission returns 503 before any upstream connection; readiness stays 200; a released slot is reusable. | Proved acquire/release/occupancy; `repeated_overload_preserves_active_streams_health_and_reusable_capacity`, `sustained_overload_preserves_active_streams_and_health`; measured. |
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
| Header read deadline | 10 s | Connection closed before dispatch; no worker or request slot is used. | `incomplete_connections_expire_without_workers_and_capacity_recovers`. |
| Inbound head size and field count | 32 KiB on the wire, 100 fields, one request per connection | 431 before health or route dispatch; duplicate security-relevant headers are 400. | `inbound_wire_head_and_header_count_limits_apply_before_health_dispatch`. |
| Body frame | 32 KiB per HTTP body frame, 16 KiB application mailbox | Larger frames are rejected and never retained; a slow reader bounds read-ahead. | `oversized_input_frame_is_rejected_without_retention_or_resumption`, `incoming_body_read_ahead_stays_bounded_with_a_slow_reader`; mailbox occupancy proved. |
| Connection deadline | 310 s (library range up to 3,600 s) | Connection aborted and its slot released; a truncated body is reported as an error, never a clean end. | `incomplete_connections_expire_without_workers_and_capacity_recovers`, `client_disconnect_before_headers_cancels_request_and_upstream_socket`. |
| Worker slots | Equal to the request limit | 503 "workers unavailable" when exhausted; permanently closed by shutdown. | Drain registry proved; `worker_budget_covers_cleanup_without_consuming_request_slots`. |

## Upstream transport

| Limit | Value | Reached | Evidence |
| --- | --- | --- | --- |
| Exchange deadline | 300 s from dispatch, including DNS wait | 504 before response headers; aborted body after them. Admission is released and nothing is replayed. | `deadline_drops_connection_and_releases_admission`. |
| DNS lookups | 4 dedicated threads, 32 queued or running lookups per transport, 64 addresses per answer | The exchange fails with 502 without queuing another lookup; extra addresses are rejected without draining; a stuck lookup keeps its credit and does not block runtime shutdown. | `address_results_are_detached_and_reject_excess_without_draining_iterator`, `canceled_lookups_keep_credit_until_blocking_work_finishes`, `stalled_lookup_does_not_block_tokio_runtime_shutdown`. |
| TLS handshakes | 4 dedicated threads, 32 queued or running handshakes per transport | 502 without a replacement thread; canceled handshakes keep state and credit until their poll returns. | `blocked_poll_keeps_credit_without_blocking_executor_or_replacements`, `canceled_queued_handshake_is_never_polled`, `cancellation_destroys_handshake_state_before_reusing_credit`. |
| TLS buffers and session cache | 64 KiB application buffer, 256 cached sessions | Oversized handshake messages fail before any upload; the cache evicts rather than grows. | `oversized_handshake_is_rejected_from_its_length_before_upload`, `tls_session_cache_bounds_servers_and_tickets_without_disabling_resumption`. |
| Upstream head size and field count | 32 KiB, 100 fields, including the status line | 502 before any response headers are forwarded. | `upstream_wire_head_and_header_count_limits_cover_status_line`. |
| Bodyless upstream statuses | 204 and 304 | Any body bytes are a 502; completion is still required. | `bodyless_status_rejects_payload_or_missing_completion`. |

## Audit log

| Limit | Value | Reached | Evidence |
| --- | --- | --- | --- |
| Queued records | 16 (library range 1 to 1,024) | A full queue refuses the append immediately; nothing waits for a slot. Strict mode then fails the request with 502 before headers or an aborted body after them; availability mode forwards and records a gap. Each request has at most one append outstanding, so `limits.requests` at or below 16 can never reach this limit; above it, bursts do. Logger health is unaffected and no worker is replaced. | FIFO and reservation proved; `production_enqueue_preserves_pairing_and_refuses_full_or_closed_before_encoding`; measured by `queue_saturation` at 32 concurrent requests. |
| Record payload | Equal to `chunk_bytes`; hard maximum 1 MiB | Larger records cannot be constructed. | Framing proof. |
| Synced-record rate | Storage dependent; about 125 to 210 records of 16 KiB per second on the benchmark laptop | Every record is written and synced by one disk worker in both modes while the log is healthy, so sustained payload throughput is the synced-record rate times `chunk_bytes`, and each forwarded frame waits behind one synced write per concurrent stream. | Measured: concurrency sweep, long streams, and 1 MiB uploads in the [benchmarks](benchmarks.md#broader-workloads). |
| Acknowledgment deadline | 2 s (library range up to 300 s) | Strict: 503 before headers or an aborted body; readiness becomes 503. Availability: gap counter increments once per request. | `stalled_log_under_load_preserves_health_deadlines_and_mode_policy`. |
| Storage faults | Full or read-only filesystem, process death | Acknowledged prefix survives; scan reports a complete, incomplete, or corrupt tail without modifying the file. | `filesystem_full_preserves_acknowledged_prefix_and_fails_closed`, `filesystem_read_only_refuses_logger_startup`, crash tests on Linux ext4. |
| Log file reuse | Never | Startup refuses an existing path and leaves it unchanged. | `check_deployment.sh`. |

## Shutdown

| Limit | Value | Reached | Evidence |
| --- | --- | --- | --- |
| Drain window | 10 s after SIGTERM or SIGINT | Remaining connections are aborted and remaining workers canceled through the shared token; admission stays closed. | Permanent closure and rank proved; `shutdown_with_blocked_disk_returns_error_without_replacement_or_replay`; [shutdown proof](shutdown-proof.md). |
| Logger join window | 2 s after workers stop | `serve` returns an error; the blocked worker is never replaced and a running syscall is not interrupted. | Same tests. |

## Measured behavior at and below these limits

The [benchmarks](benchmarks.md) report throughput, first-byte and completion
latency, client-observed inter-frame gaps, and gateway-only resident memory for
both logging modes at concurrency one through 32, with paced 4 MiB and 32 MiB
streams, 1 MiB uploads, 32 concurrent requests against the 16-record audit queue
(62 of 128 strict requests failed honestly; availability completed all 128 with
60 gaps), permanent logging failure, a blocked disk worker, ten minutes of
admission overload per mode, and 100-wave memory soaks. Those numbers are
single-machine observations. No release performance threshold has been set,
and no table above turns a logical limit into a memory, CPU, or latency guarantee.
