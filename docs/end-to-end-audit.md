# End-to-end audit: authorization through network and disk effects

This document traces one request through the production source,
from the inbound socket to the exact upstream TCP/TLS/HTTP calls and the exact
audit-file write/sync calls, then through every failure exit and graceful
shutdown. Each step names the code by symbol, states whether the step is
**proved** (a Verus contract in `gateway-core`), **tested** (a runtime test
exercises it), or **assumed** (trusted code or an external contract), and names
the evidence. It is a source-level traceability record made by reading the code,
not an independent review or a mechanized proof of the threaded runtime. Recheck
symbol names when the named modules change.

Work ownership: the connection thread's work and the exchange it runs are each
run under a lease by the private `server/leased.rs::run`, with `ConnectionLease`
(`server/connections.rs`) and `WorkerLease` (`server/workers.rs`). It starts a
verified `TaskCredit`, runs the work, which drops its captures (sockets, readers,
writers, the prepared request) before returning, records cleanup, and only then
drops the lease, which returns the credit through a verified gate that refuses
release while running or cleaning. A panic in the work drops the lease while
unwinding with the credit still running: the credit is stranded and worker
admission closes. Destructor correspondence remains a trusted join.

DNS pool: `credited_job::CreditedJob` and `Reply`. Queued/running lookups and
unread replies keep their own verified credit. The transport waits for the reply
under the exchange deadline (`Pending::wait`) and calls `Reply::adopt` before
TCP use; the target request's actual registry and stream supply the verified
`handoff_to` check. Only a live admitted target enables background release.
Dropped replies destroy their result first. There is no TLS pool: the handshake
runs on the connection thread.

Disk: `disk_worker::DiskWorker` owns the queue-to-active transfer, the
write/sync/commit sequence, and session/generation-checked release. The runtime
queue uses its `take` while locked; the worker thread uses `run`, consuming
`deliver`, then `release`. The actual file effects are isolated in
`disk_log::Storage`, and consuming oneshot delivery in `disk_log::Completion`.
Those adapter contracts remain trusted; the sequencing, exact frame binding,
active credit, and Q+1 bound are checked. See
[audit-buffer ownership](audit-buffer-lifetimes.md).

Related records: the [proof index](proof-index.md) lists every contract, the
[ownership composition](ownership-composition.md) records the lifecycle proofs, the
[storage contract](storage-crash-contract.md) and [shutdown proof](shutdown-proof.md)
cover disk and termination, and the [resource composition](resource-composition.md)
covers memory. This document composes them along one request path and lists
what still has no theorem.

## Every external effect site in production source

A grep of the non-test runtime source for socket, file, thread, process, and
environment operations finds only these sites. Code under `#[cfg(test)]` and in
`tests/` directories is excluded. `gateway-core` performs no I/O and forbids
`unsafe`; neither crate contains `assume`, `external_body`, or `unsafe`.

The socket, name-lookup, listener, file-write, and secret-read sites are also
enforced mechanically: `clippy.toml` disallows those methods throughout
`gateway-runtime` (`#![deny(clippy::disallowed_methods)]` in both crate
roots), each audited site is marked `#[allow(clippy::disallowed_methods)]`
with an "Effect site" comment, and `scripts/check_effect_sites.sh` fails when
the set of marked sites differs from its pinned list, and when the runtime
crate mentions an async executor at all. The two outbound socket sites take an
`egress::Egress` permit: the provider one is minted by the verified core from
the request's resolved route, the cloud one only from the parsed `shipping`
section's `ShippingServer`. The third socket site connects only to the
gateway's own listener, to wake its blocking accept on shutdown.

| Effect | Production site | What must already hold when it runs |
| --- | --- | --- |
| Listen on loopback | `TcpListener::bind` in `main.rs::bind` | `run` rejects a non-loopback address before loading configuration; configuration and audit log already created |
| Read root policy, routes, and secrets | `main.rs::bounded_file` and `std::env::var` in `main.rs::secret` | Startup only; bounded file reads, secrets from environment through `GatewayConfig::from_json` and `ShippingConfig::from_root_json` |
| Accept inbound connection | `listener.accept()` in `server::serve` | Connection credit from `ConnectionSlots::acquire` over the verified `ResourceAdmission`; without one the socket is closed unanswered |
| Start a connection thread and its watcher | `thread::Builder::spawn` in `server::serve` (512 KiB stack) and `server::ClientWatch::start` (64 KiB) | The connection lease is moved into the thread and spent by `leased::run`; the watcher only peeks the client socket and fires the exchange's `net::Cancel` |
| Wake the accept loop | `TcpStream::connect_timeout` in `server::wake_accept` | Only from `Shutdown::trigger`, to the address the listener bound; the loop checks the flag before serving what it accepted |
| Run the exchange | `leased::run` of the worker lease in `server::serve_connection`, calling `Gateway::run_exchange` | Worker credit from `WorkerSlots::acquire` over the verified `WorkerRegistry`/`DrainRegistry`; all four HTTP roles issued by its `WorkerHttp` |
| DNS lookup | `Resolver::resolve` (`transport/resolver.rs`) | Called only from `HttpsTransport::run` with a `PreparedRequest` borrowed; host and port read from its destination; the wait is bounded by the exchange deadline |
| Upstream TCP connect | `TcpStream::connect_timeout` in `transport::open_socket` | Same owner; addresses come only from the adopted lookup of the configured destination host/port; each attempt gets the deadline's remaining time; the socket is registered with the exchange's `net::Cancel` |
| Upstream TLS handshake | rustls `ClientConnection::complete_io` in `net::Timed::handshake`, on the connection thread | `ServerName` built from the configured destination host in `HttpsTransport::run`; socket timeouts re-armed from the exchange deadline before each step |
| Upstream HTTP request, including the provider credential header | `write_fully` of the head the verified `http1_exchange::Upstream::request` produced, then `http1::ChunkedWriter` for the body, in `HttpsTransport::run` | Head fields built only by `http_boundary::prepare` and rechecked by `PreparedRequest::take_upstream`; the writer's bytes are proved to be the head for those fields |
| Response bytes to the client | `server::Output`, which asks the verified `Connection` machine for every byte: `respond_fixed` or `respond_stream` for the head, `http1::ChunkedWriter` for each frame the body copy writes, `finish` for the last chunk | Head sent once by `Output::start`; body bytes come only from `copy_body`; an error after the head aborts without the last chunk |
| Create audit file, write/sync header, sync parent directory | `DiskLog::create_with_payload_limit` | Startup only; `create_new`, mode 0600, path chosen by the operator |
| Audit record write and sync | `Storage::write_all`/`Storage::sync` called by `DiskWorker::run` on the worker thread started in `DiskLog::start_limited` | One worker thread; frame came through the verified queue reservation |
| Read audit file for recovery | `LogReader::new`/`LogReader::next_record` over `disk_log::ReadSource` | Read-only; never truncates, appends, or replays |
| Dedicated threads | `DiskLog::start_limited` (1), `Resolver::with_limit` (4), `shipping::Shipper::spawn` (1, only with a `shipping` section); plus one connection thread and one watcher per accepted connection, at most C of each | Fixed counts at construction; never replaced after a timeout; connection threads are bounded by the connection credits |
| Read the cloud token | `main.rs::secret` through `ShippingConfig::from_root_json` in `run` and `ship` | Startup only; the value moves into the verified machine and is never held by `GatewayConfig` |
| Open the audit log for shipping | `File::open` in `shipping::Engine::{open_session,read}` (the `Effects` implementation the verified driver calls) | Read-only handle on the operator's log path; the verified scanner never writes |
| Write shipper state | `OpenOptions` (create-new, 0600), `write_all`, `sync_all`, `fs::rename` in `shipping::state::write_private` | Only `identity.json` and `checkpoint.json` under the configured state directory; contents are the server credential, a token fingerprint, and counters |
| Cloud DNS, TCP, TLS, and HTTP | `to_socket_addrs` and `TcpStream::connect_timeout` in `shipping::client::open_socket` under an `Egress::cloud` permit; rustls `ClientConnection::complete_io`, then `write_all`, `http1::read_status_head`, and `http1::BodyReader` over the deadline-armed socket in `shipping::client::Client::request` | Blocking sockets and rustls directly; every read and write runs under the request deadline by socket timeout (`net::Timed`). Host and port come only from the `ShippingServer` the configuration parser built; the request itself was chosen by the verified machine; called only from the shipper thread with the server-issued credential, never a provider credential |

No other `connect`, `write_all`, `sync_all`, thread spawn, or file-open call
exists in production runtime source outside `server.rs`, `transport.rs`,
`disk_log.rs`, `credited_job.rs`, and the `shipping` module. For sockets,
lookups, listeners, file writes, and secret reads this is lint-enforced (see
above); for `write_all`, `sync_all`, and thread spawns it remains review
evidence that must be rechecked when those modules change. The effect-site script and
clippy run are part of the documented checks.

## Mediation tokens and who can construct them

| Token | Only constructor | Private evidence it carries |
| --- | --- | --- |
| `policy::Authenticated` | `Policy::authenticate` | Proved: digest equals some identity in a valid policy |
| `policy::AuthorizedRequest` | `Authenticated::authorize` | Proved: route belongs to that tenant and selector, request ID nonzero, route is `allowed` by root grants, credential owner equals tenant |
| `owned_stream::OwnedStream` | `OwnedStream::claim` | Proved: stream owner equals the authority's request ID, slot owned by the registry, strict flag recorded, empty initial body |
| `admission::Request` | `Admission::admit` | Trusted Rust pairing the above with a private `JournalBinding`; `Lease::drop` retires the stream under the registry lock |
| `resolved_route::ResolvedRoute` | `ResolvedRoute::resolve` | Proved: destination and credential are the entries at the granted route's indices, bound to that authority |
| `config::RoutedRequest` | `GatewayConfig::admit` | Trusted pairing of the resolved route with the admitted request; destination URI and credential come only from the resolved route |
| `http_boundary::PreparedRequest` | `http_boundary::prepare` | Trusted: upstream head with configured Host, configured credential, filtered client headers; `take_upstream` rechecks it against the route before any network effect |
| `submission::AuthorizedWrite` | `Request::prepare` through `AuthorizedWrite::prepare` | Proved: ticket bound to the authority's request, tenant, route, direction (0 or 1 only), and live stream ticket; in strict mode the receipt behind it decodes to a body-kind header for that direction, never to a metadata record |

None of these has a public field, public constructor, `Clone`, or deserializer.
Compile-fail doctests in `owned_stream.rs` check that raw stream creation
and raw claim/release do not compile outside the core. `HttpsTransport::exchange`
borrows the `PreparedRequest` for the whole exchange and takes no destination or
credential parameter; `RoutedRequest::credential_header` is `pub(crate)`. Tested:
`tokens_cannot_switch_to_another_policy`, `tickets_from_independent_registries_are_rejected`,
`outstanding_ticket_cannot_advance_replacement_request`.

## Trace of one successful request

Status key: P proved, T tested, A assumed.

| Step | Code | Status | Evidence and scope |
| --- | --- | --- | --- |
| 1. Accept and connection credit | `serve` accept loop; `ConnectionSlots::acquire` over `ResourceAdmission`; one thread per accepted connection | P/T/A | Acquire/release contracts proved. Excess sockets closed. The head limits (100 fields, 32 KiB) are the verified parser's (P); the 32 KiB read buffer, the 10 s head deadline, and the connection deadline are the adapter's (T). T: `incomplete_connections_expire_without_workers_and_capacity_recovers`, `serve_invocations_share_connection_credit_and_reject_limit_changes`, `inbound_wire_head_and_header_count_limits_apply_before_health_dispatch`. |
| 2. Health endpoints need no credit | `Gateway::endpoint`, `/metrics`, `/healthz`, `/readyz` branches | P/T | Answered before worker admission. Readiness is the verified `health::readiness` of the sampled flags: it fails on poisoned/closed registries and on unhealthy strict logging, and availability mode never fails on the log (P). T: `poisoned_admission_is_unready_and_fail_closed_in_both_logging_modes`, `poisoned_worker_registry_is_unready_and_fail_closed_in_both_modes`. |
| 3. Worker credit before any request allocation | `WorkerSlots::acquire` in `serve_connection` | P/T | `WorkerRegistry::acquire` over `DrainRegistry::acquire` proved exact occupancy and refusal when full or closed. 503 without a lease. T: `worker_budget_covers_cleanup_without_consuming_request_slots`, `concurrent_workers_hold_credit_until_their_threads_finish`. |
| 4. Exchange owned before its lease | `leased::run` with the worker lease in `serve_connection`; the client watcher and shutdown cancel through `net::Cancel` | P/T/A | `TaskCredit` gates release on completed cleanup. The work's captures (sockets, readers, writers, prepared request) drop before the credit returns; a panic strands it and closes admission. A: Rust drop order and socket shutdown semantics. T: `captures_drop_before_worker_credit_returns`, `a_panicking_exchange_strands_its_credit_and_closes_admission`. |
| 5. Metadata boundary | `serve_connection` → `http_boundary::prepare` → `inbound::{route_selector,bearer}`, `headers::check_request` | P/T | POST only and origin form only (T); proved: the selector is accepted exactly for `/routes/<canonical decimal u64>`, the token exactly for one Authorization field holding `Bearer` plus one to 512 token characters, head within 100 fields and 32 KiB, `content-encoding`, `upgrade`, `trailer` rejected, duplicate `content-type` or `anthropic-version` rejected, every Connection element validated, all before a slot is taken. T: `malformed_authentication_never_issues_a_prepared_request`, `caller_cannot_select_an_arbitrary_url_path_or_method`, `connection_nominations_are_stripped_but_cannot_suppress_root_credentials`, `invalid_and_oversized_headers_do_not_leak_admission_slots`. |
| 6. Authentication | `GatewayConfig::admit`: SHA-256 of the token, then `Policy::authenticate` inside `Admission::admit` | A/P | SHA-256 and token provisioning assumed. Proved: success iff the digest equals an identity digest in a valid policy; digest comparison scans every byte but has no constant-time theorem. |
| 7. Request slot | `Admission::admit` → `ResourceAdmission::acquire` | P/T | Proved: occupancy plus one, distinct live IDs, refusal when full. Any later early return drops the lease and releases the key. T: `authorization_failures_return_capacity_and_drop_reclaims_it`, `concurrent_handlers_share_one_capacity_registry`. |
| 8. Authorization | `Authenticated::authorize` inside `Admission::admit` | P | Proved: the returned token's route has the authenticated tenant and requested selector, nonzero request ID, and is in the root grants with a credential owned by that tenant. Candidate routes cannot enlarge grants (`Policy::validate`). T: `candidate_configuration_cannot_expand_root_grants`, `untrusted_configuration_cannot_change_destinations_or_ownership`. |
| 9. Stream bound to slot and authority | `OwnedStream::claim` inside `Admission::admit` | P | Proved: stream owner equals the token's request ID, capacity equals the configured chunk, strict flag recorded, one creation per key. |
| 10. Destination and credential binding | `GatewayConfig::admit` calls `ResolvedRoute::resolve` over `destinations`/`credentials` | P/A | Proved to select the entries at the granted route's indices and to hand them out only for the bound authority. Index-to-URI and index-to-secret mapping is trusted but immutable after startup; `config::destination` admits only `https://`, ASCII DNS or bracketed IPv6 host, numeric port, no userinfo, query, or percent escapes. T: `native_provider_endpoints_keep_their_own_credentials`, `malformed_or_ambiguous_destinations_are_rejected`. |
| 11. Upstream head | `headers::forward_request` in `http_boundary::prepare`, rechecked by `PreparedRequest::take_upstream` | P/T | Proved: only allowlisted client headers, each a copy of an input field and none Connection-nominated; exactly one Host (the configured authority), exactly one credential (sensitive), exactly one `accept-encoding: identity`; the client's `authorization` never leaves. URI is the configured destination, converted to origin form once (T). T: `fixed_destination_and_credentials_replace_host_and_client_secrets`. |
| 12. Strict pre-check | `Gateway::run_exchange`, before the start record | T | If strict logging is already unhealthy, 503 before any DNS, TCP, or TLS work. T: `strict_log_failure_prevents_even_upstream_connection`. |
| 12a. Request-start record (kind 2) | `PreparedRequest::audit_request_start` → `Request::audit_metadata` → `DiskLog::append`, before `exchange` | P/T | Payload from the verified `exchange_lifecycle::start_record`: the clock, the authorized route's selector, and the configured text of the resolved destination, proved to decode to exactly those (P); chunk 0, which no body record uses (P). `JournalBinding::bind` fixes the session; the receipt is checked against the exact record but authorizes nothing. Strict: acknowledgment required before dispatch, else 503 with no upstream connection. Availability: a failed append marks the request log-failed and counts one gap. T: `failed_start_record_refuses_in_strict_mode_and_forwards_with_one_gap_in_availability_mode`, `metadata_records_use_chunk_zero_and_never_authorize_body_writes`, `stalled_log_under_load_preserves_health_deadlines_and_mode_policy`. |
| 13. Exchange deadline and ownership | `HttpsTransport::exchange` runs `run` under a `net::Deadline` whose remaining time arms every socket timeout, lookup wait, and connect (`net::Timed`), borrowing the `PreparedRequest`; the exchange's `net::Cancel` shuts its sockets when the client leaves or the gateway shuts down, and the failure is reported as `Fault::Cancelled` | T/A | `PreparedRequest` outlives `run`, whose socket, TLS state, readers, and writers are locals, so network state drops before the slot can release. A: OS socket timeouts and shutdown semantics. T: `deadline_drops_connection_and_releases_admission`, `cancelling_tls_handshake_drops_socket_and_returns_owned_request_credit`. |
| 14. Name resolution | `Resolver::resolve` then `Reply::adopt` in `HttpsTransport::run` | P/T/A | Host and port are the verified destination parts of the permit's target (`destination::parse`), never request fields. Four threads, 32 credits, at most 64 addresses; saturation fails the exchange. Adoption proved to require a live admitted target. A: system resolver, no IP-range policy (not an SSRF theorem). T: resolver tests in `transport/resolver.rs`. |
| 15. TCP and TLS | `transport::open_socket` and `net::Timed::handshake` in `HttpsTransport::run` | A/T | rustls with webpki roots verifies the configured host name; early data off, certificate decompression off, 64 KiB application buffer, 256-entry session cache. The handshake runs on the connection thread under the exchange deadline. A: rustls, webpki, PKI. T: `tls_exchange_preserves_native_payloads_and_scoped_credentials`, `untrusted_certificate_is_rejected_before_http_credentials_are_sent`, `trusted_certificate_with_large_wrong_purpose_list_is_rejected_before_upload`, `oversized_handshake_is_rejected_from_its_length_before_upload`. |
| 16. HTTP/1 client head | `http1_write::write_request_head` then `http1::read_status_head` in `HttpsTransport::run` | P/T | The request head is the verified writer's bytes for the projection's fields plus `transfer-encoding: chunked` and `connection: close`, with the configured destination's origin-form path (P). The status head is parsed by the verified parser within the same limits as inbound; 1xx other than 101 are skipped, 101 is refused (T). No separate connection thread, redirect following, pooling, or retry. T: `redirects_are_returned_without_opening_a_second_connection`, `upstream_wire_head_and_header_count_limits_cover_status_line`. |
| 17. Upload copy | `PreparedRequest::copy_body(Upload)` → `transfer::copy_body_bound` driving `body_copy::BodyCopy` | P/T | The machine names each effect and the loop performs it (P). Per chunk: `begin_read`/`finish_read` (proved: at most one retained chunk across stream and read buffer), then `audit_record`/`finish_audit`, then write tickets; proved to finish only on a clean end of input with nothing pending and to count exactly the accepted bytes. T: `multichunk_partial_writes_follow_durable_logs_and_preserve_bytes`, `real_socket_backpressure_preserves_fragmented_sse_bytes`. |
| 18. Audit record construction | `BodyCopy::audit_record`, calling `StreamChunk::audit_record` | P | Proved: header tenant equals the authority's tenant, request equals both the authority's and the stream's owner, chunk equals the current chunk, payload length and bytes equal the current body, stream neither closed nor failed. Caller headers never enter the record. `JournalBinding::bind` fixes the logger session before the first append. |
| 19. Queue reservation and encoding | `DiskLog::append` → `Queue::enqueue` | P/T/A | Health check, payload limit, nonzero request. A full queue parks the caller on a condition variable under the queue lock until the worker pops a job or the append deadline passes; the deadline covers the wait and the acknowledgment and poisons health on expiry. `FrameQueue::reserve`/`encode_reserved`/`finish_reserved` proved: slot reserved before encoding, payload limit enforced, FIFO order and completion pairing preserved, permanent closure. Encoding permit is single use. A: condition-variable wakeups and `mpsc` receipt delivery. T: `production_enqueue_preserves_pairing_waits_while_full_and_refuses_closed_before_encoding`, `closing_wakes_waiting_callers_without_constructing_their_jobs`, `expired_waiter_leaves_no_reservation_and_later_callers_proceed`, `full_queue_parks_excess_work_before_allocation_and_serves_it_in_order`, `slot_wait_is_bounded_by_the_deadline_and_poisons_health`. |
| 20. Durable write | Worker thread in `DiskLog::start_limited`: `Queue::recv` (`DiskWorker::take`), then `DiskWorker::run` | P/A | `AuditJournal::begin`, then `Storage::write_all`, then `Storage::sync`, then `commit_frame`, in a session-checked journal. Proved: a receipt exists only if the commit matched the ticket, the frame length, and a non-failed journal of that session; the acknowledged history is the prior history plus exactly this frame; `durable_commit_without_sync` mutation fails. A: syscalls report truth, storage preserves synced bytes ([storage contract](storage-crash-contract.md)). T: `strict_transfer_and_real_disk_records_have_identical_payloads`, `actual_file_acknowledgments_are_readable_and_existing_files_are_not_overwritten`, `kill_after_ack_preserves_the_acknowledged_record`. |
| 21. Receipt delivery and acknowledgment | `Completion::complete` oneshot to the copy loop, then `BodyCopy::finish_audit` → `OwnedStream::acknowledge_receipt` | P/T | Proved: acknowledgment succeeds iff the receipt matches the bound journal session and its record equals the canonical encoding of this exact header and body plus checksum; then durable offset equals body length, the receipt snapshot is bound to the current chunk, and nothing else in the stream changes. T: `mismatched_durable_receipts_never_authorize_forwarding`, `durable_receipt_matches_exact_metadata_and_payload`. |
| 22. Write tickets | `BodyCopy::write_bytes`/`finish_write` through `AuthorizedWrite` and `ResolvedRoute::write_bytes` | P/T | Proved: `prepare` in strict mode offers only durable-covered bytes; `write_bytes` returns the exact unsent slice only for the matching authority, allowed route/credential, direction, and live ticket, with a valid current-chunk receipt in strict mode; `complete` requires a matching owner and generation and advances by the accepted count; completed history is an unchanged ordered prefix of input. T: `zero_error_and_flush_failures_close_without_replay`, `spare_vector_capacity_cannot_escape_the_retained_chunk_budget`. |
| 23. Upload chunk framing | `WorkerHttp::upload_writer` over `http1::ChunkedWriter`, whose chunks the verified `http1_exchange::ChunkStream` yields, on the TLS stream | P/A | Each accepted write becomes one chunk whose framing is the verified encoder's (`write_chunk_header`, `write_chunk_end`), proved to be a chunk of the grammar the decoder accepts; `shutdown` writes the proved last chunk. Accepted count means written to the TLS stream, not peer receipt. A: socket send. |
| 24. Response head | `prepare_response_head` → `headers::forward_response`; `Output::start` | P/T | 1xx rejected (T); proved: only allowlisted provider headers, so `set-cookie`, `location`, and credentials never reach the client, and a Connection header mentioning `content-encoding` rejects the response. Head sent exactly once to `Output::start` (T). T: `upstream_response_cannot_forward_credentials_cookies_or_redirect_location`, `unsolicited_protocol_switch_is_rejected_before_client_headers`, `interim_response_does_not_replace_final_status_or_payload`. |
| 24a. Response-head record (kind 3) | `PreparedRequest::audit_response_head` in `HttpsTransport::run`, after `prepare_response_head` and before `output.start` | P/T | Payload from the verified `encode_response_head` (clock, status 100 to 999); chunk 0. Strict: a failed append ends the exchange with `TransportError::Log` before the head reaches the client. Availability: log-failed, one gap. T: `full_gateway_streams_before_upstream_eof_and_logs_exact_bytes` (trace order and status). |
| 25. Download copy | `PreparedRequest::copy_body(Download)` in `HttpsTransport::run` through `WorkerHttp::output` | P/T | Same stream, same log, direction 1, same proved gates as steps 17 to 22. `output.finish` writes the last chunk through the `Connection` machine. T: `full_gateway_streams_before_upstream_eof_and_logs_exact_bytes`, `concurrent_tenants_keep_credentials_bodies_and_audit_records_isolated`. |
| 26. Clean EOF only on success | `Gateway::run_exchange` match on the exchange result; `Output::finish` and `Output::abort` | P/T | Only `Ok` from `exchange` reaches `output.finish`, the sole path to `ChunkStream::end` and `Connection::finish` (proved: a stream ends cleanly only through its last chunk, an abort adds nothing); an error after the head calls `abort`, which closes the socket without the last chunk. T: `truncated_response_is_never_reported_as_success`, `bodyless_http_statuses_are_complete_at_the_head_and_finish_cleanly`. |
| 26a. Completion record (kind 4) | `Gateway::audit_completion` → `PreparedRequest::audit_completion`, inline on every exit of `run_exchange` after the start record, before the worker lease is released | P/T | Payload from the verified lifecycle (`exchange_lifecycle::Lifecycle::completion`): the outcome is a checked function of the terminal event, and the counts are the two body-copy machines' proved counts on success, zero otherwise. `run_exchange` returns the `Closed` token only a terminal lifecycle produces, so no admitted worker ends without reaching this step; the only other worker exit is `HttpError::close` for a request refused before admission, a lint-pinned site. Best effort in both modes: the client-visible result is already fixed; skipped when the logger is unhealthy; never a detached thread. Cancellation (client disconnect or shutdown) reaches this step through `net::Cancel` in step 13, which fails the blocked operation rather than killing the thread. T: `full_gateway_streams_before_upstream_eof_and_logs_exact_bytes`, `truncated_provider_records_a_download_failure_completion`, `client_disconnect_cancels_stalled_provider_and_releases_request`, `upstream_timeout_records_a_timeout_completion_after_the_start_record`, `shutdown_aborts_stalled_response_after_drain_and_releases_request`. |
| 27. Release | `run_exchange` returns and drops `PreparedRequest` → `Lease::drop`; the work's output and readers drop; then `WorkerLease::drop`; then, when the connection thread's work returns, `ConnectionLease::drop` | P/T | `OwnedStream::retire` proved to release exactly its live slot under the lock; `WorkerRegistry::release_task` proved to require completed cleanup and no active HTTP descendants, and `TaskCredit::release` to require a releasable credit. A panic during the reservation-to-stream transfer strands the slot rather than releasing it. T: `strict_logging_and_cancellation_keep_the_lease_until_drop`, `unwinding_releases_owned_request`, `shutdown_during_a_stalled_handshake_cancels_it_after_the_drain_and_recovers_credit`. |

Across this trace, no byte reaches the provider without passing step 8 and no
body byte is submitted in strict mode without passing step 21. Step 22 joins
these through the checked `ResolvedRoute::write_bytes` gate; the remaining joins
are trusted Rust ownership, not one theorem over the threaded runtime.

## Upstream mediation chain

The production chain from configuration to each submitted body range:

| Boundary | Checked fact / actual adapter binding |
| --- | --- |
| Configuration to resolved dispatch | `ResolvedRoute::resolve` selects the actual immutable destination and credential by the authorized indices, with root-policy permission. `RoutedRequest` privately pairs that owner with the admitted request. |
| Resolved dispatch to HTTP/TLS | `PreparedRequest::take_upstream` validates configured URI, Host, credential, and method before connection effects; transport derives the socket/TLS host from the same configured destination and sends the origin-form request once. These metadata and I/O bindings are trusted Rust, covered by configuration, HTTP boundary, and real TLS exchange tests. |
| Resolved dispatch to every body range | Both production transport directions call `PreparedRequest::copy_body`, forwarding the same `RoutedRequest` owner into `copy_body_bound`, which passes the resolved route to the verified `BodyCopy::write_bytes`; that checks the route is bound to the authority and invokes `ResolvedRoute::write_bytes`. |
| Core composition | Successful `write_bytes` establishes matching resolved/write/request authority, allowed route/credential, direction, live ticket, and exact pending slice. Strict mode additionally establishes a valid current-chunk receipt with exact tenant/request/chunk/direction/payload and the designated journal session. Availability omits receipt evidence while retaining route/authority/direction checks. |
| Submission and completion | `BodyCopy::write_bytes` returns the slice with its ticket; the loop makes one `writer.write` call and `BodyCopy::finish_write` accounts the returned count against that ticket (proved). Upload uses the provider body channel mapped into this request; download uses the response sink. Cancellation blocks further byte access without erasing issued completion accounting. |

This closes the upstream mediation row under the explicit adapter assumptions:
trusted configuration and secret provisioning, initial logger selection and
unique file-session identity, Rust private ownership/borrows, truthful
I/O/count/destructor reports, and TLS/DNS/OS behavior. The proof covers
body submission, not peer receipt or physical power-loss durability. The
test-only `copy_body` helper passes no route and releases through the ticket
alone; the production HTTPS path always passes the resolved route. Tests cover
wrong resolved request/route, foreign session, mismatched direction, exact
partial ranges, stale tickets, strict unaudited rejection, availability,
metadata substitution, and real TLS transport.

## Failure exits

Each row states what the client sees, whether any upstream effect occurred,
what the audit log holds, and how the slot is released.

| Failure | Detected at | Client | Upstream | Audit | Release and evidence |
| --- | --- | --- | --- | --- | --- |
| Bad method, URI, headers, or bearer syntax | Step 5 | 400/401/405/431, no body | None | Nothing | No request slot was taken; worker credit returns when the connection thread's work does. T: `malformed_authentication_never_issues_a_prepared_request`, `invalid_and_oversized_headers_do_not_leak_admission_slots`. |
| Unknown token or no grant for the selector | Steps 6, 8 | 401 | None | Nothing | P: no `AuthorizedRequest` exists. Lease dropped by the early return inside `Admission::admit`. T: `authorization_failures_return_capacity_and_drop_reclaims_it`, `authentication_and_tenant_scoped_dispatch`. |
| Request slots full | Step 7 | 503 | None | Nothing | P: `acquire` refuses when full. T: `repeated_overload_preserves_active_streams_health_and_reusable_capacity`, `sustained_overload_preserves_active_streams_and_health`. |
| Worker credits full | Step 3 | 503 | None | Nothing | P: `DrainRegistry::acquire`. T: `worker_budget_covers_cleanup_without_consuming_request_slots`. |
| Poisoned admission or worker registry | Steps 2, 3, 7 | 503 and `/readyz` 503, both modes | None | Nothing | Poison is never recovered; capacity stays stranded. T: `poisoned_admission_is_unready_and_fail_closed_in_both_logging_modes`, `poisoned_worker_registry_is_unready_and_fail_closed_in_both_modes`, `poisoned_connection_registry_never_reissues_credit`. |
| Strict logging already unhealthy | Step 12 | 503 | None, no DNS/TCP/TLS | Nothing | T: `strict_log_failure_prevents_even_upstream_connection`. Not counted as an audit gap. |
| DNS, TCP, or TLS failure, or pool saturation | Steps 14, 15 | 502 | TCP may have opened; TLS fails before any HTTP byte, so no credential sent | Nothing | Network futures drop inside `run` before the slot. T: `untrusted_certificate_is_rejected_before_http_credentials_are_sent`, `cancelling_tls_handshake_drops_socket_and_returns_owned_request_credit`. |
| Logger append fails or times out at the start record | Step 12a | Strict: 503. Availability: forwards normally | Strict: none, no DNS/TCP/TLS. Availability: full exchange | Strict: nothing durable for this request; a completion (outcome 6) is attempted only if the logger is still healthy, which a deadline or write failure rules out. Availability: body and head records skipped (request log-failed); gap counted once; completion attempted while healthy | T: `failed_start_record_refuses_in_strict_mode_and_forwards_with_one_gap_in_availability_mode`, `stalled_log_under_load_preserves_health_deadlines_and_mode_policy`. A stalled logger is now observed here, before any upstream connection. |
| Logger append fails or times out during a body | Step 19/20, `BodyCopy::finish_audit` with no receipt | Strict: 502 if before head, else body aborted (HTTP framing error, never clean EOF). Availability: stream continues | Strict: no further bytes submitted. Availability: forwarding continues | Strict: acknowledged prefix only; completion skipped because the logger is unhealthy. Availability: later appends skipped for this request; gap counter incremented once at first failure (`health::GapObserver`, which counts a request at most once and never in strict mode, P) | P: `fail_log` closes a strict stream and only marks an availability stream; `prepare` cannot offer undurable bytes in strict mode. Logger health goes false; the worker is never replaced. T: `logger_failure_is_closed_in_strict_mode_and_reported_in_availability_mode`, `availability_log_failure_preserves_stream_and_reports_gap`, `blocked_disk_times_out_without_spawning_replacements`, `stalled_log_under_load_preserves_health_deadlines_and_mode_policy`. |
| Write or sync syscall fails | Step 20 | As above | As above | P: `Journal::fail` prevents any later acknowledgment; receipt is `None` | Health false. T: `write_and_sync_failures_never_acknowledge_and_poison_future_appends`, `filesystem_full_preserves_acknowledged_prefix_and_fails_closed`, `filesystem_read_only_refuses_logger_startup`. |
| Receipt does not match the current record or bound session | Step 21 | Stream closed, exchange fails | No further bytes | The durable record exists but authorizes nothing | P: `acknowledge_receipt` returns false and leaves the stream unchanged; the request is canceled in both modes. T: `mismatched_durable_receipts_never_authorize_forwarding`. |
| Upstream connection error or truncated body after head | Step 25 | Head already sent; body aborted by dropping the writer, never clean EOF | Exchange ended | Prefix logged | T: `truncated_response_is_never_reported_as_success`, `truncated_generation_is_an_error_and_still_reports_audit_gap`. |
| Exchange deadline (300 s) | Step 13 | 504 before head, else body aborted | Connection dropped | Prefix logged | T: `deadline_drops_connection_and_releases_admission`. |
| Client disconnects before head | The watcher thread's peek returns EOF → the exchange's `net::Cancel` shuts the upstream and client sockets → the transport's blocked read or write fails and `exchange` returns `Fault::Cancelled` | Nothing | Upstream socket shut down | Prefix logged; a queued frame may become durable but unsent; completion with outcome 5 written inline before the worker releases its slot | P: `cancel` closes the stream so no new ticket is issued. T: `client_disconnect_before_headers_cancels_request_and_upstream_socket`, the Disconnect case of `exercise`. |
| Client disconnects during body | The write to the client fails, or the watcher cancels first | Nothing further | Same | Same, outcome 5 | T: `client_disconnect_cancels_stalled_provider_and_releases_request`. |
| Cancellation while an append is pending | The thread is blocked in `DiskLog::append` until the receipt arrives or the append deadline passes; cancellation touches only sockets, so it takes effect at the next socket operation | As above | None | Frame stays owned by the queue; worker still writes it; result discarded if the exchange has failed | T: `abandoned_audit_cannot_authorize_or_reuse_the_chunk`, `callers_that_give_up_do_not_release_queued_or_active_frame_credit`, `worker_panic_marks_health_failed_without_a_deadline_and_fails_the_waiting_caller`. |
| Bodyless 204/304 | `Output::start` writes the fixed head with `Content-Length: 0`; the transport reads a zero-length body | 204/304, no body | Exchange ended | Prefix logged | P: the `Connection` machine refuses a body after 204 or 304. |
| Gateway process killed | Any | Truncated body, HTTP framing error | Provider may have executed; no replay | Acknowledged prefix recoverable; restart uses a new file and session | T: `killed_gateway_truncates_response_preserves_audit_prefix_and_does_not_replay`, `kill_during_following_appends_preserves_the_acknowledged_prefix`, `proxy_gateway_process_failover_without_replay`. |

In every row the client never receives a clean HTTP EOF for an incomplete
generation, no row contains a retry or replay path, and authorization is never
re-evaluated more permissively. Strict mode may have opened the connection and
sent the request head before a body-logging failure; that is documented, not a
defect.

## Metadata records and outcome codes

Every exit of `run_exchange` after the start record was attempted writes one
completion record (kind 4) inline, unless the logger is unhealthy. The transport
returns the verified lifecycle's `Fault` directly, so the outcome code is the
proved `exchange_lifecycle::outcome_of` of what happened, with no mapping in
between:

| Exit | Outcome | Notes |
| --- | --- | --- |
| `Ok(ExchangeStats)` | 0 success | Byte counts are the accepted upload and download totals |
| `Connect`, `Tls`, `Http` | 1 upstream connect/TLS/HTTP failure | DNS failure and pool saturation surface as `Connect` |
| `Timeout` | 2 upstream timeout | The exchange deadline, including DNS wait |
| `Upload` | 3 upload failure | Any upload transfer error other than a strict log refusal |
| `Download` | 4 download failure | Includes provider truncation and worker-side output failure |
| `Client` | 5 client disconnect or cancellation | Sink `start`/`finish` failures |
| `Cancelled` | 5 shutdown or client disconnect through `net::Cancel` | The exchange's sockets were shut down and its blocked operation failed; counts are zero |
| `Log` | 6 strict-mode log refusal | A body or response-head append failed in strict mode; the start-record refusal also uses 6 when a completion can still be written |
| `Metadata` | 7 metadata/other | Upstream metadata rejected, or a metadata receipt that did not match its record |
| `http.input` role unavailable | 7 | No exchange was attempted |

Exits before the start record (steps 5 to 12) leave no record for the request:
there is no admitted request ID for steps 5 to 7, and steps 8 to 12 refuse
before any append. Byte counts are zero on every non-success exit even when
part of a body was forwarded; the body records themselves carry those bytes.
Clock values are the system clock in milliseconds, clamped to `u64` and zero
for a pre-epoch clock; nothing orders records across processes. The outcome
function is proved total over `Fault`; the exits are tested for success,
truncation, disconnect, timeout, and start-record refusal.

## Shutdown

`serve` after SIGINT/SIGTERM or a listener error:

| Step | Code | Status | Evidence |
| --- | --- | --- | --- |
| Stop accepting | `drop(listener)` in `serve` | T | Listening socket closes while workers continue. |
| Permanently close worker admission across all listeners | `WorkerSlots::close` | P/T | `DrainRegistry::close` proved: outstanding keys preserved, no reopening, later acquire fails. Close and acquire share one mutex. T: `shutdown_closes_shared_worker_admission_before_waiting_for_existing_work`. |
| Ten-second drain of connection and worker credits | `ConnectionSlots::wait_drained` and `WorkerSlots::wait_drained` on their condition variables | T/A | A: lease destructors notify. T: `shutdown_drains_active_response_without_truncation`, `shutdown_aborts_stalled_response_after_drain_and_releases_request`. |
| Then cancel every in-flight exchange and wait once more | `Gateway::cancel_live` fires each exchange's `net::Cancel`, shutting its upstream and client sockets | P/T/A | Each cancelled exchange's blocked operation fails, `exchange` returns `Fault::Cancelled`, the completion record (outcome 5) is written while the logger is healthy, then `leased::run` records cleanup and `release_task` runs; the logger shuts down only after the second wait. `drain_trace_rank` proved: each release lowers the finite rank, no new admission. A: a shut-down socket returns the blocked operation. T: `shutdown_cancels_stalled_workers_owned_by_another_listener`. |
| Logger close, drain, join with a two-second window | `DiskLog::shutdown` | P/T/A | `FixedQueue::close` proved: pending frames preserved and drained in order. A stuck syscall returns `TimedOut`; the worker is never replaced and may finish its write later. T: `shutdown_closes_all_clones_drains_admitted_jobs_and_joins`, `shutdown_deadline_does_not_wait_for_stuck_sync_or_replace_worker`, `shutdown_with_blocked_disk_returns_error_without_replacement_or_replay`. |

The [shutdown proof](shutdown-proof.md) states the scheduler, timer, mutex,
and destructor assumptions. Ten plus two seconds are cooperative windows, not a
process-exit bound. Restart requires a fresh `Gateway`, transport, logger, and
log path; nothing is resumed from the previous process.

## Advertised guarantees traced to this path

| README property | Steps that carry it | Proved part | Trusted joins |
| --- | --- | --- | --- |
| Authorization and fail-closed security | 5, 6, 8, 11, 12, 16, 22; failure rows 1 to 6 | Token issuance, grant membership, tenant/credential ownership, `write_bytes` gate | SHA-256, header parsing, that `run` is the only dispatch (effect-site table) |
| Tenant and credential isolation | 8, 9, 10, 11, 18, 21, 22, 27 | Credential owner equals tenant; audit header tenant/request bound to authority and stream owner; ticket owner/generation checks; distinct live IDs | Index-to-secret mapping; head serialization is the verified writer |
| Routing and configuration confinement | 8, 10, 14, 15, 16, 22 | `Policy::validate`, `allowed`, `ResolvedRoute::resolve` | URI parser, DNS, TLS name check, no IP-range policy |
| Byte integrity and ordering | 17, 22, 23, 25 | Completed history is an ordered prefix of input; one outstanding write; stale completions rejected | Writer reports the true accepted count; the connection thread writes every frame as a chunk |
| Strict audit-before-forwarding | 18 to 22 | Receipt only after commit after sync in the bound session; receipt matched to exact record; `write_bytes` bounded by durable offset | Syscall truth, storage contract, single worker, oneshot pairing |
| Crash-safe recovery | 20; process-kill rows | Acknowledged prefix survives a stable prefix; ordered reconstruction under read/checksum contracts | Filesystem and hardware persistence, SHA-256 |
| Cancellation and no replay | Failure rows for disconnect, cancellation, deadline, process kill | `cancel` blocks new tickets while completing issued writes | A shut-down socket returns the blocked operation; no retry code exists (effect-site table); external proxy retries disabled |
| Resource bounds and safe release | 1, 3, 4, 7, 9, 14, 15, 19, 27 | Registry occupancy, drain rank, queue slots, mailbox slot, per-request chunk bound, HTTP owner bounds, `cleanup_before_reuse` | Drop order, allocator, dependency allocations ([resource composition](resource-composition.md)) |
| Logging-mode separation | 12, 22, failure row for logger failure | `fail_log` mode-specific transition; same authorization path and `write_bytes` checks in both modes | No formal noninterference between modes |
| Honest completion and conditional progress | 26, failure rows, shutdown | Non-refusal postconditions, permanent closure, finite rank | Scheduler fairness, finite polls, timers |

## What this audit does not establish

- There is no single mechanized theorem over the threaded runtime. The proved
  steps are synchronous transitions; the joins between them are Rust ownership,
  mutex discipline, and drop order, checked by reading and by tests.
- The trusted computing base is listed in the
  [security contract](security-contract.md#trusted-computing-base-and-evidence).
  Origin confinement is not an IP-range or SSRF theorem.
- Acceptance into the HTTP channel is not peer receipt, and a logged request is
  not evidence the provider executed or finished it.
- The storage contract excludes power loss, device lies, and malicious rewriting.
- Bodies are logged verbatim; nothing here is a secrecy property for body
  contents, and timing is not constant.
- Metadata records are structurally verified but their values are trusted: the
  clock, the status taken from the upstream head, the outcome mapping, and the
  byte counts are runtime facts, and a missing completion record distinguishes
  an unhealthy logger or a dead process from a finished exchange only by absence.
- Availability mode shares the authorization path with strict mode but has no
  formal noninterference proof.
- Test evidence is finite: observed no-replay windows and drain times are not
  universal bounds.
- This is a self-audit against the production source. Independent review has
  not been performed. The effect-site and token tables must be rechecked when
  `transport.rs`, `disk_log.rs`, `http_boundary.rs`, `admission.rs`, or
  `config.rs` change.

## Reproduction

The effect-site table comes from this search, which must list only the sites
named above outside `#[cfg(test)]` modules and `tests/` directories:

```sh
grep -rn --include='*.rs' -E 'TcpStream::connect|connect_timeout|complete_io|OpenOptions|File::open|File::create|write_all|write_fully|\.sync\(|sync_all|TcpListener::bind|thread::Builder|std::thread::spawn|process::exit|std::env::var|to_socket_addrs|fs::rename|fs::remove_file' crates/gateway-runtime/src
grep -rn --include='*.rs' -E 'unsafe|assume\(|external_body' crates/gateway-core/src crates/gateway-runtime/src
bash scripts/check_effect_sites.sh
```

Tests, proofs, and deliberate defects are checked by the commands in the
[README](../README.md), which also records the current validation totals; CI
runs them with the pinned toolchain.
