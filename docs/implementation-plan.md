# Implementation milestones

| Milestone | Complete | Progress |
| --- | :---: | --- |
| 1. Verified streaming core | ☐ | ✓ Streaming and resource proofs; ✓ authorization/configuration proofs; ✓ tested request ownership; ✓ verified completed-chunk release; ✓ verified owner-checked stream retirement used by runtime leases; ✓ claimed slots reject non-consuming reservation release; ✓ production leases use a verified private key/stream owner with exact transition contracts and consuming retirement; ✓ network futures borrow an outer request owner, with handshake-cancellation cleanup coverage; ✓ verified read-buffer ownership and exclusive stream/read payload bound used by the driver; ✓ registry-wide owned payload bound includes pending reads and supplies the combined buffer theorem; ✓ verified configuration budget arithmetic and runtime retained-vector capacity checks; ✓ conditional combined payload bound for streams mapped to live slots; ✓ ownership-map initialization and preservation in admission, stream creation, replacement, and retirement contracts; ✓ verified zero initial occupancy and exact admission/release count changes; ✓ verified initial authority/slot/stream binding and admission/release/stream non-rejection. ✓ Source-level buffer/queue inventory and visible-payload subtotal; ✓ HTTP reader copies detach bounded frames from oversized backing owners; ✓ pinned Hyper/TLS buffering audit, explicit TLS application-data/session-cache limits, and TLS 1.2/1.3 cache-eviction regression; ✓ isolated gateway RSS fixture with per-wave measurements, Linux high-water reporting, and a dedicated 100-wave CI workload; ✓ conditional combined buffer-size theorem covers core/read/output/log/receipt/header categories and canonical frame overhead; ✓ audit-frame lifetime correspondence and canceled-caller queue-credit test; ✓ worker gate uses verified registry transitions and an explicit task-before-credit drop wrapper, with cancellation and poison coverage; ✓ root-policy snapshots erased after checked validation, startup JSON buffers released before serving, and configuration storage inventory; ✓ dedicated DNS pool with verified job credits retained through cancellation, bounded address results, and shutdown/panic coverage; ✓ detached bounded HTTP header copies, consuming metadata boundaries, and bounded relevant Connection-option storage; ✓ HTTP channel cancellation audit and regression coverage; ✓ combined payload budget includes sender-only cleanup channels; ✓ explicit wire-head byte/count limits in both parsers with exact-boundary socket tests and per-map collection/scratch audit; ✓ deterministic Hyper queue/flatten backpressure and cancellation regression with output-capacity audit; ✓ connection-task lifetime audit and repeated parent-abort cleanup/reuse coverage in both logging modes; ✓ bounded HTTP plaintext-read adapter prevents parser backing growth from rejecting valid bodies, with maximum-head Content-Length/chunked regressions in both directions; ✓ channel control-object inventory and explicit audit/DNS thread-stack reservations; ✓ production disk queue uses verified fixed-slot FIFO with exact order/full/empty contracts, permanent closure with preserved drain order, and wrapper lifecycle tests; ✓ raw stream construction/claim/release sealed inside the core, with external privacy regressions. ✓ actual queued-frame projection supplies frame validity/count and encoded-byte bounds to the combined theorem; ✓ immutable queue payload limit checked at insertion and initialized from configured K, with pre-encoding rejection and boundary/clone tests. Composed resource proofs and full allocation accounting remain. |
| 2. Minimal working gateway | ✓ | Runnable HTTP/TLS/disk path, concurrent tenant isolation, disconnect/failure and unsolicited-upgrade rejection tests, and documented adapter audit. Production hardening and broader proofs remain in the other milestones. |
| 3. Crash-safe logging | ✓ | ✓ Bounded disk writer, framing/scanner tests; ✓ Verified session-header version/identity encoding and decoding in startup/recovery; ✓ Header/payload encoding, frame-extent, recovery-cursor, and recovered-record binding and non-rejection proofs; ✓ Verified authority/stream audit-record binding; ✓ Request-scoped async audit acknowledgment; ✓ Exact durable-receipt/stream acknowledgment theorem and production receipt delivery; ✓ Immutable queued frames and composed canonical-frame/journal acknowledgment; ✓ composed durable-frame commit used by the disk worker; ✓ journal acknowledgment proof, exact acceptance/rejection contracts, and conditional prefix-survival lemma. ✓ Process-kill recovery tests and storage contract; ✓ Scanner I/O faults at every record byte. ✓ Conditional scanner source-byte/checksum refinement and justified rejection. ✓ Ordered acknowledged-prefix reconstruction under explicit storage/read/checksum assumptions. ✓ Linux ext4 ENOSPC/EROFS and process-death validation; ✓ exit audit. Complete under the documented storage/read/checksum assumptions, without power-loss certification. |
| 4. Availability hardening | ☐ | ✓ Separate verified worker registry covers rejection and cleanup, with saturation/cancellation tests; ✓ Admission/connection limits, bounded logging, network deadlines, health/readiness, and bounded connection drain. ✓ Audit-health/gap metrics and verified request-occupancy gauges; ✓ Poisoned-admission readiness/fail-closed tests; ✓ Incomplete-connection overload, pre-header/streaming disconnect, bodyless-response completion, and shutdown tests; ✓ Bounded logger drain/join and canceled-caller worker-panic health; ✓ Explicit HTTP input-frame limit; ✓ Gateway runtime process-kill test checks truncated response, strict audit prefix, and fresh-session restart; ✓ Combined TLS proxy/two-gateway process-kill test verifies no replay and a new request on standby. ✓ Eight-client paced 4 MiB responses and mid-workload permanent log failure in both modes. ✓ Repeated admission overload preserves eight active streams and health checks, rejects excess traffic before dispatch, and recovers capacity. ✓ Concurrent stalled-sync test verifies bounded queues, request cleanup, and both operator modes. Long-duration overload, broader fault/load tests, and shutdown/resource proofs remain. |
| 5. Auditable first release | ☐ | ✓ Pinned core toolchain, proof/mutation checks, security notes, and source-linked proof index; ✓ GitHub Actions test/proof workflow. ✓ Tested TLS proxy/standby example; ✓ Local TLS/disk latency and process-RSS baseline for both modes; ✓ Concurrent stalled-sync/queue-saturation test in both logging modes; ✓ Paced-peer and permanent-log-failure workload results, with a separate paced strict-mode RSS measurement. Reproducible full deployment, broader benchmarks, and end-to-end audit remain. |

✓ marks completed work within a milestone; ☐ means the full milestone's exit
criteria are not yet met. Update this table at each implementation checkpoint.
Milestone 2's evidence is recorded in the [adapter audit](adapter-audit.md); its
completion does not imply completion of the earlier composition proofs or release gates.

Status: approved direction is Rust plus Verus. Milestone 3 is closed under its
explicit storage assumptions; see the [exit audit](storage-crash-contract.md#milestone-3-exit-audit).
Next focus is closing milestone 1: composed resource ownership and allocation
accounting. Other unfinished milestones wait unless they are a direct dependency.
The [milestone 1 exit audit](milestone-1-exit-audit.md) maps all seven criteria to
evidence: six are covered within the core's stated scope; resource composition
still blocks closure.
See the [streaming-core progress notes](streaming-core-progress.md) and
[authorization core](authorization-core.md) for completed increments and remaining gaps.
The [runtime ownership layer](runtime-ownership.md) now ties authorization, a single
stream, and slot release together in tested safe Rust. Composed resource proofs
and full accounting for adapter allocations remain open; the
[resource inventory](resource-accounting.md) separates visible payload budgets from
dependency allocations and task-lifetime obligations.
Static JSON policy loading and immutable endpoint/credential mapping are implemented
and tested; see [configuration](configuration.md).
The [HTTP metadata boundary](http-boundary.md) now authenticates and prepares fixed
upstream requests.
The [async body driver](async-transfer.md) now exercises the core with Tokio I/O;
the [HTTPS transport](https-transport.md) now connects it to upstream HTTP/TLS.
The [runnable gateway](running.md) now integrates the inbound server and disk logger;
concurrent load and broader end-to-end failure validation remain open.
Scope: forward opaque HTTP request bodies and streaming responses, and log to disk.
No provider translation, automatic generation replay, billing, or plugin system.
Operators choose strict durable logging or forwarding with degraded audit coverage.
An external load balancer handles failover between gateway instances.

The [security contract](security-contract.md) specifies authorization, tenant and
credential isolation, routing integrity, and adversarial configuration handling.
Resource admission and stream tickets are not authorization. Implement and prove
the synchronous authorization/token boundary before adding network dispatch.

## 1. Verified streaming core

Replace the one-byte experiment with bounded chunks and an explicit write lifecycle.
Own immutable payload bytes; authorize a bounded range; account for the transport's
reported partial write; retain the unsent suffix. Bind authorization and completion
to a request and a generation so stale completions cannot advance another write.
Distinguish bytes authorized for submission from bytes the transport reports accepted;
neither establishes client application consumption.

Implement strict and availability-first logging policies, cancellation, logging
failure, and resource accounting. Prove byte-prefix preservation, isolation of
request state, monotonic offsets, checked arithmetic, capacity bounds, and valid
lifecycle transitions. Make state private. Do not hide unverified I/O behind assumed
lemmas that assert the properties we intend to prove.

Exit criteria:

- Compiled executable core and checked proofs cover every public transition.
- Partial, zero-progress, invalid, and stale completions have specified behavior.
- Cancellation prevents new writes while accounting for an already issued write.
- Multiple chunks and requests preserve ordering and cannot mix identities.
- Queue, buffer, and outstanding-operation limits have explicit accounting.
- Mutation tests reject corruption, cross-request writes, duplicate advancement,
  capacity violations, and strict-mode forwarding before durability.
- Verified security admission issues a private-constructor `AuthorizedRequest`
  bound to identity, policy snapshot, origin, and credential handle; invalid
  candidate configuration cannot expand the operator's root grants.

First increment: a single bounded chunk with one outstanding write, a borrowed
payload view, generation-tagged completion, and partial-write accounting. This is
not milestone completion: multi-chunk scheduling and global resource budgets follow.

## 2. Minimal working gateway

Wrap the same verified core in a narrow Rust HTTP/TLS adapter. Evaluate
Hyper/Tokio/rustls without treating their implementations as verified. Start with
fixed configured upstream origins, explicit credential ownership, opaque body
bytes, no automatic redirects, and no automatic request replay. Handle HTTP framing
and hop-by-hop headers correctly without interpreting provider JSON or SSE events.

Exit criteria:

- Real request and response streaming use the core's authorization/completion path.
- Every outbound dispatch consumes `AuthorizedRequest`; no raw-origin or credential
  override path exists. Logging availability mode never bypasses security checks.
- Integration tests preserve body bytes across fragmentation and simultaneous requests.
- Routing and credential handling cannot redirect a request to a caller-chosen origin.
- Error, disconnect, and cancellation paths stop work without synthesizing success.
- Every trusted adapter obligation is listed and exercised where feasible.

## 3. Crash-safe logging

Specify a framed log format, stable record/request identities, durable commit
acknowledgments, and startup recovery. State a target OS/filesystem crash model and
how write, sync, creation, and directory persistence meet it. Prove the recoverable
prefix and acknowledged-record properties under those assumptions; separately test
the actual disk adapter. A checksum is not a proof against arbitrary corruption.

Strict mode may authorize only ranges covered by durable acknowledgment. In
availability-first mode, logging loss must not cause unbounded queuing or waiting;
report audit gaps through independent diagnostics when possible. A crash can erase
volatile gap reports. Logged bytes may never reach their destination, and a machine's
permanent loss is outside a local-disk durability guarantee.

Exit criteria:

- Partial records cannot masquerade as complete records after recovery.
- Acknowledged records survive every modeled crash point.
- Process-kill, torn-tail, write-error, and disk-full experiments match the contract.
- No crash recovery path replays a possibly executed generation automatically.
- Both operator modes have documented guarantees and failure behavior.

### Closure evidence for milestone 3

The [exit audit](storage-crash-contract.md#milestone-3-exit-audit) maps every criterion
to the theorem, runtime path, test evidence, and limitations. Linux ext4 tests cover
actual ENOSPC, read-only startup, and process-death recovery on a private filesystem.
[CI run 40039148167](https://github.com/platypii/LogGate/actions/runs/40039148167)
passed all four jobs at `7b9ce21`, including production proofs and deliberate defects.
Hardware flush behavior, syscall correspondence, and stable read/checksum contracts
remain explicit assumptions. This milestone does not certify physical power loss.

## 4. Availability hardening

Enforce global and per-request limits, backpressure, admission control, deadlines,
and bounded worker counts. A timed-out disk operation must not spawn an unbounded
number of replacements; assess an isolated logger process if cancellation cannot
bound stuck filesystem work. Implement health/readiness endpoints and bounded
shutdown draining for the external load balancer.

Exit criteria:

- Slow clients, slow upstreams, and stalled logging stay within configured budgets.
- Fault injection covers disconnects, permanently blocked writes, process death,
  concurrent requests, and shutdown with an outstanding operation.
- New traffic can route around an unhealthy instance; interrupted streams are
  reported honestly rather than transparently replayed.
- Progress claims state scheduler/I/O assumptions; memory and latency are measured
  under load instead of inferred from core proofs.

## 5. Auditable first release

Pin compiler, verifier, solver, and dependencies; automate proof and mutation checks,
integration tests, and reproducible build instructions. Publish the exact proved
properties, assumptions, trusted code boundary, operational limits, and failure modes.
Document configuration and deployment, including credential and log-file protection.

Exit criteria:

- A clean environment can reproduce proofs, tests, and the runnable gateway.
- Every advertised guarantee maps to a theorem or is clearly identified as tested
  behavior or an assumption; deferred obligations are visible.
- Benchmarks report streaming latency and resource use for both logging modes.
- A reviewer can trace authorization through the core to the actual network/disk
  calls, including failures and shutdown.

## Decisions to settle as implementation reaches them

Before the HTTP adapter: inbound authentication, provider credential ownership,
initial protocol versions, and static route configuration. Before disk proofs:
deployment OS/filesystem, log contents, retention, and sync/batching policy. Before
load testing: concurrency, buffer, deadline, and strict-mode latency targets.

Research and earlier experiments remain linked from the README. Perennial is not
an active workstream; its notes and historical code revision remain available if
the storage verification requirements justify revisiting that decision.
