# Implementation milestones

| Milestone | Progress | Complete |
| --- | :---: | :---: |
| 1. Verified streaming core | 68/68 | ✓ |
| 2. Minimal working gateway | 6/6 | ✓ |
| 3. Crash-safe logging | 15/15 | ✓ |
| 4. Availability hardening | 16/16 | ✓ |
| 5. Auditable first release | 9/9 | ✓ |
| [6. Async ownership and effect composition](#6-async-ownership-and-effect-composition) | 5/8 | ☐ |

Progress counts completed rows in each milestone's table below. Rows are not
weighted estimates of effort or proof coverage; an open row can still block the
entire milestone. ✓ means completed within its stated scope; ☐ means unfinished.
Update the section tables and summary counts together at each checkpoint.
Milestone 2's evidence is recorded in the [adapter audit](adapter-audit.md); its
completion does not imply completion of the earlier composition proofs or release gates.

Status: approved direction is Rust plus Verus. Milestone 3 is closed under its
explicit storage assumptions; see the [exit audit](storage-crash-contract.md#milestone-3-exit-audit).
Milestone 1 is closed under the explicit assumptions in the
[resource composition](resource-composition.md); the
[milestone 1 exit audit](milestone-1-exit-audit.md) maps all seven criteria to
evidence. Milestone 4 is closed under its [availability audit](availability-audit.md)
and explicit scheduler/I/O assumptions. Milestone 5, the auditable release, is complete:
the [end-to-end audit](end-to-end-audit.md) now traces one request from authorization
to the exact network and disk calls, a [clean-environment deployment](deployment.md#clean-environment-reproduction)
is scripted and reproduced in CI and a pinned container, and the
[broader benchmarks](benchmarks.md#broader-workloads) and
[operational limits](operational-limits.md) close the last row. Every milestone
row in milestones 1–5 is now checked under its documented assumptions; milestone 6
tracks the next refactor and composition proofs. Other open obligations are listed
in the [security contract](security-contract.md) and each exit audit.
See the [streaming-core progress notes](streaming-core-progress.md) and
[authorization core](authorization-core.md) for completed increments and remaining gaps.
The [runtime ownership layer](runtime-ownership.md) now ties authorization, a single
stream, and slot release together in tested safe Rust. Composed resource
accounting is conditional on the stated correspondence, dependency, and
allocator assumptions; the
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

| Done | Submilestone |
| :---: | --- |
| ✓ | Synchronous streaming and conditional resource proofs. |
| ✓ | Authorization/configuration proofs. |
| ✓ | Tested request ownership. |
| ✓ | Verified completed-chunk release. |
| ✓ | Verified owner-checked stream retirement used by runtime leases. |
| ✓ | Claimed slots reject non-consuming reservation release. |
| ✓ | Production leases use a verified private key/stream owner with exact transition contracts and consuming retirement. |
| ✓ | Network futures borrow an outer request owner, with handshake-cancellation cleanup coverage. |
| ✓ | Verified read-buffer ownership and exclusive stream/read payload bound used by the driver. |
| ✓ | Registry-wide owned payload bound includes pending reads and supplies the combined buffer theorem. |
| ✓ | Verified configuration budget arithmetic and runtime retained-vector capacity checks. |
| ✓ | Conditional combined payload bound for streams mapped to live slots. |
| ✓ | Ownership-map initialization and preservation in admission, stream creation, replacement, and retirement contracts. |
| ✓ | Verified zero initial occupancy and exact admission/release count changes. |
| ✓ | Verified initial authority/slot/stream binding and admission/release/stream non-rejection. |
| ✓ | Source-level buffer/queue inventory and visible-payload subtotal. |
| ✓ | HTTP reader copies detach bounded frames from oversized backing owners. |
| ✓ | Pinned Hyper/TLS buffering audit, explicit TLS application-data/session-cache limits, and TLS 1.2/1.3 cache-eviction regression. |
| ✓ | Isolated gateway RSS fixture with per-wave measurements, Linux high-water reporting, and a dedicated 100-wave CI workload. |
| ✓ | Conditional combined buffer-size theorem covers core/read/output/log/receipt/header categories and canonical frame overhead. |
| ✓ | Audit-frame lifetime correspondence and canceled-caller queue-credit test. |
| ✓ | Worker gate uses verified registry transitions and an explicit task-before-credit drop wrapper, with cancellation and poison coverage. |
| ✓ | Root-policy snapshots erased after checked validation, startup JSON buffers released before serving, and configuration storage inventory. |
| ✓ | Dedicated DNS pool with verified job credits retained through cancellation, bounded address results, and shutdown/panic coverage. |
| ✓ | Detached bounded HTTP header copies, consuming metadata boundaries, and bounded relevant Connection-option storage. |
| ✓ | HTTP channel cancellation audit and regression coverage. |
| ✓ | Combined payload budget includes sender-only cleanup channels. |
| ✓ | Explicit wire-head byte/count limits in both parsers with exact-boundary socket tests and per-map collection/scratch audit. |
| ✓ | Deterministic Hyper queue/flatten backpressure and cancellation regression with output-capacity audit. |
| ✓ | Connection-task lifetime audit and repeated parent-abort cleanup/reuse coverage in both logging modes. |
| ✓ | Bounded HTTP plaintext-read adapter prevents parser backing growth from rejecting valid bodies, with maximum-head Content-Length/chunked regressions in both directions. |
| ✓ | Channel control-object inventory and explicit audit/DNS thread-stack reservations. |
| ✓ | Production disk queue uses verified fixed-slot FIFO with exact order/full/empty contracts, permanent closure with preserved drain order, and wrapper lifecycle tests. |
| ✓ | Raw stream construction/claim/release sealed inside the core, with external privacy regressions. |
| ✓ | Actual queued-frame projection supplies frame validity/count and encoded-byte bounds to the combined theorem. |
| ✓ | Immutable queue payload limit checked at insertion and initialized from configured K, with pre-encoding rejection and boundary/clone tests. |
| ✓ | Verified pre-encoding queue reservation and combined encoding/queued bound, with closure/rejection tests. |
| ✓ | Combined buffer theorem explicitly includes the encoding snapshot within the same Q budget, with omission/reservation mutations. |
| ✓ | Production encoder uses the verified reservation/payload gate, with actual body/sealed-frame size composition. |
| ✓ | Production enqueue hides queue references/callbacks and consumes a private single-use encoding permit. |
| ✓ | Audit encoding allocation-request inventory, exact header reservation, and body/seal capacity/address regressions. |
| ✓ | HTTP channels use a verified fixed slot with bounded wakeup state, receiver-drop exclusion, poison/cancellation tests, and threaded FIFO handoffs. |
| ✓ | HTTP waker clone/drop/wake callbacks run outside the mutex, with reentrancy and destructor-panic wakeup regressions. |
| ✓ | HTTP mailbox endpoint closure and exact pending-item extraction verified in production, with inline storage and no separate slot allocation. |
| ✓ | Explicit Hyper queue strategy in both directions excludes body flattening, with short non-vectored duplex regression. |
| ✓ | Pinned-source bound for Hyper retained streaming payload owners, including the partially consumed front, with repeated partial-write/drop tracking. |
| ✓ | Configured destinations capped at 8 KiB before secret loading; source-level serialized-head inventory and maximum-input wire regression. |
| ✓ | Server interim/final head wire regression and serializer reservation-request inventory. |
| ✓ | Pinned Vec/bytes per-allocation capacity and unique-buffer replacement audit. |
| ✓ | Parser backing-owner inventory including incoming-channel cancellation tails, with deterministic slow-reader regression. |
| ✓ | Trailer assembly capacity/cancellation inventory and real byte/count parser-boundary regression. |
| ✓ | Gateway-wide verified connection registry with task-before-credit destruction, shared-listener/restart/poison regressions, and fixed limit binding. |
| ✓ | TLS deframer capacity/replacement audit and header-only oversized-handshake rejection regression. |
| ✓ | Active TLS session ownership/content subtotal and resumed-connection survival across cache eviction. |
| ✓ | Explicit uncompressed-certificate policy and parsed certificate-entry capacity inventory. |
| ✓ | Verifier path/work and EKU diagnostic inventory, with large wrong-purpose rejection/cleanup regression. |
| ✓ | TLS control-queue/counter audit and real key-update burst-limit regression. |
| ✓ | Dependency-level TLS key-update/data experiment demonstrates control queue growth beyond the application-byte cap. |
| ✓ | Production TLS adapter drains queued ciphertext before further scalar or vectored plaintext writes. |
| ✓ | Real TLS stalled-output regression holds queue length stable across 3,000 key-update/data rounds and resumes exact byte delivery. |
| ✓ | Ordinary TLS application-record overhead checked across six cipher suites with scalar and vectored writes. |
| ✓ | Automatic TLS key refresh exercised at eight starting positions using a test-only shortened key limit. |
| ✓ | TLS record allocation reuse, vectored scratch, and consumed-prefix retention inventoried, with allocation-capacity/address regression. |
| ✓ | HelloRetryRequest cookie copy inventory, pinned debug-only extension-length assertion, and connector-level echo/fail-closed regression. |
| ✓ | Peer certificate chain ownership across Certificate/verify/ticket/resumption, with a large-chain equality regression. |
| ✓ | Runtime correspondence table maps every theorem category, encoding buffer, receipt, queue slot, and cancellation tail to its production owner and enforcement; see [resource composition](resource-composition.md). |
| ✓ | Composed requested-allocation bound sums the HTTP, TLS control/handshake, metadata, DNS, and instance inventories with explicit descriptor/allocator/OS assumptions; `budget.rs` computes it and the executable reports it at startup. |
| ✓ | Instance and lifetime ledger assigns every budget to one owner across serve invocations, Gateway/transport/logger instances, DNS/handshake pools, and request/worker limits, with enumerated tails. |

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

TLS resource evidence and remaining composition obligations are tracked in the
[dependency resource audit](dependency-resources.md#control-traffic-is-not-covered-by-the-application-buffer-limit).

## 2. Minimal working gateway

| Done | Submilestone |
| :---: | --- |
| ✓ | Runnable HTTP/TLS/disk streaming path uses the verified core. |
| ✓ | Outbound dispatch consumes admitted authority; availability mode preserves security checks. |
| ✓ | Opaque body preservation across fragmentation and concurrent tenant requests. |
| ✓ | Configured destination and credential binding prevents caller-selected upstream overrides. |
| ✓ | Error, disconnect, cancellation, and unsolicited-upgrade rejection tests. |
| ✓ | Trusted adapter obligations documented in the [adapter audit](adapter-audit.md). |

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

| Done | Submilestone |
| :---: | --- |
| ✓ | Bounded disk writer, framing/scanner tests. |
| ✓ | Verified session-header version/identity encoding and decoding in startup/recovery. |
| ✓ | Header/payload encoding, frame-extent, recovery-cursor, and recovered-record binding and non-rejection proofs. |
| ✓ | Verified authority/stream audit-record binding. |
| ✓ | Request-scoped async audit acknowledgment. |
| ✓ | Exact durable-receipt/stream acknowledgment theorem and production receipt delivery. |
| ✓ | Immutable queued frames and composed canonical-frame/journal acknowledgment. |
| ✓ | Composed durable-frame commit used by the disk worker. |
| ✓ | Journal acknowledgment proof, exact acceptance/rejection contracts, and conditional prefix-survival lemma. |
| ✓ | Process-kill recovery tests and storage contract. |
| ✓ | Scanner I/O faults at every record byte. |
| ✓ | Conditional scanner source-byte/checksum refinement and justified rejection. |
| ✓ | Ordered acknowledged-prefix reconstruction under explicit storage/read/checksum assumptions. |
| ✓ | Linux ext4 ENOSPC/EROFS and process-death validation. |
| ✓ | Exit audit under the documented storage/read/checksum assumptions. |

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

The [exit audit](availability-audit.md) maps criteria to current evidence and
records the conditional shutdown/resource proof, validation results, and explicit
scheduler/I/O assumptions.

| Done | Submilestone |
| :---: | --- |
| ✓ | Separate verified worker registry covers rejection and cleanup, with saturation/cancellation tests. |
| ✓ | Admission/connection limits, bounded logging, network deadlines, health/readiness, and bounded connection drain. |
| ✓ | Audit-health/gap metrics and verified request-occupancy gauges. |
| ✓ | Poisoned-admission readiness/fail-closed tests. |
| ✓ | Incomplete-connection overload, pre-header/streaming disconnect, bodyless-response completion, and shutdown tests. |
| ✓ | Bounded logger drain/join and canceled-caller worker-panic health. |
| ✓ | Explicit HTTP input-frame limit. |
| ✓ | Gateway runtime process-kill test checks truncated response, strict audit prefix, and fresh-session restart. |
| ✓ | Combined TLS proxy/two-gateway process-kill test verifies no replay and a new request on standby. |
| ✓ | Eight-client paced 4 MiB responses and mid-workload permanent log failure in both modes. |
| ✓ | Repeated admission overload preserves eight active streams and health checks, rejects excess traffic before dispatch, and recovers capacity. |
| ✓ | Concurrent stalled-sync test verifies bounded queues, request cleanup, and both operator modes. |
| ✓ | TLS handshake CPU work isolated on four dedicated threads with 32 retained job credits; saturation, cancellation, panic, and runtime-shutdown regressions. |
| ✓ | Two ten-minute overload runs, each five minutes per logging mode, preserve active streams and health while rejecting over 1.4 million total excess requests; dedicated CI soak. |
| ✓ | Complete exit-criterion fault/load matrix: six release workloads, proxy/process failure, stalled writes/logging, shared-listener shutdown, and 100-wave isolated-memory validation in both modes. |
| ✓ | Verified permanent worker-admission closure and drain rank, with a conditional shutdown/resource composition argument and shared-listener cancellation regressions under explicit scheduler/I/O assumptions. |

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

| Done | Submilestone |
| :---: | --- |
| ✓ | Pinned core toolchain, proof/mutation checks, security notes, and source-linked proof index. |
| ✓ | GitHub Actions test/proof workflow. |
| ✓ | Tested TLS proxy/standby example. |
| ✓ | Local TLS/disk latency and process-RSS baseline for both modes. |
| ✓ | Concurrent stalled-sync/queue-saturation test in both logging modes. |
| ✓ | Paced-peer and permanent-log-failure workload results, with a separate paced strict-mode RSS measurement. |
| ✓ | Reproducible deployment from a clean environment: a scripted operator path and a digest-pinned container reproduce the build, tests, proofs, provisioning, fail-closed startup, TLS proxy with standby, shutdown, and read-only scan; see [clean-environment reproduction](deployment.md#clean-environment-reproduction). |
| ✓ | Broader benchmarks cover concurrency one through 32 with repeats, half-minute paced streams, 1 MiB uploads, and a Linux CI release-workload job; every fixed and configurable limit, its exceeded behavior, and its evidence are tabulated in the [operational limits](operational-limits.md). |
| ✓ | End-to-end audit traces authorization through the enumerated network/disk effect sites, every failure exit, and shutdown, marking each step proved, tested, or assumed; see the [end-to-end audit](end-to-end-audit.md). |

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

## 6. Async ownership and effect composition

| Done | Submilestone |
| :---: | --- |
| ✓ | Consolidated worker and connection task wrappers into private `server/leased_task.rs::LeasedTask`, retaining distinct registry/tracking behavior and unit output. Lifecycle tests cover both lease types, including deterministic never-polled destruction. |
| ✓ | Worker and connection release gates: production `TaskCredit` gates release on reported cleanup completion; lifecycle/non-reuse contracts and seven mutations checked, with deterministic unpolled and cleanup-panic regressions. Actual destructor correspondence remains trusted. |
| ✓ | Disk jobs after request cancellation: production `DiskWorker` verifies queue-to-active ownership, the combined Q+1 frame bound, exact write/sync/commit order, and session/generation-checked release only after consuming completion delivery. Stalled I/O and abandoned handles retain active credit; fault/cancellation regressions and eleven deliberate mutations cover the protocol. Syscall truth, consuming channel delivery, and file-session identity remain explicit adapter assumptions. |
| ✓ | DNS jobs after request cancellation: production `CreditedJob` and `Reply` retain verified `TaskCredit` through queued/running lookup work and unread results; cleanup gates release, or `handoff_to` checks a live admitted owner before result adoption. Blocked/canceled lookup, queued cancellation, panic, reply retention, and adoption regressions pass. Rust destruction/channel behavior and registry identity remain explicit adapter assumptions. |
| ✓ | TLS jobs after request cancellation: the same credited job/reply path retains handshake state and sockets through blocked polls and unread replies; verified handoff transfers successful results to a live request before releasing pool capacity. Queued cancellation, blocked polls, panic, runtime shutdown, and actual TLS exchange regressions pass under the same adapter assumptions. |
| ☐ | HTTP cleanup tails: prove retained mailbox/body buffers remain charged to their owners after a request or connection is canceled. Reader substep implemented: production `ReadBuffer` verifies bounded frame load, exact read ranges, and full backing charge through partial consumption; mailbox cleanup ownership and owner-count composition remain open. |
| ☐ | Compose cleanup-before-capacity-reuse across all owners: connect the worker, connection, HTTP, disk, DNS, and TLS lifecycles to production ownership across cancellation, normal completion, panic, and shutdown. |
| ☐ | Authorization and journal-session receipts for upstream writes: prove every submitted body range belongs to the admitted request and its authorized destination/credential binding; strict-mode ranges additionally require an exact matching durable receipt from the request's designated journal session. |

DNS/TLS checkpoint validation: the locked workspace suite and five compile-fail
doctests pass (opt-in workloads excluded); the pinned Cargo/Verus check reports
204 verified checks and no errors; all 11 lifecycle/reply/handoff mutations are
rejected by proof. The remaining rows are not covered by that checkpoint.

Disk checkpoint validation: the locked workspace suite and six compile-fail
doctests pass (opt-in workloads excluded); Cargo/Verus reports 217 verified checks
and no errors; all 11 disk ownership/order mutations are rejected by proof.
HTTP tails, cross-owner composition, and upstream mediation remain unfinished.

HTTP reader checkpoint: Cargo/Verus reports 225 verified checks and no errors;
all six reader limit/range/retention mutations are rejected by proof. The locked
workspace suite and six compile-fail doctests pass; two new core reader regressions
and the strengthened backing-owner runtime regression also pass. This does
not complete the HTTP cleanup row or change the milestone count.

Start with the shared wrapper to reduce duplicated trusted lifetime logic. Preserve
the existing task-capture destruction tests for both lease types and their
poison, tracker-registration, and drain behavior. Generalize ownership mechanics
only; worker tracking and connection admission retain their own policies.

Then model the async lifecycle and effect boundary explicitly, connecting the
production adapters to the existing core transitions. Cancellation must prevent
new submissions without treating an uncertain write or a detached disk job as
completed. Each surviving effect must retain its own resource credit until its
cleanup finishes. Receipt matching must include journal/session ownership as well
as tenant, request, chunk, direction, payload, and submitted range; matching bytes
alone must not permit a receipt from another journal or session to authorize work.

Exit criteria:

- Both production task types use the shared wrapper, and lifecycle regressions
  cover completion, cancellation before and after first poll, panic, and shutdown.
- A checked lifecycle theorem forbids credit reuse while the resources it covers
  remain live; the correspondence to production ownership is explicit, with any
  remaining Rust/Tokio destructor, scheduling, and I/O assumptions listed.
- A checked composition theorem connects authorization, destination/credential
  binding, exact receipt provenance, and body-write submission in the production
  path. Availability mode may omit audit coverage but preserves authorization and
  routing constraints.
- Mutation checks reject premature credit release, cross-request or cross-session
  receipt substitution, unauthorized dispatch, and strict submission without audit
  coverage. Update the proof index and end-to-end audit with exact evidence and
  remaining trusted joins; an abstract model alone does not close this milestone.

These are submission and ownership guarantees, not proofs of peer receipt,
physical storage durability, or Tokio itself. Existing storage and syscall
assumptions remain explicit.

## Decisions to settle as implementation reaches them

Before the HTTP adapter: inbound authentication, provider credential ownership,
initial protocol versions, and static route configuration. Before disk proofs:
deployment OS/filesystem, log contents, retention, and sync/batching policy. Before
load testing: concurrency, buffer, deadline, and strict-mode latency targets.

Research and earlier experiments remain linked from the README. Perennial is not
an active workstream; its notes and historical code revision remain available if
the storage verification requirements justify revisiting that decision.
