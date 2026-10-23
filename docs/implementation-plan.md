# Implementation milestones

Status: approved direction is Rust plus Verus; milestone 1 is next.
Scope: forward opaque HTTP request bodies and streaming responses, and log to disk.
No provider translation, automatic generation replay, billing, or plugin system.
Operators choose strict durable logging or forwarding with degraded audit coverage.
An external load balancer handles failover between gateway instances.

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
