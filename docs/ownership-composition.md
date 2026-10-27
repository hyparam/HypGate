# Ownership composition

How the verified ownership and submission proofs compose through the production
runtime: the leased-work wrapper, worker and connection credits, HTTP role
cleanup, DNS and disk jobs, and the upstream mediation gate. It does not claim
to verify thread scheduling, Rust destruction, physical durability, peer
receipt, audit-file access controls, or whole-process memory.

## Checked claims

| Claim | Implementation and evidence |
| --- | --- |
| Shared work wrapper, including normal return, panic, and shutdown | Both lease types are spent by the private `server/leased.rs::run`. The work's captures drop before cleanup is recorded in `TaskCleanup`; only normal return reports completion. Worker/connection lifecycle tests cover capture destruction before release, escaped roles, panic, registry poison, drain, and shutdown. |
| Checked cleanup-before-reuse lifecycle composition, with explicit production correspondence | `lifecycle_composition::cleanup_before_reuse` combines the actual worker/connection HTTP release predicates. The DNS/TLS credit and active disk slot gates need no separate premise: `TaskCredit::releasable` is the negation of `retaining`, and `BatchWorker::can_take` excludes `busy`. `WorkerRegistry` and `ResponseRegistry` preserve other slot identities and entries on acquire/release, and maintain active-owner mappings across every transition. The runtime uses these exact registries and gates. The ownership table and transition argument below establish their composition with request and background handoff. |
| Authorization, concrete route/credential binding, exact receipt provenance, and body submission composed in the production path; availability retains authorization | `ResolvedRoute::write_bytes` checks the combined gate. `PreparedRequest` → routed `copy_body` → `BodyCopy::write_bytes` obtains the exact permitted slice through `ResolvedRoute::write_bytes` immediately before the borrowed writer call. Strict mode requires the designated journal session and exact tenant/request/chunk/direction/payload receipt. Availability omits only audit evidence. See the [upstream mediation audit](end-to-end-audit.md#upstream-mediation-chain). |
| Mutation rejection, proof index, and end-to-end audit with remaining trusted joins | Deliberate mutations check proof rejection for early release, foreign/stale identities, duplicate HTTP issuance, lost charges, cross-session receipts, unauthorized routes, omitted categories, and mismatched result handoff. The [proof index](proof-index.md), [end-to-end audit](end-to-end-audit.md), and this audit identify the remaining assumptions. |

## Ownership composition through production transitions

| Owner | Retained state and release boundary |
| --- | --- |
| Shared work wrapper | `leased::run` owns the lease and runs the work on the calling thread; the work returns nothing, so resources cannot escape through a result. `TaskCleanup<()>` is recorded only after the work and its captures are gone. |
| Worker and connection credits | Their lease destructors call `WorkerRegistry::release_task` and `TaskCredit::release` under the admission mutex. Both require a releasable credit; the worker gate also requires no active HTTP descendants. A leaked descendant, running credit, or poisoned registry strands capacity. Worker release failure also closes admission. |
| HTTP cleanup | The four worker roles cover the two readers, the upload writer, and the response writer, all `Reader`/`Charged` values on the connection thread. Normal-return destructor boundaries retain the permits through buffer cleanup. `http_owner_bounds` derives 2R readers and the output-queue count from the actual registry arrays; the runtime no longer has output queues, so that part over-approximates. See [HTTP ownership](http-ownership.md). |
| DNS jobs | Queued/running work and unread replies retain their independently admitted `TaskCredit`. `finish_work_with` creates `TaskResult<T>` containing the actual result and source identity. `TaskResult::adopt` checks that exact source and a live admitted target before returning the same value and permitting source release. Rejected adoption returns the intact result for credited cleanup. |
| Disk jobs | `BatchWorker::take` moves up to 16 exact queued frame/completion pairs into the independently charged active batch. `run` checks session and write/sync/commit order; consuming `deliver` must finish before a session/generation-matched token permits release. Cancellation of the request's reply receiver does not clear the queue or active slot. Stalled I/O cannot admit a replacement active operation. |
| Upstream mediation | The private resolved route and request pair survives connection setup and each body-write gate. Returned slices are exact live ranges; strict receipt evidence remains paired with its owner/chunk/session. Configuration selection and the submission theorem are checked; actual writer/file correspondence is audited below. |

The request's own `OwnedStream` is consumed by `Lease::drop` under the request
admission mutex. Its detached read buffer is cleared and its stream is consumed
before that critical section returns. Another admission cannot observe the free
slot until parameter destruction and mutex release complete. Canceling the
stream prevents further checked write capabilities; shutting the exchange's
sockets makes its blocked operation fail, after which no new one is attempted. Already submitted disk/DNS/TLS effects
retain their independent owners rather than being treated as canceled storage or
network effects.

`TaskResult::adopt` is a synchronous transfer under an exclusive request borrow
and its registry lock. The actual value is returned only after the source and
live destination checks; `Reply` then drops its source credit while the target
borrow still exists. Failure restores the same result into the reply before
normal credited destruction. The core checks destination liveness; the reviewed private transport call chain
pairs each reply with the request that scheduled it. Literal-IP resolution creates no background work
or pool credit and remains directly owned by the exchange on its thread.

## Why arbitrary cleanup order preserves safety

The composition theorem uses production objects and their release predicates;
it introduces no replacement lifecycle model or caller-supplied owner counts.
Each constructor establishes its registry invariant. Each checked transition
preserves that invariant, and acquire/release preserve unrelated occupied slot
identities. An active HTTP permit therefore continues to block the corresponding
parent release even when the parent's work is already marked cleaned. By
definition, `TaskCredit::releasable` is false while work, an unread result, or
cleanup retains credit, and `BatchWorker::can_take` is false while the previous
operation is busy.

Across registries, the runtime keeps distinct private owners and locks. A request
or worker transition does not mutate the background or disk owner it has already
transferred work to. Their only return paths are the listed checked cleanup,
adoption, and delivery gates. Applying the preserved local invariants after each
such transition yields the product safety property for normal completion,
cancellation, panic, and shutdown, regardless of which independent owner finishes
first. Allocation cannot reuse an occupied slot; exhaustion or stranded capacity
fails admission instead of manufacturing a completion.

The runtime test
`cancellation_preserves_independent_response_background_and_disk_owners` exercises
this boundary with the actual lease wrapper, credited-job implementation, and
disk worker, in the form the threaded runtime allows: after an exchange's work
returns, its slot is reusable while a blocked background job and a blocked disk
write remain independently retained. Each releases only after its own cleanup;
a timed-out disk shutdown performs no replacement write or replay. Separate DNS
tests exercise the real resolver pool and its blocking, departed-requester, and
panic paths. The cross-owner test is an adapter regression, not a substitute
for the checked transition invariants.

## Trusted joins and limits

The general trusted computing base is listed once in the
[security contract](security-contract.md#trusted-computing-base-and-evidence);
the joins specific to this composition are:

- Rust moves, private fields, non-cloneable tokens, Arc lifetime, disjoint mutable
  ownership, mutex serialization, and normal-return destructor reporting bind the
  checked states to physical resources. This is a compositional proof under those
  adapter contracts, not a mechanization of Rust or the thread scheduler.
- Registry identity is scoped by the private runtime wrappers. Numeric task IDs
  from different registries are not globally unique. Production never pairs a
  token with a different registry instance.
- The chunked writer's framed chunk, thread scheduling, socket shutdown as
  cancellation, TLS/DNS/OS allocation, and allocator capacity remain separate
  assumptions.
  Counts and payload limits do not establish a total-RSS bound or eventual
  cleanup without the documented progress assumptions.
- Disk `Storage`/`Completion` adapters must truthfully report write/sync outcomes
  and finish consuming delivery before returning. Logger/file identity, physical
  durability, secret provisioning, and actual `Write` target correspondence
  remain explicit trusted boundaries.
- There is no public exchange API outside the worker context: every exchange
  runs through the verified `exchange_driver` over `server::ConnectionEffects`,
  which issues all four HTTP roles from the connection's own worker. The
  test-only `transport::exchange` module recomposes the provider side for the
  transport tests with a worker it constructs.
