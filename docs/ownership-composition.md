# Ownership composition

How the verified ownership and submission proofs compose through the production
runtime: task wrappers, worker and connection credits, HTTP cleanup tails, DNS,
TLS, and disk jobs, and the upstream mediation gate. It does not claim to verify
Tokio, Hyper, Rust destruction, physical durability, peer receipt, audit-file
access controls, or whole-process memory.

## Checked claims

| Claim | Implementation and evidence |
| --- | --- |
| Shared task wrapper, including completion, cancellation before/after polling, panic, and shutdown | Both lease types use private `server/leased_task.rs::LeasedTask`. Actual future captures enter `TaskCleanup`; only normal destruction reports completion. Worker/connection lifecycle tests cover never-polled destruction, cancellation, capture panic, registry poison, and shutdown. |
| Checked cleanup-before-reuse lifecycle composition, with explicit production correspondence | `lifecycle_composition::cleanup_before_reuse` combines the actual worker/connection HTTP release predicates. The DNS/TLS credit and active disk slot gates need no separate premise: `TaskCredit::releasable` is the negation of `retaining`, and `DiskWorker::available` excludes `busy`. `WorkerRegistry` and `ResponseRegistry` preserve other slot identities and entries on acquire/release, and maintain active-owner mappings across every transition. The runtime uses these exact registries and gates. The ownership table and transition argument below establish their composition with request and background handoff. |
| Authorization, concrete route/credential binding, exact receipt provenance, and body submission composed in the production path; availability retains authorization | `ResolvedRoute::write_bytes` checks the combined gate. `PreparedRequest` → routed `copy_body` → `Request::routed_bytes` obtains the exact permitted slice immediately before the borrowed writer call. Strict mode requires the designated journal session and exact tenant/request/chunk/direction/payload receipt. Availability omits only audit evidence. See the [upstream mediation audit](end-to-end-audit.md#upstream-mediation-chain). |
| Mutation rejection, proof index, and end-to-end audit with remaining trusted joins | All 253 deliberate mutations fail proof, including early release, foreign/stale identities, duplicate HTTP issuance, lost charges, cross-session receipts, unauthorized routes, omitted categories, and mismatched result handoff. The [proof index](proof-index.md), [end-to-end audit](end-to-end-audit.md), and this audit identify the remaining assumptions. |

## Ownership composition through production transitions

| Owner | Retained state and release boundary |
| --- | --- |
| Shared task wrapper | `LeasedTask` owns the complete boxed future and its lease; unit output prevents task-owned resources escaping through its result. `TaskCleanup<T>` binds the actual future/captures to the source task. Extraction alone does not complete cleanup. |
| Worker and connection credits | Their lease destructors call `WorkerRegistry::release_task` and `ResponseRegistry::release_task` under the admission mutex. Both require completed task cleanup and no active HTTP descendants. A leaked descendant, failed cleanup, or poisoned registry strands capacity. Worker release failure also closes admission. |
| HTTP cleanup tails | The four worker roles cover both detached readers, the upload channel, and the response writer. The connection permit covers the response receiver. Normal-return destructor boundaries retain the permits through physical buffer cleanup. Shared upload endpoints preserve a panic flag. `http_owner_bounds` derives 2R readers and C+2R queues/tails from the actual registry arrays. See [HTTP ownership](http-ownership.md). |
| DNS jobs | Queued/running work and unread replies retain their independently admitted `TaskCredit`. `finish_work_with` creates `TaskResult<T>` containing the actual result and source identity. `TaskResult::adopt` checks that exact source and a live admitted target before returning the same value and permitting source release. Rejected adoption returns the intact result for credited cleanup. |
| TLS jobs | The same `CreditedJob`/`Reply` protocol retains the actual handshake captures, socket, and result. Blocking polls, queued cancellation, unread replies, panic, and runtime shutdown do not synthesize cleanup or adoption. Production transport adopts the checked result before using it. |
| Disk jobs | `DiskWorker::take` moves the exact queued frame/completion into the independently charged active slot. `run` checks session and write/sync/commit order; consuming `deliver` must finish before a session/generation-matched token permits release. Cancellation of the request's reply receiver does not clear the queue or active slot. Stalled I/O cannot admit a replacement active operation. |
| Upstream mediation | The private resolved route and request pair survives connection setup and each body-write gate. Returned slices are exact live ranges; strict receipt evidence remains paired with its owner/chunk/session. Configuration selection and the submission theorem are checked; actual writer/file correspondence is audited below. |

The request's own `OwnedStream` is consumed by `Lease::drop` under the request
admission mutex. Its detached read buffer is cleared and its stream is consumed
before that critical section returns. Another admission cannot observe the free
slot until parameter destruction and mutex release complete. Canceling the
stream prevents further checked write capabilities; aborting an async task stops
new polling when cancellation is observed. Already submitted disk/DNS/TLS effects
retain their independent owners rather than being treated as canceled storage or
network effects.

`TaskResult::adopt` is a synchronous transfer under an exclusive request borrow
and its registry lock. The actual value is returned only after the source and
live destination checks; `Reply` then drops its source credit while the target
borrow still exists. Failure restores the same result into the reply before
normal credited destruction. The core checks destination liveness; the reviewed private transport call chain
pairs each reply with the request that scheduled it. Literal-IP resolution creates no background work
or pool credit and remains directly owned by the request future.

## Why arbitrary cleanup order preserves safety

The composition theorem uses production objects and their release predicates;
it introduces no replacement lifecycle model or caller-supplied owner counts.
Each constructor establishes its registry invariant. Each checked transition
preserves that invariant, and acquire/release preserve unrelated occupied slot
identities. An active HTTP permit therefore continues to block the corresponding
parent release even when the parent's future is already marked cleaned. By
definition, `TaskCredit::releasable` is false while work, an unread result, or
cleanup retains credit, and `DiskWorker::available` is false while the previous
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
this boundary with the actual task wrappers, credited-job implementation, HTTP
channel, and disk worker. After worker cancellation, its slot is reusable while
the queued response's connection slot, blocked background job, and blocked disk
write remain independently retained. Each releases only after its own cleanup;
a timed-out disk shutdown performs no replacement write or replay. Separate
DNS/TLS tests exercise the real resolver/handshake pools and their specific
blocking, cancellation, and panic paths. The cross-owner test is an adapter
regression, not a substitute for the checked transition invariants.

## Trusted joins and limits

The general trusted computing base is listed once in the
[security contract](security-contract.md#trusted-computing-base-and-evidence);
the joins specific to this composition are:

- Rust moves, private fields, non-cloneable tokens, Arc lifetime, disjoint mutable
  ownership, mutex serialization, and normal-return destructor reporting bind the
  checked states to physical resources. This is a compositional proof under those
  adapter contracts, not a mechanization of Rust or the executor.
- Registry identity is scoped by the private runtime wrappers. Numeric task IDs
  from different registries are not globally unique. Production never pairs a
  token with a different registry instance.
- Hyper's dequeued-frame retention, Tokio scheduling/cancellation, TLS/DNS/OS
  allocation, and allocator capacity remain separate dependency assumptions.
  Counts and payload limits do not establish a total-RSS bound or eventual
  cleanup without the documented progress assumptions.
- Disk `Storage`/`Completion` adapters must truthfully report write/sync outcomes
  and finish consuming delivery before returning. Logger/file identity, physical
  durability, secret provisioning, and actual `AsyncWrite` target correspondence
  remain explicit trusted boundaries.
- The public embedding transport API has no gateway worker context. Its caller
  supplies its own lifetime mapping; the gateway always uses `exchange_with_http`.
