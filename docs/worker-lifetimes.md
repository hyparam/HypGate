# Worker credits and task destruction

Production `server/workers.rs` uses the same Verus-checked `ResourceAdmission`
implementation as request admission through `DrainRegistry`, in a separate private registry with R slots
and zero payload capacity. Worker keys never create streams. This replaces the
Tokio semaphore as the source of the worker-count bound; it does not verify the
executor or the runtime wrapper.

## Checked transitions and runtime bindings

- `new` establishes valid, empty slots. `acquire` preserves validity, changes
  occupancy by exactly one on success, and refuses full capacity or exhausted IDs.
- Each successful acquisition moves its non-cloneable key into a private credit
  that retains an Arc to the issuing registry. No public key extraction or
  cross-registry release exists in this wrapper.
- A mutex serializes registry operations. No lock guard crosses an await. Failure
  to lock a poisoned registry refuses admission; Drop never recovers poison.
- `release` returns the unclaimed key's one live slot and preserves every other
  slot. The private credit invokes it once in Drop. The worker tracker token is
  dropped under the registry mutex before releasing its slot, so a replacement
  never overlaps that token's tracked lifetime. Drain wait synchronizes with the
  same mutex after tracker notification.

Registry preservation and exact occupancy contracts are mechanically checked.
Their application to all concurrent worker lifetimes still assumes correct Rust
ownership, mutex serialization, and destructor execution. A skipped destructor
can strand capacity; it must not be interpreted as permission to reuse a slot.

## Task ownership covers captures

A lease local inside an async block is an insufficiently explicit boundary for
all future captures, especially when canceled before its first poll. Production
spawns a `WorkerTask` with its fields in this order:

1. A pinned, boxed future containing the entire request worker and its captures.
2. The worker lease, whose destructor removes tracking and returns registry credit
   while holding the same mutex.

Rust destroys struct fields in declaration order. The wrapper therefore retains
credit through destruction of the future, without unsafe projection or assumptions
about the compiler's internal async capture field order. Its only output is unit;
worker-owned resources cannot escape through a task result. Channels may transfer
buffers to HTTP or disk owners; those categories still require separate accounting.

Tokio may retain task bookkeeping after the future is destroyed. This wrapper
bounds live credited work, not all executor allocations. Aborting a task requests
cancellation; the credit remains occupied until Tokio actually destroys its future.
The [shutdown argument](shutdown-proof.md) states the scheduler and destruction
assumptions needed for conditional progress. Permanent admission closure and the
decreasing drain rank are now mechanically verified.

## Evidence

The existing real-socket cleanup-budget test holds worker credit with stream
admission completely free, rejects excess traffic, keeps health endpoints working,
then cancels an unpolled task and verifies credit recovery. Additional tests:

- Hold eight running workers, reject 32 additional acquisitions, cancel and join
  all eight, and reuse all eight slots.
- A capture destructor asserts the slot and tracking token are still occupied on
  successful completion, worker panic, cancellation before first poll, and
  cancellation after suspension. Reversing the wrapper's field order makes this regression test fail.
- Poison a worker registry while a credit is live, drop that credit, and verify
  readiness and forwarding refuse work in both logging modes, with no upstream
  connection and healthy independent request admission.

These are adapter correspondence tests, not new Verus theorems. Full ownership
snapshot composition and dependency allocation accounting remain open.

Graceful shutdown permanently closes worker admission across all listeners sharing
the Gateway. Closure serializes with acquisition through tracker registration;
a closed, empty tracker cannot miss a late admitted worker. The shared cancellation
token ends remaining workers after the ten-second drain window.
