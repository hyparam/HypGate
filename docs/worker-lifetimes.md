# Worker credits and work destruction

Production `server/workers.rs` uses the same Verus-checked `ResourceAdmission`
implementation as request admission through `DrainRegistry`, in a separate private registry with R slots
and zero payload capacity. Worker keys never create streams. A worker is the
exchange a connection thread runs; the registry is the source of the
worker-count bound and does not verify the thread or the runtime wrapper.

## Checked transitions and runtime bindings

- `new` establishes valid, empty slots. `acquire` preserves validity, changes
  occupancy by exactly one on success, and refuses full capacity or exhausted IDs.
- Each successful acquisition moves its non-cloneable key into a private credit
  that retains an Arc to the issuing registry. No public key extraction or
  cross-registry release exists in this wrapper.
- A mutex serializes registry operations. No lock guard is held across I/O. Failure
  to lock a poisoned registry refuses admission; Drop never recovers poison.
- `TaskCredit` owns the key and gates release through reserved, running, cleaning,
  and cleaned phases. Both running and cleaning refuse release without changing
  the registry; beginning cleanup is not evidence of its completion. Unused
  reservations can be returned without starting work.
- `release_worker` returns a releasable unclaimed key's one live slot. The private
  lease invokes it once in Drop, under the registry mutex, then notifies the drain
  condition variable. Drain wait synchronizes with the same mutex.

Registry preservation and exact occupancy contracts are mechanically checked.
Their application to all concurrent worker lifetimes still assumes correct Rust
ownership, mutex serialization, and destructor execution. A skipped destructor
can strand capacity; it must not be interpreted as permission to reuse a slot.

## Work ownership covers captures

The lease is not left as a local inside the work: `server/leased.rs::run`, shared
by worker and connection leases, is the one place a lease is spent. It:

1. Calls the verified `TaskCredit::start`.
2. Runs the work closure, which owns the sockets, readers, writers, and the
   exchange's prepared request as its captures and drops them before returning.
3. Records cleanup with `begin_cleanup_with`/`finish`/`finish_cleanup_with`,
   whose token must belong to this credit.
4. Drops the lease, whose destructor consumes the credit through its verified
   release gate.

If the work panics, unwinding drops the lease with its credit still running. The
release gate refuses the running credit and `WorkerRegistry::release_task`
closes admission: capacity is stranded rather than reported free. A connection
credit is likewise stranded. A role still alive when the lease drops (a reader or
writer that escaped the work) also refuses release and closes admission. An
indefinitely blocked work never reaches cleanup. This uses safe Rust without
assumptions about capture field order. The work returns nothing, so
worker-owned resources cannot escape through a result; channels may transfer
buffers to disk owners, which have their own accounting.

The [shutdown argument](shutdown-proof.md) states the scheduling and destruction
assumptions needed for conditional progress. Permanent admission closure and the
decreasing drain rank are mechanically verified.

## Evidence

- Hold eight running workers on eight threads, reject 32 additional acquisitions,
  release and join all eight, and reuse all eight slots.
- A capture destructor asserts the slot is still occupied when the work returns
  normally; reporting cleanup before destroying captures would fail it.
- A reader that escapes the work keeps the slot occupied after the thread finishes,
  and admission stays closed even after the reader is dropped.
- A panicking work strands its credit; worker admission becomes unhealthy and
  refuses replacements.
- Closing refuses new workers and reports unhealthy; a drained registry reports
  drained immediately.
- Poison a worker registry while a credit is live, drop that credit, and verify
  readiness and forwarding refuse work in both logging modes, with no upstream
  connection and healthy independent request admission.

`task_credit.rs` checks the executable lifecycle and both registry release gates.
`acquire_preserves_retained_task` derives non-reuse of the retained slot from the
existing registry acquisition contract. Seven mutations cover early release,
invalid cleanup transitions, denied cleanup completion, and overwriting a live
slot. The runtime tests exercise correspondence to actual destruction; that
correspondence remains trusted. The gate does not verify Rust destructors, the
thread scheduler, or dependency internals. Independent HTTP, disk, and DNS cleanup
is composed through their production gates and checked source-bound handoffs; see
the [ownership composition](ownership-composition.md). Whole-process allocation
and a complete refinement of the threaded runtime remain outside that claim.

Graceful shutdown permanently closes worker admission across all listeners sharing
the Gateway. Closure and acquisition share the registry mutex, so a closed registry
cannot admit a late worker. After the ten-second drain window the server cancels
remaining exchanges by shutting their sockets ([shutdown proof](shutdown-proof.md)).
