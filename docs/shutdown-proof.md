# Conditional shutdown and resource release

This argument composes the verified drain registry with the production server's
ownership and cancellation paths. Verus checks the registry and finite-trace rank;
Rust ownership, Tokio scheduling/cancellation, library polls, and OS effects are
explicit adapter assumptions. It is not a verification of Tokio or a hard
wall-clock shutdown guarantee.

## Mechanically checked component

`gateway-core/src/drain.rs` wraps the production resource registry and is used by
`server/workers.rs`. Its private state has no reopening operation.

- Construction establishes an open, empty registry of the specified capacity.
- Acquisition preserves validity and capacity. Success increases occupancy by
  exactly one, returns an owned unclaimed key, and requires the old registry to
  be open. Rejection preserves the complete state and is justified by closure,
  exhausted IDs, or full occupancy.
- Closing preserves the entire inner registry, including every outstanding key,
  and sets the closed flag. Repeated close is harmless.
- Release succeeds exactly for a matching unclaimed key. It decreases occupancy
  by one, preserves closure and every other slot, and invalidates that key.
  Failed release changes nothing.
- `drain_trace_rank` proves that a trace of successful post-closure releases has
  final occupancy plus release count equal to initial occupancy. At most that
  many releases can succeed, and that many releases leave zero occupancy.

The initial rank is at most R. After closure no successful acquisition can
increase it, and a repeated/stale release cannot decrease it twice. This is a
safety and finite-rank theorem, not an assumption that tasks eventually run.
Five deliberate defects test ignored closure, admission after closure, refusal
of valid open admission, reopening on release, and forgotten release.

## Correspondence to production workers

The worker registry is private to one `Gateway`. Acquisition holds its mutex
through creation of the tracker token and non-cloneable lease. Closing takes the
same mutex before closing the tracker. Thus any successful concurrent acquisition
is already tracked before closure can finish; an acquisition after closure fails.
A tracker becoming empty cannot race with a newly admitted worker.

`WorkerTask` owns its boxed future before its lease in declaration order. The
future, including unpolled captures and network/body owners, is destroyed first.
`WorkerLease::drop` then locks the issuing registry, removes tracking, and returns
its key before unlocking. The drain waiter synchronizes with this same mutex
after the tracker wait, covering the interval between notification and the end
of that destructor. A replacement cannot reuse the slot while its prior future
or tracking token remains alive.

No task result exports a worker resource: the result is unit. HTTP mailboxes,
audit jobs, DNS jobs, and TLS handshake jobs have their own owners and credits
when data/work leaves the worker. Cancellation therefore cannot erase those
categories from accounting. See the [resource composition](resource-composition.md),
[HTTP ownership](http-buffer-lifetimes.md), and [audit ownership](audit-buffer-lifetimes.md).

Mutex poison refuses admission and never recovers registry state to release a
slot. The healthy-registry rank argument then stops applying to capacity reuse;
capacity remains conservatively stranded. The future and its captures still
drop, tracking disappears, and shutdown can finish. Zero reusable occupancy is
claimed only for unpoisoned registries.

## Conditional termination argument

Assume a functioning monotonic Tokio timer, fair scheduling of awakened tasks,
finite completion of each synchronous poll/destructor and lock acquisition, and
normal Rust unwinding/field destruction. These assumptions exclude an executor
thread stuck forever inside a synchronous poll or a permanently held mutex.
They do not require network peers, disk syscalls, DNS calls, or TLS handshake
verification to make progress.

On a shutdown signal or listener error, `serve` drops its listener and permanently
closes shared worker admission. Its finite set of at most C inbound tasks has a
ten-second drain window. Once the window expires, it aborts and joins all remaining
local tasks. Under the scheduling/destruction assumptions these joins terminate.
Dropping a response abort guard requests cancellation of its worker; successful
body EOF may instead leave the worker finishing bookkeeping.

The same absolute drain deadline covers all R tracked workers, including workers
started through other listeners sharing the Gateway. If tracking has not drained,
the server cancels the shared worker token. Every production worker selects that
token with priority over its operation. At its next scheduled poll it drops the
operation and finishes; the wrapper destroys the future and returns its credit.
Each initially live healthy credit therefore supplies one decreasing rank step.
There are finitely many such steps, and new ones cannot be admitted. Tracker wait
and its final mutex synchronization terminate with no live worker futures and,
for an unpoisoned registry, zero occupied worker slots. This also covers a worker
whose response had already reached clean EOF.

The logger then closes its fixed queue and waits at most its two-second timer
window for the one existing worker. A finished worker is joined; a still-blocked
worker produces a timeout error. It is never replaced. Therefore `serve` returns
success only after a successful logger shutdown, or returns an error while the
existing blocked worker remains separately charged. A timed-out logger may later
finish its outstanding syscall; timeout does not retract an already-issued effect.

Fair scheduling and finite polls imply eventual completion, but do not supply
numerical scheduling delays. Ten plus two seconds describes the two cooperative
windows, not a universal twelve-second upper bound: abort/join, destruction,
mutex acquisition, and timer scheduling add delay. A numerical service-level
bound requires bounds for those scheduler/OS costs. Load tests measure them for
particular workloads; they do not prove such bounds universally.

## Scope and retained work

Shared Gateway shutdown closes worker admission on every listener. Other active
`serve` invocations can still serve health/metrics and reject traffic; they own
and must close their own listeners and inbound tasks. Their sockets remain under
the shared C-credit bound. Stopping one listener does not claim to destroy another
caller's listener. A graceful shutdown permanently closes this Gateway; restart
requires a fresh Gateway/logger. Dropping/aborting `serve` bypasses graceful
closure and only requests its child cleanup, preserving the documented abort and
restart behavior.

A blocked disk worker keeps one active frame and at most Q queued/reserved frames.
DNS has four fixed threads and 32 retained job credits per transport. TLS has four
fixed threads and 32 retained job credits per transport. Cancellation returns
request/worker slots without reclaiming those independent credits. A stuck call
cannot create replacement work beyond these limits. Successful TLS replies still
held by a live request are charged to that request; canceled running handshakes
are charged separately, even when R is smaller than 32. All captured state is
destroyed before job credit release. Full termination of those background threads
requires their calls/polls to return, or process exit. They do not hold Tokio
runtime shutdown open.

The shared cancellation token adds one Tokio-util token state per Gateway, with
at most R active cancellation-wait registrations in worker futures. Production
clones that token; it does not create a growing tree of child tokens. Each
`serve` drain adds its own tracker wait future, charged to that invocation.
These are control objects/wakers, not payload bytes, and belong to the task and
channel control inventory rather than the visible-payload theorem.

Separate Gateway, transport, logger, and listener instances add their own budgets.
No theorem turns a per-instance bound into a process-global bound for arbitrary
library construction. Requested allocations, allocator overhead, kernel memory,
and measured RSS retain the explicit distinctions in the resource inventory.

## Regression evidence

The workspace suite checks normal drain, a stalled response canceled after ten
seconds, shared-listener admission closure, and a stalled stream on another
listener canceled in both logging modes. It also checks shutdown while the disk
worker stays blocked, poison/fail-closed behavior, and worker capture destruction
before credit reuse. TLS pool tests cover a blocked synchronous poll, no replacement
work, canceled queued jobs, panic recovery, state-before-credit destruction, and
Tokio runtime shutdown while the poll remains blocked. The local tests exercise
these adapter assumptions; the core contracts and rank are separately verified.
