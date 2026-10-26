# Conditional shutdown and resource release

This argument composes the verified drain registry with the production server's
ownership and cancellation paths. Verus checks the registry and finite-trace rank;
Rust ownership, thread scheduling, socket shutdown semantics, library calls, and
OS effects are explicit adapter assumptions. It is not a verification of the
thread scheduler or a hard wall-clock shutdown guarantee.

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
safety and finite-rank theorem, not an assumption that threads eventually run.
Five deliberate defects test ignored closure, admission after closure, refusal
of valid open admission, reopening on release, and forgotten release.

## Correspondence to production workers

The worker registry is private to one `Gateway`. Acquisition holds its mutex
through creation of the non-cloneable lease. Closing takes the same mutex. Thus
an acquisition after closure fails, and a drain waiter that sees zero occupancy
under that mutex sees it after every lease destructor has run.

`server/leased.rs::run`, its `TaskCredit` cleanup gate, and the order in which
`WorkerLease::drop` releases credit under the registry mutex are described in
[worker lifetimes](worker-lifetimes.md#work-ownership-covers-captures). What the
shutdown argument needs from them: the work's captures (sockets, readers,
writers, the prepared request) are dropped before cleanup is recorded and the
credit returned, so a replacement cannot reuse a slot while its prior work's
resources remain alive; and the work returns nothing, so audit jobs and DNS jobs
keep their own owners and credits when work leaves the worker. See the
[resource composition](resource-composition.md), [HTTP ownership](http-ownership.md),
and [audit ownership](audit-buffer-lifetimes.md).

Mutex poison refuses admission and never recovers registry state to release a
slot. The healthy-registry rank argument then stops applying to capacity reuse;
capacity remains conservatively stranded. The work and its captures still drop,
and shutdown can finish. Zero reusable occupancy is claimed only for unpoisoned
registries with normally completed work. A panic in the work leaves its credit
running; the release gate strands capacity and worker admission closes.

## Conditional termination argument

Assume a functioning monotonic clock behind the socket timeouts, fair OS
scheduling of runnable threads, finite completion of each library call, lock
acquisition, and destructor, normal Rust unwinding/field destruction, and that
shutting down a socket makes a thread blocked on it return. These assumptions
exclude a thread stuck forever inside a system call that ignores shutdown or a
permanently held mutex. They do not require network peers, disk syscalls, or DNS
calls to make progress on their own.

When `Shutdown::trigger` fires or the listener fails, `serve` stops accepting
(a loopback self-connection wakes the blocking accept) and permanently closes
shared worker admission. Its finite set of at most C connection threads and R
exchanges has a ten-second drain window, observed through the two registries'
condition variables. Once the window expires, `Gateway::cancel_live` fires every
in-flight exchange's `net::Cancel`: the upstream and client sockets are shut
down, the blocked read or write returns an error, the transport reports
`Fault::Cancelled`, and the exchange writes its completion record while the
logger is healthy, drops its captures, and returns its credit. Each initially
live healthy credit therefore supplies one decreasing rank step. There are
finitely many such steps, and new ones cannot be admitted. A second window of
the same length bounds that wait; `serve` then proceeds to the logger whether or
not it reached zero. A connection blocked in a system DNS lookup or a disk
append is the exception the socket assumption does not cover: it finishes on
that call's own terms and returns its credit then.

The logger then closes its fixed queue and waits at most its two-second window
for the one existing worker. A finished worker is joined; a still-blocked
worker produces a timeout error. It is never replaced. Therefore `serve` returns
success only after a successful logger shutdown, or returns an error while the
existing blocked worker remains separately charged. A timed-out logger may later
finish its outstanding syscall; timeout does not retract an already-issued effect.

Fair scheduling and finite calls imply eventual completion, but do not supply
numerical scheduling delays. Ten plus ten plus two seconds describes the
cooperative windows, not a universal upper bound: destruction, mutex
acquisition, and scheduling add delay. A numerical service-level bound requires
bounds for those scheduler/OS costs. Load tests measure them for particular
workloads; they do not prove such bounds universally.

The executable itself installs no signal handler, so a signal ends the process
without this drain; acknowledged records are durable and the recovery scanner
tolerates a torn tail ([storage contract](storage-crash-contract.md)).
`Shutdown` is for embedders and tests.

## Scope and retained work

Shared Gateway shutdown closes worker admission on every listener. Other active
`serve` invocations can still serve health/metrics and reject traffic; they own
and must close their own listeners and connection threads. Their sockets remain
under the shared C-credit bound. Stopping one listener does not claim to destroy
another caller's listener. A graceful shutdown permanently closes this Gateway;
restart requires a fresh Gateway/logger.

A blocked disk worker keeps one active frame and at most Q queued/reserved frames.
DNS has four fixed threads and 32 retained job credits per transport. Cancellation
returns request/worker slots without reclaiming those independent credits. A stuck
call cannot create replacement work beyond these limits. All captured state is
destroyed before job credit release. Full termination of those background threads
requires their calls to return, or process exit.

Each in-flight exchange adds one `net::Cancel` handle (an atomic flag and the
duplicated socket handles it may shut down) in the gateway's live table, removed
when the exchange ends. These are control objects, not payload bytes, and belong
to the thread and control inventory rather than the visible-payload theorem.

Separate Gateway, transport, logger, and listener instances add their own budgets.
No theorem turns a per-instance bound into a process-global bound for arbitrary
library construction. Requested allocations, allocator overhead, kernel memory,
and measured RSS retain the explicit distinctions in the resource inventory.

## Regression evidence

The workspace suite checks normal drain, a stalled response canceled after the
drain window, shared-listener admission closure, and a stalled stream on another
listener canceled in both logging modes. It also checks shutdown while the disk
worker stays blocked, poison/fail-closed behavior, and worker capture destruction
before credit reuse. DNS pool tests cover a blocked lookup, no replacement work,
skipped queued work whose requester left, panic recovery, and state-before-credit
destruction. The local tests exercise these adapter assumptions; the core
contracts and rank are separately verified.
