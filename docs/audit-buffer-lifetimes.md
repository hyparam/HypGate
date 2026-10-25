# Audit-buffer ownership and cancellation

This is a source-level correspondence argument for the audit terms in
`Buffers::accounted_payload_bound`, checked against the production DiskLog path
and the verified fixed FIFO with Tokio 1.54.1 completion oneshots. It does not
formally verify synchronization, Tokio channels, or Rust destruction.
Let Q be disk queue capacity, R the request limit, and K the request chunk size.
The production log-frame payload is at most K; independent library callers can
supply up to `MAX_RECORD_BYTES` and must account for retained receipts separately.

| Stage | Owner and credit | Frame count charged |
| --- | --- | --- |
| Before reservation | `LogRecord` borrows the request's existing payload. No copied frame exists. | Already in the request chunk term |
| Encoding | `Queue::enqueue` uses private `push_with` to call verified `FrameQueue::reserve` while holding the queue mutex before invoking the encoding callback. That callback builds a `RecordBody` through verified `FrameQueue::encode_reserved`. The mutex excludes insertion and shutdown until the constructed Job is installed. | One of Q encoding/queued slots |
| Queued | Verified `FrameQueue::finish_reserved` transfers the immutable frame and receipt sender into a fixed slot. The caller retains only the receipt receiver. | One of Q encoding/queued slots |
| Writing/syncing/committing | Verified `DiskWorker::take` moves the exact queued frame/sender into a private `ActiveAppend` and charges the independent active slot. `DiskWorker::run` owns it across synchronous write and sync calls. Dequeue returns queue credit, allowing another producer to encode. | One active frame in addition to Q |
| Delivering | `commit_frame` moves the same frame into `DurableFrame`; no payload clone is made. `FinishedAppend::deliver` consumes the receipt/sender into the caller's oneshot or destroys the undeliverable value, then returns a private release token. | Active-frame term until transfer, then receipt term |
| Delivered, awaiting consumption | `Request::audit_current` retains exclusive request ownership across append and checks the exact receipt before dropping it. | At most one receipt per live production request, hence R |
| Dropped/canceled | The frame is dropped at its current owner; dropping the caller alone cannot drop a queued Job or interrupt its syscall. | Credit follows the surviving frame, not the caller's task |

The resulting frame term is `(Q + 1 + R) * (K + 65)`. The checked production
encoding derives 65 bytes of header/checksum overhead. The journal's byte history
and canonical-frame sequence are erased ghost state, not retained old payloads.
Header encoding/comparison scratch is accounted separately and now requests
33 bytes up front; the [allocation inventory](dependency-resources.md#audit-encoding-allocation-requests)
records simultaneous header/body requests and the sealing-capacity regression. Channel nodes,
oneshot state, allocator slack, and thread stacks are outside the frame-payload term.
The worker explicitly requests a 2 MiB stack rather than inheriting the
environment-dependent Rust default; reservation, committed pages, and OS overhead
remain distinct. The [control-storage inventory](dependency-resources.md#channel-control-storage)
counts completion oneshots separately; both HTTP body channels and the audit
queue now use fixed-slot storage.

## Verified active-worker ownership

`gateway-core/src/disk_worker.rs` owns the production worker protocol. Its
`take` transition runs under the queue mutex, refuses an already busy worker,
generation exhaustion, or an incompatible payload limit, and atomically moves
the oldest exact frame/completion pair into `ActiveAppend`. The queue and active
slot have independent credits. `queued_and_active_bound` derives the actual
queue plus encoding plus active-frame bound of `(Q + 1) * (K + 65)` from the
queue invariant and the retained active-frame snapshot. The private active and
finished handles preserve that snapshot's bytes and completion association.

`DiskWorker::run` borrows its owner while consuming the active handle. The verified
sequence begins the journal append, calls `Storage::write_all` on that exact
frame, calls `Storage::sync` only after successful writing, and commits only
after successful sync. Successful output binds the exact record to both the
acknowledged journal prefix and the storage model's stable bytes. Failure marks
the journal permanently failed; later queued frames are discarded without new
writes, even if the external fault recovers. A disabled worker performs no I/O.

The worker stays busy through `FinishedAppend` delivery. Only its consuming
`deliver` method constructs `ReleasedAppend`; there is no public constructor,
clone, or raw frame extraction. `release` checks both the file session and the
monotonic generation before enabling another dequeue. Dropping an active or
finished handle without delivery strands the active credit instead of silently
reusing it. A stuck syscall cannot reach delivery or release. Caller cancellation
only closes its receipt receiver and never holds an active-slot release token.

The remaining adapter contracts are narrow: `Storage` truthfully appends the
supplied bytes and reports sync under the storage crash model; `Completion`
transfers its sole receipt to the request-owned channel or destroys it before
returning. Production implementations are `Write::write_all`, `sync_all`, and
one consuming oneshot send. They neither retain application payload copies nor
spawn replacement/delivery tasks. Rust destruction, mutex/channel behavior, one
worker per logger, and the fresh file-session binding remain explicit assumptions.
Receipt-to-request accounting joins the separate composition proof; this does
not claim that request cancellation stops filesystem operations.

Core regressions cover busy-slot refusal through delivery, abandoned active and
finished handles, mismatched payload limits, closed-queue drain, write/sync
failure, permanent failure without retry, exact reply association, and rejecting
another session's completion token. The real queue regression cancels the first
caller while retaining its active credit. Existing stalled-sync, process-kill,
disk-error, and shutdown tests run through this verified protocol. Eleven deliberate
mutations test early dequeue/release, wrong session/generation, lost active charge,
omitted active bytes, ignored limits, disabled/failed-state I/O, and write/sync bypasses.

## Verified fixed queue and synchronization obligations

`FrameQueue<Completion>` wraps the fixed queue with an invariant that every
retained frame is structurally valid. Exact tuple contracts preserve each frame's
completion handle through enqueue, rejection, and dequeue. Its ghost frame
projection supplies count and validity to the combined buffer theorem without
another runtime collection. The queued-frame bound is Q times
(the immutable queue payload limit + 65). The executable supplies configured K;
append rejects excess before encoding, and verified insertion independently checks
the bound while preserving the rejected frame/completion tuple. The default library
constructor uses 1 MiB. Encoding scratch, active frames, and receipt lifetimes
still require their separate correspondence arguments.

The core now records one encoding reservation. `reserve` accepts exactly when
open, unreserved, and below capacity; repeated reservation and direct `push` are
refused while it is held. `finish_reserved` releases that reservation and either
inserts the exact frame/completion tuple or returns it unchanged if closed or
oversized. Close and dequeue preserve the reservation. The invariant bounds
queued count plus the reservation by Q. `encoding_and_queued_bound` includes one
in-progress encoding in the same Q-frame subtotal, conditional on its bytes
fitting the configured limit plus framing overhead. `Buffers::accounted_payload_with_encoding` lifts this to the combined subtotal,
adding a separate encoding byte snapshot to the queued projection. It requires
that snapshot to be empty without a reservation and to fit the configured limit
plus overhead. The production callback now uses `encode_reserved`, which refuses
missing/closed reservations and excessive payloads before constructing a body.
`RecordBody::retained_size` derives its exact 33-byte overhead; consuming `seal`
preserves payload identity and adds the checksum. `Buffers::accounted_payload_with_encoding`
takes its encoding snapshot from those containers' derived lengths.

The production queue now exposes `enqueue(record)`, not a callback or core queue
reference. Its private callback receives a non-cloneable `EncodingPermit` whose
`encode(self, record)` method consumes it. Only the queue module can mint that
permit; encoding, sealing, and completion pairing occur together before insertion.
This Rust ownership/privacy boundary prevents production callers from repeating
encoding through a borrowed queue reference. The module's implementation and
mutex scope remain trusted. Independent core-library clients can still call the
immutable encoder repeatedly; its contract does not prove global uniqueness.
Its payload bound does not account for Vec spare capacity or transient allocations
inside encoding/checksum computation.

A construction panic leaves the reservation charged in poisoned queue state;
the adapter never recovers that state to admit more work. This deliberately avoids
claiming that an unwinding or abandoned producer has already released its storage.

`gateway-core/src/fixed_queue.rs` owns one vector of Q optional Job slots, a head
index, and an occupied count. Its invariant states that exactly the occupied
logical prefix contains values, including across wraparound. Checked constructor,
query, push, and pop contracts establish empty initialization, exact full/empty
rejection, FIFO identity/order, occupancy bounds, and unchanged physical slot
count. Pop moves the oldest Job out and clears its slot; push never overwrites
an occupied slot. The core also owns closure: `close` preserves the exact queued
sequence and capacity, and all later push/pop operations preserve the closed flag.
Push refuses a closed queue even after it has been completely drained. Pop still
returns the oldest pending value when closed, so closure cannot discard admitted
records or manufacture an empty result. Repeated closure is harmless. All arithmetic
is checked. No new assumed lemma or external-body
contract hides queue behavior.

The production wrapper uses a mutex and condvar. A producer reserves capacity under
the same lock held through encoding and verified insertion; no await or reservation
escapes it. The sole worker pops under that lock, then releases it before file I/O.
Canceling an append caller only drops its completion receiver; it cannot remove
an admitted Job. Shutdown calls verified `close` and wakes the worker, which drains
existing entries before exiting. Dropping the last DiskLog handle also closes the
producer side. With an unpoisoned mutex, worker exit closes admission and drops
queued receipt senders. Queue-mutex poisoning refuses work rather than recovering
the queue; a producer unwind wakes the consumer so it can observe the poison.
Poisoned queued storage stays charged to Q until its final owner is destroyed;
waiting callers still have their logging deadline. It is never reused for new work.

Backing storage requests Q `Option<Job>` elements once at initialization. Push/pop
use indexed replacement and swap without resizing; there are no audit mpsc block
allocations or permit futures. Vec capacity/allocator rounding, mutex/condvar and
Arc layout, payload storage inside Jobs, and completion oneshots are still separate
from the verified slot-count theorem. Synchronization and destructor execution
remain trusted; this is not a proof of arbitrary thread scheduling.

In [oneshot.rs](https://docs.rs/crate/tokio/1.54.1/source/src/sync/oneshot.rs), sending
to an already closed receiver returns the unsent value. DiskLog immediately drops
that result, including the receipt's frame. If delivery wins the race, receiver
Drop closes the channel and consumes/drops the delivered value. The receipt is
moved, not cloned; `DurableFrame` has no cloning API. These channel/drop semantics
are trusted obligations supporting the count hypotheses, not Verus-checked code.

## Cancellation and failure evidence

`canceling_append_callers_does_not_release_queued_or_active_frame_credit` stalls
one writer in sync, queues a second Job in a one-slot channel, and aborts both
append callers. The queued slot remains occupied and sixteen excess appends are
refused. Releasing the same worker produces exactly the two admitted frames and
one later frame, with three sync calls. The later caller gets its own exact
receipt. The two canceled callers receive none; their records may still be durable.
This is permitted logged-but-unsent data, not replay of a model generation.

Existing tests separately exercise timeout poisoning, blocked shutdown, queue
saturation, write/sync failures, and worker panic after caller cancellation.
FIFO tests compare repeated wraparound/full rejection against VecDeque at capacities
1, 2, 31, 32, 33, and 1024; ownership probes check each value is dropped once.
Wrapper tests check that rejected jobs are never constructed, closure drains queued
jobs, worker exit closes pending receipts, construction panic fails closed, and
dropping the final logger handle releases an idle worker. Deliberate queue mutations
exercise full overwrite, oldest-value loss, skipped head advancement, and refusal
of a valid insertion, plus accepting after closure, reopening during drain, and
ignoring closure. A wrapped-queue closure test checks repeated close, preserved
drain order, and refusal before and after draining. The runtime no longer maintains
a separate unverified closure flag. A two-thread adapter regression holds a producer
inside job construction while shutdown attempts to close; closure waits for that
admitted Job, preserves it for drain, and refuses subsequent construction.
A maximum-record regression writes and scans a full 1 MiB payload through the
production worker, rejects one byte over the limit without poisoning logging,
then writes and recovers a subsequent record and checks the exact file extent.
A timeout bounds caller waiting, not syscall duration. It never creates a new
worker to bypass a blocked syscall. The combined stalled-log workload checks
these effects with concurrent gateway requests and both logging policies.

Remaining formal work is a checked transition-level correspondence between all
runtime ownership events and the complete buffer snapshot, together with allocation
accounting beyond payload lengths. This audit supports the explicit adapter
contracts; it does not remove them or close the resource milestone by itself.
