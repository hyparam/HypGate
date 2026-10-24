# Audit-buffer ownership and cancellation

This is a source-level correspondence argument for the audit terms in
`Buffers::accounted_payload_bound`, checked against the production DiskLog path
and Tokio 1.54.1. It does not formally verify Tokio channels or Rust destruction.
Let Q be disk queue capacity, R the request limit, and K the request chunk size.
The production log-frame payload is at most K; independent library callers can
supply up to `MAX_RECORD_BYTES` and must account for retained receipts separately.

| Stage | Owner and credit | Frame count charged |
| --- | --- | --- |
| Before reservation | `LogRecord` borrows the request's existing payload. No copied frame exists. | Already in the request chunk term |
| Encoding | `DiskLog::append` holds the worker mutex and a successful `try_reserve` permit before `encode_record` allocates. | One of Q reserved/queued slots |
| Queued | `Permit::send` transfers the immutable frame and receipt sender into one `Job`. The caller retains only the receipt receiver. | One of Q reserved/queued slots |
| Writing/syncing/committing | The sole worker receives one Job and owns its frame until failure or journal commit. Dequeue returns queue credit, allowing another producer to encode. | One active frame in addition to Q |
| Delivering | `commit_frame` moves the same frame into `DurableFrame`; no payload clone is made. Sending moves that receipt into the caller's oneshot. | Active-frame term until transfer, then receipt term |
| Delivered, awaiting consumption | `Request::audit_current` retains exclusive request ownership across append and checks the exact receipt before dropping it. | At most one receipt per live production request, hence R |
| Dropped/canceled | The frame is dropped at its current owner; dropping the caller alone cannot drop a queued Job or interrupt its syscall. | Credit follows the surviving frame, not the caller's task |

The resulting frame term is `(Q + 1 + R) * (K + 65)`. The checked production
encoding derives 65 bytes of header/checksum overhead. The journal's byte history
and canonical-frame sequence are erased ghost state, not retained old payloads.
Header encoding/comparison scratch is accounted separately. Channel nodes,
oneshot state, allocator slack, and thread stacks are outside the frame-payload term.

## Pinned channel obligations

In Tokio's [mpsc/bounded.rs](https://docs.rs/crate/tokio/1.54.1/source/src/sync/mpsc/bounded.rs),
dropping an unused Permit returns its credit, whereas `Permit::send` deliberately
forgets that permit before enqueueing the value. The receive implementation in
[mpsc/chan.rs](https://docs.rs/crate/tokio/1.54.1/source/src/sync/mpsc/chan.rs)
returns credit when it removes the Job. Canceling the append caller drops a
*different* object, its oneshot receiver, so it cannot return queued frame credit.
The worker mutex prevents a reserved producer from escaping shutdown admission;
there is no await between reservation, encoding, and send.

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
A timeout bounds caller waiting, not syscall duration. It never creates a new
worker to bypass a blocked syscall. The combined stalled-log workload checks
these effects with concurrent gateway requests and both logging policies.

Remaining formal work is a checked transition-level correspondence between all
runtime ownership events and the complete buffer snapshot, together with allocation
accounting beyond payload lengths. This audit supports the explicit adapter
contracts; it does not remove them or close the resource milestone by itself.
