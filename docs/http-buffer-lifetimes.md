# HTTP body buffers, credit, and cancellation

This is the production `http_body.rs` correspondence audit for the reader and
output-channel terms in `Buffers::accounted_payload_bound`.

**Status (2026-10-26).** The output channel no longer exists. The connection
thread runs the exchange itself and copies body bytes straight from
`http1::BodyReader` to `http1::ChunkedWriter`, so there is no mailbox, no End
acknowledgment, and no queued HTTP payload; the theorem's output-queue term
over-approximates the runtime, which has none. `http_body.rs` keeps the
`Reader` role binding (input and output readers) and the `Charged` writer role
binding (upload and response writers); the four roles are issued by
`WorkerHttp` and released on drop, before the worker's credit can return. The
mailbox sections below describe the verified `Mailbox` and the removed adapter
for the record; the verified core keeps the type. Rust destruction and thread
scheduling remain trusted.

## Writer queue and pending operations

Each channel owns one inline optional message, one Arc/mutex control allocation,
and at most two registered wakers. `http_body/slot.rs` exposes non-cloneable sender and
receiver endpoints. There are no linked message blocks, semaphore permits, or
PollSender acquisition futures. The production message is `http_message::HttpMessage`, stored directly in the
mailbox with no separate slot vector. Its verified payload projection distinguishes
bounded Data frames from zero-byte End. `queued_payload_bound` derives the
16 KiB queued-byte bound from the actual item charge. `closing_payload_bound`
combines the closed mailbox with its transferred `Cleanup<HttpMessage>` and
bounds their total through extraction and reported destruction. The consuming
`into_payload` operation connects that projection to the exact vector the
connection task frames as a chunk.
Verified push/pop preserve exact item identity and reject full-slot overwrite.
The core owns both endpoint-open flags: sender closure preserves the item for
draining, receiver closure returns the item and clears the slot, and neither
endpoint can reopen. Production receiver destruction uses
`close_receiver_charged`, which transfers the exact pending value into a private
`Cleanup` owner. Its postcondition conserves the combined mailbox-plus-cleanup
item charge. The mailbox is empty after closure, but a pending payload's charge
remains in the cleanup owner. `Cleanup::begin` extracts the exact value once
without releasing its charge; `finish` requires cleanup to have begun and marks
it complete once. The adapter calls `finish` only after dropping the extracted
payload outside the mutex. A panicking payload destructor skips that report.
The enclosing task cleanup gate likewise cannot finish when future destruction
panics. Rust destruction and truthful completion reporting remain trusted joins;
these transitions do not themselves prove the global owner-count mapping.
The mailbox's retained count is at most one and zero after receiver closure;
the transferred cleanup charge must also be counted until destruction completes.

Production writers construct `output_frame::OutputFrame`, a private immutable
core-owned vector whose constructor copies exactly the requested prefix, capped
at 16 KiB. Its checked length is the write's reported accepted count. The copy is
created only inside the existing locked send callback, so a full/closed mailbox
never constructs it. The consuming `into_vec` handoff preserves the exact bytes;
the connection task frames that vector as one chunk and drops it. Logical
payload length is proved; allocator rounding and the chunked writer's pending
buffer ([dependency resources](dependency-resources.md#chunk-framing-buffers))
remain separate. `poll_send_with` checks
receiver liveness and queue capacity while holding the mutex, then constructs and
inserts the payload under that same lock. Pending sends store only a waker, never
a copy of the caller's bytes. Canceling a write future leaves no pending payload;
the next poll supplies its own bytes. A new waiter replaces the previous waker.

Dequeue returns capacity and wakes the writer after releasing the lock. Pending
receive registration shares that lock with send, preventing a send/registration
race from losing the notification. Sender destruction closes the queue while
preserving its buffered item, then wakes the reader. Receiver destruction closes
and empties the queue, drops its payload outside the lock, and wakes the writer.
No send reservation escapes the lock, so no late payload can be published after
receiver destruction. The sender-only control allocation can still outlive it.

Waker clones are created before locking. Replaced or cleared wakers are moved
out of the state and dropped after unlocking; explicit wakes also run after
unlocking. This matters because a custom waker's clone/drop/wake hooks can execute
code that re-enters the channel. A regression observed three under-lock waker
drops before this fix and now verifies none during replacement, dequeue, and
endpoint destruction. Notification guards also wake a blocked writer if dropping
a queued payload panics during receiver destruction, without poisoning the mutex.
These tests cover callback placement, not arbitrary callback termination.

An encoding panic wakes a waiting reader after poisoning and unlocking the mutex;
poisoned operations refuse resumption. Poisoned storage remains charged until
final destruction. Waker clone/drop/wake behavior and mutex ordering remain trusted.
Callbacks are invoked only for bounded byte copies in production. A dequeued
frame is owned by the connection task until its chunk is written, so this slot
bound does not cover the chunked writer's pending buffer.

## Ownership count

The HTTP owner counts (two readers per worker, C + 2R mailboxes and sender-only
tails, and the resulting `2R × 32 KiB + (C + 2R) × 16 KiB` subtotal) are derived
from the production `WorkerRegistry` and `ResponseRegistry` by
`http_accounting::http_owner_bounds`; the owner table, charge attachment, and
trusted joins are in the [HTTP ownership audit](http-ownership.md). This document
covers the buffer mechanics behind those counts.

Production readers use `read_buffer::ReadBuffer`, which owns the detached vector
and its read offset. Checked load refuses replacement of a live frame and rejects
frames above the configured limit. Peek returns the exact next range; consume
preserves the original backing charge through every partial read, then replaces
the vector with an empty vector after the final byte. Failed loads and overlarge
consumes preserve the existing state. The retained-byte accessor counts the
original copied payload, including consumed prefixes, rather than just the
visible remainder. Actual vector destruction and allocator capacity/rounding
remain Rust/allocator assumptions; the proof bounds logical backing bytes.
The runtime constructs this owner with the 32 KiB input limit, copies from the
checked peek into the caller's read buffer, and reports consumption synchronously.

Readers no longer copy: the body reader yields bytes straight from its one
32 KiB read buffer into the caller's buffer, and there are no shared backing
owners to detach from. Borrowed mutable read slices cannot resize the core owner's
pending read buffer. Metadata has its own [ownership boundary](http-boundary.md#metadata-ownership-and-allocation).

## End markers and cancellation evidence

`Writer::poll_shutdown` must reserve and send End, then wait for the consumer to
acknowledge it. End carries no payload. Dropping a writer before End is sent makes
the consumer report UnexpectedEof after queued data, rather than clean completion.
Dropping the consumer before End acknowledgment makes shutdown fail. A successful
write means bytes were copied into the channel; successful shutdown means the
application queue was drained, not that the remote application consumed the bytes.

The tests cancel a blocked write and resume the same Writer with different bytes,
drop receivers during a blocked write and during End acknowledgment, and cancel
shutdown while its End marker is still waiting for a full queue. They check exact
received bytes and distinguish BrokenPipe/UnexpectedEof from clean completion.
These complement fragmentation, trailer rejection, oversized-input rejection,
large-backing-owner release, and immediate payload release/no-late-construction
on receiver drop. Slot tests check latest-waker replacement, panic wakeup and
poison refusal, 10,000 ordered handoffs between two threads, and receiver destruction blocked
behind in-progress construction followed by exact payload release. Release workload
and isolated-memory regressions exercise both logging modes through this path.

Current test totals are maintained in the [README](../README.md); the suite includes
all six slot-adapter tests and both core mailbox ownership tests. All six
release load/fault workloads pass. A three-wave isolated process run in each mode
also passes, with sampled peaks of 12,992,512 bytes in strict mode and 12,959,744
bytes in availability mode on macOS. These observations are regression evidence,
not a memory ceiling or a comparative performance benchmark.


## Role regressions

`server::workers::tests::a_live_stream_keeps_the_credit_after_the_work_returns`
lets a credited `Reader` escape the work through a channel: the worker slot stays
occupied after the thread finishes, and because the lease dropped with a role
still active the registry closes admission rather than reusing the slot even
once the reader is gone. `captures_drop_before_worker_credit_returns` checks the
normal order. `http_body::worker::tests` cover both reader roles and both writer
roles holding their role until destruction or `into_inner`. These are adapter
regressions, not the missing global owner-count or cross-owner preservation
theorem.
