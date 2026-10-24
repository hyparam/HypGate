# HTTP body buffers, credit, and cancellation

This is the production `http_body.rs` correspondence audit for the reader and
output-channel terms in `Buffers::accounted_payload_bound`. The channel uses a
verified `FixedQueue` under a trusted Rust mutex/waker adapter; Tokio oneshots
acknowledge End. Rust destruction, wakeups, and async scheduling remain trusted.

## Writer queue and pending operations

Each channel owns one fixed queue slot, one Arc/mutex control allocation, and at
most two registered wakers. `http_body/slot.rs` exposes non-cloneable sender and
receiver endpoints. There are no linked message blocks, semaphore permits, or
PollSender acquisition futures. Queue initialization requests one `Option<Message>`
element; verified push/pop preserve slot count and exact FIFO identity.

Production writers copy at most 16 KiB per data message. `poll_send_with` checks
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
Callbacks are invoked only for bounded byte copies in production. Dequeued frames
become Hyper-owned, so this slot bound does not cover Hyper output allocations.

## Conservative ownership count

Let C be the inbound connection limit and R the worker/request limit. HTTP/1
keep-alive is disabled and each connection owns at most one client response body.

| Buffer category | Count and lifetime |
| --- | --- |
| Client channel with a live receiver | At most C, owned by connection/service/response state |
| Client channel whose receiver is gone | At most R control objects, owned by a worker's Writer until cleanup; normal receiver drop has already discarded payload |
| Provider upload channel | At most R, owned within the worker's inline exchange/connection future |
| Reader copies | At most two per worker, each at most 32 KiB; the verified worker lease encloses destruction of the entire future |

The output-channel term is therefore **(C + 2 × R) × 16 KiB**. It conservatively
includes sender-only cleanup objects even though ordinary receiver destruction
now discards their payloads. Upload/download sequencing
could support a tighter payload estimate, which remains unproved. The conservative
count covers channel ownership through cancellation independently of that sequencing.
Worker keys use checked registry transitions; the wrapper's field drop order is
described in [worker lifetimes](worker-lifetimes.md). Completed task bookkeeping,
channel control objects, wakers, and allocator overhead remain outside payload lengths.

Reader copies detach accepted frames from shared backing owners, and clear their
copy when consumed. An input frame and its new copy coexist synchronously during
copying; source frames and references retained by Hyper belong to the dependency
allocation account. Borrowed mutable read slices cannot resize the core owner's
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

Validation on 2026-10-23: 152 regular workspace tests and five compile-fail doctests
pass (the final payload-drop panic regression was rerun with all six slot tests). All six
release load/fault workloads pass. A three-wave isolated process run in each mode
also passes, with sampled peaks of 12,992,512 bytes in strict mode and 12,959,744
bytes in availability mode on macOS. These observations are regression evidence,
not a memory ceiling or a comparative performance benchmark.
