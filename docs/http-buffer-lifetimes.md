# HTTP body buffers, credit, and cancellation

This is the production `http_body.rs` correspondence audit for the reader and
output-channel terms in `Buffers::accounted_payload_bound`. It uses Tokio 1.54.1
and tokio-util 0.7.20. Channel semantics, Rust ownership/destruction, and async
scheduling remain trusted; the composition theorem checks the size arithmetic
under the resulting snapshot hypotheses.

## Writer queue and pending operations

Each `channel` has one mpsc slot. Production writers copy at most 16 KiB per data
message. `Writer::poll_write` reserves capacity before copying bytes and immediately
sends the copy in the same poll; a pending reservation retains no copy of the
caller's write input. Canceling a write future while keeping its Writer can leave
PollSender's reservation attempt alive, but cannot leave stale write bytes in it.
The next write supplies its own input after credit becomes available.

In [PollSender](https://docs.rs/crate/tokio-util/0.7.20/source/src/sync/mpsc.rs),
`poll_reserve` owns the reservation future and then the successful OwnedPermit;
`send_item` consumes the permit into the channel. Dequeue returns queue credit.
The consumed data frame becomes the receiver/Hyper's responsibility, so an empty
application queue is not a bound on Hyper's own retained output storage.

Receiver destruction closes and drains the current queue, but a sender that
already holds a permit can enqueue afterward. Tokio's OwnedPermit send path does
not recheck receiver presence. The channel's final destruction drops remaining
messages; a PollSender can keep the channel alive even after it observes closure.
Thus a client-output payload can outlive the connection's receiver until worker
cleanup. The direct regression test reserves, drops the receiver, sends a tracked
payload, and observes its destruction only when the Writer is dropped. It models
an interleaving permitted when sender and receiver run on different executor
threads; the CLI's current-thread scheduling is not a premise of this inventory.

## Conservative ownership count

Let C be the inbound connection limit and R the worker/request limit. HTTP/1
keep-alive is disabled and each connection owns at most one client response body.

| Buffer category | Count and lifetime |
| --- | --- |
| Client channel with a live receiver | At most C, owned by connection/service/response state |
| Client channel whose receiver is gone | At most R, owned by a worker's Writer until cleanup |
| Provider upload channel | At most R, owned within the worker's inline exchange/connection future |
| Reader copies | At most two per worker, each at most 32 KiB; the verified worker lease encloses destruction of the entire future |

The output-channel term is therefore **(C + 2 × R) × 16 KiB**. This replaces the
earlier connection-only accounting of client queues. Upload/download sequencing
could support a tighter payload estimate, which remains unproved. The conservative
count covers channel ownership through cancellation independently of that sequencing.
Worker keys use checked registry transitions; the wrapper's field drop order is
described in [worker lifetimes](worker-lifetimes.md). Completed task bookkeeping,
channel nodes, reservations, and allocator overhead remain outside payload lengths.

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
large-backing-owner release, and the reserved-send-after-receiver-drop test.
