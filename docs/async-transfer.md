# Async body transfer

The trusted `transfer::copy_body` driver now connects a managed request to Tokio
AsyncRead and AsyncWrite. It reads bounded chunks, records each through an awaited
AuditLog callback, and performs ticketed writes of the core's exact borrowed slice.
Each completion uses the writer's reported partial count. Zero-progress writes,
read/write/flush failures, and invalid core transitions close the stream; nothing
automatically retries an uncertain effect. Each chunk is flushed for streaming
latency. HTTP framing and TLS remain unimplemented. The [disk logger](disk-logging.md)
now supplies the production logging callback.

The logger receives tenant, request, chunk, direction, and exact payload. Success
must mean that record is durable under its documented crash model. The new
Verus-checked `log_bytes` accessor preserves payload identity; `is_closed` exposes
the verified closure state. These accessors add two verification checks. They do
not establish the disk or async library contracts.

Strict mode stops before submitting a chunk whose log append fails. Availability
mode marks an audit gap and continues forwarding, suppressing subsequent append
attempts for that request. Degradation persists across upload and download; it is
reported in transfer statistics. Availability mode still awaits a healthy logger:
the disk logger now bounds acknowledgment waiting and worker/queue growth.
End-to-end availability under blocked I/O still requires integration and fault tests.

A cancellation guard closes the stream when its future is dropped during a read,
log append, write, or flush. The caller still owns the request and its lease; capacity
is released only when that request is dropped. A canceled request cannot start
another transfer, even with empty input. Successful EOF leaves it usable for the
next direction, with monotonically increasing chunk IDs. This is sequential
upload/download; full duplex requires separately budgeted directional state.

There are no detached tasks in the driver. External writer/logger implementations
must account for their own buffering and any effects surviving cancellation.
Accepted writes are not proof of peer receipt. Before each input allocation, the
driver calls the verified `discard_completed` transition. It drops the previous
payload only when fully completed, without a pending write and while open. Thus
the driver no longer retains an old chunk allocation while allocating its next
chunk. The admission allowance is still not a bound on allocator overhead or
total HTTP/TLS/logger memory. The runtime `Request::advance` boundary rejects vectors with capacity above the
request budget; the production driver creates its own bounded buffers. That
capacity check is tested Rust, outside the current Verus allocation model.

Six driver tests exercise multi-chunk partial writes, strict log-before-write
ordering, both logging failure modes, persistent audit gaps, write/read/flush errors,
zero progress, cancellation at read/log/write waits, capacity retention, and fragmented
SSE bytes through bounded Tokio duplex streams. The in-memory test logger is an
event recorder, not a durable implementation. The driver is tested Rust; its async
control flow and cancellation guard are not formally verified.

## HTTP frame retention

The HTTP-to-byte reader retains at most one accepted data frame, with a visible
length at most 32 KiB. The same constant configures both inbound and upstream
HTTP/1 parser buffer limits. Larger frames fail with `InvalidData` before the
reader retains them or forwards their bytes; trailers and body errors also stop
further polling. The transfer driver treats that first error as terminal and
cancels its stream, so a later reader EOF cannot synthesize successful transfer.
The limit applies to individual adapter frames, not total request/response size.

Tests cover a maximum-size frame consumed through small reads and an oversized
frame rejected without retention or further body polling. All 67 workspace tests
pass. These checks bound visible bytes owned by this adapter; `Bytes` may share a
larger backing allocation, and the producing body already allocated the rejected
frame. They therefore do not prove peak memory or the dependency's allocations.
A full memory budget must also account for one driver chunk per active request,
one frame per HTTP output queue, logger queue/worker frames, connection state,
TLS buffers, allocator overhead, and filesystem caches. Load measurements and
formal composition remain open.
