# Async body transfer

The trusted `transfer::copy_body` driver now connects a managed request to Tokio
AsyncRead and AsyncWrite. It reads bounded chunks, records each through an awaited
AuditLog callback, and performs ticketed writes of the core's exact borrowed slice.
Each completion uses the writer's reported partial count. Zero-progress writes,
read/write/flush failures, and invalid core transitions close the stream; nothing
automatically retries an uncertain effect. Each chunk is flushed for streaming
latency. The HTTP body and TLS adapters supply the production I/O. The [disk logger](disk-logging.md)
now supplies the production logging callback.

The logger receives tenant, request, chunk, direction, and exact payload. Success
must mean that record is durable under its documented crash model.
`Request::audit_current` exclusively borrows the request across the awaited append,
derives the identity, chunk, and length internally, and acknowledges only after
success. The runtime request API no longer accepts caller-supplied numeric durable
acknowledgments. Its own drop guard closes a canceled audit even when called outside
the transfer driver. The Verus-checked `log_bytes` and `is_closed`
accessors expose exact core state. The async binding and logger implementation
remain trusted/tested Rust, not a journal-to-stream composition theorem.

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

Accepted data is copied into a reader-owned buffer before the original frame
reference is dropped. This prevents a small `Bytes` view from retaining a much
larger backing allocation. Exhausting the copy releases it immediately. The cost
is one bounded copy per frame; Hyper may still retain its own input references,
and allocator overhead is outside this payload budget.

Tests cover a maximum-size frame consumed through small reads, an oversized frame
rejected without retention or further polling, and a 40-byte slice whose 256 KiB
backing owner must be dropped after the first one-byte read. The producing body
already allocated each input frame before this adapter can accept or reject it;
this is not a whole-process allocation guarantee.

## Responses without HTTP bodies

HTTP 204 and 304 suppress body polling in Hyper. The inbound adapter therefore
drains their internal empty completion channel and waits for the tracked worker
to finish before returning fixed empty responses. Cancellation retains the worker
abort guard while waiting. An unexpected payload or missing clean completion
returns 502 before upstream headers are sent. Normal streaming responses continue
to release the abort guard only at clean EOF. Tests reproduce the original aborted
accounting path over real HTTP and cover unexpected data and dropped writers.
This is trusted async adapter behavior, not a Verus proof of Hyper or cancellation.

The transfer driver now reads through `Request::read_next` into the verified
owner's pending buffer. It no longer allocates an independent chunk. See the
[read-buffer ownership proof](runtime-ownership.md#verified-read-buffer-ownership)
for the exact prefix, exclusive-buffer, EOF, and mutable-slice trust boundary.
