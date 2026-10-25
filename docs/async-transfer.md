# Async body transfer

The body copy is a verified machine, `body_copy::BodyCopy` in the core. It
names the next effect (read a chunk into the stream's buffer, append that
chunk's record, write the gated bytes, flush), and the runtime loop in
`transfer::copy_body_bound` performs it on the Tokio reader, the logger, and
the writer, then reports the result back. The loop decides nothing: which
effect comes next, whether a chunk is audited, which bytes are released, when
the copy is finished, and how many bytes were accepted are all the machine's,
and all checked. The reader's bytes, the writer's accepted count, and the
logger's durable acknowledgment remain external contracts. Each chunk is
flushed for streaming latency. The HTTP body and TLS adapters supply the
production I/O and the [disk logger](disk-logging.md) the logging.

The machine's contracts: the accepted count equals the growth of the stream's
completed history, so the completion record's counts are the bytes the writer
took; every chunk's record is issued unless the request's log already failed;
in strict mode a failed append closes the copy before any byte of that chunk
is released; bytes leave only through `ResolvedRoute::write_bytes` with the
ticket the machine prepared; a read error, write error, zero-byte write, flush
error, or refused transition closes the stream; and the copy finishes only on
a zero-length read with no chunk pending. The logger receives tenant, request,
chunk, direction, and exact payload, and its receipt is checked against that
exact record by `OwnedStream::acknowledge_receipt` before durability advances.
Success must mean the record is durable under the logger's documented crash
model. The Verus-checked `log_bytes` and `is_closed` accessors expose exact
core state. The logger implementation and the loop's effects remain
trusted/tested Rust.

Strict mode stops before submitting a chunk whose log append fails. Availability
mode marks an audit gap and continues forwarding, suppressing subsequent append
attempts for that request. Degradation persists across upload and download; it is
reported by the finished machine's `audit_gap`. Availability mode still awaits a healthy logger:
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
machine's `begin_read` runs the verified `discard_completed` transition. It drops
the previous payload only when fully completed, without a pending write and while
open. Thus no old chunk allocation is retained while the next chunk is allocated. The admission allowance is still not a bound on allocator overhead or
total HTTP/TLS/logger memory. The runtime `Request::advance` boundary rejects vectors with capacity above the
request budget; the production driver creates its own bounded buffers. That
capacity check is tested Rust, outside the current Verus allocation model.

Six driver tests exercise multi-chunk partial writes, strict log-before-write
ordering, both logging failure modes, persistent audit gaps, write/read/flush errors,
zero progress, cancellation at read/log/write waits, capacity retention, and fragmented
SSE bytes through bounded Tokio duplex streams. The in-memory test logger is an
event recorder, not a durable implementation. The loop and its cancellation guard
are tested Rust; every decision inside the loop is the machine's and verified.

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

The machine reads through the verified owner's pending buffer (`begin_read`,
`read_buffer`, `finish_read`); no independent chunk is allocated. See the
[read-buffer ownership proof](runtime-ownership.md#verified-read-buffer-ownership)
for the exact prefix, exclusive-buffer, EOF, and mutable-slice trust boundary.
