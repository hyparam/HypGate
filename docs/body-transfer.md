# Body transfer

The body copy is a verified machine, `body_copy::BodyCopy` in the core. It
names the next effect (read a chunk into the stream's buffer, append that
chunk's record, write the gated bytes, flush), and the runtime loop in
`transfer::copy_body_bound` performs it on the blocking reader, the logger, and
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
reported by the finished machine's `audit_gap`. Availability mode still waits for
a healthy logger: the disk logger bounds acknowledgment waiting and worker/queue
growth.

A guard closes the stream when the loop leaves by error or by panic during a
read, log append, write, or flush. The loop blocks the calling thread; a
cancellation from another thread (`net::Cancel`) shuts the exchange's sockets so
the blocked read or write returns an error and the guard fires. The caller
still owns the request and its lease; capacity is released only when that
request is dropped. A canceled request cannot start another transfer, even with
empty input. Successful EOF leaves it usable for the next direction, with
monotonically increasing chunk IDs. This is sequential upload/download; full
duplex requires separately budgeted directional state.

There are no detached threads in the driver. External writer/logger implementations
must account for their own buffering and any effects surviving cancellation.
Accepted writes are not proof of peer receipt. Before each input allocation, the
machine's `begin_read` runs the verified `discard_completed` transition. It drops
the previous payload only when fully completed, without a pending write and while
open. Thus no old chunk allocation is retained while the next chunk is allocated. The admission allowance is still not a bound on allocator overhead or
total HTTP/TLS/logger memory. The runtime `Request::advance` boundary rejects vectors with capacity above the
request budget; the production driver creates its own bounded buffers. That
capacity check is tested Rust, outside the current Verus allocation model.

The driver tests exercise multi-chunk partial writes, strict log-before-write
ordering, both logging failure modes, persistent audit gaps, write/read/flush errors,
zero progress, failure at read/log/write, capacity retention, and fragmented
SSE bytes through small-buffered streams. The in-memory test logger is an
event recorder, not a durable implementation. The loop and its guard are tested
Rust; every decision inside the loop is the machine's and verified.

## HTTP frame retention

Body bytes come from `http1::BodyReader`, which reads at most 32 KiB from the
socket into its own buffer and yields only body bytes, delimited as the verified
framing selection says: a Content-Length count, the verified chunked decoder, or
until the connection closes. The same constant bounds the inbound and upstream
head buffers. The end of the body is a clean EOF; a body that stops early or a
chunk coding fault is an error, never an EOF, and the transfer driver treats
that first error as terminal and cancels its stream, so a later EOF cannot
synthesize a successful transfer. The limit applies to individual reads, not
total request/response size. There are no shared frame owners; allocator
overhead is outside this payload budget.

## Responses without HTTP bodies

HTTP 204 and 304 carry no body. The verified exchange driver writes the fixed
head with `Content-Length: 0` through the `Connection` machine, which refuses
a body for those statuses, and asks the download effect to read a zero-length
body into a sink that refuses bytes; the connection is then closed. That the
driver takes this path for exactly these statuses is proved; that the effect
reads nothing is the adapter's framing, trusted.

The machine reads through the verified owner's pending buffer (`begin_read`,
`read_buffer`, `finish_read`); no independent chunk is allocated. See the
[read-buffer ownership proof](runtime-ownership.md#verified-read-buffer-ownership)
for the exact prefix, exclusive-buffer, EOF, and mutable-slice trust boundary.
