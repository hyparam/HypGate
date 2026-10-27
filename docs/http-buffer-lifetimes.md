# HTTP body buffers, credit, and cancellation

The connection thread copies body bytes directly from `http1::BodyReader` to
`http1::ChunkedWriter`. There is no HTTP body channel, queued payload, or End
acknowledgment. The verified resource theorem retains an output-queue term as
an upper bound; production contributes no queue storage to that term.

## Buffer ownership

Each body reader owns one buffer of at most 32 KiB. Reads yield body bytes into
the transfer driver's stream-owned buffer, without shared backing owners or a
separate detached-frame copy. Partial reads retain the body reader's allocation.
The transfer driver uses the verified owner's pending buffer; see
[read-buffer ownership](runtime-ownership.md#verified-read-buffer-ownership).

Each chunked writer retains at most one framed chunk and writes it in full
before accepting another. Framing overhead and vector capacity are counted in
[dependency resources](dependency-resources.md#chunk-framing-buffers), separately
from logical body bytes. Metadata has its own
[ownership boundary](http-boundary.md#metadata-ownership-and-allocation).

## Role lifetime and cancellation

`WorkerHttp` issues four roles: input reader, output reader, upload writer, and
response writer. `http_body::Reader` and `worker::Charged` hold the corresponding
permit. Their fields drop the wrapped stream before releasing its role;
`Charged::into_inner` explicitly returns the writer and releases the role.
An outstanding role prevents worker credit from returning. Registry transitions
and count bounds are described in the [HTTP ownership audit](http-ownership.md).

Cancellation shuts the exchange's sockets so blocked I/O returns an error.
The transfer guard closes the stream, and worker capacity remains occupied
until cleanup completes. Successful writes establish accepted bytes, not peer
receipt. Body framing distinguishes clean EOF from truncation or malformed
chunking; see [body transfer](body-transfer.md).
Rust destruction, mutex behavior, and thread scheduling remain trusted.
Allocator capacity and total process memory are outside the logical payload bound.

## Role regressions

`server::workers::tests::a_live_stream_keeps_the_credit_after_the_work_returns`
lets a credited reader escape the work: the slot remains occupied, and failed
lease cleanup closes admission rather than reusing it.
`captures_drop_before_worker_credit_returns` checks normal cleanup order.
`http_body::worker::tests` covers both reader roles holding their permits until
destruction and both writer roles holding theirs until destruction or
`into_inner`, including refusal to issue a writer role twice.
These are adapter regressions; they do not prove Rust destruction or scheduler
behavior. Current workload measurements are in [benchmarks](benchmarks.md).
