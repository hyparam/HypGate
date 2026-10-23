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
Accepted writes are not proof of peer receipt. At a chunk rollover, both the
previous retained allocation and one incoming allocation may exist, so this driver
can retain two chunk allocations per request. The current admission allowance is
not a bound on allocator overhead or total HTTP/TLS/logger memory.

Six driver tests exercise multi-chunk partial writes, strict log-before-write
ordering, both logging failure modes, persistent audit gaps, write/read/flush errors,
zero progress, cancellation at read/log/write waits, capacity retention, and fragmented
SSE bytes through bounded Tokio duplex streams. The in-memory test logger is an
event recorder, not a durable implementation. The driver is tested Rust; its async
control flow and cancellation guard are not formally verified.
