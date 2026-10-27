# Runtime resource accounting

This is a source-level inventory of the production path, not a whole-process
memory theorem. The verified registry bound covers both stream payload and pending read buffers
in production owners mapped to live registry slots. The adapter additionally allocates buffers and owns
queues outside that model. RSS measurements include still more memory.

## Parameters and ownership

Let R be the configured request-slot limit, K the per-request chunk size, C the
inbound connection limit, and Q the disk queue capacity. Configuration checks
R × K ≤ 128 MiB, R ≤ 65,536, and K ≤ 1 MiB. The executable currently sets C = 128
and Q = 16; library callers can configure these separately. Each body reader
reads at most 32 KiB at a time into its own buffer; each chunked writer frames
one write of at most 16 KiB at a time. One DiskLog owns one disk worker. The
runtime links no executor: each connection is one thread plus a watcher thread.

| Retained object | Budget and ownership | Evidence and limitation |
| --- | --- | --- |
| Core chunk or next transfer buffer | At most K per admitted exchange in the production sequential driver | `OwnedStream::payload_bound` proves the combined stream/read-buffer logical length stays within K, with only one nonempty at a time. The driver reads into the owner and verified completion moves the filled prefix into its stream. External `Request::advance` still rejects excessive vector capacity. Slice I/O correspondence, Vec backing capacity, and allocator size remain trusted. |
| Inbound/outbound body read buffers | One 32 KiB read buffer per body; conservatively two per admitted exchange | `http1::BodyReader` reads at most 32 KiB at a time into its own vector and yields body bytes from it; chunk framing is consumed in place. There are no shared backing owners. Upload and download run sequentially; the inbound reader object remains alive. Allocator overhead remains separate. |
| Client response writer | One framed chunk of at most 16 KiB plus framing per connection | `http1::ChunkedWriter` in `ConnectionEffects::download`, around the driver's `ChunkStream`; the body copy's write becomes one chunk written to the client socket before the next is accepted. There is no channel between the copy and the socket; the verified subtotal's C + 2R output-queue term has no runtime counterpart and over-approximates. |
| Provider upload framing | One pending framed chunk of at most 16 KiB plus framing per admitted exchange | `http1::ChunkedWriter` in `Session::upload`; a frame is framed and written before the next is accepted. No channel sits between the copy and the TLS stream. |
| Disk frames being encoded or queued | At most Q reserved/queued records, each at most A + 65 bytes, where A = max(K, 8,210) admits the metadata records | `Queue::enqueue` calls verified `FrameQueue::reserve` before encoding, then inserts through verified `FrameQueue::finish_reserved` under the same queue mutex. The executable passes A to `DiskLog::create_with_payload_limit`; append rejects larger payloads before encoding, and the verified queue independently rejects oversized frames. The default library constructor retains the 1 MiB limit. |
| Active disk frame | Up to 16 additional frames, each at most A + 65 bytes | Verified `BatchWorker` moves the exact queued frame into a private active handle, preserves its charge through write/sync and completion delivery, and checks the release token's session/generation. The Q+16 bound includes the full active batch. Caller cancellation cannot return its credit; a stalled worker is never replaced. |
| Delivered durable receipts | At most one frame of at most K + 65 bytes per admitted exchange (metadata receipts are dropped as soon as they are checked) | The job's `mpsc` channel transfers its owned frame to the waiting thread. Exact receipt validation then drops it; a caller that stopped waiting drops undelivered receipts. The worker can advance to another job before delivery is consumed. Custom library callers retaining receipts must budget separately. |
| Encoding/comparison scratch | One 33-byte header vector per logger encoder plus one per validating request | `framing::encode_payload` copies a canonical header into the reserved frame; header encoding requests exactly 33 bytes up front. Receipt validation also encodes the expected 33-byte header, then compares payload slices without copying the payload. SHA-256 state and the 32-byte digest are additional fixed-size implementation state. |
| Inbound connection threads | At most C live connection leases across one Gateway, each one connection thread (512 KiB stack) and one watcher thread (64 KiB) | A separate verified registry is shared by every serve invocation on that Gateway. The thread's work and its captures return before its credit. Listener and accept-loop state remain per invocation. |
| Server request workers, including rejection and cleanup | At most R worker leases | A separate verified `ResourceAdmission` registry issues a private key before the exchange starts. `leased::run` lets the work drop its captures before recording cleanup and returning the key. Registry transitions and the `TaskCredit` cleanup/release gate are verified; mutex serialization, truthful destruction reporting, and socket shutdown as cancellation remain trusted. |
| Admitted exchanges and upstream connections | At most R live leases; one upstream connection per exchange | Verified slot transitions plus trusted ownership. The exchange owns admission while `run` borrows it for the TCP/TLS/HTTP work, whose socket and TLS state are locals of `run`, so network cleanup precedes request release. No pooling, replay, or detached upstream connection. Failed authentication can still take a worker lease briefly without a request lease. |
| TLS handshakes | On the connection thread, one per exchange | The handshake state is the exchange's `ClientConnection`, owned by `run`; nothing survives the exchange. See [TLS on the connection thread](https-transport.md#tls-on-the-connection-thread). |
| DNS lookups | Four dedicated threads; at most 32 queued/running jobs or unadopted replies per transport | Jobs and unread replies retain verified credit across request cancellation until cleanup or checked adoption. Returned address vectors contain at most 64 addresses. System-resolver internal allocations remain trusted; see [DNS accounting](dns-resources.md). |
| Disk operations | One worker, one sequential write/sync operation | A timeout bounds caller waiting, not syscall duration. Outstanding work retains its frame until completion or process exit. |

The [HTTP buffer lifetime audit](http-buffer-lifetimes.md) follows reservations,
receiver closure, sender cleanup, and End acknowledgment. Its conservative channel
count includes cleanup after a client connection has gone away.

### Connection-thread lifetime boundary

The first validated `serve` invocation fixes C in a OnceLock on its Gateway.
Later invocations must request the same C or fail with InvalidInput before
acceptance. Each accepted socket must obtain a private lease from the shared
`ConnectionSlots` registry before a thread is started for it. The same verified
`ResourceAdmission` transitions used for request/worker admission enforce this
count; connection keys never create streams. Poison prevents new credits and is
not recovered on drop.

`leased::run` on the connection thread lets the work return, and with it its
socket, head buffer, output writer, and watcher, before marking its
`TaskCredit` cleaned and releasing it. A panic in the work leaves the credit
running and capacity stranded. Mutex serialization, Rust destruction, OnceLock
initialization, and thread scheduling remain trusted; no refinement theorem of
the threaded runtime is claimed. The registry itself retains C fixed u64 slots
plus its control fields, for the Gateway lifetime.

Multiple invocations share live connection capacity but still have separate
listeners and one just-accepted socket each. A whole-process bound must count
those invocation objects separately.

Normal shutdown drains/joins its connection set, then waits for shared request
workers and shuts down the logger. Aborting `serve` only requests child abort;
joining the parent does not imply completed child destruction. Its connection
leases remain charged against the same Gateway's C during that cleanup, preventing
restarts from multiplying live connection budgets. Worker tails retain separate
R credits. Library callers should trigger `Shutdown` and let `serve` return when
they require completed cleanup; concurrent graceful shutdown still affects the
shared worker registry/logger and is not an independent multi-listener lifecycle.

The shared-listener regression fills C = 1 through one listener, verifies closure
of an excess socket at a second listener, rejects changing C, aborts the first
server, then serves health traffic through the second after credit is reclaimed.
Lease tests check capture-before-credit destruction on normal return, escaped
roles, and panic, plus fail-closed behavior after registry poison.

The repeated-abort regression withholds the provider's TLS handshake, then shuts
the actual server down in each of 16 waves per logging mode. It checks client
and provider socket closure, listener closure, zero connection/worker/request occupancy,
and reuse of the same one-slot gateway on the next wave. The test explicitly
waits for child cleanup before restarting; it does not claim that joining the
aborted parent synchronously joins its descendants. The shared logger remains
healthy across these cancellations and is explicitly shut down at the end.
Removing `CancelOnDrop`'s worker cancellation makes this regression hit its deadline,
confirming that it detects a detached worker still waiting on the handshake.
These are trusted Rust and OS lifecycle facts and adapter tests, not a new formal
thread-liveness or whole-process allocation proof.

A conservative **visible payload subtotal**, under the ownership relationships
above, is:

    R × K + 2 × R × 32 KiB + (C + 2 × R) × 16 KiB + (Q + R + 16) × (A + 65) + (R + 1) × 33 bytes

with A = max(K, 8,210), the audit payload limit that admits metadata records.

This intentionally overcounts reader copies and queue data that may not coexist.
It is useful for finding missing categories, not for promising a memory ceiling.
`Buffers::accounted_payload_bound` in `gateway-core/src/buffer_accounting.rs`
proves this subtotal from complete ghost snapshots of the listed categories;
`Buffers::accounted_payload_with_encoding` adds the in-progress encoding under the
same Q budget using the queue's `encoding_and_queued_bound`. The mapping from each
theorem category to its production owner, insertion, and removal event is the
[runtime correspondence table](resource-composition.md#runtime-correspondence-to-the-combined-theorem);
the queue reservation, encoding permit, and receipt mechanics are in the
[audit-buffer lifetime audit](audit-buffer-lifetimes.md). This is a
size-composition proof, not proof that every runtime state supplies those
snapshots; the runtime correspondence and all excluded allocations below remain
separate obligations.
Do not substitute the lower observed concurrent-request count for R when publishing
configuration guarantees. Multiple gateway/logger instances multiply their budgets.

The [audit allocation inventory](dependency-resources.md#audit-encoding-allocation-requests)
accounts for a P + 65 byte frame reservation and a simultaneous 33-byte header
scratch request. The unsealed body uses only P + 33 bytes of that reservation;
sealing fills the remaining checksum space without needing vector growth under
standard Vec behavior. Capacity/address regressions supplement the length proofs
but do not establish allocator or physical-memory bounds.

The [audit-buffer lifetime audit](audit-buffer-lifetimes.md) follows queue credit,
worker ownership, and receipt delivery through cancellation, including the
`mpsc` send/receive/drop operations and a stalled-worker cancellation test.

## Allocations outside that subtotal

The [dependency audit](dependency-resources.md) traces the codec adapter's own
buffers and the pinned TLS implementation's thresholds, extra queues, and
retained storage. In particular,
HTTP buffer thresholds and TLS application-data limits are not hard heap caps.
The upstream explicitly configures a 64 KiB TLS application-data buffer limit
before handshake; control traffic and record overhead have separate accounting.
Its explicit session-cache policy retains up to 32 server entries after cache
operations (33 transiently during insertion), independent of active requests;
the dependency audit accounts for ticket/certificate/secret byte contents and
identifies excluded metadata and active owners.


- The codec adapter's head buffers (32 KiB each, two during the split that
  hands the leftover to the body reader), serialized heads (under 64 KiB), and
  chunked-writer pending frames, and data frames already consumed from our
  mailbox but not yet written. The
  [dependency audit](dependency-resources.md#http1-storage) bounds each. The
  [HTTP metadata boundary](http-boundary.md#metadata-ownership-and-allocation)
  copies bounded allowed values out of the parsed head, which is dropped before
  any network effect; its copied-value subtotal and inserted Host/credential data
  remain separate from the stream/log buffer theorem. The body reader's own
  32 KiB buffer caps each upstream TLS plaintext read without imposing a
  wire-chunk/body length limit.
- rustls handshake and record buffers, certificate/root-store data, TLS overhead,
  system-resolver internals, and kernel socket buffers. The
  [DNS inventory](dns-resources.md) accounts for lookup jobs, dedicated threads,
  stacks, and bounded returned address vectors separately from request leases.
- The worker registry adds R `u64` entries (8 × R logical bytes, at most 512 KiB
  with validated limits), plus vector spare capacity and mutex/registry metadata.
  Acquisition scans at most R slots under a synchronous mutex; it creates no
  waiter object.
- Each in-flight exchange adds one `net::Cancel` handle in the gateway's live
  table: an atomic flag and the duplicated socket handles it may shut down.
  These are control objects, not payload bytes.
- Thread stacks and kernel thread objects, `mpsc` channel nodes, allocator
  rounding/fragmentation, and condition-variable bookkeeping.
  The [channel inventory](dependency-resources.md#channel-control-storage) now
  bounds control-object counts separately from variable payloads and identifies
  fixed HTTP slots and their two registered wakers; the former mpsc block-reuse obligation no longer applies. The disk
  queue instead requests one fixed Q-element vector of optional Jobs; checked
  FIFO operations preserve its slot count without resizing. The audit worker
  requests a 2 MiB stack; with four DNS and four TLS handshake workers, the executable requests
  18 MiB of dedicated background stacks, excluding OS overhead and its main stack.
- Immutable identity/route tables, URI and credential storage, configuration
  parsing scratch, metrics strings, and error/header metadata. The
  [configuration inventory](configuration.md#configuration-storage-and-startup-scratch)
  separates retained data from startup scratch: root proof snapshots are erased,
  and the CLI drops its JSON input buffers before serving.
- Filesystem page cache and storage-controller state. Audit-file disk usage grows
  with cumulative traffic; bounded in-memory queues do not bound disk usage.

The request tracker includes rejected/unauthenticated requests and completion tails
after body EOF. It has a separate R-slot verified registry, so a free stream slot does not imply
that a new worker can start. `leased::run` runs the exchange under its lease:
the work's return and the destruction of its captures precede the verified
cleanup-complete transition and credit release. The lease returns its key to
its original registry. Saturation returns 503 without starting any work.
Health, readiness, and metrics bypass this worker gate
but remain subject to the inbound connection limit. A poisoned registry at gateway
construction produces a zero-worker gate, preserving fail-closed behavior. Worker
registry poisoning also permanently closes that gate and fails readiness in both
logging modes. Exhausted registry IDs refuse new work rather than wrap.

The real-socket worker-budget test holds a cleanup lease with all core slots free,
checks sixteen excess requests plus health endpoints, observes no upstream
connection, and verifies permit recovery when the work returns. Existing
stream, disconnect, and shutdown tests exercise normal worker lifetimes. Formal
composition still depends on the trusted mutex/private-key/drop relationships;
the OS may also retain thread bookkeeping after a thread exits.
[Worker lifetime notes](worker-lifetimes.md) map the checked transitions to the
production wrapper and document the remaining assumptions.

## Evidence and outstanding work

The [runtime ownership notes](runtime-ownership.md) and [proof index](proof-index.md)
identify the checked core contracts and trusted bindings. Body-channel tests cover
fragmentation, bounded frame acceptance, trailers, and cancellation. Real TLS tests
exercise overload, slow peers, deadlines, and shutdown. The stalled-sync test
fills a two-record queue while eight requests run, observes one blocked writer,
checks reclaimed request slots and both logging modes, and releases that same
worker without any additional write. [Benchmark results](benchmarks.md) report
whole-fixture RSS separately from these logical budgets.

The production lease uses a verified private `OwnedStream` key/stream/read-buffer
owner; its transitions preserve pairing and consuming retirement returns the slot.
`registry_owned_payload_bound` includes pending read bytes and supplies the chunk
predicate for the combined subtotal, under a complete registry-owner snapshot.
Core ownership-map preservation is now checked for admission, stream creation,
replacement, and retirement; see the [ownership notes](runtime-ownership.md#ownership-map-preservation).
Remaining work includes correspondence between the full runtime ownership and
those ghost-map events, dependency/backing-allocation accounting, formal worker-lifetime composition,
and broader isolated-gateway measurements. A separate gateway-child
fixture measures three paced waves per logging mode, with an extended 100-wave
workload in a dedicated CI job. Both exclude provider/client memory and check
audit coverage and clean shutdown; see the [benchmark notes](benchmarks.md#isolated-gateway-process-memory). Until the remaining obligations are resolved,
neither the subtotal nor the core's 128 MiB allowance is a whole-process guarantee.
The [resource composition](resource-composition.md) assigns each budget above to
one owner, maps the theorem categories to production owners, and sums these
inventories into a conditional requested-allocation bound with explicit assumptions.
