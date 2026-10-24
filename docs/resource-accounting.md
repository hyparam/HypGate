# Runtime resource accounting

This is a source-level inventory of the production path, not a whole-process
memory theorem. The verified registry bound covers both stream payload and pending read buffers
in production owners mapped to live registry slots. The adapter additionally allocates buffers and owns
queues outside that model. RSS measurements include still more memory.

## Parameters and ownership

Let R be the configured request-slot limit, K the per-request chunk size, C the
inbound connection limit, and Q the disk queue capacity. Configuration checks
R × K ≤ 128 MiB, R ≤ 65,536, and K ≤ 1 MiB. The executable currently sets C = 128
and Q = 16; library callers can configure these separately. Each HTTP body channel
has one message slot and a maximum copied data frame of 16 KiB. Each reader accepts
at most 32 KiB of frame data into its own bounded copy. One DiskLog owns one disk worker.

| Retained object | Budget and ownership | Evidence and limitation |
| --- | --- | --- |
| Core chunk or next transfer buffer | At most K per admitted exchange in the production sequential driver | `OwnedStream::payload_bound` proves the combined stream/read-buffer logical length stays within K, with only one nonempty at a time. The driver reads into the owner and verified completion moves the filled prefix into its stream. External `Request::advance` still rejects excessive vector capacity. Slice I/O correspondence, Vec backing capacity, and allocator size remain trusted. |
| Inbound/outbound reader copies | At most 32 KiB of copied payload per reader; conservatively two readers per admitted exchange | `http_body::Reader` copies accepted visible frame bytes and releases its input reference before yielding; it clears the copy immediately when consumed. It cannot retain a large input owner through a small slice. Upload and download run sequentially; the inbound reader object remains alive. Allocator overhead and references retained inside Hyper remain separate. |
| Client response channel | At most C + R channels, one data message of at most 16 KiB each | Created before authorization but after acquiring worker credit in `Gateway::handle`; charging this solely to authorized request leases is incorrect. Live receivers are charged to C; sender-only control-storage cleanup tails are conservatively charged to R; the fixed-slot adapter now discards queued payload and forbids late sends when the receiver drops. A consumed message becomes Hyper-owned. End markers carry no payload. |
| Provider upload channel | One data message of at most 16 KiB per admitted exchange | Constructed in `HttpsTransport::run`; `Writer::poll_write` reserves queue credit before copying bytes. Hyper may retain previously consumed frames outside the channel. |
| Disk frames being encoded or queued | At most Q reserved/queued records, each at most K + 65 bytes for production requests | `Queue::push_with` calls verified `FrameQueue::reserve` before encoding, then inserts through verified `FrameQueue::finish_reserved` under the same queue mutex. The executable passes validated K to `DiskLog::create_with_payload_limit`; append rejects larger payloads before encoding, and the verified queue independently rejects oversized frames. The default library constructor retains the 1 MiB limit. |
| Active disk frame | One additional frame of at most K + 65 bytes | The worker owns the job after receiving it, through write, sync, and acknowledgment. Cancellation of its caller does not reclaim or duplicate that frame. A stalled worker is never replaced. |
| Delivered durable receipts | At most one frame of at most K + 65 bytes per admitted exchange | The job oneshot transfers its owned frame to the waiting request. Exact receipt validation then drops it; cancellation drops undelivered receipts. The worker can advance to another job before delivery is consumed. Custom library callers retaining receipts must budget separately. |
| Encoding/comparison scratch | One 33-byte header vector per logger encoder plus one per validating request | `framing::encode_payload` copies a canonical header into the reserved frame; header encoding requests exactly 33 bytes up front. Receipt validation also encodes the expected 33-byte header, then compares payload slices without copying the payload. SHA-256 state and the 32-byte digest are additional fixed-size implementation state. |
| Inbound connection tasks | At most C live connection leases across one Gateway, including canceled-parent tails | A separate verified registry is shared by every serve invocation on that Gateway. A boxed connection future drops before its credit. Each invocation also caps its JoinSet at C, including completed-but-unreaped entries. Listener/accept-loop and completed task metadata remain per invocation. |
| Server request workers, including rejection and cleanup | At most R worker leases | A separate verified `ResourceAdmission` registry issues a private key before response allocation or spawning. `WorkerTask` drops the entire boxed task future before its lease; the lease drops tracking before returning the key. Registry transitions are verified; mutex serialization, Rust field drop order, and Tokio cancellation remain trusted. |
| Admitted exchanges and upstream connections | At most R live leases; one upstream connection per exchange | Verified slot transitions plus trusted ownership. The outer exchange owns admission while the timed TCP/TLS/HTTP future borrows it, so network-future cleanup precedes request release. No pooling, replay, or detached upstream connection task. Failed authentication can still create a tracked server worker without a lease. |
| DNS lookups | Four dedicated threads; at most 32 queued/running jobs per transport | Jobs retain separate verified registry credit across request cancellation. Returned address vectors contain at most 64 addresses. System-resolver internal allocations remain trusted; see [DNS accounting](dns-resources.md). |
| Disk operations | One worker, one sequential write/sync operation | A timeout bounds caller waiting, not syscall duration. Outstanding work retains its frame until completion or process exit. |

The [HTTP buffer lifetime audit](http-buffer-lifetimes.md) follows reservations,
receiver closure, sender cleanup, and End acknowledgment. Its conservative channel
count includes cleanup after a client connection has gone away.

### Connection-task lifetime boundary

The first validated `serve` invocation fixes C in a OnceLock on its Gateway.
Later invocations must request the same C or fail with InvalidInput before
acceptance. Each accepted socket must obtain a private lease from the shared
`ConnectionSlots` registry before spawning. The same verified `ResourceAdmission`
transitions used for request/worker admission enforce this count; connection keys
never create streams. Poison prevents new credits and is not recovered on drop.

`ConnectionTask` owns the boxed connection future before its lease in field drop
order. Socket, parser, service, and response-body captures are therefore destroyed
before registry release, including never-polled cancellation and panic. Mutex
serialization, Rust destruction, OnceLock initialization, and Tokio scheduling
remain trusted; no async refinement theorem is claimed. The registry itself
retains C fixed u64 slots plus its control fields, for the Gateway lifetime.

Each invocation also checks JoinSet length before spawning. Completed-but-unreaped
entries remain counted by that local cap, and biased selection reaps them before
acceptance. Multiple invocations share live connection capacity but still have
separate listeners, one just-accepted socket each, and JoinSet/completed-task
metadata. A whole-process bound must count those invocation objects separately.

Normal shutdown drains/joins its connection set, then waits for shared request
workers and shuts down the logger. Aborting `serve` only requests child abort;
joining the parent does not imply completed child destruction. Its connection
leases remain charged against the same Gateway's C during that cleanup, preventing
restarts from multiplying live connection budgets. Worker tails retain separate
R credits. Library callers should use graceful shutdown and await `serve` when
they require completed cleanup; concurrent graceful shutdown still affects the
shared worker tracker/logger and is not an independent multi-listener lifecycle.

The shared-listener regression fills C = 1 through one listener, verifies closure
of an excess socket at a second listener, rejects changing C, aborts the first
server, then serves health traffic through the second after credit is reclaimed.
Lease tests check capture-before-credit destruction on success, cancellation
before/after polling, and panic, plus fail-closed behavior after registry poison.

The repeated-abort regression withholds the provider's TLS handshake, then aborts
the actual server future in each of 16 waves per logging mode. It checks client
and provider socket closure, listener closure, zero connection/worker/request occupancy,
and reuse of the same one-slot gateway on the next wave. The test explicitly
waits for child cleanup before restarting; it does not claim that joining the
aborted parent synchronously joins its descendants. The shared logger remains
healthy across these cancellations and is explicitly shut down at the end.
Removing `AbortOnDrop`'s worker abort makes this regression hit its deadline,
confirming that it detects a detached worker still waiting on the handshake.
These are trusted Tokio/Rust lifecycle facts and adapter tests, not a new formal
task-liveness or whole-process allocation proof.

A conservative **visible payload subtotal**, under the ownership relationships
above, is:

    R × K + 2 × R × 32 KiB + (C + 2 × R) × 16 KiB + (Q + R + 1) × (K + 65) + (R + 1) × 33 bytes

This intentionally overcounts reader copies and queue data that may not coexist.
It is useful for finding missing categories, not for promising a memory ceiling.
The conditional composition theorem `Buffers::accounted_payload_bound` now proves
this subtotal in `gateway-core/src/buffer_accounting.rs`. It takes complete ghost
snapshots of the listed categories, with explicit per-category count and chunk-size
hypotheses. `bounded_frames` and `DurableFrame::retained_size` derive the 65-byte
frame overhead from the production encoding; receipts count their actual retained
frame, not the erased acknowledged-history prefix. `covers_categories` prevents
an accidentally omitted category from silently weakening the modeled total.

The production queue now stores `FrameQueue<Completion>`, whose ghost projection
contains exactly its retained frames. `frame_layout` derives their validity and
count from the actual fixed slots; `accounted_frame_bytes` bounds their encoded
bytes by Q times (the queue payload limit + 65). `Buffers::accounted_payload_with_queue` uses that
projection to discharge the combined theorem's queued count and validity premises.
The queue invariant now proves every retained payload fits its immutable limit.
The executable initializes that limit from validated K; the composition theorem
requires the queue limit to be at most K instead of a premise for every frame.
Other category snapshots and the trusted startup configuration binding remain.
`encoding_and_queued_bound` charges one in-progress encoding together with queued
frames to Q, using the actual reservation bit and an explicit encoding-size premise.
`Buffers::accounted_payload_with_encoding` composes this with every other category:
its `bytes_with_encoding` total includes the retained-queue snapshot plus the
separate encoding byte sequence, under the same published subtotal. A coverage
lemma and omission mutation prevent silently dropping that sequence. The
queue-only theorem is the empty-encoding specialization. The snapshot must not
include the in-progress encoding in `queued_log` as well.
Production now calls verified `encode_reserved` through the mutex-held callback;
it checks the queue's own payload limit and reservation before building the body.
The typed body/sealed-frame composition theorems derive encoding bytes from the
actual container, including 33-byte body or 65-byte sealed overhead. The production
`enqueue(record)` boundary exposes no callback or core reference; its private
callback consumes a non-cloneable encoding permit, then pairs the frame with its
receipt channel. This ownership restriction supports the single-construction
argument; the queue module and synchronization remain trusted. Independent users
of the core constructor must still enforce call multiplicity. Allocation capacity/scratch,
the active worker frame, and delivered receipts remain separate obligations.

This is a size-composition proof, not proof that every async runtime state supplies
those snapshots. The verified owner now enforces exclusive accounting of each request's stream body
and pending read buffer under the mutable-slice length contract. Queue reservations
must still precede encoding, the
worker must retain only one active frame, and receipts must be counted until
consumed or dropped. The runtime correspondence and all excluded allocations
below remain separate obligations.
Do not substitute the lower observed concurrent-request count for R when publishing
configuration guarantees. Multiple gateway/logger instances multiply their budgets.

The [audit allocation inventory](dependency-resources.md#audit-encoding-allocation-requests)
accounts for a P + 65 byte frame reservation and a simultaneous 33-byte header
scratch request. The unsealed body uses only P + 33 bytes of that reservation;
sealing fills the remaining checksum space without needing vector growth under
standard Vec behavior. Capacity/address regressions supplement the length proofs
but do not establish allocator or physical-memory bounds.

The [audit-buffer lifetime audit](audit-buffer-lifetimes.md) follows queue credit,
worker ownership, and receipt delivery through cancellation, including the pinned
Tokio send/receive/drop operations and a stalled-worker cancellation test.

## Allocations outside that subtotal

The [dependency audit](dependency-resources.md) traces the pinned Hyper/TLS
implementation's thresholds, extra queues, and retained storage. In particular,
HTTP buffer thresholds and TLS application-data limits are not hard heap caps.
The upstream explicitly configures a 64 KiB TLS application-data buffer limit
before handshake; control traffic and record overhead have separate accounting.
Its explicit session-cache policy retains up to 32 server entries after cache
operations (33 transiently during insertion), independent of active requests;
the dependency audit accounts for ticket/certificate/secret byte contents and
identifies excluded metadata and active owners.


- Hyper parser and output buffers, incoming-body channels, HTTP headers and URIs,
  and data frames already consumed from our channels. Production now explicitly
  selects Hyper queue mode on both sides, excluding body flattening into the
  serialized-head vector; header and parser backing capacities remain separate.
  The [queued-output audit](dependency-resources.md#output-backpressure-and-retained-capacity)
  bounds retained streaming payload owners per Hyper writer conditionally on the
  pinned source; its mailbox-inclusive bound overlaps the subtotal above. The
  [HTTP metadata boundary](http-boundary.md#metadata-ownership-and-allocation)
  now detaches bounded allowed values and drops original Parts before awaits;
  its copied-value subtotal and inserted Host/credential data remain separate
  from the stream/log buffer theorem. Both HTTP/1 builders set a
  32 KiB parser-buffer limit, but that setting alone does not prove total Hyper
  allocation bounds or backing-storage sizes. A separate plaintext-read adapter
  caps each actual HTTP read at 32 KiB without imposing a wire-chunk/body length
  limit; it adds no owned payload buffer.
- rustls handshake and record buffers, certificate/root-store data, TLS overhead,
  system-resolver internals, and kernel socket buffers. The
  [DNS inventory](dns-resources.md) accounts for lookup jobs, dedicated threads,
  stacks, and bounded returned address vectors separately from request leases.
- The worker registry adds R `u64` entries (8 × R logical bytes, at most 512 KiB
  with validated limits), plus vector spare capacity and mutex/registry metadata.
  Acquisition scans at most R slots under a synchronous mutex; it creates no async
  waiter. Each `WorkerTask` additionally boxes its future to enforce safe drop order.
- Tokio task/future state, task trackers, queue nodes, channel permits/oneshots,
  thread stacks, allocator rounding/fragmentation, and runtime bookkeeping.
  The [channel inventory](dependency-resources.md#channel-control-storage) now
  bounds control-object counts separately from variable payloads and identifies
  fixed HTTP slots and their two registered wakers; the former mpsc block-reuse obligation no longer applies. The disk
  queue instead requests one fixed Q-element vector of optional Jobs; checked
  FIFO operations preserve its slot count without resizing. The audit worker
  requests a 2 MiB stack; with the four DNS workers, the executable requests
  10 MiB of dedicated background stacks, excluding OS overhead and its main stack.
- Immutable identity/route tables, URI and credential storage, configuration
  parsing scratch, metrics strings, and error/header metadata. The
  [configuration inventory](configuration.md#configuration-storage-and-startup-scratch)
  separates retained data from startup scratch: root proof snapshots are erased,
  and the CLI drops its JSON input buffers before serving.
- Filesystem page cache and storage-controller state. Audit-file disk usage grows
  with cumulative traffic; bounded in-memory queues do not bound disk usage.

The request tracker includes rejected/unauthenticated requests and completion tails
after body EOF. It has a separate R-slot verified registry, so a free stream slot does not imply
that a new worker can start. A `WorkerTask` owns the pinned task future followed
by its lease: Rust field drop order destroys all captures before returning credit,
including cancellation before the first poll. The lease removes tracking before
returning its key to its original registry. Saturation returns 503 without
spawning a waiter or worker. Health, readiness, and metrics bypass this worker gate
but remain subject to the inbound connection limit. A poisoned registry at gateway
construction produces a zero-worker gate, preserving fail-closed behavior. Worker
registry poisoning also permanently closes that gate and fails readiness in both
logging modes. Exhausted registry IDs refuse new work rather than wrap.

The real-socket worker-budget test holds a cleanup lease with all core slots free,
checks sixteen excess requests plus health endpoints, observes no upstream
connection, and verifies permit recovery when an unpolled task is aborted. Existing
stream, disconnect, and shutdown tests exercise normal worker lifetimes. Formal
composition still depends on the trusted mutex/private-key/drop relationships;
the Tokio executor may also retain completed task bookkeeping outside our lease.
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
