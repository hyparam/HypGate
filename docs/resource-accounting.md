# Runtime resource accounting

This is a source-level inventory of the production path, not a whole-process
memory theorem. The verified combined bound covers logical payload in streams
mapped to live registry slots. The adapter additionally allocates buffers and owns
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
| Core chunk or next transfer buffer | At most K per admitted exchange in the production sequential driver | `transfer::copy_body` discards the completed core payload before allocating the next read buffer, then moves it into the stream. `Request::advance` rejects excessive vector capacity. The ghost theorem covers logical lengths, not allocator size. |
| Inbound/outbound reader copies | At most 32 KiB of copied payload per reader; conservatively two readers per admitted exchange | `http_body::Reader` copies accepted visible frame bytes and releases its input reference before yielding; it clears the copy immediately when consumed. It cannot retain a large input owner through a small slice. Upload and download run sequentially; the inbound reader object remains alive. Allocator overhead and references retained inside Hyper remain separate. |
| Client response channel | One data message of at most 16 KiB per connection with a response body | Created before authorization but after acquiring a worker permit in `Gateway::handle`; charging this solely to authorized request leases is incorrect. A consumed message leaves this queue and becomes Hyper-owned. End markers carry no payload. |
| Provider upload channel | One data message of at most 16 KiB per admitted exchange | Constructed in `HttpsTransport::run`; `Writer::poll_write` reserves queue credit before copying bytes. Hyper may retain previously consumed frames outside the channel. |
| Disk frames being encoded or queued | At most Q reserved/queued records, each at most K + 65 bytes for production requests | `DiskLog::append` reserves before encoding. Encoding and enqueueing are serialized under the worker mutex. Other library callers may supply up to 1 MiB per record independently of K. |
| Active disk frame | One additional frame of at most K + 65 bytes | The worker owns the job after receiving it, through write, sync, and acknowledgment. Cancellation of its caller does not reclaim or duplicate that frame. A stalled worker is never replaced. |
| Delivered durable receipts | At most one frame of at most K + 65 bytes per admitted exchange | The job oneshot transfers its owned frame to the waiting request. Exact receipt validation then drops it; cancellation drops undelivered receipts. The worker can advance to another job before delivery is consumed. Custom library callers retaining receipts must budget separately. |
| Encoding/comparison scratch | One 33-byte header vector per logger encoder plus one per validating request | `framing::encode_payload` copies a canonical header into the reserved frame. Receipt validation also encodes the expected 33-byte header, then compares payload slices without copying the payload. SHA-256 state and the 32-byte digest are additional fixed-size implementation state. |
| Inbound connection tasks | At most C entries in the server JoinSet | Admission checks the set before spawning; completed-but-unreaped entries also consume the limit. Excess accepted sockets are closed. The listener and one just-accepted socket are additional objects. |
| Server request workers, including rejection and cleanup | At most R worker leases | A semaphore permit is acquired before allocating response channels or spawning. A private lease drops its task-tracker token before returning the permit; cancellation before first poll also releases it. This is trusted Rust/Tokio behavior, not a Verus theorem. |
| Admitted exchanges and upstream connections | At most R live leases; one upstream connection per exchange | Verified slot transitions plus trusted ownership. The outer exchange owns admission while the timed TCP/TLS/HTTP future borrows it, so network-future cleanup precedes request release. No pooling, replay, or detached upstream connection task. Failed authentication can still create a tracked server worker without a lease. |
| Disk operations | One worker, one sequential write/sync operation | A timeout bounds caller waiting, not syscall duration. Outstanding work retains its frame until completion or process exit. |

A conservative **visible payload subtotal**, under the ownership relationships
above, is:

    R × K + 2 × R × 32 KiB + (C + R) × 16 KiB + (Q + R + 1) × (K + 65) + (R + 1) × 33 bytes

This intentionally overcounts reader copies and queue data that may not coexist.
It is useful for finding missing categories, not for promising a memory ceiling.
The conditional composition theorem `Buffers::accounted_payload_bound` now proves
this subtotal in `gateway-core/src/buffer_accounting.rs`. It takes complete ghost
snapshots of the listed categories, with explicit per-category count and chunk-size
hypotheses. `bounded_frames` and `DurableFrame::retained_size` derive the 65-byte
frame overhead from the production encoding; receipts count their actual retained
frame, not the erased acknowledged-history prefix. `covers_categories` prevents
an accidentally omitted category from silently weakening the modeled total.

This is a size-composition proof, not proof that every async runtime state supplies
those snapshots. In particular, each request's stream body and pending read buffer
must be accounted for exclusively, queue reservations must precede encoding, the
worker must retain only one active frame, and receipts must be counted until
consumed or dropped. The runtime correspondence and all excluded allocations
below remain separate obligations.
Do not substitute the lower observed concurrent-request count for R when publishing
configuration guarantees. Multiple gateway/logger instances multiply their budgets.

## Allocations outside that subtotal

The [dependency audit](dependency-resources.md) traces the pinned Hyper/TLS
implementation's thresholds, extra queues, and retained storage. In particular,
HTTP buffer thresholds and TLS application-data limits are not hard heap caps.
The upstream explicitly configures a 64 KiB TLS application-data buffer limit
before handshake; control traffic and record overhead have separate accounting.


- Hyper parser and output buffers, incoming-body channels, HTTP headers and URIs,
  and data frames already consumed from our channels. Both HTTP/1 builders set a
  32 KiB parser-buffer limit, but that setting alone does not prove total Hyper
  allocation bounds or backing-storage sizes.
- rustls handshake and record buffers, certificate/root-store data, TLS overhead,
  DNS resolution, and kernel socket buffers.
- Tokio task/future state, task trackers, queue nodes, channel permits/oneshots,
  thread stacks, allocator rounding/fragmentation, and runtime bookkeeping.
- Immutable policy, routes, credential strings, configuration parsing scratch,
  metrics response strings, and error/header metadata.
- Filesystem page cache and storage-controller state. Audit-file disk usage grows
  with cumulative traffic; bounded in-memory queues do not bound disk usage.

The request tracker includes rejected/unauthenticated requests and completion tails
after body EOF. It has a separate R-permit gate, so a free core slot does not imply
that a new worker can start. The worker lease retains its permit through task
cleanup and removes tracking before returning credit. Saturation returns 503 without
spawning a waiter or worker. Health, readiness, and metrics bypass this worker gate
but remain subject to the inbound connection limit. A poisoned registry at gateway
construction produces a zero-worker gate, preserving fail-closed behavior.

The real-socket worker-budget test holds a cleanup lease with all core slots free,
checks sixteen excess requests plus health endpoints, observes no upstream
connection, and verifies permit recovery when an unpolled task is aborted. Existing
stream, disconnect, and shutdown tests exercise normal worker lifetimes. Formal
composition still depends on proving these trusted semaphore/drop relationships;
the Tokio executor may also retain completed task bookkeeping outside our lease.

## Evidence and outstanding work

The [runtime ownership notes](runtime-ownership.md) and [proof index](proof-index.md)
identify the checked core contracts and trusted bindings. Body-channel tests cover
fragmentation, bounded frame acceptance, trailers, and cancellation. Real TLS tests
exercise overload, slow peers, deadlines, and shutdown. The stalled-sync test
fills a two-record queue while eight requests run, observes one blocked writer,
checks reclaimed request slots and both logging modes, and releases that same
worker without any additional write. [Benchmark results](benchmarks.md) report
whole-fixture RSS separately from these logical budgets.

The production lease now uses a verified private `OwnedStream` key/stream pair;
its transitions preserve pairing and consuming retirement returns the slot.
Core ownership-map preservation is now checked for admission, stream creation,
replacement, and retirement; see the [ownership notes](runtime-ownership.md#ownership-map-preservation).
Remaining work includes correspondence between the full runtime ownership and
those ghost-map events, dependency/backing-allocation accounting, formal worker-lifetime composition,
and longer-duration isolated-gateway measurements. A separate gateway-child
fixture now measures three paced waves per logging mode, excluding provider/client
memory, and checks audit coverage and clean shutdown; see the [benchmark notes](benchmarks.md#isolated-gateway-process-memory). Until the remaining obligations are resolved,
neither the subtotal nor the core's 128 MiB allowance is a whole-process guarantee.
