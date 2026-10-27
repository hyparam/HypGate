# Resource composition

This document composes the separate resource inventories into one conditional
bound. It states which object owns
each budget, how the production owners correspond to the categories of the
verified buffer theorem, and how the dependency allocation inventories sum. The
result is a **requested-allocation ceiling under explicit assumptions**, listed
at the end. It is not a whole-process RSS theorem: allocator rounding, kernel
memory, and thread bookkeeping are assumptions, not accounted bytes.

**Status (2026-10-26).** The runtime no longer links Tokio or tokio-rustls; it
runs one thread per connection over blocking sockets. The per-exchange
dependency allowance below is the Hyper-era and tokio-rustls-era figure, kept
as an upper bound on the codec adapter's and rustls's storage; the handshake
pool terms are gone, and each inbound connection now carries its two thread
stacks. `budget.rs` is the authority for the exact sums.

Let R be the configured request limit, K the chunk size, C the inbound
connection limit, and Q the disk queue capacity. The executable uses C = 128
and Q = 16; the [running example](running.md#configuration-example) sets R = 32
and K = 16,384. The verified `validate_limits` contract bounds R by 65,536, K by
1 MiB, and R × K by 128 MiB. `gateway-runtime/src/budget.rs` computes the
composed figure from these four limits with checked arithmetic, and the
executable prints it at startup.

## Instance and lifetime scopes

Every budget below belongs to exactly one owner. The executable constructs one
of each; library callers that construct more instances multiply the budgets.

| Owner | Lifetime | Budgets it holds | Tails that outlive callers |
| --- | --- | --- | --- |
| `GatewayConfig` (`Admission` registry) | Process, immutable after construction | R request slots (8 bytes each), identity/route/destination/credential storage, K | Request leases retire under the admission mutex; a panic during reservation-to-owner transfer strands one slot until restart |
| `Gateway` | Until the last `Arc` drops | R worker slots, C connection slots (fixed by the first `serve`), the table of live exchanges' cancel handles, counters | An exchange keeps R credit until its work returns and drops its captures after a client disconnect; a connection keeps C credit until its thread's work returns |
| One `serve` invocation | From listener bind to drained shutdown | Listener, one just-accepted socket | Connection threads it started that are still finishing their work, bounded by C |
| `HttpsTransport` | Until dropped | TLS client config and root store, session cache (32 servers, 33 during insertion), DNS pool (4 threads, 32 credits) | DNS jobs and unread replies keep verified credit until cleanup or checked adoption by a live request; the cache survives when no request is live |
| `DiskLog` | Until the last clone drops and the worker exits | Q fixed frame slots, one encoding reservation, up to 16 active frames, one worker thread stack | The active frame stays owned through a stuck syscall; queued jobs survive caller cancellation; poisoned storage stays charged until destruction |
| Admitted exchange (`PreparedRequest` → `HttpsTransport::connect` and the `Session` effects, under the verified driver) | From admission to retirement of the owned stream | One K chunk/read owner, one upstream connection and its TLS state, one chunked upload writer, two 32 KiB body read buffers, one receipt | HTTP cleanup precedes request credit return; the TLS handshake runs on the same thread and leaves nothing behind |
| Inbound connection thread | From accept to the thread's work returning | One 512 KiB thread stack and one 64 KiB watcher stack, one 32 KiB head buffer, one chunked response writer, one cancel handle | A client disconnect cancels the exchange through the watcher; the thread finishes its completion record before its credit returns |

Instances compose additively. A second `serve` on the same `Gateway` shares C
but adds its own listener; a second `Gateway` or `HttpsTransport` adds every
budget in its row. There is no path that reclaims an operation's resources
because its caller timed out: a deadline fails the waiting thread's operation,
and the rows above list what remains owned afterward.

## Runtime correspondence to the combined theorem

`Buffers::accounted_payload_bound` in `gateway-core/src/buffer_accounting.rs`
takes a ghost snapshot with seven categories. Each row maps a category to the
production owner that realizes it, the event that inserts and removes it, and
the mechanism that keeps the count hypothesis true.

| Theorem category and hypothesis | Production owner | Inserted by | Removed by | Count enforcement |
| --- | --- | --- | --- | --- |
| `chunks`: at most R, each at most K | `OwnedStream` inside `admission::Request` (stream body or pending read buffer, never both nonempty) | `OwnedStream::claim` in `Admission::admit` | `OwnedStream::retire` in `Lease::drop` under the admission mutex | Verified registry occupancy; `registry_owned_payload_bound` supplies the chunk predicate; raw construction is crate-private |
| `readers`: at most 2R, each at most 32 KiB | `http1::BodyReader` buffers for the inbound body and for the upstream response body, under `http_body::Reader` roles | `WorkerHttp::input` in `ConnectionEffects::bind_input` and `WorkerHttp::output` in `Session::download`, both effects the verified driver asks for | The work returns and drops them before `leased::run` records cleanup | Production `WorkerRegistry` issues each reader role once; active permits prevent release. `http_owner_bounds` derives 2R; buffers remain charged through partial reads and destruction |
| `output_queues`: at most C + 2R, each at most 16 KiB | None: the runtime has no body queue; the connection thread writes each copied frame as a chunk before accepting the next | The chunked writers under `WorkerHttp::upload_writer` and `WorkerHttp::response_writer` | Dropped with the work | The theorem's term is kept and over-approximates; the framed chunk in flight is charged under [chunk framing buffers](dependency-resources.md#chunk-framing-buffers). See [HTTP ownership](http-ownership.md) for the runtime mapping |
| `queued_log`: at most Q, each at most A = max(K, 8,210) | `FrameQueue<Completion>` slots in `disk_log::queue::Queue` | `enqueue` through the verified reservation and `finish_reserved` | Worker `recv` pops under the queue mutex | Verified fixed-queue occupancy; the executable binds the payload limit to A so metadata records fit; the theorem is instantiated at A, which bounds K |
| Encoding snapshot: at most one, within A + 65 | `RecordBody`/`RecordFrame` built by the single-use `EncodingPermit` | `FrameQueue::reserve` under the queue mutex | `finish_reserved` or construction panic (poisoned, still charged) | Verified reservation bit; the permit is non-cloneable and consumed |
| `active_log`: at most 16, each within A | `ActiveBatch` / `FinishedBatch` matched to the disk worker's retained frame snapshot | Verified `BatchWorker::take` inside `recv` returns credit to Q and charges the active slot | Verified run commits or drops the frame; consuming delivery and a matching session/generation token permit release | Verified busy gate and `queued_and_active_bound`; one worker per `DiskLog`, never replaced |
| `receipts`: at most R, each within K | `DurableFrame` delivered through the job oneshot to the body-copy loop (`BodyCopy::finish_audit`) | `commit_frame` and oneshot send | Exact receipt validation drops it; cancellation drops it with the receiver | One outstanding append per request; the worker can run ahead by one job, which is the active-frame term |
| `headers`: at most R + 1, each 33 bytes | Canonical header scratch in `encode_payload` and in receipt comparison | Encoding entry | Function return | One per encoding logger plus one per validating request |

Cancellation tails are the only places where a snapshot entry survives its
caller. They are enumerated here so that no entry is dropped from the sum:

- A canceled request keeps its chunk until `Lease::drop` retires the owner;
  `copy_body` cancels the stream through `CancelOnDrop` first.
- A canceled client connection leaves the exchange running until its blocked
  socket operation fails; the 2R output-queue term of the verified subtotal has
  no runtime counterpart any more and over-approximates.
- A canceled append leaves its queued or active frame where it is; the receipt
  for that frame is dropped unsent or dropped with the dead receiver.
- A DNS lookup whose requester stopped waiting keeps its credit and hostname
  until the system call returns, in the transport's 32-job budget.
- A connection thread keeps its C credit until its work returns, including the
  head buffer and the response writer.

The correspondence is enforced by Rust ownership and privacy: each owner type
is constructed only by the listed production path, holds its credit in a field
declared after the resource it guards, and has no accessor that moves the
resource out. This is checked by the lifetime regressions cited in the
[runtime ownership](runtime-ownership.md), [worker](worker-lifetimes.md),
[HTTP](http-buffer-lifetimes.md), and [audit](audit-buffer-lifetimes.md) notes,
not by a mechanized refinement of the threaded runtime. That remains the first
assumption listed below.

## Composed allocation bound

The visible payload subtotal is the verified theorem's conclusion:

    V(R, K, C, Q) = R × K + 2R × 32,768 + (C + 2R) × 16,384 + (Q + R + 16) × (A + 65) + (R + 1) × 33

where A = max(K, 8,210) is the audit payload limit the executable passes to the
logger: metadata records (at most 8,210 bytes) share the queue with body chunks.
For the documented 16 KiB chunk A equals K. Instantiating the verified theorem at
A is sound because every chunk is at most K and hence at most A; the figure is
conservative for small chunks, where retained body receipts are in fact at most K.

The dependency inventories in the [dependency audit](dependency-resources.md)
give per-owner requested-allocation bounds. They are summed below. Every row
cites the section that derives it; descriptor and control objects whose sizes
are private ABI facts are listed with counts in the assumptions, not here.

### Per inbound connection (multiply by C)

| Allocation | Bytes | Source |
| --- | ---: | --- |
| Request head buffer, with its leftover split off during the return | 65,536 | [Head buffers](dependency-resources.md#head-buffers) |
| Body read buffer | 32,768 | [Body read buffer](dependency-resources.md#body-read-buffer) |
| Chunked writer pending frame, with doubling | 32,808 | [Chunk framing buffers](dependency-resources.md#chunk-framing-buffers) |
| Serialized response head, with doubling | 65,536 | [Written head lengths](dependency-resources.md#written-head-lengths) |
| Filtered response head copied for the client | 32,768 | [Metadata ownership](http-boundary.md#metadata-ownership-and-allocation) |
| Total | 229,416 | |

### Per admitted exchange (multiply by R)

| Allocation | Bytes | Source |
| --- | ---: | --- |
| Status head buffer, with its leftover split off during the return | 65,536 | Head buffers |
| Body read buffer | 32,768 | Body read buffer |
| Chunked writer pending frame, with doubling | 32,808 | Chunk framing buffers |
| Serialized request head, with doubling | 65,536 | Written head lengths |
| Filtered request values with Host/credential, plus filtered response values | 81,967 | Metadata ownership: 41,007 + 8,192 + 32,768 |
| TLS deframer backing, during replacement | 196,608 | [TLS deframer backing capacity](dependency-resources.md#tls-deframer-backing-capacity) |
| TLS transcript buffer through a HelloRetryRequest, during growth | 262,228 | Two copies of 36 + 2 × 65,539; [cookie storage](dependency-resources.md#helloretryrequest-cookie-storage) |
| Retry handler transient copies (decoded cookie, extension clone, encoded hello) | 196,617 | Cookie storage |
| Queued ciphertext window plus consumed-prefix allowance | 82,194 | Derived below |
| Peer certificate chain, owned copy plus the transient Certificate-step copy | 131,072 | [Peer certificate chain owners](dependency-resources.md#peer-certificate-chain-owners) |
| Active session values, two per connection | 262,238 | [Active session owners](dependency-resources.md#active-session-owners) |
| Received plaintext queue with one crossing record | 32,768 | [Upstream TLS storage](dependency-resources.md#upstream-tls-storage) |
| Verifier failure diagnostics: 32,768 inner vectors (24 bytes each) plus 2 × 65,536 `usize` components | 1,835,008 | [Verifier scratch](dependency-resources.md#certificate-verifier-scratch-and-diagnostics) |
| DNS hostname and 64 socket addresses (32 bytes each) | 2,301 | [DNS inventory](dns-resources.md#allocation-inventory-and-shutdown) |
| Total | 3,279,649 | |

The queued ciphertext window composes the control-traffic audit with the
production write path. rustls's blocking `Stream` writes plaintext only after
the previously queued ciphertext has been written, and `perhaps_write_key_update`
moves a pending key-update reply only from `buffer_plaintext` (application
writes) and `queue_tls_message` (control records); the unbuffered
`write_plaintext` path is unused. Between drains the queue therefore holds at
most one application batch of 65,536 bytes in four records (29 bytes of
overhead each for the largest pinned suite), one automatic refresh request
(27), one transferred peer-triggered reply (27), one fatal alert or close
notification (24) with the reply it transfers (27), and one further close
notification (24): 65,781 bytes. The initial handshake flight (a second
ClientHello of at most 65,632 bytes plus the compatibility CCS and Finished)
is smaller than that window. `ChunkVecBuffer` keeps one consumed front record
of at most 16,413 bytes, giving 82,194. Peer key updates without an
intervening local write cannot transfer more than one reply, because the
pending slot holds one record and `should_update_key` refuses while it is
occupied; `tls_drain_guard_holds_control_queue_stable_and_resumes_exact_bytes`
checks this over 3,000 rounds.

### Per instance

| Allocation | Bytes | Source |
| --- | ---: | --- |
| Verified registries: R request, R worker, C connection, 32 DNS slots | 8 × (2R + C + 32) | [Resource inventory](resource-accounting.md) |
| Dedicated thread stacks: audit worker, four DNS workers, the 64 KiB signal thread | 10,551,296 | [Dedicated thread stacks](dependency-resources.md#dedicated-thread-stacks); the per-connection and watcher stacks are charged per inbound connection |
| TLS session cache contents, 33 servers × 9 sessions × 131,119 | 38,942,343 | [Shared TLS session storage](dependency-resources.md#shared-tls-session-storage) |
| Queued DNS jobs, 32 × (253 + 2,048) | 73,632 | DNS inventory |
| Retained configuration content, bounded by both one-MiB input documents | 2,097,152 | [Configuration storage](configuration.md#configuration-storage-and-startup-scratch) |
| Disk queue slot vector | Q × size of `Option<(RecordFrame, Sender)>` | [Audit ownership](audit-buffer-lifetimes.md#verified-fixed-queue-and-synchronization-obligations) |
| Batch descriptor vectors (payloads charged in V) | 16 × (size of `Option<(RecordFrame, Sender)>` + size of `(Option<DurableFrame>, Sender)`) | `budget::BATCH_DESCRIPTORS`; bounded recursion uses the existing worker stack |
| Root store trust-anchor descriptors | root count × size of `TrustAnchor` | `webpki-roots` static table, cloned descriptors over static DER |
| Optional shipper thread (only with a `shipping` section): its stack, `O × E` assembler bytes, `O × 2 × (E + 16,384)` queued rows, one scanned record, one 4 MiB batch and its request copy, a 64 KiB reply, 128 KiB S3 credential/signing/header scratch | 2,097,152 + O × E + O × 2 × (E + 16,384) + 1,048,641 + 8,388,608 + 65,536 + 131,072 | [Cloud shipping](cloud-shipping.md#resources); `budget::shipping`, printed separately at startup |

The composed bound is:

    B(R, K, C, Q) = V(R, K, C, Q) + C × 1,523,725 + R × 3,984,134 + instance(R, C, Q)

where the per-connection term is the 512 KiB connection stack, the 64 KiB
watcher stack, and the retained 933,901-byte adapter allowance. For the
executable example (R = 32, K = 16,384, C = 128, Q = 16), V is
6,820,993 bytes and B is about 380.9 MB; `budget::tests` pins the exact value
from the sizes computed at build time. The isolated-process workload measured a
kernel peak of 14,168,064 bytes on Linux with R = 8 ([benchmarks](benchmarks.md#isolated-gateway-process-memory)).
The gap is expected: the bound charges every owner at its replacement peak
simultaneously, including verifier failure diagnostics and a full session cache,
while the workload exercises none of those extremes. The bound's purpose is to
show that no owner is unaccounted, not to predict usage.

## Assumptions

The composed figure is conditional on the following. Each is a stated
assumption of this composition, not a proved property.

1. **Runtime correspondence.** The production owners in the table above are
   the only holders of the theorem's categories, and Rust field drop order,
   mutex serialization, and socket shutdown as cancellation behave as
   documented. This is supported by the lifetime regressions, not a
   mechanized refinement of the threaded runtime.
2. **Pinned dependency source.** rustls 0.23.46, rustls-webpki 0.103.16, and
   the Rust 1.99.1 `Vec` growth policy behave as inspected; the HTTP/1.1
   buffers are the codec adapter's own, and no executor is linked. Every
   dependency upgrade must re-audit the cited sections.
3. **Allocator and OS.** Requested capacities are not allocator byte counts.
   Size-class rounding, fragmentation, freed-memory caching, thread-local
   caches, guard pages, committed stack pages, kernel socket buffers, page
   cache, and process mappings are outside the sum. Allocation is assumed to
   succeed; the gateway does not handle allocation failure.
4. **Fixed-size descriptors and control objects.** The sum omits objects whose
   size is a private ABI fact: `HeaderMap` buckets (at most 256 index slots,
   192 buckets, 128 extra values per parsed head), certificate-entry
   descriptors (at most 16,384 slots, 24,576 during growth), kernel thread
   objects (at most 2C + 6 live threads plus the shipper), `mpsc` channel
   control blocks (one per append and per DNS job), cancel handles (one per
   in-flight exchange), `Arc`/mutex/condvar headers, and TLS key schedules and
   cipher states. Their counts are bounded by the same R, C, Q, and 32-job
   limits.
5. **One instance of each owner.** The executable constructs one
   `GatewayConfig`, `Gateway`, `HttpsTransport`, `DiskLog`, and `serve`
   invocation on the main thread, plus at most one shipper thread, charged on
   its own row. Library callers multiply the per-instance row and must budget
   their own threads and main stack.
6. **Protocol scope.** One HTTP/1 exchange per connection without keep-alive,
   pipelining, trailers, Content-Length forwarding, ECH, client authentication,
   certificate compression, QUIC, or early data. TLS peers are bounded by the
   65,535-byte handshake-message limit and the cipher suites pinned in the
   audit.
7. **Honest effects.** Transports report accepted byte counts truthfully and
   the storage contract holds, as required by the core contracts.

Within these assumptions, every queue, buffer, and outstanding operation in the
production path is charged to exactly one owner with a bounded count and a
bounded requested size. The remaining obligations are the assumptions
themselves, which this document does not hide.


## Cross-owner regressions and lifecycle composition

The role regressions that exercise the credited readers and writers under
the worker lease are described in the
[HTTP buffer lifetime audit](http-buffer-lifetimes.md#role-regressions);
the checked lifecycle composition they support is recorded in the
[ownership composition](ownership-composition.md). The allocation snapshot
theorem above retains its stated correspondence and allocator assumptions.
