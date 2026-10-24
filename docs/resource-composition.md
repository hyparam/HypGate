# Resource composition

This document closes the resource criterion of milestone 1 by composing the
separate inventories into one conditional bound. It states which object owns
each budget, how the production owners correspond to the categories of the
verified buffer theorem, and how the dependency allocation inventories sum. The
result is a **requested-allocation ceiling under explicit assumptions**, listed
at the end. It is not a whole-process RSS theorem: allocator rounding, kernel
memory, and executor bookkeeping are assumptions, not accounted bytes.

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
| `Gateway` | Until the last `Arc` drops | R worker slots, C connection slots (fixed by the first `serve`), task tracker, counters | Worker tasks keep R credit through future destruction after client disconnect; connection tasks keep C credit through aborted-parent cleanup |
| One `serve` invocation | From listener bind to drained shutdown | Listener, JoinSet of at most C entries, one just-accepted socket | Completed-but-unreaped JoinSet entries until reaped; aborted children until Tokio destroys them |
| `HttpsTransport` | Until dropped | TLS client config and root store, session cache (32 servers, 33 during insertion), DNS pool (4 threads, 32 credits), handshake pool (4 threads, 32 credits) | DNS/handshake jobs and unread replies keep verified credit until cleanup or checked adoption by a live request; the cache survives when no request is live |
| `DiskLog` | Until the last clone drops and the worker exits | Q fixed frame slots, one encoding reservation, one active frame, one worker thread stack | The active frame stays owned through a stuck syscall; queued jobs survive caller cancellation; poisoned storage stays charged until destruction |
| Admitted exchange (`PreparedRequest` → `HttpsTransport::exchange`) | From admission to retirement of the owned stream | One K chunk/read owner, one upstream connection, one upload channel, reader copies, one receipt | HTTP cleanup precedes request credit return; dispatched TLS handshake work retains separate pool credit through cancellation |
| Inbound connection task | From accept to connection-task destruction | Hyper server state, one response mailbox, one worker abort guard | A client disconnect leaves the worker running until it observes the dropped receiver |

Instances compose additively. A second `serve` on the same `Gateway` shares C
but adds its own listener and JoinSet; a second `Gateway` or `HttpsTransport`
adds every budget in its row. There is no path that reclaims an operation's
resources because its caller timed out: timeouts drop waiting futures, and the
rows above list what remains owned afterward.

## Runtime correspondence to the combined theorem

`Buffers::accounted_payload_bound` in `gateway-core/src/buffer_accounting.rs`
takes a ghost snapshot with seven categories. Each row maps a category to the
production owner that realizes it, the event that inserts and removes it, and
the mechanism that keeps the count hypothesis true.

| Theorem category and hypothesis | Production owner | Inserted by | Removed by | Count enforcement |
| --- | --- | --- | --- | --- |
| `chunks`: at most R, each at most K | `OwnedStream` inside `admission::Request` (stream body or pending read buffer, never both nonempty) | `OwnedStream::claim` in `Admission::admit` | `OwnedStream::retire` in `Lease::drop` under the admission mutex | Verified registry occupancy; `registry_owned_payload_bound` supplies the chunk predicate; raw construction is crate-private |
| `readers`: at most 2R, each at most 32 KiB | `http_body::Reader::buffered` for the inbound body and for the upstream response body | `Reader::new` in `Gateway::handle` and `HttpsTransport::run` | Worker future destruction (`LeasedTask` drops its future before its lease) | One reader per direction per worker; R workers; copies cleared when consumed |
| `output_queues`: at most C + 2R, each at most 16 KiB | `http_body` mailbox items: client response channel (one per connection), its sender-only cleanup tail (one per worker), upload channel (one per exchange) | `http_body::channel` in `Gateway::handle` and `HttpsTransport::run` | Receiver drop extracts the item; sender drop preserves it for draining | Verified `Mailbox` slot bound; C and R registries bound the owners |
| `queued_log`: at most Q, each at most K | `FrameQueue<Completion>` slots in `disk_log::queue::Queue` | `enqueue` through the verified reservation and `finish_reserved` | Worker `recv` pops under the queue mutex | Verified fixed-queue occupancy; the executable binds the payload limit to K |
| Encoding snapshot: at most one, within K + 65 | `RecordBody`/`RecordFrame` built by the single-use `EncodingPermit` | `FrameQueue::reserve` under the queue mutex | `finish_reserved` or construction panic (poisoned, still charged) | Verified reservation bit; the permit is non-cloneable and consumed |
| `active_log`: at most one, within K | `ActiveAppend` / `FinishedAppend` matched to the disk worker's retained frame snapshot | Verified `DiskWorker::take` inside `recv` returns credit to Q and charges the active slot | Verified run commits or drops the frame; consuming delivery and a matching session/generation token permit release | Verified busy gate and `queued_and_active_bound`; one worker per `DiskLog`, never replaced |
| `receipts`: at most R, each within K | `DurableFrame` delivered through the job oneshot to `Request::audit_current` | `commit_frame` and oneshot send | Exact receipt validation drops it; cancellation drops it with the receiver | One outstanding append per request; the worker can run ahead by one job, which is the active-frame term |
| `headers`: at most R + 1, each 33 bytes | Canonical header scratch in `encode_payload` and in receipt comparison | Encoding entry | Function return | One per encoding logger plus one per validating request |

Cancellation tails are the only places where a snapshot entry survives its
caller. They are enumerated here so that no entry is dropped from the sum:

- A canceled request keeps its chunk until `Lease::drop` retires the owner;
  `copy_body` cancels the stream through `CancelOnDrop` first.
- A canceled client connection leaves the worker's sender-only mailbox control
  object, charged to the 2R term, until the worker future is destroyed.
- A canceled append leaves its queued or active frame where it is; the receipt
  for that frame is dropped unsent or dropped with the dead receiver.
- A canceled DNS or handshake job keeps its credit, hostname, socket, and TLS
  state until the blocking work returns, in the transport's 32-job budgets.
- A canceled connection task keeps its C credit until Tokio destroys the boxed
  future, including the parser buffer and the response mailbox receiver.

The correspondence is enforced by Rust ownership and privacy: each owner type
is constructed only by the listed production path, holds its credit in a field
declared after the resource it guards, and has no accessor that moves the
resource out. This is checked by the lifetime regressions cited in the
[runtime ownership](runtime-ownership.md), [worker](worker-lifetimes.md),
[HTTP](http-buffer-lifetimes.md), and [audit](audit-buffer-lifetimes.md) notes,
not by a mechanized refinement of the async runtime. That remains the first
assumption listed below.

## Composed allocation bound

The visible payload subtotal is the verified theorem's conclusion:

    V(R, K, C, Q) = R × K + 2R × 32,768 + (C + 2R) × 16,384 + (Q + R + 1) × (K + 65) + (R + 1) × 33

The dependency inventories in the [dependency audit](dependency-resources.md)
give per-owner requested-allocation bounds. They are summed below. Every row
cites the section that derives it; descriptor and control objects whose sizes
are private ABI facts are listed with counts in the assumptions, not here.

### Per inbound connection (multiply by C)

| Allocation | Bytes | Source |
| --- | ---: | --- |
| Hyper server parser backing, four owners, during replacement | 589,824 | [Live parser backing owners](dependency-resources.md#live-parser-backing-owners) |
| Server header vector, during replacement | 196,608 | [Header-vector backing capacity](dependency-resources.md#header-vector-backing-capacity) |
| Queued output original payload owners | 65,549 | [Output backpressure](dependency-resources.md#output-backpressure-and-retained-capacity) |
| Request trailer assembly, during replacement | 49,152 | [Rejected trailer storage](dependency-resources.md#rejected-trailer-storage) |
| Filtered response head copied for the client | 32,768 | [Metadata ownership](http-boundary.md#metadata-ownership-and-allocation) |
| Total | 933,901 | |

### Per admitted exchange (multiply by R)

| Allocation | Bytes | Source |
| --- | ---: | --- |
| Hyper client parser backing, four owners, during replacement | 589,824 | Live parser backing owners |
| Client header vector, during replacement | 196,608 | Header-vector backing capacity |
| Queued upload payload owners | 65,549 | Output backpressure |
| Response trailer assembly, during replacement | 49,152 | Rejected trailer storage |
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
| Total | 3,984,134 | |

The queued ciphertext window composes the control-traffic audit with the
production drain guard. `DrainBeforeWrite` writes plaintext only after the
previously queued ciphertext has been written, and `perhaps_write_key_update`
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
| Verified registries: R request, R worker, C connection, 32 DNS, 32 handshake slots | 8 × (2R + C + 64) | [Resource inventory](resource-accounting.md) |
| Dedicated thread stacks: audit worker, four DNS, four handshake workers | 18,874,368 | [Dedicated thread stacks](dependency-resources.md#dedicated-thread-stacks), [TLS scheduling](https-transport.md#tls-scheduling-isolation) |
| TLS session cache contents, 33 servers × 9 sessions × 131,119 | 38,942,343 | [Shared TLS session storage](dependency-resources.md#shared-tls-session-storage) |
| Queued/running handshake jobs including canceled callers, conservatively charged the full exchange allowance | 32 × 3,984,134 = 127,492,288 | [TLS scheduling](https-transport.md#tls-scheduling-isolation); separate from request credit, includes unused HTTP categories for a conservative subtotal |
| Queued DNS jobs, 32 × (253 + 2,048) | 73,632 | DNS inventory |
| Retained configuration content, bounded by both one-MiB input documents | 2,097,152 | [Configuration storage](configuration.md#configuration-storage-and-startup-scratch) |
| Disk queue slot vector | Q × size of `Option<(RecordFrame, Sender)>` | [Audit ownership](audit-buffer-lifetimes.md#verified-fixed-queue-and-synchronization-obligations) |
| Root store trust-anchor descriptors | root count × size of `TrustAnchor` | `webpki-roots` static table, cloned descriptors over static DER |

The composed bound is:

    B(R, K, C, Q) = V(R, K, C, Q) + C × 933,901 + R × 3,984,134 + instance(R, C, Q)

For the executable example (R = 32, K = 16,384, C = 128, Q = 16), V is
6,574,258 bytes and B is about 441.1 MB; `budget::tests` pins the exact value
from the sizes computed at build time. The isolated-process workload measured a
kernel peak of 14,168,064 bytes on Linux with R = 8 ([benchmarks](benchmarks.md#isolated-gateway-process-memory)).
The gap is expected: the bound charges every owner at its replacement peak
simultaneously, including verifier failure diagnostics and a full session cache,
while the workload exercises none of those extremes. The bound's purpose is to
show that no owner is unaccounted, not to predict usage.

## Assumptions

The composed figure is conditional on the following. Each is a stated
assumption of this milestone, not a proved property.

1. **Runtime correspondence.** The production owners in the table above are
   the only holders of the theorem's categories, and Rust field drop order,
   mutex serialization, and Tokio cancellation behave as documented. This is
   supported by the lifetime regressions, not a mechanized async refinement.
2. **Pinned dependency source.** Hyper 1.12.0, rustls 0.23.46, tokio-rustls
   0.26.6, bytes 1.12.1, http 1.5.0, Tokio 1.54.1, rustls-webpki 0.103.16, and
   the Rust 1.99.1 `Vec` growth policy behave as inspected. Every dependency
   upgrade must re-audit the cited sections.
3. **Allocator and OS.** Requested capacities are not allocator byte counts.
   Size-class rounding, fragmentation, freed-memory caching, thread-local
   caches, guard pages, committed stack pages, kernel socket buffers, page
   cache, and process mappings are outside the sum. Allocation is assumed to
   succeed; the gateway does not handle allocation failure.
4. **Fixed-size descriptors and control objects.** The sum omits objects whose
   size is a private ABI fact: `HeaderMap` buckets (at most 256 index slots,
   192 buckets, 128 extra values per parsed head), certificate-entry
   descriptors (at most 16,384 slots, 24,576 during growth), Tokio task
   harnesses (at most C + R + 1 live tasks), wakers (two per mailbox), oneshot
   control blocks (one per worker response, append, DNS job, and handshake job),
   `Arc`/mutex/condvar headers, and TLS key schedules and cipher states. Their
   counts are bounded by the same R, C, Q, and 32-job limits.
5. **One instance of each owner.** The executable constructs one
   `GatewayConfig`, `Gateway`, `HttpsTransport`, `DiskLog`, and `serve`
   invocation on a current-thread runtime. Library callers multiply the
   per-instance row and must budget their own runtime threads and main stack.
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
themselves, which later milestones may narrow but which this document does not
hide.


## Milestone 6 cross-owner HTTP regression

The worker lifecycle suite now exercises the actual HTTP channel across two
separately credited tasks: canceling the writer's worker allows worker reuse while
the receiver's connection credit remains occupied and its queued frame remains
intact. Canceling and joining that connection then returns its credit. A second
regression checks actual Reader destruction before worker-slot/tracker release,
including a retained partial frame. This strengthens the production correspondence
evidence above; it does not change the conditional snapshot theorem into the
still-pending milestone 6 lifecycle/composition theorem.
