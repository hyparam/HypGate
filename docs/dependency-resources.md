# Dependency resource audit

Source inspection on 2026-10-23 of the versions in Cargo.lock: Hyper 1.12.0,
rustls 0.23.46, and tokio-rustls 0.26.6. These are trusted implementation facts,
not Verus proofs or whole-process allocation ceilings. Recheck them on upgrades.
The [resource inventory](resource-accounting.md) separately accounts for our own
buffers and the number of live connections and requests.

## HTTP/1 storage

Both production builders explicitly set `max_buf_size(32768)`,
`max_header_size(32768)`, `max_headers(100)`, and `writev(true)`; the inbound builder disables
keep-alive. The upstream performs one exchange
per connection. Neither enables pipelined flush aggregation. Explicit `writev(true)` selects
Hyper's queue strategy on both sides, including TLS, instead of allowing adapter
capabilities to choose the buffering representation. Standard non-vectored I/O
still works through its vectored-write fallback.

In Hyper's [h1/io.rs](https://docs.rs/crate/hyper/1.12.0/source/src/proto/h1/io.rs),
`set_max_buf_size` sets both the adaptive read strategy maximum and the write
buffer threshold. `poll_read_from_io` limits the requested reserve but passes the
available `BytesMut` spare capacity to the I/O reader. Allocation rounding and
shared backing storage therefore prevent treating 32768 as a hard allocation
or per-read byte cap. Both production connections now wrap their HTTP plaintext
I/O in `http_io::ReadLimited`, which exposes at most 32768 bytes per read even
when Hyper offers larger spare capacity. Inbound reads wrap TCP; upstream reads
wrap the completed TLS stream, so this is not a TLS handshake-buffer limit.
The adapter allocates no separate read buffer and preserves vectored writes.
Its safe ReadBuf projection may initialize up to 32768 previously uninitialized
bytes; it preserves existing filled bytes and propagates pending/error/EOF states.
Our frame reader still independently rejects visible frames above 32768 and
detaches accepted frames into bounded copies.

This cap fixes an observed compatibility defect, not just an accounting ambiguity:
an exactly 32768-byte valid response head grew Hyper's parser backing storage;
subsequent body reads reused that larger allocation, and our Reader rejected a
valid body with `InvalidData`. A deterministic eager-input regression failed
without the wrapper and now preserves a 256 KiB opaque payload after a maximum
head in both client/server parsers, with Content-Length and chunked framing.
The chunked case uses a single 256 KiB wire chunk, demonstrating that the read
limit does not impose an HTTP chunk-size or whole-body-size limit. Parser backing
capacity, shared owners, and allocator overhead remain separate accounting work.

`WriteBuf::can_buffer` checks the buffered length *before* accepting the next body
buffer. The next buffer can cross the threshold. Queue strategy additionally
limits its buffer list to 16 entries; flatten strategy copies into a growable
header vector. Our output frames contain at most 16384 payload bytes, but HTTP
framing overhead, serialized headers, retained vector capacity, and allocator
rounding are additional. Headers enter through a separate encoding path. Thus
neither 32768 nor the one-slot application channel bounds all Hyper output storage.

### Output backpressure and retained capacity

The pinned dispatcher's `poll_write` checks `can_buffer_body` before polling the
next body frame. With pipeline aggregation disabled, a data append therefore
starts below the 32768-byte remaining-output threshold. Our largest data frame
is 16384 bytes; chunked encoding adds at most eight bytes (four hexadecimal digits
and two CRLF pairs). The separate chunked end marker is five bytes. Headers are
encoded separately and must be budgeted separately, including configured URI and
credential lengths; a large serialized head can exceed the body threshold before
any body is polled. The queue strategy additionally stops at 16 encoded buffers.
These limits bound pending output, not all retained contents: a partially consumed
queued Bytes still owns its complete original allocation.

For the production **streaming** path, let H = 32768 and F = 16384. Inspection of
`dispatch.rs::poll_write`, `conn.rs::{write_body,write_body_and_end,end_body}`,
`encode.rs`, and `common/buf.rs::BufList::advance` gives these conditional bounds:

| Quantity per Hyper writer | Source-derived bound | Scope |
| --- | --- | --- |
| Queued encoded body descriptors | 16 | `can_buffer` checks the count before the dispatcher obtains another body frame; each encode/end operation appends one descriptor. The serialized head is separate. |
| Remaining encoded body bytes | H + F + 13 = 49,165 | One append may cross H. Ordinary chunk framing adds at most eight bytes; 13 also covers the combined chunk/end form. A standalone end marker is five bytes. |
| Original payload bytes retained by those descriptors | H + 2F + 13 = 65,549, and at most 16F | Fully consumed front descriptors are immediately popped. Only the front can retain a consumed payload prefix, adding at most F beyond remaining bytes. |
| Original payload bytes including our mailbox | min(17F, H + 3F + 13) = 81,933 | One additional application frame can wait outside Hyper. This term overlaps the existing application-channel budget and must not be added twice. |

The queued flush path uses `chunks_vectored` followed by `advance`; it does not
invoke `BufList::copy_to_bytes`, whose fallback would allocate copied storage.
The 64-entry IoSlice array is fixed stack scratch and borrows existing buffers.

These are payload/descriptor bounds under the pinned source behavior, not Verus
proofs or allocator-byte bounds. They rely on opaque copied frames no larger than
F, queue mode, no trailers/pipelining, and one exchange per connection. Forwarded
Content-Length is removed by both header allowlists, so streamed output uses
chunked or close-delimited encoding rather than `BufKind::Limited` retaining an
unused suffix. Reintroducing Content-Length or arbitrary shared Bytes owners
requires revisiting this argument. Generated fixed responses have a separate
size obligation. Descriptor ABI size, VecDeque spare capacity/growth overlap,
Bytes ownership metadata, serialized-head capacity, and allocator overhead remain
outside these numeric payload bounds.

`queued_hyper_partial_writes_bound_original_payload_owners` tracks destruction of
original buffers through the real queued client dispatcher. It repeatedly grants
zero, one, fractional-frame, and crossing-frame write budgets, for 1-, 1024-, and
16384-byte frames. Over 64 rounds, cumulative traffic exceeds the bound while live
original payloads remain below it; canceling releases every tracked owner. The
probe counts original payload lengths, not only remaining Bytes views, so partial
front-buffer retention is visible. This is regression evidence for the audited
argument, not a measurement of total heap or RSS.

The unused flatten mode has another distinction. `Cursor<Vec<u8>>::maybe_unshift` removes
consumed prefix bytes only when spare capacity cannot fit the next encoded frame.
The vector can therefore retain already-written bytes alongside remaining output;
its length need not equal `WriteBuf::remaining()`. Capacity survives clearing,
and vector growth can overlap old and new allocations. A complete backing-storage
bound for that mode would need initial capacity, largest serialized head, growth
and compaction. Production now excludes body flattening by selecting queue mode;
serialized-head vector capacity, queued frame owners/control storage, and parser
storage still require their own accounting.

`stalled_hyper_output_bounds_body_consumption_and_cancellation` runs the actual
Hyper client dispatcher and production ChannelBody against an I/O adapter that
never accepts a byte. It exercises both queue and flatten modes with 1-, 1024-,
and 16384-byte frames. Accepted application payload stops within the 32768-byte
threshold plus one crossing frame plus the one-slot application channel; queue
mode also stays within 16 Hyper frames plus that channel. Sixteen further polls
make no progress, with Tokio's cooperative budget renewed between polls so task
budget exhaustion cannot produce a false plateau. Dropping the connection makes
the blocked producer fail. This is dependency/backpressure regression evidence,
not a heap bound, a partial-write capacity test, or a proof of the async runtime.

`queued_hyper_output_preserves_duplex_bytes_with_short_nonvectored_writes`
forces queue mode in both client and server over a 257-byte duplex pipe. Its I/O
wrapper reports no native vectored support and accepts at most seven bytes per
write. A 65,537-byte opaque upload and streamed echo response survive exactly,
including End acknowledgments and completed connection tasks. This exercises
partial vectored fallback through chunk headers, payload, and terminators. It is
byte/lifecycle regression evidence, not a retained-capacity theorem.

Hyper's [body/chan.rs](https://docs.rs/crate/hyper/1.12.0/source/src/body/chan.rs)
holds one data item, a separate pending error, and optional trailers. This adds a
slot beyond our reader copy. That item can reference shared parser backing storage;
its count alone is not a byte-allocation theorem. Peer metadata is parsed before
our filtering can reject it. Our 100-value/32768-byte header checks bound accepted
name/value bytes, not HeaderMap allocation or URI/parser scratch. The metadata
adapter now detaches allowed header values into bounded copies and consumes original
request/response Parts before awaiting further I/O; a tiny forwarded header cannot
retain a large source owner through that copy. Connection-option storage retains
at most five/six relevant distinct names. See [metadata accounting](http-boundary.md#metadata-ownership-and-allocation)
for inserted credential/Host bytes and excluded serialization/collection storage.

### Serialized head lengths

A root-configured destination is now limited to 8,192 ASCII bytes before secret
loading. Previously, a path could consume nearly the one-MiB config input limit
and be serialized again for each admitted request. The new limit bounds that
amplification while retaining fixed native provider paths. Credential values
remain capped at 8,192 bytes before the optional seven-byte bearer prefix.

For a production POST, let H be configured authority length and P the origin-form
path length. The complete URI limit implies H + P <= 8,192, even with unusually
long numeric port spelling; the DNS hostname limit alone would not establish
this. The following conservative wire-length inventory uses the filtered header
allowlists and Hyper 1.12.0's default serialization:

| Request-head part | Byte allowance |
| --- | ---: |
| Forwarded plus injected header names/values, excluding Host value | 41,007 |
| Separators and CRLF for up to 103 fields | 412 |
| Host value plus request path | 8,192 |
| POST/version/spaces/start-line CRLF | 16 |
| Generated Transfer-Encoding: chunked line | 28 |
| Final CRLF | 2 |
| Total | 49,657 |

Response forwarding retains at most 32,768 name/value bytes and 100 fields. A
128-byte allowance covers Hyper's canonical status line; 37 bytes cover Date,
19 cover Connection: close, and 66 conservatively cover generated framing lines.
Together with separators and the final CRLF, this is at most 33,420 bytes. The
upstream's arbitrary reason phrase is not forwarded: only its StatusCode is kept.
Generated fixed responses have small fixed headers within this allowance.

Both inventories fit 64 KiB. `maximum_configured_request_head_serializes_below_64_kib`
uses the real client serializer with an exact-limit URI, a 253-byte DNS name,
a five-digit port, an 8,192-byte bearer secret, and 100 inbound fields filling the
32 KiB name/value budget. It captures the complete outgoing head, checks the
exact path/credential, and completes the empty streamed exchange. The config
boundary test accepts 8,192 bytes, rejects 8,193, and observes no secret calls
on rejection. These are adapter/source bounds and regressions, not Verus proofs.

Hyper requests an initial 8,192-byte header vector and can grow it while encoding
a larger head. A bound on serialized length does not itself bound Vec spare
capacity, allocator rounding, or overlap between old and replacement allocations.
Those remain explicit backing-storage obligations; body data uses queue mode and
does not extend this header vector during streaming.

### Header collections and parser scratch

The explicit wire-head limit includes the request/status line, field separators,
and terminal CRLF, rather than only the names/values checked by the adapter.
Hyper checks the completed parsed head length before constructing its HeaderMap;
the parser-buffer threshold still governs incomplete heads. The same explicit
limit also applies to chunked trailer parsing, although the gateway rejects
trailers. Socket tests accept exactly 32 KiB/100 fields and reject one byte/field
more on both directions, including a large upstream reason phrase with almost no
header-value content. These checks do not bound backing-buffer capacity or every
transient read allocation.

Pinned `http` 1.5.0 [header/map.rs](https://docs.rs/crate/http/1.5.0/source/src/header/map.rs)
stores an index array, a vector of distinct-name buckets, and a separate vector
for additional values under repeated names. A count of 100 values is therefore
not a count of 100 equal-sized allocations. The following are source-derived
collection slot requests for this gateway, before allocator overhead:

| Map at the inspected boundary | Index slots | Distinct-name bucket capacity request | Additional-value count |
| --- | ---: | ---: | ---: |
| Hyper parsed head, at most 100 fields | At most 256 | At most 192 | At most 99 |
| Newly filtered/injected request map, at most eight distinct names | At most 16 | At most 12 | At most 99 |
| Newly filtered response map, at most six distinct names | At most 16 | At most 12 | At most 99 |

Hyper reserves for the parsed field count. HeaderMap rounds raw capacity to a
power of two and uses three quarters for distinct-name buckets. Its insertion
path reserves before checking whether the name already exists, so appending a
duplicate can grow a six-name map from eight to sixteen index slots. The adaptive
hashing growth thresholds are 128 displaced / 512 shifted entries, beyond these
100-or-fewer-distinct-name maps. This reasoning assumes the parser's cached map
starts empty and only retains capacities from the same bounded head path; it does
not apply to arbitrary externally pre-reserved HeaderMaps.

The extra-value vector grows independently; with the pinned standard Vec growth
and at most 99 extras, its requested capacity is at most 128 elements. Each
private Bucket contains a HeaderName, HeaderValue, hash, and optional link pair;
each ExtraValue contains a HeaderValue and two links. Their ABI sizes, padding,
shared Bytes control blocks, and allocator rounding must be added separately.
Growth can temporarily retain old and new arrays; the final capacities above are
not peak allocation bounds. Hyper may also modify a map after the adapter handoff.

`role.rs` additionally uses two parser scratch arrays of up to 100 elements each:
one of httparse header views, one of header byte-range indices. Their SmallVec
storage and frame/stack placement are separate from the HeaderMap. A noncanonical
response reason phrase has its own copied bytes, now bounded by the wire-head
limit and released with response Parts at the metadata boundary. Header-case
preservation and original-order recording are not enabled in this transport.

These per-map facts advance collection accounting; composing every live/cached
map, parser scratch, and growth overlap across connections and worker cleanup
remains part of the complete allocation inventory. They are source audits, not
Verus proofs of Hyper/http/Vec or a total process-memory ceiling.

## Upstream TLS storage

`HttpsTransport` explicitly sets `set_buffer_limit(Some(65536))` on each rustls
client connection before the handshake, using tokio-rustls `connect_with`.
This preserves the current default while making the intended application-data
policy independent of future default changes.

Rustls [conn.rs](https://docs.rs/crate/rustls/0.23.46/source/src/conn.rs) applies
that limit to pre-handshake application plaintext and queued outgoing TLS records.
It is not a limit on all control/handshake traffic. `send_appdata_encrypt` in
[common_state.rs](https://docs.rs/crate/rustls/0.23.46/source/src/common_state.rs)
charges plaintext against the encrypted queue allowance, so record/cipher overhead
can exceed the threshold. The received-plaintext queue uses a separate 16384-byte
limit; neither is a total TLS heap bound.

The [deframer](https://docs.rs/crate/rustls/0.23.46/source/src/msgs/deframer/buffers.rs)
limits its working vector length to 65535 while joining handshake messages and
18437 for ordinary wire records, with reads grown in steps of up to 4096. These
are working-length limits, not allocator-capacity bounds. Certificate parsing,
verification scratch, decrypted messages, and handshake state need separate
accounting, including overlapping lifetimes.

## Shared TLS session storage

`HttpsTransport` explicitly selects `Resumption::in_memory_sessions(256)` and
sets `enable_early_data` to false. This preserves the pinned library's previous
resumption behavior while making the budget independent of future defaults.
It does not disable TLS resumption or change the no-replay HTTP policy.

In [client/handy.rs](https://docs.rs/crate/rustls/0.23.46/source/src/client/handy.rs),
256 is rounded to **32 server entries**, each holding up to eight TLS 1.3 tickets,
one TLS 1.2 session, and a fixed-size key-exchange hint. Tickets are removed when
used; TLS 1.2 lookup clones the stored session. This storage belongs to the shared
transport, not to one active exchange, and can survive when no requests are live.

[limited_cache.rs](https://docs.rs/crate/rustls/0.23.46/source/src/limited_cache.rs)
maintains the insertion-order keys and map under the cache mutex. It inserts
before evicting, so an insertion can transiently hold **33 server entries**.
It stores server-name keys twice. Production DNS names are at most 253 bytes;
IPv4/IPv6 names have fixed-size representations. Allocation capacity, map buckets,
and temporary caller-owned names are separate from this logical key-byte count.

[Session values](https://docs.rs/crate/rustls/0.23.46/source/src/msgs/persist.rs)
retain ticket bytes, secret bytes, a certificate chain, and fixed-size metadata.
For this TCP transport and pinned ring cipher suites, a conservative subtotal of
these three variable byte contents per cached session is:

- At most 65,535 ticket bytes, parsed with the TLS u16 length field.
- At most 65,536 certificate DER bytes. Certificate lists and TLS 1.3 certificate
  decompression use `CERTIFICATE_MAX_SIZE_LIMIT` in `msgs/handshake.rs`; ordinary
  handshake deframing imposes an additional 65,535-byte message limit. Cached
  chains originate from these checked peer-certificate messages.
- At most 48 secret bytes: the TLS 1.2 master secret is a 48-byte array; TLS 1.3
  ticket secrets use the negotiated SHA-256 or SHA-384 output length with ring.
  QUIC parameters are empty on this TCP path.

Counting all nine sessions independently, even where Arc-backed contents overlap,
gives **32 × 9 × (65,535 + 65,536 + 48) = 37,762,272 bytes** of these variable
contents after a cache operation. Substituting 33 for 32 conservatively covers
entries during insertion before eviction. This is a source-derived payload
subtotal, **not a cache heap bound**: it excludes certificate-entry vectors,
Arc/Weak headers, hash-map/deque storage and spare capacity, session metadata,
allocator overhead, and values held by active connections or awaiting the mutex.
TLS 1.2 clones and taken TLS 1.3 tickets can keep data alive after cache eviction;
the active-connection allocation account must include those owners separately.
The root store, verifier, and client configuration also remain separate.

The real TLS regression test
`tls_session_cache_bounds_servers_and_tickets_without_disabling_resumption` exercises
both TLS 1.2 and TLS 1.3 with the production connector: a second connection resumes,
32 other authenticated server names evict the original entry, and the original
name then performs a full handshake followed by successful resumption again.
The TLS 1.3 provider deliberately issues 24 tickets; when replacement tickets
are disabled, exactly eight subsequent handshakes resume and the ninth is full.
This checks server/ticket eviction and continued functionality, not all retained byte sizes or
adversarial certificate/ticket inputs. Re-audit the source on dependency upgrades.

## Blocking hostname resolution

Tokio 1.54.1's `net/addr.rs` implements hostname resolution with `spawn_blocking`.
Canceling its caller does not bound the lifetime of an already started lookup.
The production [dedicated resolver](dns-resources.md) now owns a fixed worker pool,
separate verified admission credits, and bounded returned address vectors. This
closes the accumulation of detached DNS jobs across request timeouts and removes
DNS from Tokio's shutdown wait, while leaving libc/NSS internal allocations and
termination as explicit dependencies.

## Channel control storage

Payload limits exclude the storage that carries messages and their wakeups. The
following counts apply to the production sequential driver, one server invocation,
one shared logger, and one shared transport. R, C, and Q have the meanings in the
[resource inventory](resource-accounting.md). They count channel allocations by
their surviving owners; they do not add another copy of message payloads.

| Control object | Conservative simultaneous count | Owner argument |
| --- | ---: | --- |
| HTTP fixed-slot channels | C + 2R | Client receivers, client sender cleanup, and provider upload channels |
| HTTP body drain oneshots | C + 2R | One per body channel, including either surviving endpoint |
| Response-head oneshots | C + R | Waiting inbound service futures or surviving worker senders |
| Audit completion oneshots | Q + 1 + R | Encoding/queued jobs, sole active worker, and live request receivers |
| DNS completion oneshots | 32 + R | Credited lookup jobs or live request receivers after result handoff |

Each HTTP channel now has one Arc-backed mutex state containing an inline
`Mailbox<Message>`, with no separate slot allocation. The core proves exact
item identity, full-slot refusal, sender-close preservation, receiver-close
extraction, and permanent closure of both endpoints. The trusted adapter stores at most
two registered wakers and non-cloneable sender/receiver endpoints. Cloning and
retirement occur outside the state lock, as do wake callbacks. Waker replacement
and wake invocation have bounded temporary handles, separate from the two stored
slots; underlying task allocations and arbitrary waker implementations remain
trusted. ABI padding, Arc headers, allocator overhead, and underlying task storage
must still be distinguished from logical payload size.

The prior Tokio mpsc linked-block growth/reuse obligation is removed from this
production path. No semaphore permit or PollSender acquisition future remains.
Closure and capacity checks share the mutex with payload construction, preventing
late sends after receiver destruction. Normal receiver drop clears the slot before
returning; sender-only cleanup retains control storage but no queued payload.
Poisoned storage remains charged until final destruction. See the
[HTTP lifetime audit](http-buffer-lifetimes.md) for races and cancellation evidence.

Tokio's `oneshot::Inner<T>` has one optional result slot, state flags, and sender/
receiver task-waker slots in an Arc allocation. The result's variable storage is
charged to its payload category. A closed receiver does not necessarily destroy
the control allocation while its job still owns the sender, which is why the
counts above include jobs after caller cancellation. DNS delivered address vectors
likewise belong to waiting requests after lookup credit is returned.

The disk queue also uses a verified fixed FIFO: one Q-slot vector plus a
mutex/condvar, with no message blocks or permit futures. See
[audit ownership](audit-buffer-lifetimes.md#verified-fixed-queue-and-synchronization-obligations).
These source-derived object counts still exclude
private ABI sizes, allocator bookkeeping, transient replacement allocations,
and task references retained by wakeups.

## Audit encoding allocation requests

For payload length P, the production encoder has the following storage requests.
The caller's borrowed payload already belongs to the request budget.

| Storage | Request and lifetime | Evidence and limit |
| --- | --- | --- |
| Canonical header scratch | One 33-byte Vec, dropped when `encode_payload` returns | `encode` now uses `Vec::with_capacity(33)`, avoiding repeated geometric growth from an empty vector. Receipt comparison uses the same encoder. |
| Record body and sealed frame | One Vec requested at P + 65 bytes, moved from `RecordBody` into `RecordFrame` | The initial length is P + 33; 32 bytes of spare capacity are reserved for the checksum. Total pushes never exceed the initial request, under standard Vec behavior. |
| Checksum | SHA-256 computation state and 32-byte result | Fixed-size algorithm state is separate from the frame's stored checksum; it is not another payload allocation. Library implementation and stack accounting remain trusted. |

Header scratch and body storage coexist during construction, so requested byte
storage at that stage is P + 98, in addition to the borrowed input. After header
drop, sealing appends the 32-byte checksum into the existing reserve. Moving a
Vec through the queue, journal, and completion channel does not clone its payload;
control-object and receipt lifetimes are accounted separately.

`record_encoding_reserves_exact_capacity_and_sealing_reuses_the_allocation`
checks zero, small alignment boundaries, page-size boundaries, 64 KiB, and 1 MiB
payloads. It checks actual reported Vec capacities, exact bytes, and unchanged
allocation address across sealing. These are regressions for the supported Rust
and allocator targets, not a Verus allocator theorem: vstd's Vec specification
models contents, not backing capacity. Allocator size classes, bookkeeping,
fragmentation, and physical pages remain outside this request inventory.

## Dedicated thread stacks

The audit worker explicitly requests a 2 MiB stack, independent of the
`RUST_MIN_STACK` environment default. Together with four resolver workers that
also request 2 MiB each, one executable instance requests 10 MiB of background
thread stacks. The executable's Tokio runtime uses the main thread; its stack,
OS guards/rounding, committed pages, TLS/thread-local state, and kernel thread
objects are additional. Requested stack reservation is not RSS or a verified
bound on recursive execution. Library callers supplying a multithreaded runtime
or additional gateway instances must add those resources separately.

## Remaining closure work

The bounded counts above help identify retained allocations but cannot be summed
as a proven RSS ceiling. Still needed are backing-capacity/lifetime bounds for
Hyper parser/output storage, TLS handshake state and the cache metadata/active owners excluded above, task/channel nodes,
configuration and credential storage, allocator/thread overhead, and kernel socket
buffers. Source-level inspection and isolated process measurements must distinguish
these from the verified logical payload budget. The current milestone remains open;
this audit does not replace the async ownership-composition obligation.
