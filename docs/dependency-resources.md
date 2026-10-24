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

The server can additionally generate a 25-byte `100 Continue` head when the
client supplies `Expect: 100-continue`. In `conn.rs::poll_read_body`, the
`Reading::Continue` branch appends it only while writing is still in `Init`, then
changes reading to `Body` before recurring. Thus it occurs at most once for the
single request on a production connection. Budget it even if it has not drained
before final-head encoding: the combined server-head allowance is 33,445 bytes.
Provider informational responses are not forwarded as output heads; the client
decoder skips them and no informational callback is installed.

Both inventories fit 64 KiB. `maximum_configured_request_head_serializes_below_64_kib`
uses the real client serializer with an exact-limit URI, a 253-byte DNS name,
a five-digit port, an 8,192-byte bearer secret, and 100 inbound fields filling the
32 KiB name/value budget. It captures the complete outgoing head, checks the
exact path/credential, and completes the empty streamed exchange. The config
boundary test accepts 8,192 bytes, rejects 8,193, and observes no secret calls
on rejection. These are adapter/source bounds and regressions, not Verus proofs.

`maximum_response_head_with_continue_serializes_below_64_kib` exercises the real
server serializer with 100 filtered response fields filling the 32 KiB metadata
budget. The client waits for the exact interim response before sending its body;
the test checks that all 100 final fields survive and that the total interim/final
wire length fits 33,445 bytes. This tests the protocol path and length inventory,
not simultaneous internal-buffer occupancy or allocation capacity.

### Serialized head reservation requests

The pinned `role.rs` encoders call `reserve(30 + 30 * header_count)` before
encoding. The client calls `set_length` first, which can add one framing field:
103 application fields plus one generated field therefore request at most 3,150
additional bytes. The server's 100 application fields request at most 3,030;
including a retained interim head, the required length is at most 3,055. Its
additional Date reservation is 37 bytes, covered by the remaining final-head
inventory (the subsequent Date line and terminal CRLF occupy 39 bytes).
Default lowercase writers and `FastWrite` append actual slices; they do not
reserve an arbitrary URI formatting estimate. Under these production paths,
every header-vector required length (`len + additional`) remains below 64 KiB.

Fully consumed headers call `Cursor::reset`, which clears length but preserves
capacity; partially consumed headers retain their original vector length. The
interim-head allowance covers that retained prefix. One exchange per connection,
no server keep-alive, no pipelined flush aggregation, and queue-only body output
are essential to this reservation inventory. It is not a general Hyper bound.

### Header-vector backing capacity

The Rust 1.99.1 `rust-src` component supplies the next step of this audit:
`library/alloc/src/raw_vec/mod.rs::{grow_amortized,set_ptr_and_cap}` requests
`max(2 * old_capacity, required_capacity, minimum_capacity)` and records that
requested capacity. For byte vectors the minimum is eight. Slice extension in
`vec/spec_extend.rs` uses `append_elements`, reserving the actual appended count.
`alloc/src/alloc.rs::Global::grow_impl_runtime` passes the new layout size to
reallocation. These are pinned implementation facts, not stable Vec API promises.

Hyper starts its header vector at 8,192 bytes. Let M = 65,536, the conservative
upper bound on every required length established above. A growth occurs only
when old capacity C is below the required length, so C < M. The new capacity is
at most 2M. Once capacity reaches M, no further growth is needed on these paths.
Thus each writer retains at most 131,072 requested header-vector bytes, including
spare capacity. A replacement can overlap an old allocation below M and a new
allocation at most 2M: allow 196,608 requested bytes during that operation.
Do not add both the retained and replacement allowances for the same writer.

These bounds exclude allocator size-class rounding, allocator-internal scratch,
freed-memory caching, and OS mappings. They do not guarantee successful allocation
or bound RSS. The existing wire regressions validate the serializer inputs, not
the private Vec capacity. No Verus claim is made about Hyper, Vec, or the allocator.

### Parser backing allocation requests

For the read side let M = 32,768. All production paths into
`Buffered::poll_read_from_io` start with visible length L < M: head parsing checks
the threshold first, `MemRead::read_mem` reads only when empty, and the idle/EOF
and notification paths likewise check emptiness. It reserves additional A with
L + A <= M. The plaintext adapter limits each completed read to M bytes, so the
visible length after a read is less than 2M even if spare capacity is larger.
Splitting/advancing can leave an offset into a larger backing vector; visible
length alone is therefore insufficient for its allocation bound.

Inspection of bytes 1.12.1 `bytes_mut.rs::reserve_inner` gives a backing-vector
capacity bound of 4M = 131,072 requested bytes per allocation, using the pinned
Vec growth rule above. For a uniquely owned vector with backing capacity B and
offset O, a reservation that needs allocation has two cases:

- If O < L, the underlying required length O + L + A is less than 2M.
- If O >= L, bytes reclaims the prefix whenever B >= L + A. Allocation in this
  case therefore implies B < M, and O + L + A is again less than 2M.

In either case growth is unnecessary once B >= 2M; when growth is necessary,
doubling B and the underlying required length are at most 4M. The same reasoning
applies to the uniquely owned shared-vector branch, including its explicit
doubling. With multiple owners, bytes allocates a replacement of
`max(L + A, original_capacity)`. Its original-capacity representation rounds
down and caps at 65,536, so this branch requests at most 2M. The initial empty
buffer and first reserve satisfy the bound.

Unique-vector reallocation can overlap an old allocation below 2M and a new
allocation at most 4M: allow 6M = 196,608 requested bytes for that operation.
Shared replacement instead retains old allocations through outstanding header
or body views. **This per-allocation bound does not bound their count or sum.**
Composition must count distinct live backing owners, shared control blocks,
detached application copies, and canceled-task tails; allocator overhead remains
excluded. Recheck every read call site and bytes/Vec growth branch on upgrades.

### Live parser backing owners

For one production HTTP/1 exchange, the following locations can hold distinct
allocations originating in `Buffered::read_buf`. Several locations often share
one allocation; charging them independently is conservative.

| Location | Maximum distinct parser allocations | Lifetime |
| --- | ---: | --- |
| Current parser buffer | 1 | Connection driver, including its cleanup tail |
| Parsed request/response head | 1 | Original Parts until the consuming metadata boundary completes |
| Incoming-body channel item or producer's decoded data frame | 1 | Delivery, rejection, or final channel destruction |
| Reader's transient input data | 1 | Synchronous bounded copy; released before that poll returns |

`role.rs` splits a complete head from one contiguous read buffer. Its retained
HeaderValue slices all refer to that allocation; field count does not multiply
parser backing owners. Request URI/response reason-phrase copies and collection
storage are separate categories. Production disables header-case/order extensions
and installs no informational-response callback; skipped 1xx heads drop before
the next parse iteration. Only one final head is delivered per connection.

Hyper's `body/chan.rs` has one `item` slot. The sole producer in
`dispatch.rs::poll_read` checks `poll_ready` before decoding the next frame and
moves that frame into `try_send_data`; there is no independent producer backlog.
Once the reader takes a frame, the producer may fill the slot again while the
reader copies. Both must be charged. Our Reader retains only its detached copy
after the poll, and never stores the source frame across an await. Decoder trailer
assembly copies bytes into a separate buffer; it does not retain prior data
frames or parser slices. Trailer storage/metadata remain separate obligations.

Receiver cancellation does **not** immediately release Hyper's queued item:
`Receiver::drop` marks it closed but does not take `state.item`. An outstanding
sender can therefore keep the item alive until it is dropped. The producer checks
receiver closure before another decode; a cancellation racing a decode returns
the rejected frame for local destruction. Keep the channel item charged through
this tail, even after the application has released its request slot. This differs
from our outgoing mailbox, whose receiver drop extracts its pending item.

These four locations give a conservative 512 KiB of requested parser backing
capacity per live exchange, using the per-allocation bound above. During a
replacement, charge the other three locations at 128 KiB each and old/new parser
storage together at 192 KiB: 576 KiB. In the shared-replacement branch the new
allocation is at most 64 KiB; in the unique branch the old allocation is below
64 KiB. This also covers overlap rather than silently reclaiming the old buffer.

This is a trusted source/ownership argument for this adapter, not a Verus theorem
or a per-connection total-memory bound. It excludes detached Reader copies,
trailer buffers/maps, errors, metadata/control objects, allocator internals, TLS,
and other HTTP output storage. Do not multiply it solely by active request count:
inbound connections and canceled connection/channel tails have separate lifetimes.
It assumes no arbitrary user extension retains additional raw Incoming frames.

`incoming_body_read_ahead_stays_bounded_with_a_slow_reader` keeps the original
response header alive, offers a two-MiB eager body, repeatedly polls the actual
driver with renewed cooperative budgets, and consumes one byte per round.
Read-ahead reaches a plateau while the detached remainder is occupied; the test
also checks exact bytes and destruction of the I/O owner on cancellation. This
measures read-ahead and task destruction, **not** private allocation identities or
heap capacity. The separate tracked-owner Reader test checks immediate release
of a large source owner after copying a small visible frame.

### Header collections and parser scratch

#### Rejected trailer storage

Rejecting trailer frames in our Reader does not avoid Hyper's prior parsing
allocations. `decode.rs` assembles trailers in a separate `BytesMut`, starting
with capacity 64. Each following byte is appended before the length check;
reaching 32,768 bytes returns an error, so successful trailer blocks are strictly
smaller than that limit. No more than 100 trailer fields reach `decode_trailers`.
The buffer is neither split nor shared during assembly. `BufMut::put_u8` reaches
`BytesMut::chunk_mut`, which reserves 64 when full; with the pinned Vec policy
its capacities double from 64 through at most 32,768. Allow 49,152 requested
bytes during the largest old/new replacement, excluding allocator overhead.

During decoding, that assembly buffer overlaps a scratch vector of at most 100
httparse header views and a newly built HeaderMap. Names and values are copied
from the assembly buffer, with combined logical contents below 32 KiB; apply the
parsed-map collection inventory below separately. The assembly and scratch
vectors drop when decoding returns. The resulting trailer map can then occupy
Hyper's separate channel `trailers` slot until delivered/rejected or the final
channel owner drops. Receiver drop alone does not clear this slot either.
Malformed-header diagnostic formatting is additional error storage, not included
in the payload or assembly-capacity allowance.

`incoming_trailer_parser_enforces_byte_and_field_limits` uses a real queued
client connection and raw chunked responses: 32,767 trailer bytes and 100 fields
are delivered by Hyper, while 32,768 bytes and 101 fields produce body errors
before a trailer map is delivered. The existing Reader test independently rejects
delivered trailer frames. Neither test measures private allocator capacity.

#### Head and trailer maps

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

### TLS deframer backing capacity

The TCP `ConnectionCommon::read_tls` path calls
`DeframerVecBuffer::read` / `prepare_read`. It exposes only the initialized
`buf[used..]` slice to the reader. Resizing requests at most 65,535 bytes, growing
in steps of up to 4,096; ordinary record buffering uses the smaller 18,437-byte
limit. `discard` moves retained bytes within this same vector rather than creating
shared views. The unconstrained `DeframerVecBuffer::extend` path is used by QUIC,
which this transport does not enable.

Using the pinned Rust Vec growth policy audited above, one deframer retains at
most 128 KiB of requested capacity. Growth can overlap an old capacity below
64 KiB with a new capacity below 128 KiB; shrink can overlap an old capacity at
most 128 KiB with a new request below 64 KiB. Budget 192 KiB during either
replacement. Shrinking the vector's length alone is not counted as freeing its
capacity. Allocator rounding, internal reallocation scratch, and retained freed
pages are excluded. The deframer has one owner in the client TLS connection;
handshake payloads copied into owned messages are additional allocations.

`HandshakeDeframer::coalesce` independently rejects declared handshake payloads
larger than 65,535 before needing their full contents. The raw-peer regression
`oversized_handshake_is_rejected_from_its_length_before_upload` sends only the
four-byte ServerHello handshake header and keeps the socket open. A declared
65,536-byte payload yields `TransportError::Tls`; the 65,535-byte incomplete
control instead waits until the configured exchange timeout. Both leave the
request body unread, produce no audit/body/status output, and release admission.
This tests the real connector's early rejection and cleanup, not heap capacity.

These bounds cover only the deframer's byte vector. Its handshake span vector,
owned decoded messages, certificate verification, session values,
and TLS application/control queues still require separate composition. They do
not turn the 64 KiB application buffer setting into a total TLS-memory bound.

### HelloRetryRequest cookie storage

A TLS 1.3 server may answer the first ClientHello with a HelloRetryRequest that
carries a stateless cookie. The pinned client
([client/hs.rs](https://docs.rs/crate/rustls/0.23.46/source/src/client/hs.rs)
`handle_hello_retry_request` and `emit_client_hello_for_retry`) accepts any
non-empty cookie that fits the 65,535-byte handshake-message limit and echoes it
in the second ClientHello. The state after a retry accepts only a ServerHello, so
one connection echoes at most one cookie. For a cookie of C bytes, source
inspection finds these copies beyond the deframer's working vector:

| Copy | Lifetime |
| --- | --- |
| Decoded `PayloadU16` cookie; `msgs/base.rs` copies the sub-slice into a Vec | Until the retry handler returns |
| Cookie clone inside the retry ClientHello extensions | Until the second hello is encoded |
| Encoded second ClientHello; `MessagePayload::handshake` encodes eagerly | Until the message is fragmented and dropped |
| Transcript buffer: 36-byte message_hash, the HelloRetryRequest encoding, and the second ClientHello encoding | Until the ServerHello selects the hash in `ExpectServerHello` |
| Per-record plaintext copies from `to_unencrypted_opaque`, exact `PrefixedPayload` capacity, 16,384-byte fragments | Queued in `sendable_tls` until written to the socket |

At peak this is about six cookie-sized copies plus the deframer; after the
handler returns, about three (two transcript copies and the queued records)
remain until the ServerHello arrives or the exchange deadline fires. The
transcript buffer grows with `extend_from_slice`, so its capacity follows the
audited Vec growth policy rather than its content length. With the fixture's
134-byte extension list, the largest cookie that fits is 65,395 bytes: the
HelloRetryRequest is 65,483 bytes and the second ClientHello 65,632 bytes.
Longer configured server names reduce the fitting cookie by the same amount.
Handshake output uses `ChunkVecBuffer::append`, not `append_limited_copy`, so
`set_buffer_limit` does not cap the queued second hello.

`LengthPrefixedBuffer::drop` in `msgs/codec.rs` checks the u16 extension-list
length only with `debug_assert!`. A cookie one byte beyond the fit therefore
panics inside `process_new_packets` in debug builds, including `cargo test`,
while release builds emit a ClientHello whose extension-length field wraps to
zero; a conforming server rejects it. Neither case stores more than the copies
above. A debug panic unwinds the connection task, whose credits are released by
owner drop and whose registry poison behavior is tested separately; the
production binary uses the release profile.

`tls_retry_cookie_echo_is_bounded_by_the_client_hello_extension_field` checks the
largest fitting cookie is echoed exactly, that the queued output exceeds the
64 KiB application limit, and the overflow branch for the active build profile.
The release branch was validated locally with `cargo test --release` on
2026-10-23; CI exercises the debug branch.
`retry_cookie_is_echoed_above_the_buffer_limit_and_closure_fails_before_upload`
drives the production connector with a raw peer: the peer receives the echoed
cookie in a hello above 64 KiB, then closes without a ServerHello. The exchange
returns `TransportError::Tls`, leaves the request body unread, produces no
output or audit bytes, and releases admission. Key-share changes with a new key
exchange, ECH, PSK binders, and the transcript Vec capacity are not measured by
these tests.

### Certificate parsing metadata and compression policy

The production ClientConfig explicitly clears `cert_decompressors`. Current
Cargo features already enable rustls std/ring/tls12 without brotli or zlib, but
the explicit policy remains in force if dependency feature unification changes.
The ClientHello omits certificate-compression algorithms when this list is empty;
`tls13.rs` rejects a peer-selected unoffered algorithm before allocating its
decompression output buffer or calling a codec. Standard uncompressed certificate
chains remain supported. This is independent of opaque HTTP body forwarding.

The 65,536-byte certificate-list limit is not a certificate-entry allocation
limit. `msgs/codec.rs` checks the length-prefixed sub-reader before pushing parsed
entries into a Vec. `CertificateDer::read` consumes at least its three-byte length
prefix, even for an empty DER value; TLS 1.3 `CertificateEntry::read` additionally
consumes at least the two-byte extension-list prefix. Thus the list bound implies:

| Parsed list | Maximum entry count from wire length | Vec capacity request under pinned growth | Old/new array overlap, elements |
| --- | ---: | ---: | ---: |
| TLS 1.2 CertificateChain | 21,845 | 32,768 | 49,152 |
| TLS 1.3 CertificateEntry list | 13,107 | 16,384 | 24,576 |

These are deliberately conservative: the handshake-size limit and a valid leaf
certificate reduce the realizable counts. Empty or malformed certificates can
still occupy entries before later validation fails. Each slot is a certificate
descriptor (plus extensions in TLS 1.3), not a single byte. Multiply by the
appropriate pinned ABI size when composing allocation bytes. Parsed DER views,
owned-chain conversions/clones, extension payloads, and verifier intermediates
can overlap these arrays; this table is not their combined heap bound. Codec
parsing and Vec capacity remain trusted source facts, not Verus proofs.

### Certificate-verifier scratch and diagnostics

The pinned rustls-webpki 0.103.16 verifier borrows the peer's DER when constructing
`Cert` descriptors. `PartialPath` stores six optional intermediate descriptors in
a fixed array plus a reference to the end entity. It rejects pushing a seventh
intermediate. This bounds the selected path, not the number of supplied candidate
certificates or all parser/signature-verifier scratch.

Its per-verification `Budget` allows 100 signature checks, 200,000 path-building
calls, and 250,000 name-constraint comparisons, returning errors when depleted.
These are algorithm counters, not wall-clock deadlines or memory-byte bounds.
Production supplies no CRLs, so rustls's collected CRL-reference vector is empty;
the built-in roots and supported signature-algorithm list are configuration data.

Failure diagnostics allocate too. With the enabled alloc feature,
`KeyUsage::validate` accumulates presented, nonmatching EKU OIDs in a
`Vec<Vec<usize>>`; rustls maps that error to `InvalidPurposeContext`, retaining
the presented purposes. The transport eventually maps it to `TransportError::Tls`
and drops the detailed error, but its transient allocations still count.
For a certificate with at most D = 65,536 DER bytes, each parsed OID consumes at
least two tag/length bytes (do not assume its content is nonempty), so there can
be at most 32,768 entries. A nonempty OID with L content bytes decodes to at most
L + 1 integer components; an empty one decodes to none. Thus the total decoded
component count is at most D. The original pushed outer vector requests at most
32,768 descriptor slots, while its inner vectors together request at most 2D
usize slots under the pinned doubling/minimum-capacity policy. Descriptor sizes,
conversion overlap, other certificate errors, and simultaneously retained path
errors must still be added before claiming a verifier heap bound.

`trusted_certificate_with_large_wrong_purpose_list_is_rejected_before_upload`
uses a trusted self-signed localhost certificate with either one or 4,096 wrong
purpose OIDs. Both handshakes fail before reading the request body, emit no audit
or response data, and release admission. This exercises diagnostic construction
and cleanup; it does not measure its private allocations or certify worst-case
verification latency.

TLS verification runs synchronously within the connector's poll. The executable
uses a current-thread Tokio runtime, so a long verification poll can delay other
requests and health checks. Tokio timeout cannot preempt that synchronous work.
CPU isolation or a demonstrated worst-case scheduling bound remains availability
work; these source budgets must not be described as proving deadline enforcement.

### Control traffic is not covered by the application buffer limit

In `common_state.rs`, ordinary application encryption consults the sendable-byte
limit, but `queue_tls_message` appends encoded control records directly.
`ChunkVecBuffer::append` does not enforce its configured byte limit itself.
Therefore the 64 KiB application setting cannot be used as a bound for all
outgoing TLS records or their descriptor storage.

The pinned `TemperCounters` admits at most 32 consecutive peer key-update
messages, four warning alerts, one renegotiation request, and two TLS 1.3
middlebox ChangeCipherSpec messages. The key-update allowance resets when
application data is received, including an empty application payload; it is not
a connection-lifetime traffic allowance. These other counters do not reset there.

Key-update replies have a separate `Option<Vec<u8>>` slot. While occupied,
another request does not generate a second pending notification. For the pinned
ring TLS 1.3 suites its encoded record contains 27 bytes: five handshake bytes,
one inner content type, sixteen authentication-tag bytes, and five record-header
bytes. This is logical encoded length, not total allocation capacity.
`perhaps_write_key_update` moves that notification into `sendable_tls`, including
before `buffer_plaintext` checks application capacity. The pending slot then
becomes reusable. A single pending slot consequently does not establish a
one-record bound for notifications already transferred to the output queue.

`tls_key_update_burst_limit_rejects_without_response_or_replay` uses a real TLS
1.3 provider to emit 32 or 33 key updates without intervening application data.
At 32 the gateway forwards and audits the exact subsequent response; at 33 it
fails before response headers/body, releases admission, and opens no second
provider connection during the observation window. This validates the burst
counter, not a global control-buffer ceiling. A complete queue bound still needs
the application's read/write interleavings, backpressure, queued record owners,
and counter-reset behavior; alternating control and application traffic must not
be justified by the consecutive-burst test alone.

The dependency-level regression
`tls_control_replies_can_exceed_application_buffer_limit` makes this limitation
concrete using authenticated TLS 1.3 client/server connections. After filling the
client's 65,536-byte application allowance, it stops draining client ciphertext.
For 3,000 rounds the server sends a key update followed by one application byte;
the client consumes that byte and attempts another application write. Every
attempt accepts zero application bytes, yet moves a pending key-update reply
into the ciphertext queue. The observed queued length increases by exactly
81,000 bytes (3,000 times 27), exceeding twice the configured limit.

This is a counterexample to treating the rustls application setting as a total
ciphertext-queue bound. It is not a production gateway exploit: the fixture
explicitly schedules reads and writes, without Hyper or tokio-rustls. The next
obligation is to establish whether production polling and body backpressure
permit equivalent repeated interleavings, including empty peer application
records, or enforce an explicit queue bound at the TLS adapter. The consecutive
key-update counter alone cannot discharge that obligation.

The production HTTP transport now wraps the established TLS stream in
`DrainBeforeWrite`. Both scalar and vectored plaintext writes first poll the
TLS stream's flush and propagate pending/error without invoking its writer.
In pinned tokio-rustls, flush drains `sendable_tls` without transferring the
pending key-update slot. Thus a blocked ciphertext drain prevents successive
plaintext-write calls from moving additional replies into that queue. Reads
remain available while writes are blocked, preserving full-duplex progress.
The adapter retains vectored writes and does not allocate a staging buffer.

The adapter test covers repeated stalled scalar/vectored attempts, concurrent
read progress, successful resumption, and flush-error propagation. Existing
real TLS exchange tests exercise its production placement. This closes the
specific repeated-write enqueue path demonstrated above, not the full TLS heap
accounting obligation: direct control appends during reads, handshake state,
record capacities/overhead, and maximum transient allocations still need
composition.

`tls_drain_guard_holds_control_queue_stable_and_resumes_exact_bytes` exercises
this wrapper around real tokio-rustls TLS 1.3 over loopback TCP. A synthetic
write gate below TLS stops all outgoing ciphertext after handshake while the
client holds a full application buffer. Across 3,000 peer key-update/data
rounds, alternating scalar and vectored write polls remain pending and the
queued ciphertext length stays exactly at its initial value. Reads continue.
Opening the gate delivers the complete original 65,536 bytes followed by the
new byte, and leaves zero queued ciphertext. This validates the guarded
interleaving and recovery without depending on OS socket-buffer saturation;
it does not enumerate all TLS control paths or prove an allocation bound.

### Application-write record subtotal

For an established connection with the production default fragment size,
`MessageFragmenter::Chunker` splits the logical payload at 16,384 bytes even
when the input consists of many `IoSlice`s. A single ordinary
`send_appdata_encrypt` call accepts at most 65,536 plaintext bytes, hence creates
at most four application records. It subtracts existing queued ciphertext from
the allowance before accepting plaintext. Pinned ring record overhead, including
the five-byte TLS header, is 22 bytes for TLS 1.3, 29 for TLS 1.2 AES-GCM, and
21 for TLS 1.2 ChaCha20-Poly1305. If the queue starts at or below the allowance, ordinary application encryption
cannot take its logical bytes above 65,652 (65,536 plus four times 29). If it
already exceeds the allowance, the call accepts no further application bytes.
This subtotal excludes control records appended outside that call.

`tls_application_write_fragment_overhead_is_bounded_for_pinned_suites` checks
six suites (all three TLS 1.3 suites and the three ECDSA-authenticated TLS 1.2
suites) with scalar input and 65,537 one-byte vectored slices. Each case accepts
65,536 bytes, emits exactly four records with the expected cipher overhead,
and decrypts to the exact accepted prefix. The fixture certificate is ECDSA;
RSA-authenticated TLS 1.2 suites use the same record ciphers but are not separately
exercised by this test.

For automatic refresh, `send_plaintext` can call `buffer_plaintext` again after
`maybe_refresh_traffic_keys`; it is not just one ordinary encryption call.
`send_appdata_encrypt` stops at a record boundary before the key-limit record,
then the key schedule emits a 27-byte request, installs fresh keys, and clears
the refresh flag. Pinned ring TCP confidentiality limits are at least 2^24
records, much larger than one four-record application batch. At most one such
refresh is needed within that batch; splitting at a fragment boundary does not
create an extra partial application fragment. Subsequent application acceptance
rechecks available ciphertext capacity, including the update already queued.
For an initially empty output queue without a pending reply, a conservative
TLS 1.3 buffered-write subtotal is 65,651 logical bytes: 65,536 plaintext, four
22-byte application-record overheads, and one 27-byte automatic request.

`tls_automatic_refresh_bounds_records_at_each_batch_boundary` exercises the
actual buffered writer and key schedule with real AES-GCM, lowering only the
test suite's confidentiality limit to eight records. All eight starting positions
are checked before a 65,537-byte input write. Each accepts at most 65,536 bytes,
produces at most four application records and one key-update record, matches the
exact byte accounting, and decrypts to the exact accepted prefix. Several cases
cross the refresh boundary. Production cipher limits are unchanged. The test
validates the low-threshold mechanism; the pinned-source argument relates that
mechanism to production limits. Neither this test nor the subtotal accounts for
pending-reply/control overlap, handshake output, Vec capacities, descriptor
storage, allocator overhead, or total TLS heap.

### Outgoing record allocation and vectored scratch

The pinned ring TLS 1.2 AES-GCM/ChaCha and TLS 1.3 encrypters allocate a
`PrefixedPayload` sized to the final ciphertext payload plus the five-byte
record header. Plaintext is copied from borrowed fragments into that allocation
and encrypted in place. Nonce/inner-type/tag appends fit the original reservation.
`OutboundOpaqueMessage::encode` writes into the reserved header and moves the
same Vec; `queue_tls_message` and `ChunkVecBuffer::append` move it again without
copying record bytes. Thus those paths do not require an additional full-record
copy or geometric growth of each ciphertext vector. Requested record capacity
matches final encoded length under the pinned allocation model; allocator
rounding and cryptographic key/scratch objects remain separate.

`tls_record_encoding_reuses_exact_sized_encryption_allocation` checks TLS 1.3
AES-256-GCM and ChaCha20-Poly1305 with payload lengths 0, 1, 5, 16,383, and
16,384, represented by one-byte slices. It verifies exact Vec capacity and that
encoding retains the original allocation address. This is pinned-dependency
regression evidence, not a portability guarantee about arbitrary allocators.
TLS 1.2 and AES-128 follow the audited analogous source paths but are not
separately covered by this allocation-address test.

Hyper passes at most 64 `IoSlice`s per queued vectored call. Rustls's
`PlaintextSink::write_vectored` collects the borrowed slice references into a
`Vec<&[u8]>` for two or more slices. The pinned exact-size collection path requests
at most 64 fat-pointer entries (1,024 bytes on the supported 64-bit ABI).
`OutboundChunks` borrows those references and does not clone their payloads.
The Vec exists only during that synchronous writer call. Hyper and rustls each
also use a 64-entry `IoSlice` stack array, and these can overlap during the nested
write; count both (2,048 bytes on the same ABI), separately from heap storage and
other stack frames. The test with 65,537 slices deliberately bypasses Hyper and
therefore does not represent production descriptor usage.

`ChunkVecBuffer::len` subtracts `prefix_used`, while its first Vec keeps the
entire original allocation until `consume` pops that record. Consequently a
bound on remaining ciphertext bytes needs an additional consumed-prefix
allowance of up to one original record (conservatively 16,413 bytes for the
pinned default fragment size and ring suites) when bounding retained record
allocations. The drain-before-write guard empties old records before new
application writes, but read-side alerts can still overlap a partly sent front
record. VecDeque descriptor capacity and replacement overlap depend on the
maximum simultaneous record count over the whole connection, including its
handshake; those are still required for the total allocation bound.

### Established-connection control paths

The remaining read-side paths must be separated from plaintext writes. In the
pinned TCP client state machines, the post-handshake branches are:

| Incoming event | Output effect and limiting mechanism |
| --- | --- |
| TLS 1.3 application data | Stores plaintext and resets the consecutive key-update counter; emits no control response. |
| TLS 1.3 NewSessionTicket | Inserts a session in the bounded shared cache; emits no response. Ticket parsing/insertion allocations remain accounted separately. |
| TLS 1.3 KeyUpdate | May populate the single pending notification slot. `should_update_key` refuses to create another notification while that slot is occupied; this does not by itself limit already queued records. |
| TLS 1.2 application data | Stores plaintext; emits no control response. |
| TLS 1.2 HelloRequest | `process_main_protocol` checks the one-request renegotiation allowance before emitting `NoRenegotiation`. A second request errors before another warning is emitted. |
| Peer close notification | `process_alert` marks received closure without emitting a reply. `process_new_packets` stops processing subsequent records after closure. Local shutdown is a separate path. |
| Accepted peer warning | Consumes the four-warning allowance and emits no reply. Disallowed TLS 1.3 warnings may instead generate a fatal alert. |
| Malformed/unexpected message | May enqueue a fatal alert; `process_new_packets` stores its error state. Subsequent calls return the stored error without reprocessing messages. |

Source anchors are `client/tls13.rs::ExpectTraffic`,
`client/tls12.rs::ExpectTraffic`, `CommonState::process_main_protocol`,
`CommonState::process_alert`, and `ConnectionCore::process_new_packets`.
In particular, `queue_tls_message` first transfers a pending key-update reply,
so a fatal alert can add both that reply and its own record while output is
stalled. The guard does not promise that read polls never grow the output queue.

The record-layer read sequence soft limit can also call `send_close_notify`
before decrypting a record (`conn.rs` deframing path). This is another read-side
control source, even though reaching it is impractical in the fixture.
Local `send_close_notify` suppresses duplicate close notifications using
`sent_fatal_alert`; tokio-rustls shutdown invokes it separately from reads.
Automatic traffic-key refresh also has a separate output path:
`ConnectionCommon::send_plaintext` invokes `maybe_refresh_traffic_keys`, which
can emit a key-update request between application records. The gateway does not
call manual refresh, but automatic refresh cannot be omitted from accounting.
These finite state-machine paths narrow the remaining queue composition work;
they are a source audit, not a proved sum of capacities. Initial handshake output,
automatic refresh, alert/reply overlap, fragment storage and descriptor growth
still need a combined bound before declaring TLS allocation accounting complete.

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
- At most 65,536 certificate DER bytes. Certificate lists use
  `CERTIFICATE_MAX_SIZE_LIMIT` in `msgs/handshake.rs`; ordinary
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

### Active session owners

`client/hs.rs::ClientSessionValue::retrieve` selects one TLS 1.3 ticket, or one
TLS 1.2 session if no ticket is available. Retrieval runs once when constructing
the initial ClientHello input; later handshake states move that optional value
or borrow it. TLS 1.3 retrieval removes the value from the cache. TLS 1.2 retrieval
clones it: its ticket and certificate chain use Arc ownership, while its secret
has owned copied bytes. Either kind can therefore outlive the cache entry.

`tls12.rs::ExpectFinished::save_session` and
`tls13.rs::ExpectTraffic::handle_new_ticket_impl` construct one new session value
and synchronously transfer it into the store. Budget that value even while its
thread waits for the cache mutex; it is not yet covered by the cache's slot count.
TLS 1.2 can still hold its retrieved session while constructing the replacement.
There is no queue of these callbacks per connection: the connection state machine
processes them serially. Conservatively charge two session values per active TLS
connection (one retrieved, one being constructed/inserted), without assuming
shared ticket/certificate contents reduce the total.

For one production transport with at most R admitted exchanges, these session
values contribute at most `2 * R * 131119` logical bytes of ticket, certificate
DER, and secret contents. Including the cache's conservative insertion peak gives
`(33 * 9 + 2 * R) * 131119` bytes **for these three contents only**. The timed
network future borrows its outer request owner, so its TLS session cleanup occurs
before that admission credit is returned. Custom connector use outside this
production admission path must supply its own live-connection count.

This is not a TLS heap bound. It excludes the connection's own authenticated
peer-certificate chain, encoded ClientHello/ticket copies, parsed handshake
messages, key schedules, certificate verification scratch, collection capacities,
Arc/Weak control blocks, and allocator overhead. Cache eviction is not treated as
destruction of active-session data. Each additional transport has its own cache.

The real TLS regression test
`tls_session_cache_bounds_servers_and_tickets_without_disabling_resumption` exercises
both TLS 1.2 and TLS 1.3 with the production connector: a second connection resumes,
32 other authenticated server names evict the original entry, and the original
name then performs a full handshake followed by successful resumption again.
The TLS 1.3 provider deliberately issues 24 tickets; when replacement tickets
are disabled, exactly eight subsequent handshakes resume and the ninth is full.
The fixture also holds a resumed connection open while 32 other authenticated
names evict its entry, then checks that its peer certificates and exact application
bytes remain usable. The test server retains 4,096 sessions so server-side
eviction does not invalidate tickets read late from that held connection; the
production client cache remains unchanged. This checks server/ticket eviction,
active-connection survival, and continued functionality, not all retained byte sizes or
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
