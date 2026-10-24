# Dependency resource audit

Source inspection on 2026-10-23 of the versions in Cargo.lock: Hyper 1.12.0,
rustls 0.23.46, and tokio-rustls 0.26.6. These are trusted implementation facts,
not Verus proofs or whole-process allocation ceilings. Recheck them on upgrades.
The [resource inventory](resource-accounting.md) separately accounts for our own
buffers and the number of live connections and requests.

## HTTP/1 storage

Both production builders explicitly set `max_buf_size(32768)`,
`max_header_size(32768)`, and `max_headers(100)`; the inbound builder disables
keep-alive. The upstream performs one exchange
per connection. Neither enables pipelined flush aggregation.

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

Flatten mode has another distinction. `Cursor<Vec<u8>>::maybe_unshift` removes
consumed prefix bytes only when spare capacity cannot fit the next encoded frame.
The vector can therefore retain already-written bytes alongside remaining output;
its length need not equal `WriteBuf::remaining()`. Capacity survives clearing,
and vector growth can overlap old and new allocations. A complete backing-storage
bound must account for initial capacity, largest serialized head, growth and
compaction, rather than multiplying the pending-byte threshold by connections.

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

## Remaining closure work

The bounded counts above help identify retained allocations but cannot be summed
as a proven RSS ceiling. Still needed are backing-capacity/lifetime bounds for
Hyper parser/output storage, TLS handshake state and the cache metadata/active owners excluded above, task/channel nodes,
configuration and credential storage, allocator/thread overhead, and kernel socket
buffers. Source-level inspection and isolated process measurements must distinguish
these from the verified logical payload budget. The current milestone remains open;
this audit does not replace the async ownership-composition obligation.
