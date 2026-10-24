# Dependency resource audit

Source inspection on 2026-10-23 of the versions in Cargo.lock: Hyper 1.12.0,
rustls 0.23.46, and tokio-rustls 0.26.6. These are trusted implementation facts,
not Verus proofs or whole-process allocation ceilings. Recheck them on upgrades.
The [resource inventory](resource-accounting.md) separately accounts for our own
buffers and the number of live connections and requests.

## HTTP/1 storage

Both production builders set `max_buf_size(32768)`; the inbound builder also
sets `max_headers(100)` and disables keep-alive. The upstream performs one exchange
per connection. Neither enables pipelined flush aggregation.

In Hyper's [h1/io.rs](https://docs.rs/crate/hyper/1.12.0/source/src/proto/h1/io.rs),
`set_max_buf_size` sets both the adaptive read strategy maximum and the write
buffer threshold. `poll_read_from_io` limits the requested reserve but passes the
available `BytesMut` spare capacity to the I/O reader. Allocation rounding and
shared backing storage therefore prevent treating 32768 as a hard allocation
or per-read byte cap. Our frame reader independently rejects visible frames above
32768 and detaches accepted frames into bounded copies.

`WriteBuf::can_buffer` checks the buffered length *before* accepting the next body
buffer. The next buffer can cross the threshold. Queue strategy additionally
limits its buffer list to 16 entries; flatten strategy copies into a growable
header vector. Our output frames contain at most 16384 payload bytes, but HTTP
framing overhead, serialized headers, retained vector capacity, and allocator
rounding are additional. Headers enter through a separate encoding path. Thus
neither 32768 nor the one-slot application channel bounds all Hyper output storage.

Hyper's [body/chan.rs](https://docs.rs/crate/hyper/1.12.0/source/src/body/chan.rs)
holds one data item, a separate pending error, and optional trailers. This adds a
slot beyond our reader copy. That item can reference shared parser backing storage;
its count alone is not a byte-allocation theorem. Peer metadata is parsed before
our filtering can reject it. Our 100-value/32768-byte header checks bound accepted
name/value bytes, not HeaderMap allocation or URI/parser scratch.

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

## Remaining closure work

The bounded counts above help identify retained allocations but cannot be summed
as a proven RSS ceiling. Still needed are backing-capacity/lifetime bounds for
Hyper parser/output storage, TLS handshake state and the cache metadata/active owners excluded above, task/channel nodes,
configuration and credential storage, allocator/thread overhead, and kernel socket
buffers. Source-level inspection and isolated process measurements must distinguish
these from the verified logical payload budget. The current milestone remains open;
this audit does not replace the async ownership-composition obligation.
