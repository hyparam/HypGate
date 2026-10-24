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

The shared ClientConfig also owns roots and a resumption cache across exchanges.
In this version `Resumption::default` requests 256 sessions; the constructor in
[client/handy.rs](https://docs.rs/crate/rustls/0.23.46/source/src/client/handy.rs)
rounds that to 32 server entries, with up to eight TLS 1.3 tickets per server plus
TLS 1.2/key-exchange state. Entry count does not bound ticket/certificate byte size.
This storage is charged per transport instance, not once per active exchange.

## Remaining closure work

The bounded counts above help identify retained allocations but cannot be summed
as a proven RSS ceiling. Still needed are backing-capacity/lifetime bounds for
Hyper parser/output storage, TLS handshake and cache entries, task/channel nodes,
configuration and credential storage, allocator/thread overhead, and kernel socket
buffers. Source-level inspection and isolated process measurements must distinguish
these from the verified logical payload budget. The current milestone remains open;
this audit does not replace the async ownership-composition obligation.
