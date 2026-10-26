# Dependency resource audit

Source inspection on 2026-10-23 of the versions in Cargo.lock: rustls 0.23.46 and
tokio-rustls 0.26.6, with the HTTP/1.1 buffers of the gateway's own codec adapter
added on 2026-10-25. These are trusted implementation facts, not Verus proofs or
whole-process allocation ceilings. Recheck them on upgrades. The
[resource inventory](resource-accounting.md) separately accounts for our own
buffers and the number of live connections and requests.

**Status (2026-10-26).** Tokio, tokio-util, and tokio-rustls are no longer
linked; the runtime uses rustls directly over blocking sockets, one thread per
connection, with the exchange deadline enforced by socket timeouts
([HTTPS transport](https-transport.md)). The rustls sections below still
describe the linked library and remain the per-exchange TLS allowances, kept as
upper bounds. The sections on the Tokio async adapters (`ReadLimited`,
`DrainBeforeWrite`, tokio-rustls `connect_with`, the handshake pool, Tokio's
DNS and channel storage) describe code that no longer exists; each is marked
below with what replaced it. There is no per-task or per-future storage left to
account for; thread stacks take its place
([dedicated thread stacks](#dedicated-thread-stacks)).

## HTTP/1 storage

The gateway links no HTTP library. Heads are parsed and written by the verified
codec ([codec](http1-codec.md)); the adapter in `gateway-runtime/src/http1.rs`
owns every HTTP buffer, and each one is a plain `Vec<u8>` with a stated bound.
The bounds below are requested allocations under the Rust 1.99.1 `Vec` growth
policy, not the logical byte counts the proofs state.

### Head buffers

`read_request_head` and `read_status_head` read into one `Vec<u8>`. Before each
read the vector is resized to at most `headers::MAX_BYTES` (32,768) bytes in
total, so its capacity never exceeds 32,768, and a head that has not parsed by
that size is refused as too large rather than read further. When a head parses,
`split_off` moves the bytes after it into a second vector of at most 32,768
bytes; the first is dropped when the function returns, so the two coexist only
during that return. The leftover vector becomes the body reader's buffer.

The upstream status head is read the same way; interim 1xx heads other than 101
are discarded and the buffer reused, so skipping them allocates nothing new.

### Body read buffer

`BodyReader` keeps one `Vec<u8>` of at most `READ_BYTES` (32,768) bytes: the
leftover from the head, then each socket read refills it after it is spent. It
is never grown past 32,768. Chunk framing bytes are consumed in place; body
bytes are copied into the caller's read buffer, which for the verified body copy
is the stream's own chunk owner (at most K bytes, see
[resource accounting](resource-accounting.md)). The decoder (`ChunkDecoder`)
holds four integers and ghost state only.

Every upstream TLS plaintext read is a `BodyReader` read into its own
32,768-byte buffer, so no read requests more than that from rustls regardless
of the destination buffer the body copy offers; inbound reads go straight to
the TCP socket with the same buffer. (`http_io::ReadLimited`, which imposed
this bound on the async stream, is gone.)

### Chunk framing buffers

`ChunkedWriter` frames each write as one chunk in a `pending` vector: the hex
size line (at most 18 bytes), the data, and CRLF. Writes come from the body copy
in frames of at most 16,384 bytes, so one framed chunk is at most 16,404 bytes.
The vector is built with `extend_from_slice` and two pushes, so doubling can
request up to 32,808 bytes; it is cleared, not shrunk, once written, and reused.
The last chunk is five bytes. There is one `ChunkedWriter` per upload (the
transport's request body) and one per streamed response (the server's
`Output`). A framed chunk is written in full, blocking under the deadline,
before the next write is accepted, so a slow peer holds at most one framed
chunk here; there is no body queue behind it.

### Written head lengths

Heads are serialized by the verified writer into a fresh `Vec<u8>` and written
with `write_all`. The logical length is the sum of the field names and values
(at most 32,768 bytes, 100 fields, by the projection's `fits` check), plus `: `
and CRLF per field, the start line, the empty line, and the two fields the
adapter adds (`connection: close` and either `transfer-encoding: chunked` or a
`content-length`). Requests also carry the configured path (at most 8,192 bytes
with the authority). The boundary tests pin the maxima: a maximum configured
request head is below 65,536 bytes, and a maximum response head is at most
33,445 bytes. `Vec` doubling can request up to 65,536 bytes for either. The
vector is dropped as soon as `write_all` returns.

Error responses the adapter writes itself (`431`, `400`, `503`, `502`, `504`)
have empty field lists and a `content-length: 0`, so their heads are under 100
bytes. The `100 Continue` interim response is a 25-byte constant.

### What no longer exists

There is no parser backing store that grows past the head limit, no header
vector or `HeaderMap`, no URI, no dequeued-frame retention outside our mailbox,
and no trailer assembly: trailers are refused by the chunked decoder at the
first byte of a trailer field. The `Bytes` type and its shared backing owners
are gone with the dependency, so a small value can no longer pin a large
parser buffer; every field value is its own `Vec<u8>` copy made by the parser.
Allocator rounding and `Vec` spare capacity remain outside the logical bounds.

## Upstream TLS storage

`HttpsTransport` explicitly sets `set_buffer_limit(Some(65536))` on each rustls
`ClientConnection` before the handshake.
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
65,536-byte payload yields `Fault::Tls`; the 65,535-byte incomplete
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
above. A debug panic unwinds the connection thread, whose credits are stranded
by the lease gate and whose registry poison behavior is tested separately; the
production binary uses the release profile.

`tls_retry_cookie_echo_is_bounded_by_the_client_hello_extension_field` checks the
largest fitting cookie is echoed exactly, that the queued output exceeds the
64 KiB application limit, and the overflow branch for the active build profile.
The release branch was validated locally with `cargo test --release` on
2026-10-23; CI exercises the debug branch.
`retry_cookie_is_echoed_above_the_buffer_limit_and_closure_fails_before_upload`
drives the production connector with a raw peer: the peer receives the echoed
cookie in a hello above 64 KiB, then closes without a ServerHello. The exchange
returns `Fault::Tls`, leaves the request body unread, produces no
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

### Peer certificate chain owners

The parsed TLS 1.3 Certificate message borrows each DER entry from the deframer
buffer. `client/tls13.rs::ExpectCertificate` then calls
`into_certificate_chain().into_owned()`, copying every entry into its own Vec, and
copies the end-entity OCSP staple with `to_vec`. The borrowed message and the
owned chain coexist until the handler returns and the processed flight is
discarded, so the Certificate step holds up to two copies of the chain bytes.
Each copy is bounded by the 65,535-byte handshake-message limit; entry counts
follow the table above. The verifier borrows the owned chain. After
`CertificateVerify`, the chain moves without copying into
`CommonState.peer_certificates`, where it stays for the connection's lifetime,
including the entire HTTP exchange, until the TLS stream is dropped. TLS 1.2
(`client/tls12.rs`) retains the chain the same way.

Each accepted NewSessionTicket clones that chain into a `Tls13ClientSessionValue`
(`cx.peer_certificates.cloned()`) alongside a copy of the ticket bytes, and
inserts it into the shared cache. The client counts received tickets but does
not limit them; the cache's eight-ticket-per-server bound evicts earlier values,
so a ticket flood allocates transiently but does not accumulate in the
connection. On resumption the new connection receives no Certificate message and
instead clones the cached chain into its own `peer_certificates`
(`tls13.rs` ServerHello handling, `tls12.rs` resumption). A resumed connection
therefore owns a chain copy independent of the cache entry, which the cache
audit below counts separately.

`tls_peer_certificate_chain_is_owned_per_connection_and_restored_on_resumption`
performs two in-memory handshakes against a two-certificate chain whose DER
totals more than 48 KiB. The full handshake's `peer_certificates` equals the
served chain exactly; the resumed handshake reports `HandshakeKind::Resumed`
and the same chain, which survives dropping the first connection. The test
observes content equality through the public accessor, not allocation
addresses or capacities; per-entry Vec capacity, descriptor sizes, and the
OCSP copy are source facts outside this regression.

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
the presented purposes. The connect effect eventually reports `ConnectFailure::Tls`, which the driver names `Fault::Tls`,
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

TLS verification runs synchronously inside `complete_io` on the connection
thread ([TLS on the connection thread](https-transport.md#tls-on-the-connection-thread)).
Cancellation cannot create replacement work: the thread that owns the exchange
is the only one doing the verification, and a slow verification costs that
exchange its deadline. The socket timeout bounds each network step of the
handshake, not the CPU time of verification itself; these source budgets do not
prove a hard CPU deadline.

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
explicitly schedules reads and writes, without the HTTP adapter or tokio-rustls. The next
obligation is to establish whether production polling and body backpressure
permit equivalent repeated interleavings, including empty peer application
records, or enforce an explicit queue bound at the TLS adapter. The consecutive
key-update counter alone cannot discharge that obligation.

The production transport writes through rustls's blocking `Stream`
(`StreamOwned`), whose `write` first completes prior I/O: while the connection
wants to write, it drains `sendable_tls` to the socket before accepting more
plaintext, and the socket write blocks under the exchange deadline's timeout
rather than returning pending. A blocked ciphertext drain therefore blocks the
writing thread instead of letting successive plaintext writes move additional
replies into the queue, which is what the async adapter's `DrainBeforeWrite`
wrapper existed to ensure. Reads are a separate blocking call on the same
thread; the transport never reads and writes the TLS stream concurrently, so
full-duplex progress is not a question here.

This closes the specific repeated-write enqueue path demonstrated above, not
the full TLS heap accounting obligation: direct control appends during reads,
handshake state, record capacities/overhead, and maximum transient allocations
still need composition.

The async-era test `tls_drain_guard_holds_control_queue_stable_and_resumes_exact_bytes`
exercised the wrapper around real tokio-rustls TLS 1.3 over loopback TCP, with
a synthetic write gate below TLS and 3,000 peer key-update/data rounds; it went
with the wrapper. The blocking `Stream` behavior it relied on is rustls's own
(`complete_prior_io` in `stream.rs`), re-audited on upgrade like the rest of
this section.
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

The adapter writes heads and chunks with `write_all`, one slice at a time, so
production never reaches rustls's `PlaintextSink::write_vectored` collection
path with more than one slice. That path collects borrowed slice references into
a `Vec<&[u8]>` for two or more slices and is kept in this audit for
completeness: the pinned exact-size collection requests one fat pointer per slice.
`OutboundChunks` borrows those references and does not clone their payloads.
The Vec exists only during that synchronous writer call. The test with 65,537
slices deliberately bypasses the adapter and therefore does not represent
production descriptor usage.

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
`(33 * 9 + 2 * R) * 131119` bytes **for these three contents only**. The
transport's `run` borrows its outer request owner and owns the TLS connection
as a local, so its TLS session cleanup occurs before that admission credit is
returned. Custom connector use outside this
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

Hostname resolution is a blocking system call whose started lookup no caller
can cancel. The production [dedicated resolver](dns-resources.md) owns a fixed
worker pool, separate verified admission credits, and bounded returned address
vectors, so a connection thread that stops waiting at its deadline leaves one
credited lookup behind rather than an unbounded accumulation across timeouts.
libc/NSS internal allocations and termination remain explicit dependencies.

## Channel control storage

Payload limits exclude the storage that carries messages and their wakeups. The
following counts apply to the production sequential driver, one server invocation,
one shared logger, and one shared transport. R, C, and Q have the meanings in the
[resource inventory](resource-accounting.md). They count channel allocations by
their surviving owners; they do not add another copy of message payloads.

| Control object | Conservative simultaneous count | Owner argument |
| --- | ---: | --- |
| HTTP body channels | 0 | Removed: the connection thread copies bodies directly |
| Audit completion `mpsc` channels | Q + 1 + R | Encoding/queued jobs, sole active worker, and live request receivers |
| DNS completion `mpsc` channels | 32 + R | Credited lookup jobs or live request receivers after result handoff |

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

The HTTP body channel between worker and connection no longer exists: the
connection thread copies body bytes straight from the body reader to the
chunked writer, so there is no queued HTTP payload and no mailbox control
storage. See the [HTTP lifetime audit](http-buffer-lifetimes.md).

The remaining channels are `std::sync::mpsc`: one per disk append carries the
receipt back to the waiting thread, one per DNS job carries its reply, and one
bounded channel per DNS pool queues jobs. Each `mpsc` channel is one Arc
allocation with a linked list of blocks that grows with queued items; here each
carries at most one item (a receipt, a reply) or at most the pool's job limit,
so its growth is bounded by the same Q and 32-job limits. The result's variable
storage is charged to its payload category. A receiver that stopped waiting does
not destroy the channel while the job still owns the sender, which is why the
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
also request 2 MiB each and the signal thread that requests 64 KiB, one
executable instance requests 10 MiB plus 64 KiB of fixed background thread
stacks. Each accepted connection adds a connection thread
with a 512 KiB stack and a watcher thread with a 64 KiB stack, at most C of
each, charged per inbound connection in the
[resource composition](resource-composition.md). The accept loop uses the main
thread; its stack, OS guards/rounding, committed pages, TLS/thread-local
state, and kernel thread objects are additional. Requested stack reservation is
not RSS or a verified bound on recursive execution. Library callers running
additional gateway instances must add those resources separately.

## Remaining closure work

The bounded counts above help identify retained allocations but cannot be summed
as a proven RSS ceiling. Still needed are backing-capacity/lifetime bounds for
the codec adapter's `Vec` spare capacity, TLS handshake state and the cache metadata/active owners excluded above, channel nodes and thread objects,
configuration and credential storage, allocator/thread overhead, and kernel socket
buffers. Source-level inspection and isolated process measurements must distinguish
these from the verified logical payload budget. This audit does not replace the
[ownership composition](ownership-composition.md).
