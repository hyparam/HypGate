# HTTPS upstream transport

The runtime performs real HTTP/1.1 exchanges through rustls over blocking
sockets and the gateway's own verified codec ([codec](http1-codec.md)); no
executor is linked. The [runnable gateway](running.md) wraps this transport in
a listening server. The transport consumes a private-constructor
`PreparedRequest`, retaining its admission lease through request upload and
response streaming. No separate URL or credential override is accepted by the
exchange API.

DNS/TCP connection targets come from the configured endpoint. TLS validates that
host using webpki roots; test-only construction accepts a local test certificate.
TLS certificate compression is explicitly disabled; peers use ordinary certificate
chains. This keeps optional decompressor implementations outside the transport
even if another dependency enables their rustls features.
The transport drives one connection directly, without an HTTP client redirect,
proxy-discovery, connection-pool, or retry layer. It sends the fixed path in
origin-form and preserves the bound Host and provider credential headers.
Approved-host DNS resolution is trusted and is not an IP-range/SSRF restriction.

The exchange runs on the connection thread that called it, with no spawned
thread of its own. One configurable total exchange deadline, at most one hour,
covers DNS wait, connection, TLS handshake, upload, and download. It is an
instant (`net::Deadline`); before every read and write the `net::Timed` stream
sets the socket timeout to the time left, so a peer that trickles bytes cannot
outlast it, and `TcpStream::connect_timeout` and the lookup wait take the same
remaining time. A passed deadline fails the exchange with `Fault::Timeout`
before releasing request ownership. There is no transparent replay. A system
DNS lookup already running cannot be interrupted; its credit returns when it
does ([DNS](dns-resources.md)).

Cancellation from another thread is `net::Cancel`: the transport registers its
socket with the exchange's cancel handle as soon as it is connected, and a
client that leaves or a gateway shutdown shuts that socket down. The blocked
read or write then fails, and the transport reports `Fault::Cancelled`, which
the server records in the completion record.

The body transfer driver writes upload bytes through a chunked writer onto the
TLS stream, one chunk per frame of at most 16 KiB. A successful write means
written to the stream, not received by the provider. Only explicit successful
upload completion writes the last chunk; leaving the writer unfinished leaves
the body unterminated, which the provider sees as an aborted request. Download
frames are read incrementally through the same verified stream driver and
supplied logger. The chunked decoder refuses trailers at their first byte.
Truncated bodies remain errors, not successful EOF. No JSON/SSE parsing or
compression/decompression is performed.

The transport is a set of effects the verified exchange driver asks for:
`HttpsTransport::connect` opens the session, and `Session::write`, `upload`,
`read_status_head`, and `download` move bytes. The driver reads status heads
until `upstream_status` names a final one, so ordinary interim responses such
as 103 are skipped and an unsolicited 101 is refused before any client header
is written; no upgraded protocol bytes are forwarded or logged as a response
body. Redirects are returned as status/body without following Location. The
status and filtered headers reach the client, through the driver's
`Connection` machine, before any body byte. Local TLS tests cover rejection
without replay, slot release, and a 103 followed by a normal 200. After a
response starts, any later error makes the driver abort framing, never emit a
last chunk; only a download the effect reports complete lets the driver end
the stream and write the last chunk.

The upload is written to completion before the response head is read, so a
provider that rejects an upload early may cause an upload error or total timeout
instead of having its error body relayed. Full duplex and
early-response handling require separate directional stream ownership; they must
not bypass the current cancellation invariants.

Local TLS tests cover exact opaque payload forwarding, fixed destination and
credential headers, certificate rejection, redirects without another connection,
deadline cleanup, and truncated responses. Body-bridge tests cover explicit
EOF, canceled uploads, trailer rejection, and input-frame limits. The
test logger records events in memory; real-disk integration is separately tested
through the same transfer driver. Live Anthropic and OpenAI exchanges are recorded
in the [HypAware setup](hypaware.md#smoke-test-record) smoke test.

Network code, TLS, DNS, thread scheduling, and socket timeouts remain trusted
and tested rather than Verus-verified; HTTP head parsing and writing, framing
selection, chunk coding, and the exchange machines are verified core code. The
32 KiB read buffers do not prove whole-process memory bounds.

## Admission lifetime through network cleanup

`exchange` owns the prepared request for the whole call. The inner `run`
borrows that owner mutably for the entire TCP/TLS/HTTP operation; it takes only
the upstream head out of it, leaving the verified stream/key owner with the
caller. Success, error, timeout, and cancellation all return through `run`
before the caller can release its slot, and the socket, TLS state, readers, and
writers are locals of `run` that drop on that return. This is enforced by Rust
lifetimes and ownership, not a Verus proof of socket syscalls. No connection is
detached. The separate server worker credit continues through response cleanup
after exchange completion.

A real-socket cancellation test waits until the peer receives a TLS handshake
record, checks that the request slot remains occupied, then cancels the exchange.
The peer must reach EOF, capacity must be reusable, and no HTTP response, body
bytes, or audit record may have been produced. The existing deadline test covers
timeout cleanup.

The shared TLS session cache is explicitly configured for the pinned rustls
256-session policy (32 server entries, eight TLS 1.3 tickets and one TLS 1.2
session per server). TLS resumption remains enabled; early data is explicitly
disabled. [Dependency accounting](dependency-resources.md#shared-tls-session-storage)
records persistent and transient cache storage separately from active requests.

Hostname resolution uses a [separate bounded resolver](dns-resources.md): four
threads and at most 32 queued/running lookups or unadopted replies per transport.
A request whose deadline passes stops waiting; the lookup keeps its credit until
the system call finishes. Only bounded socket-address results enter the TCP
connect; TLS authenticates the original configured hostname.

## TLS on the connection thread

The TLS handshake runs on the connection thread itself, through rustls
`ClientConnection::complete_io` under the exchange deadline
(`net::Timed::handshake`). There is no handshake pool: certificate verification
occupies the thread that owns the exchange and no other, so a slow or stuck
verification costs that connection its deadline and nothing else. The client
connection's application buffer is limited to 64 KiB before the handshake.
rustls's blocking `Stream` drains queued ciphertext before accepting more
plaintext and completes the handshake before the first application write, so
the drain guard the async adapter needed is now the library's own behavior
([dependency resources](dependency-resources.md#control-traffic-is-not-covered-by-the-application-buffer-limit)).
