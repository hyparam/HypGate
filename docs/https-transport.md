# HTTPS upstream transport

The runtime performs real HTTP/1.1 exchanges through Tokio, rustls, and the
gateway's own verified codec ([codec](http1-codec.md)).
The [runnable gateway](running.md) wraps this transport in a listening server. The transport
consumes a private-constructor `PreparedRequest`, retaining its admission lease
through request upload and response streaming. No separate URL or credential
override is accepted by the exchange API.

DNS/TCP connection targets come from the configured endpoint. TLS validates that
host using webpki roots; test-only construction accepts a local test certificate.
TLS certificate compression is explicitly disabled; peers use ordinary certificate
chains. This keeps optional decompressor implementations outside the transport
even if another dependency enables their rustls features.
The transport drives one connection directly, without an HTTP client redirect,
proxy-discovery, connection-pool, or retry layer. It sends the fixed path in
origin-form and preserves the bound Host and provider credential headers.
Approved-host DNS resolution is trusted and is not an IP-range/SSRF restriction.

The exchange runs inline on the worker, with no spawned connection task. One configurable total exchange deadline, at most one hour,
covers DNS, connection, TLS, upload, and download. Timeout drops the exchange
futures before releasing request ownership. There is no transparent replay. TLS handshake work has separate retained credits, as described
below; a canceled handshake can outlive the request until its current poll returns.
Per-phase/idle deadlines and load-tested cancellation remain future hardening.

The async transfer driver writes upload bytes through a chunked writer onto the
TLS stream, one chunk per frame of at most 16 KiB. A successful write means
written to the stream, not received by the provider. Only explicit successful
upload completion writes the last chunk; dropping the writer leaves the body
unterminated, which the provider sees as an aborted request. Download frames are
read incrementally through the same verified stream driver and supplied logger.
The chunked decoder refuses trailers at their first byte.
Truncated bodies remain errors, not successful EOF. No JSON/SSE parsing or
compression/decompression is performed.

Status and filtered response headers reach a `ResponseSink` before body bytes.
Redirects are returned as status/body without following Location. Unsolicited 101
protocol switches are rejected before calling the client response sink; no upgraded
protocol bytes are forwarded or logged as a response body. The adapter skips ordinary
interim responses such as 103 and continues to the final response. Local TLS tests
cover rejection without replay, slot release, and a 103 followed by a normal 200. After a response
starts, any later error must cause the eventual server adapter to abort framing,
not emit a successful final chunk. After successful body transfer, the transport invokes the sink completion hook
while it still owns admission. The server hook sends a clean end marker and waits
for its application queue to drain. Errors do not invoke that hook.

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

Network code, TLS, DNS, async scheduling, and body queues remain trusted and
tested rather than Verus-verified; HTTP head parsing and writing, framing
selection, and chunk coding are verified core code. The 32 KiB read buffers and
bounded channel do not prove whole-process memory bounds.
The inbound server, executable, response completion/abort integration, health/readiness,
and an end-to-end disk test now exist; broader fault and concurrency coverage remain.

## Admission lifetime through network cleanup

`exchange` owns the prepared request outside its timeout future. The inner `run`
borrows that owner mutably for the entire TCP/TLS/HTTP operation; it takes only
the upstream head out of it, leaving the verified stream/key owner in the outer
future. Success, error, timeout, and cancellation drop the borrowed network future
before the outer request can release its slot. A dispatched TLS handshake instead
retains a separate pool credit through its asynchronous cancellation tail. This is
enforced by Rust lifetimes and future ownership, not a Verus proof of Tokio or
socket syscalls. No HTTP connection task is detached. The separate server worker
credit continues through response
cleanup after exchange completion.

A real-socket cancellation test waits until the peer receives a TLS handshake
record, checks that the request slot remains occupied, then drops the exchange.
The peer must reach EOF, capacity must be reusable, and no HTTP response, body
bytes, or audit record may have been produced. The existing deadline test covers
timeout cleanup; this additional test explicitly covers dropping a pending future.

The shared TLS session cache is explicitly configured for the pinned rustls
256-session policy (32 server entries, eight TLS 1.3 tickets and one TLS 1.2
session per server). TLS resumption remains enabled; early data is explicitly
disabled. [Dependency accounting](dependency-resources.md#shared-tls-session-storage)
records persistent and transient cache storage separately from active requests.

Hostname resolution uses a [separate bounded resolver](dns-resources.md): four
threads and at most 32 queued/running lookups or unadopted replies per transport. Canceled requests do
not release lookup credit before the actual system call finishes. Only bounded
socket-address results enter the TCP connector; TLS authenticates the original
configured hostname. These DNS workers can outlive a canceled network future,
but have separate accounting and cannot hold Tokio shutdown open.

## TLS scheduling isolation

The production connector is polled by `transport/handshake.rs` on four dedicated
threads, with 32 total queued/running jobs or unadopted replies per transport. Each thread reserves a
2 MiB stack. The existing Tokio reactor still drives socket readiness; threads
use its handle to poll the handshake and return the established stream. HTTP
processing resumes on the caller's executor. No request body, credentials, stream
owner, or audit operation is sent to the handshake pool.

Admission uses the verified resource registry. Full or poisoned pools fail closed.
Cancellation closes a reply channel; queued jobs skip polling, and running jobs
select cancellation when their current poll returns. A blocked verification poll
retains its job credit, socket, and TLS storage. No replacement thread is created.
Shared `credited_job::CreditedJob` uses the verified `TaskCredit` cleanup gate;
destruction completes before release is enabled. Successful output moves into a
`Reply` retaining the same credit, including while waiting unread in the oneshot.
`HttpsTransport::run` adopts that stream through `Request::adopt_background`:
`TaskCredit::handoff_to` verifies a live admitted target and records its identity
before the pool slot can return. The borrowing request then owns the stream.
Canceled replies destroy their sockets/TLS state before release. Panics are caught
outside the job so normal unwinding does not shrink the fixed pool; a panic during
wrapper cleanup strands its slot. Rust destruction and channel semantics remain
trusted correspondence points, not claims that Verus checks Tokio or rustls.

The caller's timeout and other executor work can progress while verification is
blocked, assuming OS scheduling and the other executor polls return. This is not a
hard verification CPU deadline: four stuck polls can exhaust the pool permanently.
The detached threads do not hold Tokio shutdown open; process exit is the final
boundary for permanently stuck work. Separate transport instances have separate
pools, so the limits are per instance, not global across arbitrary construction.
The five pool regression tests cover blocked-poll saturation, cancellation,
skipping queued work, state-before-credit destruction, panic recovery, and runtime
shutdown while work is blocked.
Real TLS transport tests exercise the production dispatch and returned sockets.
