# HTTPS upstream transport

The runtime now performs real HTTP/1.1 exchanges through Tokio, Hyper, and rustls.
It is a library transport, not yet a listening gateway executable. The transport
consumes a private-constructor `PreparedRequest`, retaining its admission lease
through request upload and response streaming. No separate URL or credential
override is accepted by the exchange API.

DNS/TCP connection targets come from the configured endpoint. TLS validates that
host using webpki roots; test-only construction accepts a local test certificate.
The transport uses a direct Hyper connection, without an HTTP client redirect,
proxy-discovery, connection-pool, or retry layer. It sends the fixed path in
origin-form and preserves the bound Host and provider credential headers.
Approved-host DNS resolution is trusted and is not an IP-range/SSRF restriction.

The connection future runs inline alongside upload/response work, with no spawned
connection task. One configurable total exchange deadline, at most one hour,
covers DNS, connection, TLS, upload, and download. Timeout drops those futures and
their connection before releasing request ownership. There is no transparent replay.
Per-phase/idle deadlines and load-tested cancellation remain future hardening.

The async transfer driver feeds upload bytes into a one-slot HTTP body channel,
with at most 16 KiB per queued frame. A successful write means accepted into that
queue, not received by the provider. Only explicit successful upload completion
sends an end marker; dropping a writer causes a body error. Download frames are
read incrementally through the same verified stream driver and supplied logger.
The HTTP body bridge rejects trailers and bounds empty-frame work per poll.
Truncated bodies remain errors, not successful EOF. No JSON/SSE parsing or
compression/decompression is performed.

Status and filtered response headers reach a `ResponseSink` before body bytes.
Redirects are returned as status/body without following Location. After a response
starts, any later error must cause the eventual server adapter to abort framing,
not emit a successful final chunk. The transport does not itself shut down the
caller-owned output sink; only its successful return authorizes a clean end.

Upload and response-header reception are driven concurrently, but download starts
after upload completion. Providers that reject an upload early may cause an upload
error or total timeout instead of having their error body relayed. Full duplex and
early-response handling require separate directional stream ownership; they must
not bypass the current cancellation invariants.

Five local TLS tests cover exact opaque payload forwarding, fixed destination and
credential headers, certificate rejection, redirects without another connection,
deadline cleanup, and truncated responses. Three body-bridge tests cover explicit
EOF, canceled uploads, and trailer rejection. All 45 workspace tests pass. The
test logger records events in memory; real-disk integration is separately tested
through the same transfer driver. No live model provider was contacted.

All network code, TLS, HTTP parsing/framing, DNS, async scheduling, and body queues
remain trusted and tested rather than Verus-verified. The 32 KiB Hyper connection
buffer setting and bounded channel do not prove whole-process memory bounds.
Next work is the inbound server, executable configuration, response completion and
abort integration, health/readiness, and end-to-end tests using the disk logger.
