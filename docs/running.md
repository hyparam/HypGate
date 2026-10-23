# Running the prototype

Build with the pinned Rust toolchain: `cargo build --locked --bin soundgate`.
Run `target/debug/soundgate ROOT.json ROUTES.json NEW_LOG [127.0.0.1:8080]`.
The log path must not exist; its parent directory must already exist and be private
to the operator. Configuration and secret-loading failures prevent startup.

The executable binds loopback only. Remote clients require a trusted TLS reverse
proxy on the same host; do not expose the cleartext internal connection to an
untrusted network. The public library accepts a caller-owned listener and relies
on the embedding application to provide that deployment boundary.

## Configuration example

Use the schema in [configuration](configuration.md). For example, a root policy
for an Anthropic-native endpoint can look like this (replace the digest placeholder
with the SHA-256 hex digest of a securely generated gateway token):

```json
{
  "identities": [{"tenant": 1, "sha256": "REPLACE_WITH_64_HEX_DIGEST"}],
  "destinations": ["https://api.anthropic.com/v1/messages"],
  "credentials": [{"tenant": 1, "kind": "api_key", "env": "PROVIDER_KEY"}],
  "grants": [{"tenant": 1, "selector": 7, "origin": 0, "credential": 0}],
  "limits": {"requests": 32, "chunk_bytes": 16384},
  "logging": "strict"
}
```

The separate candidate route file selects the permitted grant:

```json
{"routes": [{"tenant": 1, "selector": 7, "origin": 0, "credential": 0}]}
```

Provision `PROVIDER_KEY` in the process environment through your secret-management
mechanism. Use at least 32 random bytes of entropy for gateway tokens, encoded in
bearer-token-compatible characters. Hash the exact token bytes without a trailing
newline. Keep the raw gateway token separate from provider credentials and logs.
The placeholder above deliberately fails validation until a real digest is set.

Clients send `POST /routes/7` with `Authorization: Bearer <gateway-token>`, native
provider headers such as Content-Type and Anthropic-Version, and the unmodified
native JSON body. The gateway forwards to the fixed configured path. For an
OpenAI-native endpoint, use its HTTPS URL and credential kind `bearer` instead.
There is no provider-body translation and live-provider compatibility has not yet
been tested. Upload compression, trailers, arbitrary query parameters, HTTP/2,
and full duplex are outside the current interface.

## Operational behavior

GET `/healthz` reports process responsiveness. GET `/readyz` fails when the logger
is unhealthy in strict mode; availability mode stays ready despite logging loss.
Readiness does not yet probe upstream availability, request capacity, or disk space.
The library exposes in-memory failed-exchange and audit-gap counters; persistent
gap diagnostics and a metrics endpoint remain to be added. Crashes can lose these
counters. Changing `logging` to `availability` permits unaudited forwarding after
logging failure while retaining the same authentication/routing checks.

The executable currently uses 128 connection slots, a 10-second header deadline,
100 headers/32 KiB HTTP buffer settings, a 300-second upstream exchange deadline,
and a 310-second connection deadline. It serves one request per HTTP/1 connection.
Excess connections are closed; authorized request capacity is separately configured
in root policy. The logger uses 16 queued records and a two-second acknowledgment
deadline. These operational defaults are not yet CLI/config options.

SIGINT or SIGTERM stops acceptance and allows up to ten seconds for connections to
drain, then aborts them and waits for tracked request workers to drop. A stuck disk
worker is not replaced and does not hold the Tokio executor; explicit disk-worker
joining and crash-model guarantees remain open. Never retry a generation solely
because the gateway disconnected: the provider may already have executed it.

The response body owns its worker's abort guard. Client disconnects or connection
timeouts cancel that worker. Successful completion drains the bounded application
body queue before releasing request capacity; it does not prove that a client
application consumed the bytes. Errors after response headers abort the body
instead of emitting a successful final chunk. Before headers, transport errors
produce 502 or 504; authentication/admission errors retain their separate status.

## Evidence and limits

A full local test sends requests through the listening gateway to a TLS provider
fixture and a real disk logger. It checks that unauthorized requests make no
provider connection, secret headers are replaced, response data arrives before
provider EOF, logged request/response bytes match, and workers drain on shutdown.
A separate executable smoke test starts the actual binary from JSON configuration
and checks its health endpoint. All 48 workspace tests pass.

This is a runnable prototype, not a production-ready or wholly verified gateway.
Concurrent-request stress tests, all end-to-end failure modes, resource composition
proofs, crash-recovery proofs, load measurements, retention/rotation, and operator
deployment hardening remain open. See the milestone checklist for the full scope.
