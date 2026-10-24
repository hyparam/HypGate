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

`target/debug/soundgate scan LOG` reads an existing log without changing it. It
prints newline-delimited JSON metadata for each valid record, then a summary with
session ID, record count, valid-prefix byte offset, and status. Raw payloads are
not printed. A malformed header or incomplete/corrupt tail gives a nonzero exit;
valid earlier records remain reported. Scanning never replays or truncates data.
See the [storage crash contract](storage-crash-contract.md) for its limits.

GET `/healthz` reports process responsiveness. GET `/readyz` fails when the
admission or worker registry is poisoned in either logging mode, or when the logger is
unhealthy in strict mode. Availability mode stays ready despite logging loss but
never overrides admission failure.
Readiness does not yet probe upstream availability, request capacity, or disk space.
After authorization, strict-mode requests also receive 503 without opening an
upstream connection if logger health is already failed; later failures are handled
by the stream durability gate.
GET `/metrics` exposes `soundgate_failed_exchanges_total`,
`soundgate_audit_gap_requests_total`, and `soundgate_audit_healthy` without payloads
or credentials. It also exposes `soundgate_requests_active`,
`soundgate_requests_limit`, and `soundgate_admission_healthy`; occupancy is a
verified count of live registry slots, sampled under the runtime lock. Poisoned
admission omits the occupancy gauges and reports health zero. These gauges are
not process memory or connection counts. `soundgate_worker_admission_healthy`
separately reports whether the worker registry is unpoisoned; worker registry
failure also makes readiness fail in both logging modes. Counters live in memory and crashes reset them. Failed exchanges
count transport errors returned to the worker, not all externally canceled tasks.
The gap counter increments once per availability-mode request at its first failed
log append, even if the generation later fails or is canceled. It reports potential
incomplete audit coverage, not a precise count of unlogged bytes. Strict-mode
refusal is not counted as an audit gap. Persistent diagnostics remain open. Changing `logging` to `availability` permits unaudited forwarding after
logging failure while retaining the same authentication/routing checks.

The executable currently uses 128 connection slots, a 10-second header deadline,
100 headers/32 KiB HTTP buffer settings, a 300-second upstream exchange deadline,
and a 310-second connection deadline. It serves one request per HTTP/1 connection.
Excess connections are closed; authorized request capacity is separately configured
in root policy. The logger uses 16 queued records and a two-second acknowledgment
deadline. These operational defaults are not yet CLI/config options.

SIGINT or SIGTERM stops acceptance and allows up to ten seconds for connections to
drain, then aborts them and waits for tracked request workers to drop. A stuck disk
worker is not replaced and does not hold the Tokio executor. After request workers
stop, the server gives the logger two seconds to drain and join; a timeout returns
an error and cannot interrupt an in-progress filesystem syscall. Crash-model
guarantees remain conditional on the storage contract. Never retry a generation solely
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
and checks its health endpoint. Additional end-to-end scenarios inject failed logger health and provider truncation.
They check strict refusal without a provider connection, availability-mode forwarding
with unchanged authorization, audit-gap reporting after failure, metrics, and
rejection of a second request while the sole slot is occupied. Logger I/O failures
are tested separately at the disk adapter. All 71 workspace tests pass.

This is a runnable prototype, not a production-ready or wholly verified gateway.
Concurrent-request stress tests, all end-to-end failure modes, resource composition
proofs, crash-recovery proofs, load measurements, retention/rotation, and operator
deployment hardening remain open. See the milestone checklist for the full scope.

See [proxy deployment and failover](deployment.md) for a tested HAProxy example
with TLS, readiness checks, a standby instance, and generation retries disabled.

DNS resolution has a fixed per-transport budget of four workers and 32 queued or
running jobs. Saturation fails the exchange without queuing another lookup;
results above 64 addresses are rejected. Request deadlines include DNS wait time,
but cannot interrupt a running system lookup. Dedicated resolver threads do not
block Tokio runtime shutdown. See [DNS accounting](dns-resources.md) for the
remaining system-resolver assumptions and behavior under a permanent stall.
