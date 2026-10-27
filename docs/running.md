# Running the gateway

Build with the pinned Rust toolchain: `cargo build --locked --bin hypgate`.
Run `target/debug/hypgate CONFIG.json NEW_LOG [127.0.0.1:8080]`.
The log path must not exist; its parent directory must already exist and be private
to the operator. Configuration and secret-loading failures prevent startup.

The executable binds loopback only. Remote clients need a trusted TLS reverse proxy
on the same host; do not expose the cleartext connection to an untrusted network.
The library accepts a caller-owned listener and leaves that boundary to the
embedding application. See [deployment](deployment.md) for a tested HAProxy setup
with TLS, readiness checks, a standby instance, and retries disabled.

See [installation](installation.md) for a local installer or runtime container.
For provider clients, see [SDK setup](sdks.md); for closed audit files, see
[retention](retention.md).

## Configuration example

Use the schema in [configuration](configuration.md). A configuration for an
Anthropic-native endpoint looks like this (replace the digest placeholder with the
SHA-256 hex digest of a securely generated gateway token):

```json
{
  "identities": [{"tenant": 1, "sha256": "REPLACE_WITH_64_HEX_DIGEST"}],
  "destinations": ["https://api.anthropic.com/v1/messages"],
  "credentials": [{"tenant": 1, "kind": "api_key", "env": "PROVIDER_KEY"}],
  "grants": [{"tenant": 1, "selector": 7, "origin": 0, "credential": 0}],
  "limits": {"requests": 16, "chunk_bytes": 16384},
  "logging": "strict"
}
```

Save this as `config.json`. Each entry in `grants` defines an active route;
there is no separate route-selection file. Remove a grant to disable that route.
Configuration is loaded at startup, so changes require a restart.

Provide `PROVIDER_KEY` in the process environment through your secret manager.
Gateway tokens need at least 32 random bytes, encoded in bearer-token characters.
Hash the exact token bytes with no trailing newline. Keep the raw token separate
from provider credentials and logs. The placeholder above fails validation until a
real digest is set.

Clients send `POST /routes/7` with `Authorization: Bearer <gateway-token>`, the
provider's native headers such as Content-Type and Anthropic-Version, and the
unmodified native JSON body. The gateway forwards to the fixed configured path. For
an OpenAI-native endpoint, use its HTTPS URL and credential kind `bearer`. There is
no provider-body translation. SDKs may append the exact configured endpoint path
to `/routes/7`; see [SDK setup](sdks.md).
Upload compression, trailers, query parameters, HTTP/2, and full duplex are not
supported.

To upload exchanges to HypAware Cloud, add a `shipping` section to the root policy
and provide its token through the named environment variable; see
[cloud shipping](cloud-shipping.md). `hypgate ship CONFIG.json LOG` uploads a
finished log without starting the gateway.

## Scanning a log

`hypgate scan LOG` reads an existing log without changing it. It prints one JSON
line of metadata per valid record, then a summary with session ID, record count,
valid-prefix byte offset, and status. Scanning never replays or truncates data.

Every row carries `tenant`, `request`, `chunk`, `kind`, `payload_bytes`, and
`valid_end`. Body rows (`kind` `upload` or `download`) add `direction` and never
print the payload. Metadata rows add fields decoded by the verified codecs:

- `request_start`: `time_ms`, `selector`, `destination`
- `response_head`: `time_ms`, `status`
- `completion`: `time_ms`, `outcome`, `upload_bytes`, `download_bytes`

A metadata payload that does not decode is reported as `"metadata":"invalid"`.
Outcome codes are listed in the [disk logging notes](disk-logging.md#format-and-scanner).
A malformed header or an incomplete or corrupt tail gives a nonzero exit; the valid
earlier records are still reported. The [storage crash contract](storage-crash-contract.md)
describes what the scanner can and cannot tell you.

## Health, readiness, and metrics

`GET /healthz` reports that the process responds.

`GET /readyz` fails when the admission or worker registry is poisoned, when worker
admission is closed for shutdown, or, in strict mode only, when the logger is
unhealthy. Availability mode stays ready through logging loss but never overrides
an admission failure. The rule is the verified `health::readiness`; the server
only samples its inputs. Readiness does not probe upstream availability, request
capacity, or disk space. In strict mode, once logger health has failed, authorized
requests get 503 without opening an upstream connection; failures during a stream
are handled by the durability gate instead.

`GET /metrics` exposes these gauges and counters, with no payloads or credentials:

- `hypgate_failed_exchanges_total`: transport errors returned to the worker,
  including exchanges cancelled by a client leaving or by shutdown.
- `hypgate_audit_gap_requests_total`: availability-mode requests whose first log
  append failed, counted once per request even if the request later fails or is
  canceled (the verified `health::GapObserver` decides when an append counts). It
  flags possible incomplete audit coverage, not a count of unlogged bytes.
  Strict-mode refusals are not gaps.
- `hypgate_audit_healthy`: logger health.
- `hypgate_requests_active` and `hypgate_requests_limit`: live registry slots,
  sampled under the runtime lock. These are not memory or connection counts.
- `hypgate_admission_healthy`: zero when admission is poisoned, in which case the
  occupancy gauges are omitted.
- `hypgate_worker_admission_healthy`: whether the worker registry is unpoisoned and
  open. Worker registry failure also fails readiness in both modes.
- `hypgate_shipping_*`: present when the root policy has a `shipping` section;
  otherwise `hypgate_shipping_enabled 0`. See [cloud shipping](cloud-shipping.md).

Counters live in memory, so a restart resets them. Switching `logging` to
`availability` allows unaudited forwarding after a logging failure while keeping the
same authentication and routing checks.

## Built-in limits

Set request capacity and chunk size in your configuration. Connection, HTTP,
DNS, and logging limits also apply; see [operational limits](operational-limits.md)
for defaults, failure behavior, and which settings can be changed. More request
slots can increase waiting for audit writes, so measure your workload with the
[benchmark fixtures](benchmarks.md).

## Response behavior

Each connection is one thread, and a small watcher thread peeks the client
socket while the exchange runs: a client disconnect shuts the exchange's sockets
and cancels it, and the connection deadline bounds the whole connection through
socket timeouts. Successful completion writes the last chunk before releasing
request capacity; it does not prove the client consumed the bytes. Errors after
response headers abort the body rather than emitting a clean
final chunk. Before headers, transport errors give 502 or 504; authentication and
admission errors keep their own status codes.

Never retry a generation only because the gateway disconnected. The provider may
already have run it.

## Shutdown

SIGTERM or SIGINT stops acceptance and starts a cooperative drain. Connections
and workers get ten seconds to finish, then remaining exchanges are canceled.
The logger gets two seconds to drain and join; a stuck filesystem call cannot be
interrupted and a stuck worker is never replaced. The shipper has its own
two-second shutdown window. These are cooperative windows, not a hard exit
guarantee; exit status 0 indicates a successful drain.

SIGKILL or a crash ends in-flight exchanges abruptly. Recovery preserves synced
records under the [storage contract](storage-crash-contract.md), tolerates torn
tails, and never replays a generation. Restart with a new log filename.

Embedders trigger `server::Shutdown` for each listener. Shutdown permanently
closes shared worker admission; restarting requires a fresh `Gateway`. See the
[shutdown proof](shutdown-proof.md) for cancellation and cleanup assumptions.

## What the tests cover

A full local test sends requests through the listening gateway to a TLS provider
fixture and a real disk logger. It checks that unauthorized requests open no
provider connection, that secret headers are replaced, that response data arrives
before provider EOF, that logged bytes match the forwarded bytes, and that workers
drain on shutdown. An executable smoke test starts the real binary from JSON
configuration and checks its health endpoint. Further end-to-end scenarios inject
failed logger health and provider truncation, and check strict refusal without a
provider connection, availability-mode forwarding with unchanged authorization,
audit-gap reporting, metrics, and rejection of a second request while the only slot
is occupied. Logger I/O failures are tested at the disk adapter. See [contributing](../CONTRIBUTING.md) for validation commands.

This is a runnable prototype, not a production-ready or wholly verified gateway.
Stress, failure-mode, and load commands are in the [benchmark guide](benchmarks.md). Resource and crash-recovery proofs are conditional
on the assumptions in [resource composition](resource-composition.md) and the
[storage contract](storage-crash-contract.md). Log retention and rotation and
deployment hardening are operator obligations.
