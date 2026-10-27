# Running the gateway

Build with the pinned Rust toolchain: `cargo build --locked --bin hypgate`.
Run `target/debug/hypgate ROOT.json ROUTES.json NEW_LOG [127.0.0.1:8080]`.
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

Use the schema in [configuration](configuration.md). A root policy for an
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

The separate candidate route file selects the permitted grant:

```json
{"routes": [{"tenant": 1, "selector": 7, "origin": 0, "credential": 0}]}
```

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
to `/routes/7`; see [SDK setup](sdks.md). Anthropic Messages and OpenAI Responses, JSON and
SSE, were exercised live on 2026-10-25 and again on 2026-10-26 ([smoke record](hypaware.md#smoke-test-record)).
Upload compression, trailers, query parameters, HTTP/2, and full duplex are not
supported.

To upload exchanges to HypAware Cloud, add a `shipping` section to the root policy
and provide its token through the named environment variable; see
[cloud shipping](cloud-shipping.md). `hypgate ship ROOT.json LOG` uploads a
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

The executable uses 128 connection slots, a 10-second header deadline, 100 headers
and a 32 KiB HTTP head buffer, a 300-second upstream exchange deadline, and a
310-second connection deadline. It serves one request per HTTP/1 connection and
closes excess connections. Authorized request capacity is set separately in the root
policy. These defaults are not yet CLI or config options. Library callers fix the
connection limit on the first serve call for a Gateway; later calls must use the
same limit and share its capacity, including canceled connections awaiting cleanup.
Changing the limit needs a new Gateway.

The logger queues 16 records with a two-second acknowledgment deadline. Each request
has one audit append outstanding at a time, so with more than 16 request slots the
extra appends wait, in arrival order, for a slot. The deadline covers that wait, and
expiry marks logging unhealthy in either mode. More slots therefore add latency per
frame rather than failures, as the [benchmarks](benchmarks.md#broader-workloads) show.

Both inbound and upstream HTTP/1 heads are limited to 32 KiB on the wire and 100
header fields, counting the request or status line, delimiters, and fields the
gateway later discards. Oversized inbound heads get 431 before dispatch; oversized
upstream heads fail the exchange before response headers are forwarded. These limits
do not cap body length.

DNS resolution has a fixed budget per transport of four workers and 32 queued or
running jobs. When it is saturated the exchange fails rather than queuing another
lookup, and answers with more than 64 addresses are rejected. Request deadlines
include DNS wait time but cannot interrupt a running system lookup. Resolver threads
do not block shutdown. See [DNS accounting](dns-resources.md) for the
system-resolver assumptions and behavior under a permanent stall.

The [operational limits](operational-limits.md) page lists every limit, what happens
when it is reached, and the test behind each.

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

SIGTERM or SIGINT starts the cooperative drain and the process exits with
status 0 when it is done: acceptance stops, connections and workers get up to
ten seconds to finish, remaining exchanges are then cancelled and write their
completion records, and the logger and shipper close. A second signal during
the drain is absorbed; the drain is bounded, and SIGKILL remains available.
SIGKILL or a crash ends in-flight exchanges abruptly; every record already
acknowledged is durable, the recovery scanner tolerates a torn tail, and
nothing is replayed. Crash guarantees stay conditional on the
[storage contract](storage-crash-contract.md). The handler is the
executable's one C binding (`signal.rs`): it writes a byte to a socket pair
and a thread triggers `server::Shutdown`.

Embedders trigger `server::Shutdown` themselves. It stops acceptance, allows up to
ten seconds for connections and workers to drain, then cancels remaining
exchanges by shutting their sockets, so each writes its completion record and
returns its credit. The server then gives the logger two seconds to drain and
join; a timeout returns an error and cannot interrupt an in-progress filesystem
syscall. A stuck disk worker is not replaced. The windows are cooperative, not a
hard exit guarantee.

Graceful shutdown permanently closes worker admission across every listener that
shares the Gateway. One ten-second window covers local connections and shared
workers; remaining exchanges are then canceled, including those whose connections
belong to another listener. Each listener still owns its socket and must be told to
stop accepting. Restarting after a graceful shutdown needs a fresh Gateway and a new
log file. The [shutdown proof](shutdown-proof.md) covers the scheduler and destructor
assumptions, poison behavior, and retained disk and DNS work.

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
Stress, failure-mode, and load evidence is in the [benchmarks](benchmarks.md). Resource and crash-recovery proofs are conditional
on the assumptions in [resource composition](resource-composition.md) and the
[storage contract](storage-crash-contract.md). Log retention and rotation and
deployment hardening are operator obligations.
