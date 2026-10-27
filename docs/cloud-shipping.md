# Cloud shipping to HypAware or S3

The shipper runs on one dedicated thread inside `hypgate`, enabled by an
optional `shipping` section of the root policy. HypAware is the default backend;
[S3](#s3-destination) reuses the same driver with signed PUT requests. The
HypAware behavior is described below, followed by the S3 differences. Every decision is made by the
verified shipper machine (`gateway_core::shipper::Machine`): which records
form which exchange, which exchanges go into the next batch, which request to
send with which credential, how to read a reply, and how long to wait. The
loop that calls it is verified too (`gateway_core::shipping_driver::drive`):
it runs against an `Effects` trait whose runtime implementation is a clock, a
record source, a row projector, one request sender, sleeps, a checkpoint
writer, and a metrics sink, with no decisions in it. The projection of an
exchange into HypAware rows is verified too (`gateway_core::projection`, see
[the projection](#the-projection)), reading provider bodies through the
verified JSON reader and writing rows through the verified writer, with
timestamps from the verified calendar. The request head and the reading of
each reply are verified too (`gateway_core::shipping_wire`), and the HTTPS
exchange runs under a verified client driver (`gateway_core::client_exchange`);
the TLS connection, name resolution, the state files'
I/O, and the server's own behavior are trusted and tested; the whole
runtime, these adapters included, is held to a panic-free standard by clippy
denies on unwrap, expect, panic, unreachable, indexing, and unchecked
arithmetic. The client runs on the
shipper's own thread with blocking sockets and rustls used directly, no
executor: one deadline covers connect, handshake, request, and reply,
enforced by setting the socket timeout to the time left before every read
and write.

## What it does

The shipper opens the audit log read-only and tails it with the verified
scanner, resuming from the last validated offset whenever the machine asks it
to read. Records are grouped by request into exchanges inside the machine.
Each emitted exchange comes back as a numbered token; the verified driver has
the runtime project it into two `ai_gateway_messages` rows (a user part with
the request text and an assistant part with the response text and token
usage), serialized as NDJSON, and hands the token straight back with the
bytes. The machine accepts tokens only in emission order and keeps the
projections as the unresolved suffix of a ghost history; the driver is proved
never to hold a token across an iteration. When it chooses to upload, the
request body is exactly the concatenation of the next queued exchanges, at
most 5,000 rows and 4 MiB, sent to `POST /v1/ingest/proxy` with the gateway
credential the server issued at enrollment. A request carries a path and a
body but no host: the host lives only in the client built from
`shipping.server`. Progress is checkpointed after every acknowledged or
poisoned batch.

The shipper never writes to the log, never replays provider traffic, and never
touches admission, forwarding, or readiness. It shares no resolver or socket
with request workers; like them it runs blocking sockets on its own thread.

## Configuration

Add to the root policy (all fields but the first three optional):

```json
"shipping": {
  "server": "https://api.hypaware.ai",
  "token_env": "HYPAWARE_TOKEN",
  "state_dir": "/var/lib/hypgate/shipping",
  "max_open_exchanges": 64,
  "max_exchange_bytes": 1048576,
  "poll_ms": 1000
}
```

- `server` is validated by the same strict `https://` rules as provider
  destinations. It is the only network destination the shipper ever uses.
- `token_env` names the environment variable holding the operator token, like
  a provider credential: 1 to 512 visible ASCII bytes, never in JSON or argv.
  An org service-account token (`hsa_` prefix) is recommended: re-enrolling
  with it returns the same server-side gateway, while a plain bootstrap token
  creates a new gateway row on every enrollment.
- `state_dir` must exist and be private to the operator. The shipper writes
  `identity.json` and `checkpoint.json` there, mode 0600, by temporary file
  and rename. `identity.json` holds the server's gateway credential and a
  SHA-256 fingerprint of the operator token, not the token.
- `max_open_exchanges` (1 to 65,536) bounds both the assembler's open
  exchanges and the queue of projected rows; when the queue is full the
  shipper stops reading until a batch resolves, so the log file is the buffer.
- `max_exchange_bytes` (4 KiB to 16 MiB) caps the body bytes retained per
  exchange; the rest is counted, dropped, and reported as `truncated`.
- `poll_ms` (100 to 60,000) is the idle poll interval.

`GatewayConfig` ignores the section: the gateway's own configuration never
holds the server or the token. `main.rs` reads the token once through the same
environment resolver as provider keys and moves it into the shipper thread.
This is an ownership and module boundary inside one process, not a process
boundary.

`hypgate ship CONFIG.json LOG` runs the same loop on the current thread over a
finished log and exits when every exchange is resolved; exchanges still open
after five idle polls are flushed as `incomplete`.

## S3 destination

Set a nonempty `s3_region` to select S3 instead of HypAware. The same live
shipper and `hypgate ship CONFIG.json LOG` upload the same projected NDJSON
batches (not raw audit frames). No AWS SDK or new dependency is needed.

```json
"shipping": {
  "server": "https://my-audit-bucket.s3.us-east-1.amazonaws.com/hypgate/",
  "s3_region": "us-east-1",
  "s3_access_key_env": "AWS_ACCESS_KEY_ID",
  "token_env": "AWS_SECRET_ACCESS_KEY",
  "s3_session_token_env": "AWS_SESSION_TOKEN",
  "state_dir": "/var/lib/hypgate/s3-shipping",
  "poll_ms": 1000
}
```

Omit `s3_session_token_env` for long-lived access keys. All secrets come from
the named environment variables, once at startup; temporary credentials require
restarting with refreshed values before expiry. There is no instance metadata,
STS, profile-file discovery, credential refresh, bucket creation, or redirect
following. Grant `s3:PutObject` on the chosen prefix and configure bucket encryption,
lifecycle, and access policy separately. A bucket requiring extra encryption
headers is not supported by this initial implementation.

`server` is the sole HTTPS destination. Its path is the object prefix and must
end in `/`; a path-style endpoint can include `/bucket/prefix/`. Prefixes support
ASCII letters, digits, hyphens, underscores and slashes, up to 1024 bytes; spaces,
dots, percent escapes and queries are rejected. The region and access key use
the same character set without slashes. The secret access key is `token_env`
(1–512 visible ASCII bytes); a session token can be up to 16 KiB.

Each upload is an AWS Signature Version 4 PUT with `host`, `x-amz-date`,
`x-amz-content-sha256`, and, when present, `x-amz-security-token` signed. The
verified core implements HMAC using the existing verified SHA-256 and proves
the canonical request, signing-key derivation, string to sign, and authorization
bytes match their specifications. Time comes from the system clock; `s3_delivery::date` proves the exact
16-byte UTC representation of the verified calendar's civil fields, and rejects
years beyond four digits. `s3_delivery::{prepare,send}` proves that only ingest
creates a PUT, its body is unchanged, its headers are exactly the signed fields,
and a successful ingest reply requires an observed HTTP 200.

Object names are the prefix, hex batch identity, a hyphen, the full SHA-256
payload hash, and `.ndjson`. A retry of identical data overwrites the same key.
Only HTTP 200 resolves a PUT. Every other response or transport failure retains
the batch and retries; 429/503 honor the existing bounded Retry-After policy.
Authentication failures, redirects, and S3 400 errors never trigger the
HypAware poison behavior. Oversized projections still follow the shared
machine's local poison rules. Credential activation is a local core action:
no bootstrap or refresh request goes to S3, and AWS secrets never enter the
machine's enrollment token or an identity file.

Checkpoints bind the log session, assembler limits, S3 authority, prefix, and
region. The `s3-v2:` identity hex-encodes length-prefixed scope fields and the
log session; injectivity is proved without a hash-collision assumption. The
verified checkpoint codec rejects duplicate, unknown, missing, or wrongly typed
fields. Old hash-based S3 checkpoints are deliberately ignored, causing safe
replay with the same object identities. Changing the destination replays the log. Keep each shipper's
state directory private and exclusive. A failed checkpoint write safely causes
replay. Without an atomic server-side row ledger, changed batch boundaries after
a restart can store overlapping rows in different objects: consumers needing
row-level deduplication should use `part_id`. Versioned buckets can retain
multiple versions of an overwritten object. S3 provides at-least-once delivery,
not the HypAware server's exactly-once row-storage contract.

The core's existing queue, driver, cursor, recovery, and bounded retry proofs
are reused through `s3_driver::run`, an executable verified adapter implementing
the existing `shipping_driver::Effects`. Its send method calls the verified
S3 delivery code. `shipping_driver::deliver` composes the backend's reply
contract with the actual machine transition: an S3 reply never poisons a batch,
and every non-acknowledgment preserves both queue and progress. Restore and
capture use the same exact scope; only matching checkpoints restore progress,
and saved counters come from the machine itself.

`s3_config::load` proves backend selection, credential validation, the exact
configured name used for each secret, and a bounded read sequence (once per
credential role). The only secret-source assumption is that a lookup returns
the requested variable from a stable startup environment. The runtime never
receives an AWS SDK credential chain and never puts an AWS secret into the
shared machine's enrollment token.

The remaining external assumptions are explicit effect contracts: the clock
supplies its timestamp, environment lookup returns its named value, the TLS
transport attempts the provided request against the configured authority and
reports the peer's status, and the exclusive state directory implements atomic
persistence (a failed read may cause replay; an unsuccessful save may leave old
or new state). Header construction, date formatting, reply interpretation,
checkpoint codecs, scope matching, and restore/save decisions are verified
executable code, not runtime assumptions. Thread scheduling, OS/filesystem/TLS
correctness, cryptographic security, and AWS durability remain external facts;
Verus does not prove the implementation of AWS or the operating system.

## HypAware protocol

Enrollment: `POST /v1/identity/bootstrap` with `{"bootstrap_token": ...}`
returns `{jwt, expires_at, org}`. The gateway id is the credential's `sub`
claim; the shipper reads `sub` and `exp` without verifying the signature, which
the server does on every request. That reading is verified
(`shipping_wire::jws_claims`): a result is always the claims of the token's
one payload segment, found by its exactly two dots, decoded by the verified
base64url codec (`gateway_core::base64url`), which accepts exactly the
encodings of some bytes, and parsed by the verified JSON reader; the subject
is 1 to 128 bytes. The credential document is read the same way
(`shipping_wire::issued`), its expiry the earlier of `expires_at` and `exp`.
`POST /v1/identity/refresh` with the current
credential renews it; the shipper refreshes when less than 24 hours remain or
once after a rejected upload, and re-enrolls when a refresh is rejected.
`service_token_revoked` and `service_account_disabled` stop the shipper
permanently; `hypgate_shipping_stopped` reports it.

Upload: `POST /v1/ingest/proxy` with `Authorization: Bearer <credential>`,
`Content-Type: application/x-ndjson`, and `X-Hyp-Batch-Id`. The batch id is
the verified hex of the verified encoding of (log session, index range of the
exchanges, FNV-1a checksum of the body), computed inside the machine, so a
retry or a restart that rebuilds the same batch sends the same id and the
server's ledger acknowledges it without storing it again. Row identities are the verified hex of verified fixed-width encodings of
(session, request id, message index, part index), so a batch rebuilt
differently after a restart repeats part ids the server deduplicates.

Replies: 202 resolves the batch. 401 earns one refresh and a retry, then a
re-enrollment. 403 with a revocation code stops the shipper. 400, 413, 415,
and 422 are poison: a multi-exchange batch is retried one exchange at a time
until the bad exchange is isolated, poisoned, counted, and skipped. 429 and
503 wait for `Retry-After` (1 to 300 seconds) or a 30/60/120/300-second
ladder; other failures wait 2, 4, 6 seconds and then the ladder. Each request
has a 30-second deadline and the reply body is capped at 64 KiB.

## Rows

Both rows carry `schema_version` 7, `session_id` (the request's
`metadata.user_id` or `user` field when present, else the exchange id),
`provider` (from the destination host), `model`, timestamps and the UTC `date`
from the request-start record, `is_error`, and `attributes.gateway` with the
exchange id, destination host and path, status code, outcome, byte counts,
and the `truncated`, `incomplete`, and `orphan` flags. The assistant row adds
`attributes.usage` with `input_tokens` net of cache, `cache_read_tokens`,
`cache_write_tokens`, `output_tokens`, and `total_tokens`, parsed from
Anthropic Messages (JSON and SSE), OpenAI Responses (JSON and SSE), and
chat-completions bodies. Unparseable bodies ship as raw text, capped at
`max_exchange_bytes`. Headers and raw frames are never shipped; the server
stamps `gateway_id`, `org`, and `received_at` itself. Full parity with the
HypAware client's projector (tool parts, thinking blocks, compaction) is not
implemented.

## HypAware properties

| Property | Evidence |
| --- | --- |
| Cannot affect authorization, forwarding, or readiness | Structural: the thread receives only the log path, server, token, state directory, and limits; `Gateway` holds a read-only metrics view; readiness never reads it. Tested: `shipping_uploads_forwarded_exchanges_without_touching_readiness` with a hanging server, and the executable test with an unreachable server. |
| Never modifies the log | The only file handle is read-only (`File::open`); the scanner never truncates or appends (proved). |
| Retained bytes are an ordered prefix of the received bytes, within the cap | `exchange_assembler::Exchange::valid` proved; `assembler_interleaves_requests_and_truncates_at_the_cap`. |
| Bounded open exchanges and pending rows | `Assembler::valid` proved; `Machine::valid` bounds queued plus outstanding projections by `max_open_exchanges` and `wants_records` refuses reads beyond it (proved); the drain run tests it. |
| Nothing is dropped between emission and upload: every emitted exchange is queued in order, an ingest body is exactly the next queued exchanges, an acknowledgment pops exactly those, a poison pops exactly one | `Machine::{admit,enqueue,next,reply}` postconditions over the ghost history (proved); `machine_enrolls_then_ships_queued_exchanges_in_order_and_resolves_on_acknowledgment`. |
| The loop honors the machine's turn-taking: every token is projected and queued at once, every send gets exactly one reply, records are read only while wanted and only with valid headers, at most `PUMP_BATCH` (1024) a round so a stop is seen within a bounded batch, flushes respect the queue bound, and a checkpoint carries the machine's own progress; each round of the loop terminates | `shipping_driver::{drive,drive_step,pump,flush,settle}` verified against the machine's contracts and the `Effects::checkpoint` precondition. |
| The only request bodies are the escaped bootstrap token, nothing, or queued rows; the token appears only in a bootstrap body; no request names a host | `Machine::next` postconditions and the `Request` type (proved). |
| Every wait is 1 to 300 seconds; every state has a next action; pending work with a usable credential is sent or poisoned at once | `Machine::next` and `Machine::reply` postconditions (proved). |
| Each exchange is emitted exactly once, on its completion record or its eviction | `Assembler::admit` and `evict_oldest` postconditions proved. |
| Batches hold whole exchanges within 5,000 rows and 4 MiB | `BatchBuilder` proved; `ships_many_exchanges_in_bounded_batches_with_drain_mode`. |
| Progress advances only through an acknowledgment of the in-flight batch or an explicit poison; abandonment changes nothing | `UploadCursor` and `Machine::reply` proved; `upload_cursor_resolves_only_the_acknowledged_in_flight_batch`. |
| Batch and row identities are injective in their inputs | `shipping_identity` lemmas proved; stable ids across restarts tested. |
| A restart from a checkpoint skips exactly the resolved exchanges and resends the rest with identical identities | Emission numbering is a proved function of record kinds and request ids (`exchange_assembler::{step,emitted_requests}`); the machine ties every projection to its emission number (`Machine::replay_numbering`); `restart_from_a_checkpoint_skips_exactly_the_resolved_exchanges`. |
| No upload without an unexpired credential; one refresh per rejection; revocation is absorbing; delays within 1 to 300 seconds | `Enrollment`, `throttle_delay`, `transport_delay` proved; `recovers_from_rejected_tokens_throttling_and_poison_and_stops_on_revocation`. |
| At-least-once delivery, exactly-once storage | Trusted server contract: batch-id ledger and `part_id` dedup. Tested against the fake server, including a restart without a checkpoint. |
| Shutdown within a bounded window, no replacement thread | Tested: `shutdown_returns_within_its_window_while_the_server_hangs`; a thread inside a request is left to finish on its own. |
| A panic in the shipper thread changes only its metrics | The thread body runs under `catch_unwind`; the handle's `shutdown` reports it. Tested: `shipping_thread_panic_changes_only_metrics` keeps forwarding, readiness, and gateway shutdown intact. |
| A crash at any step resends only the unacknowledged exchanges | Replay numbering proved (above); tested exhaustively over every step of a run against a ledger-and-dedup fake: `a_crash_at_any_step_resends_only_the_unacknowledged_exchanges_and_the_server_stores_each_once`. |

## Trust assumptions

- The HypAware server honors its documented ledger and dedup semantics and
  issues credentials only to holders of a valid operator token.
- rustls, DNS, the OS socket timeouts that enforce the deadline, and the
  filesystem; nothing in the process uses an async executor. The HTTPS
  client's head parsing, framing, and chunk decoding are the verified codec,
  and its exchange order is the verified `client_exchange` driver: the head
  and body are handed to the wire once and in order, at most eight interim
  heads are skipped, a head with ambiguous framing is refused, and the reply
  body is exactly one body of the head's framing within the 64 KiB cap. What
  remains trusted is that the wire moves the bytes it reports.
- The system clock for renewal decisions and row timestamps.
- The `Effects` implementation performs what it is asked: `send` reaches the
  configured server and returns that server's reply, `read` returns the log's
  records in order, `project` hands the exchange to the verified projection
  with the runtime's calendar, and `checkpoint` writes the values it is
  given. The driver that calls them is verified.
- The checkpoint names the log session, and the restarted shipper reads the
  same file from its header. Given that, emission numbering is proved to be a
  function of the records (`exchange_assembler::emitted_requests`), so the
  resolved count skips exactly the exchanges the earlier run resolved. A
  checkpoint from different limits is ignored and everything is re-sent; the
  server drops the repeated rows.
- Token provisioning and revocation are operator and server obligations.

## Resources

One extra 2 MiB thread stack and the shipper's 256 KiB lookup thread; at most `max_open_exchanges × max_exchange_bytes`
in the assembler and `max_open_exchanges × 2 × (max_exchange_bytes + 16 KiB)`
of queued rows; one scanned record of at most 1 MiB; one batch of at most 4 MiB
and its copy in the request; a 64 KiB reply; a 128 KiB allowance for S3
credentials, signing, and request-header scratch (charged for either backend). `budget::shipping` composes these
and the executable prints the figure at startup. See
[resource composition](resource-composition.md#per-instance).

## What is not covered

No proof connects the thread's loop to the verified transitions; that is the
same trusted-join situation as the gateway's threaded shell. The projection's
choice of provider fields is a heuristic and lossy by design. gzip, dataset
registration, config pulls, diagnostics,
and fan-out to several servers are not implemented.

## The projection

`gateway_core::projection::rows` builds the two `ai_gateway_messages` rows
of an exchange. It is proved to return exactly two objects with fixed key
lists (`user_keys`, `assistant_keys`, and `gateway_keys` inside
`attributes`), every row well formed for the writer, every string value
well-formed UTF-8 (`gateway_core::utf8`, which also proves the sanitizer
keeps well-formed text and replaces each other byte with U+FFFD), each
`content_text` at most `max_exchange_bytes` long and cut only at a character
boundary, the message and part ids the hex of the verified keys, the request
id the hex of the exchange key, and the schema version and message indexes
fixed. Which provider fields it reads (`model`, `messages`/`input` and the
last user message's content blocks, `usage` in its Anthropic and OpenAI
spellings, the SSE event types) is a choice pinned by tests against recorded
bodies, not a theorem. The timestamps are the verified calendar's
(`gateway_core::calendar`): `civil` is proved to return the one proleptic
Gregorian date whose day number is the day of the given Unix milliseconds,
with the time of day decomposed exactly, and the formatters to print RFC 3339
text of exactly those fields; the rows' `conversation_started_at`, `date`,
and `message_created_at` are proved to be that text of the exchange's start
and completion times.

## Rotated logs

Live shipping and `hypgate ship CONFIG.json LOG` follow the numbered segments from
`LOG`. Rotation preserves the session ID, assembler, batch identities, and
checkpoint sequence, so requests spanning files are assembled normally. The
verified session recovery driver rechecks a sealed predecessor after discovering
its successor, preserving records appended during the handoff. On restart
the shipper reads the complete session from its original path and skips resolved
exchanges using the existing checkpoint. Keep all segments in place until shipping
and required replay finish; shipping an individual middle segment is not a
replacement for shipping the complete session. No segments are deleted by shipping.
