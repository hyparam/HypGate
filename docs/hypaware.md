# Setting up LogGate with HypAware

This is the operator walkthrough: get a token, point the gateway at a HypAware
server, run a request, and confirm the exchange on the server. The protocol,
the proofs, and the trust assumptions are in [cloud shipping](cloud-shipping.md).

## What ships

Every completed exchange in the audit log becomes two rows in the HypAware
dataset `ai_gateway_messages`: a user row with the request text and an
assistant row with the response text and token usage. Rows go to the one
server named in the root policy and nowhere else. Headers, provider keys, and
the gateway token never leave the host.

## 1. Get a HypAware token

The shipper enrolls with `POST /v1/identity/bootstrap`, so it needs an
operator-issued bootstrap token. Use an **org service-account token** for
anything that runs unattended, and a **CI enrollment token** only for a quick
local trial.

### Service-account token (recommended)

A service account is an automation identity owned by the organization, not by
a person. An organization admin creates one in the HypAware dashboard under
the org's service accounts and mints a named token for it. The token starts
with `hsa_`, is shown once, and never expires; an admin revokes it from the
same page, and the gateway stops on its next request. Nobody has to sign in
on the gateway host, and nothing breaks when the person who set it up leaves.

Each token is bound to its own server-side gateway. Re-enrolling with the same
token, even after the state directory is lost, returns the same gateway id, so
the id you filter on in queries stays stable for the life of the token. Two
tokens on one account are two gateways.

There is no `hyp` command for this yet; the dashboard is the way, or the API
the dashboard uses (`POST /v1/org/service-accounts`, then
`POST /v1/org/service-accounts/<id>/tokens`) with an admin's session.

### CI enrollment token (local trial)

```sh
hyp remote login hypaware          # once, browser sign-in
hyp remote mint --label loggate-dev --expires-days 30
```

This mints a bootstrap token bound to one gateway that belongs to you and
expires. It depends on your personal remote login session, which itself
expires after about a month. That session is a different credential from the
machine enrollment that `hyp status` reports, so `hyp status` can look healthy
while mint says `remote session expired`; the fix is `hyp remote login hypaware`.

### Handling the token

Hand the token to the gateway through an environment variable only. It is never
a JSON field or a command-line argument. The shipper stores only a SHA-256
fingerprint of it beside the gateway credential.

## 2. Configure shipping

Add a `shipping` section to the root policy. The example below also shows two
provider routes, one Anthropic and one OpenAI, which is the configuration the
smoke test below used:

```json
{
  "identities": [{"tenant": 1, "sha256": "<sha256 hex of the gateway token>"}],
  "destinations": [
    "https://api.anthropic.com/v1/messages",
    "https://api.openai.com/v1/responses"
  ],
  "credentials": [
    {"tenant": 1, "kind": "api_key", "env": "ANTHROPIC_API_KEY"},
    {"tenant": 1, "kind": "bearer", "env": "OPENAI_API_KEY"}
  ],
  "grants": [
    {"tenant": 1, "selector": 1, "origin": 0, "credential": 0},
    {"tenant": 1, "selector": 2, "origin": 1, "credential": 1}
  ],
  "limits": {"requests": 16, "chunk_bytes": 16384},
  "logging": "strict",
  "shipping": {
    "server": "https://api.hypaware.ai",
    "token_env": "HYPAWARE_TOKEN",
    "state_dir": "/var/lib/loggate/shipping"
  }
}
```

The route file selects both grants:

```json
{"routes": [
  {"tenant": 1, "selector": 1, "origin": 0, "credential": 0},
  {"tenant": 1, "selector": 2, "origin": 1, "credential": 1}
]}
```

`state_dir` must already exist and be private to the operator (mode 700). The
shipper keeps two files there, both mode 600: `identity.json` with the
server-issued gateway credential and a fingerprint of the operator token, and
`checkpoint.json` with upload progress. The gateway id is the credential's
`sub` claim; you will want it for queries. The optional fields
`max_open_exchanges`, `max_exchange_bytes`, and `poll_ms` are described in
[cloud shipping](cloud-shipping.md#configuration).

## 3. Run

```sh
export ANTHROPIC_API_KEY=... OPENAI_API_KEY=... HYPAWARE_TOKEN=...
mkdir -m 700 logs state
target/release/loggate root.json routes.json logs/session-001.log
```

Startup fails with `invalid shipping configuration or missing token` when the
variable named by `token_env` is empty or unset. Each start needs a new log
filename.

Send native provider requests to the selector you granted. The gateway swaps in
the provider key and sets Host; everything else passes through unchanged:

```sh
curl http://127.0.0.1:8080/routes/1 \
  -H "Authorization: Bearer $GATEWAY_TOKEN" \
  -H 'content-type: application/json' -H 'anthropic-version: 2023-06-01' \
  -d '{"model":"claude-haiku-4-5","max_tokens":30,
       "metadata":{"user_id":"alice"},
       "messages":[{"role":"user","content":"Say hello."}]}'

curl http://127.0.0.1:8080/routes/2 \
  -H "Authorization: Bearer $GATEWAY_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"model":"gpt-4.1-mini","user":"alice","input":"Say hello."}'
```

Anthropic's `metadata.user_id` and OpenAI's `user` field become the row's
`session_id` on the server, so set them if you want exchanges grouped by caller.
Streaming (`"stream": true`) works the same way and is parsed for usage.

## 4. Check it

Locally, `GET /metrics` reports `loggate_shipping_enabled 1`,
`loggate_shipping_batches_acknowledged_total` climbing once per confirmed
batch, and `loggate_shipping_stopped 0`. `loggate scan logs/session-001.log`
lists every record and ends with a summary whose status is `complete`.

On the server, query the dataset as yourself with the HypAware CLI. Take the
gateway id from `state/identity.json`:

```sh
hyp query sql "select date, provider, model, session_id, role, part_type,
  left(content_text, 50) as text, json_extract(attributes, '\$.usage') as usage
  from ai_gateway_messages where gateway_id = '<gateway id>'
  order by message_created_at, part_index" --remote hypaware
```

Name the remote target explicitly (`--remote hypaware`); a bare `--remote`
placed before the SQL swallows the query as the target name. The SQL dialect
is DuckDB's, so use `json_extract` rather than the `->` operator.

Enrollment is lazy: `loggate_shipping_enrolled` stays 0 and `identity.json`
is absent until the first exchange completes. After that, shipping lags the
log by at most `poll_ms` plus one upload round trip, so rows normally appear
within a few seconds of the completion record.

## 5. Ship a finished log later

Shipping does not have to run inside the gateway. To upload a log written
without a `shipping` section, or to replay one after the state directory was
lost, run the same loop on its own:

```sh
HYPAWARE_TOKEN=... target/release/loggate ship root.json logs/session-001.log
```

It exits when every exchange is resolved. The server stores each exchange once
even if a batch is sent twice, so re-running is safe.

## Smoke test record

Run on 2026-10-25 from a MacBook against the live providers and HypAware Cloud
with the two-route configuration above, debug build at commit `f1070a2` plus
the changes in this commit. The same four requests were sent three times: with
no `shipping` section, with a CI enrollment token from `hyp remote mint`, and
with a service-account token. For the CI token, the gateway id printed at mint
time was the id the shipper enrolled under.

| Step | Result, each run |
| --- | --- |
| Anthropic Messages, JSON | 200, outcome 0 |
| Anthropic Messages, SSE stream | 200, outcome 0 |
| OpenAI Responses, JSON | 200, outcome 0 |
| OpenAI Responses, SSE stream | 200, outcome 0 |
| `loggate scan` | 37 or 38 records, status `complete`, `loggate_audit_gap_requests_total 0` |
| Shipping (both token kinds) | `enrolled 1`, 4 exchanges emitted, 4 batches acknowledged, 0 poisoned |
| Server query (both token kinds) | 8 rows under the gateway id: a user and an assistant row per exchange |

Response bodies came back byte for byte as the providers sent them, including
SSE padding. On the server, `provider` was `anthropic` or `openai`, `model` was
the requested model, `session_id` was the caller id from `metadata.user_id` or
`user`, and `attributes.usage` carried input, output, and total tokens for all
four exchanges, streamed or not.

The local-only log was then uploaded with `loggate ship` and a second
service-account token, twice: once into an empty state directory, then again
after deleting `identity.json` and `checkpoint.json`. Both runs enrolled under
the same gateway id and both reported one acknowledged batch; the server holds
8 rows for those 4 exchanges, not 16, which is the batch ledger doing its job.

Later the same day the gateway's HTTP library was replaced by the verified
HTTP/1.1 codec ([codec](http1-codec.md)), and the same four requests were run
again through it, plus a request with `Expect: 100-continue` and a request
with a bad token: all four exchanges returned 200 with the providers' bytes
intact, the two refusals were 100-then-200 and 401, the log scanned complete,
and two exchanges shipped and were acknowledged by HypAware Cloud through the
new shipping client.

That run also found a bug, fixed in this commit: `loggate ship` panicked at
startup with "Cannot start a runtime from within a runtime", because the
subcommand built the shipper's Tokio runtime on the thread that already ran the
executable's. It now runs on its own thread, as it does beside the gateway, and
the executable test covers the subcommand to the end of its drain loop.

On 2026-10-26 the shipping client moved off Tokio entirely: blocking sockets
and rustls used directly on the shipper's thread, with the request deadline
enforced by socket timeouts. `loggate ship` was run again against HypAware
Cloud with a fresh service-account token and state directory: it enrolled,
read the smoke log's 32 records into four exchanges, and had the one batch
acknowledged in about two seconds.

Later on 2026-10-26 the gateway itself followed: Tokio, tokio-util, and
tokio-rustls left the dependency tree, and the server now runs one thread per
connection over blocking sockets, with the exchange deadline enforced by
socket timeouts. The same smoke was run through the threaded server: Anthropic
and OpenAI, JSON and SSE, all returned 200 with the providers' bytes intact; a
bad token got 401; a request with `Expect: 100-continue` got its 100 and then
200; `/metrics` showed no failed exchanges and a healthy log; and the log
scanned complete with 37 records.

Also on 2026-10-26 the sequencing of each connection moved into the verified
exchange driver (`gateway_core::exchange_driver`), with the server reduced to
performing the effects it names. The same smoke was run through the driver:
Anthropic and OpenAI, JSON and SSE, all 200 with the providers' bytes intact;
a bad token got 401; `Expect: 100-continue` got its 100 and then 200;
`/metrics` showed no failed exchanges and a healthy log; the log scanned
complete.
