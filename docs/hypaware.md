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
operator-issued bootstrap token. Two kinds work:

- **Org service-account token** (starts with `hsa_`). An organization admin
  creates a service account in HypAware and mints a named token for it; the
  token is shown once and does not expire. Recommended for anything that
  restarts: re-enrolling with it returns the same server-side gateway, so the
  gateway id in your queries stays stable.
- **CI enrollment token** from the HypAware CLI:

  ```sh
  hyp remote login hypaware          # once, browser sign-in
  hyp remote mint --label loggate-dev --expires-days 30
  ```

  Each enrollment with such a token creates a new gateway row on the server.
  Fine for a smoke test, noisy for a deployment.

`hyp remote mint` and `hyp remote tokens` use your personal remote login
session, which expires after a while. This is a different credential from the
machine enrollment that `hyp status` reports, so `hyp status` can look healthy
while mint says `remote session expired`; the fix is `hyp remote login hypaware`.

Hand the token to the gateway through an environment variable only. It is never
a JSON field or a command-line argument.

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
this document. The token was a CI enrollment token from `hyp remote mint`; the
gateway id it printed at mint time was the id the shipper enrolled under.

| Step | Result |
| --- | --- |
| Anthropic Messages, JSON | 200, outcome 0 |
| Anthropic Messages, SSE stream | 200, outcome 0 |
| OpenAI Responses, JSON | 200, outcome 0 |
| OpenAI Responses, SSE stream | 200, outcome 0 |
| `loggate scan` | 37 records, status `complete`, `loggate_audit_gap_requests_total 0` |
| Shipping | `enrolled 1`, 4 exchanges emitted, 4 batches acknowledged, 0 poisoned |
| Server query | 8 rows under the gateway id: a user and an assistant row per exchange |

Response bodies came back byte for byte as the providers sent them, including
SSE padding. On the server, `provider` was `anthropic` or `openai`, `model` was
the requested model, `session_id` was the caller id from `metadata.user_id` or
`user`, and `attributes.usage` carried input, output, and total tokens for all
four exchanges, streamed or not. A first run with the same four requests and no
`shipping` section logged identically on disk, which is the local-only path.
