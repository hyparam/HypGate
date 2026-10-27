# Provider SDKs

HypGate forwards provider-native request and response bodies. It does not
translate between providers or expose every endpoint of a provider's API.
Each configured route grants access to one fixed HTTPS endpoint.

The original `POST /routes/7` form still works. SDKs can instead use a route
prefix as their base URL and append the provider's endpoint path. For example,
`POST /routes/7/v1/responses` is accepted only when route 7 is configured for a
destination whose path is exactly `/v1/responses`. A different suffix, query
string, or trailing slash is rejected, not forwarded to another endpoint.

## OpenAI Python

Configure route 7 for `https://api.openai.com/v1/responses` with credential kind
`bearer`. Supply the real provider key only to the gateway; use a gateway token
in the client. The SDK appends `/responses` to this base URL:

```python
import os
from openai import OpenAI

client = OpenAI(
    base_url="http://127.0.0.1:8080/routes/7/v1",
    api_key=os.environ["GATEWAY_TOKEN"],
    max_retries=0,
)
response = client.responses.create(model=os.environ["OPENAI_MODEL"], input="Hello")
print(response.output_text)

with client.responses.create(
    model=os.environ["OPENAI_MODEL"], input="Hello", stream=True
) as stream:
    for event in stream:
        if event.type == "response.output_text.delta":
            print(event.delta, end="", flush=True)
```

For Chat Completions, grant a separate route to
`https://api.openai.com/v1/chat/completions` and use that route's base URL with
`client.chat.completions.create(...)`. Pointing the Responses route at Chat
Completions is rejected even when both are OpenAI endpoints.

The [official Python SDK documentation](https://developers.openai.com/api/reference/python)
describes base URLs and retry settings. Disable automatic retries: a timeout or
disconnect does not establish that the provider did not run the request.

## Anthropic Python

Configure route 8 for `https://api.anthropic.com/v1/messages` with credential kind
`api_key`. The Anthropic SDK appends `/v1/messages`, so its base URL does **not**
include `/v1`. Use `auth_token` for gateway bearer authentication:

```python
import os
from anthropic import Anthropic

client = Anthropic(
    base_url="http://127.0.0.1:8080/routes/8",
    auth_token=os.environ["GATEWAY_TOKEN"],
    api_key=None,
    max_retries=0,
)
with client.messages.stream(
    model=os.environ["ANTHROPIC_MODEL"],
    max_tokens=256,
    messages=[{"role": "user", "content": "Hello"}],
) as stream:
    for text in stream.text_stream:
        print(text, end="", flush=True)
```

Keep `ANTHROPIC_API_KEY` unset in the client environment: the SDK may load it
even when `api_key=None`. The gateway strips client credentials and injects the
route's provider key, but the client does not need to possess that key at all.
Use a TLS proxy URL instead of loopback HTTP for remote access.

## Compatibility scope and checks

JSON responses and SSE streams are exercised through the real Python SDKs for
Responses, Chat Completions, and Messages. The test starts a local TLS provider,
checks endpoint and credential binding, and compares logged body bytes with the
bytes exchanged. No paid API call or live credential is needed.

```sh
python3 -m venv /tmp/hypgate-sdks
/tmp/hypgate-sdks/bin/pip install -r scripts/sdk-requirements.txt
HYPGATE_SDK_PYTHON=/tmp/hypgate-sdks/bin/python \
  cargo test -p gateway-runtime --locked --lib real_python_sdks -- --ignored --nocapture
```

This is compatibility with those SDK operations, not the entire SDK surface.
GET, DELETE, file uploads requiring other content handling, query parameters,
WebSockets, Realtime, dynamic resource paths, and provider API translation are
outside this support. Additional fixed POST endpoints need their own grants.
Only allowlisted headers pass through; custom provider headers may need a
reviewed extension to the header policy.
