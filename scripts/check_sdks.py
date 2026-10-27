#!/usr/bin/env python3
"""Real SDK clients for the local Rust TLS/provider fixture; no live API calls."""
import sys
import anthropic
import openai

base = sys.argv[1]
for route, api in [(7, "responses"), (8, "chat")]:
    with openai.OpenAI(api_key="gateway", base_url=f"{base}/routes/{route}/v1",
                       max_retries=0, timeout=10, http_client=openai.DefaultHttpxClient(trust_env=False)) as client:
        if api == "responses":
            assert client.responses.create(model="sdk-test", input="hello").output_text == "hello"
            with client.responses.create(model="sdk-test", input="hello", stream=True) as stream:
                assert "".join(e.delta for e in stream if e.type == "response.output_text.delta") == "hello"
        else:
            args = dict(model="sdk-test", messages=[{"role": "user", "content": "hello"}])
            assert client.chat.completions.create(**args).choices[0].message.content == "hello"
            with client.chat.completions.create(**args, stream=True) as stream:
                assert "".join(e.choices[0].delta.content or "" for e in stream) == "hello"
with anthropic.Anthropic(api_key=None, auth_token="gateway", base_url=f"{base}/routes/9",
                         max_retries=0, timeout=10, http_client=anthropic.DefaultHttpxClient(trust_env=False)) as client:
    args = dict(model="sdk-test", max_tokens=16, messages=[{"role": "user", "content": "hello"}])
    assert client.messages.create(**args).content[0].text == "hello"
    with client.messages.stream(**args) as stream:
        assert "".join(stream.text_stream) == "hello"
print(f"OpenAI {openai.__version__} and Anthropic {anthropic.__version__}: JSON and SSE passed")
