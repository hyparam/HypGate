# HTTP metadata boundary

The runtime converts Hyper's header maps to byte fields, hands them to the
verified projection in `gateway_core::headers`, and converts the result back.
The route selector and the bearer token are parsed by the verified
`gateway_core::inbound`; the admission binding is tested Rust. Every header,
selector, and token rule below is proved. No sockets, TLS, request bodies, response bodies,
or disk effects are implemented in this layer.

Clients use `POST /routes/<selector>` with one `Authorization: Bearer <gateway-token>`
header. Proved by `inbound::route_selector`: a path is accepted exactly when it is
`/routes/` followed by the canonical decimal of a `u64`, so escaped selectors,
extra path components, leading zeros, and out-of-range values are rejected and
every canonical selector is accepted. Absolute-form URLs and queries are rejected
before the path is parsed. Proved by `inbound::bearer`: the token is accepted
exactly when there is one Authorization field, its scheme is `bearer` in any case,
and the token is one to 512 token characters. Authorization is still decided by
the verified tenant-scoped policy. Capacity exhaustion returns an unavailable error.

The resulting private-constructor `PreparedRequest` owns the admitted routed request
and its capacity lease. Its URI is the configured HTTPS endpoint, Host comes from
that endpoint's authority, and its credential is loaded from the same policy
snapshot. It has no public cloning, mutation, or raw-request extraction API.
The future transport must consume this object and retain it through response work.

Proved by `headers::forward_request`: only Content-Type, Accept,
Anthropic-Version, Anthropic-Beta, and OpenAI-Beta are copied from client headers,
each byte for byte; Connection-nominated names among them are removed; gateway
Authorization, caller API keys, cookies, proxy headers, forwarding headers, and
framing headers never appear; the root-authorized credential, Host, and
`Accept-Encoding: identity` appear exactly once each. Upload Content-Encoding,
Upgrade, and Trailer are rejected, as are duplicate Content-Type or
Anthropic-Version headers. The HTTP library must generate framing from the actual
body stream, not discarded client metadata.

The gateway requests identity response encoding. If an upstream nevertheless sends
encoded bytes, it must forward them unchanged with Content-Encoding; there is no
automatic decompression. Proved by `headers::forward_response`: response metadata
is limited to Content-Type, Content-Encoding, Cache-Control, Retry-After,
Request-Id, and X-Request-Id, excluding Connection-nominated fields, and a
response whose Connection header mentions Content-Encoding is rejected, so an
encoding is never dropped while its bytes are kept. Cookies, credential headers,
and Location are excluded. A future transport must preserve status and return redirects without
following them; this metadata code cannot itself establish no-redirect behavior.

Proved: heads over 100 fields or 32 KiB of name and value bytes are refused. These
are post-parsing checks; the server also caps header allocation in its parser.
Malformed upstream metadata must become a gateway failure, not successful output.
Errors contain categories only. Body content remains opaque and may contain or
echo secrets; header filtering is not arbitrary content secrecy.

Boundary tests exercise the same rules end to end: fixed destination/credential
binding, caller header overrides, duplicate/malformed authentication, forbidden
paths and methods, Connection nominations, header limits, admission cleanup, and
response filtering.
Workspace test totals are maintained in the [README](../README.md). No live provider
was contacted. Network dispatch, body forwarding, and logging are covered by the
[HTTPS transport](https-transport.md), [async transfer](async-transfer.md), and
[running](running.md) notes.

## Metadata ownership and allocation

The production server consumes request `Parts` through `prepare_request_parts`;
the transport consumes response `Parts` through `prepare_response_parts`. These
synchronous boundaries finish and destroy the original metadata, including
extensions, before the caller can await DNS, response output, or body streaming.
The borrowed preparation functions remain available for library callers, who own
and must budget their original input metadata separately.

The verified projection copies each allowed field's bytes into a fresh vector;
the runtime rebuilds each HeaderValue with `from_bytes` and preserves its
sensitive/redaction flag. Nothing clones shared input backing.
This matters because a tiny HeaderValue can own a slice of a much larger parser
buffer, including unrelated headers. Static allowlisted header names require no
copy of an input name. Configured provider credentials remain shared with their
immutable configuration; they are not derived from input header storage.

Both production HTTP/1 parsers cap the complete wire head, including its start
line and delimiters, at 32 KiB and 100 fields. The subsequent adapter checks also
allow at most 100 values and 32 KiB of header names plus values.
Consequently, each filtered request or response owns at most 32 KiB of copied
value contents. Requests additionally insert the configured Host, credential,
and `accept-encoding: identity`. If H is the configured authority spelling length,
a conservative outgoing request name/value subtotal is 41,007 + H bytes, with at
most 103 values. The configured full HTTPS URI is now capped at 8,192 bytes. If P is its
origin-form path length, H + P is conservatively at most 8,192 (including default
path handling); this uses the whole-URI limit, not an assumption about port
spelling length. Configuration validation rejects oversize before secret loading.
Wire separators and start lines are budgeted in the
[serialization audit](dependency-resources.md#serialized-head-lengths), which puts
production request and response heads below 64 KiB under the pinned serializer.
HeaderMap storage, value metadata, allocator slack, and Hyper's backing capacities
remain outside these logical wire-length bounds.

The verified Connection parsing validates every comma-separated element,
including unknown names, but retains only distinct allowlisted names: at most
five for requests and six for responses. A repeated or irrelevant element list
cannot create an arbitrarily long retained list. Every retained name is proved to
be an element of some Connection value (soundness); that the parser finds every
element is not a theorem, which is why the response rule is a substring check
that covers every nomination.

Regression tests supply small headers backed by 256 KiB owners and metadata
extension drop probes. Both original owners must be destroyed while prepared
output remains live. Tests preserve opaque non-ASCII header bytes, repeated value
order, status, and sensitivity flags, and reject an invalid unknown Connection
token after a long valid list. Existing filtering and upgrade tests still apply.
This is source-level lifetime evidence, not a Verus heap theorem. Hyper or a
library caller can retain other references, and releasing an allocation does not
zeroize its contents or require the allocator to return pages to the OS.
