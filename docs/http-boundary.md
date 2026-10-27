# HTTP metadata boundary

The verified HTTP/1.1 parser ([codec](http1-codec.md)) delivers each head as
byte fields; the runtime hands them to the verified projection in
`gateway_core::headers` and the verified writer serializes the result.
The route selector and the bearer token are parsed by the verified
`gateway_core::inbound`; the admission binding is tested Rust. The header, canonical selector, and token parsers have soundness and
completeness contracts. The SDK splitter proves both acceptance and rejection against its canonical
route-prefix and suffix-boundary specification; the endpoint comparison is exact. No sockets, TLS, request bodies, response bodies,
or disk effects are implemented in this layer.

Clients use `POST /routes/<selector>` or append the configured endpoint path
for SDK calls, with one `Authorization: Bearer <gateway-token>` header.
`inbound::route_selector` accepts exactly the canonical route spelling;
`route_target` proves that the selected prefix is that spelling and the optional
suffix begins with a slash. After admission, `matches_endpoint` requires that
suffix to equal the fixed destination path. It never changes the destination.
Escaped selectors, leading zeros, out-of-range values, absolute URLs, queries,
and mismatched suffixes are rejected. A suffix mismatch releases the admitted
capacity before any upstream connection or audit effect.
Proved by `inbound::bearer`: the token is accepted
exactly when there is one Authorization field, its scheme is `bearer` in any case,
and the token is one to 512 token characters. Authorization is still decided by
the verified tenant-scoped policy. Capacity exhaustion returns an unavailable error.

The resulting private-constructor `PreparedRequest` owns the admitted routed request
and its capacity lease. Its URI is the configured HTTPS endpoint, Host comes from
that endpoint's authority, and its credential is loaded from the same policy
snapshot. It has no public cloning, mutation, or raw-request extraction API.
The transport consumes this object and retains it through response work.

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
Request-Id, and X-Request-Id, excluding every Connection-nominated field, and a
response whose Connection header nominates Content-Encoding is rejected, so an
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
Network dispatch, body forwarding, and logging are covered by the
[HTTPS transport](https-transport.md), [body transfer](body-transfer.md), and
[running](running.md) notes.

## Metadata ownership and allocation

The driver passes the parsed `RequestHead` to `prepare` (the `admit` effect)
and drops it as soon as the prepared request exists, before any network
effect; it passes the final `StatusHead`'s fields to the verified
`headers::forward_response` and keeps only the projection. The parser already
made every field its own vector copy, so no field shares storage with the read
buffer or with other fields, and dropping the head frees everything the
projection did not copy.

The verified projection copies each allowed field's bytes into a fresh vector
and keeps its sensitive flag. Static allowlisted header names require no copy
of an input name. Configured provider credentials remain shared with their
immutable configuration; they are not derived from input header storage.

The verified parser caps the complete wire head, including its start line and
delimiters, at 32 KiB and 100 fields (proved). The projection's `fits` check
independently allows at most 100 values and 32 KiB of header names plus values.
Consequently, each filtered request or response owns at most 32 KiB of copied
value contents. Requests additionally insert the configured Host, credential,
and `accept-encoding: identity`. If H is the configured authority spelling length,
a conservative outgoing request name/value subtotal is 41,007 + H bytes, with at
most 103 values. The configured full HTTPS URI is now capped at 8,192 bytes. If P is its
origin-form path length, H + P is conservatively at most 8,192 (including default
path handling); this uses the whole-URI limit, not an assumption about port
spelling length. Configuration validation rejects oversize before secret loading.
Wire separators and start lines are budgeted in the
[written head lengths](dependency-resources.md#written-head-lengths), which put
production request and response heads below 64 KiB under the verified writer.
Vector spare capacity and allocator slack remain outside these logical
wire-length bounds.

The verified Connection parsing validates every comma-separated element,
including unknown names, but retains only distinct allowlisted names: at most
five for requests and six for responses. A repeated or irrelevant element list
cannot create an arbitrarily long retained list. The retained list is proved
exact: every retained name is a trimmed, lowercased element of some Connection
value, and every allowlisted name that any element lowercases to is retained
(`headers::complete`). The response Content-Encoding rule is therefore the exact
nomination test, not an approximation.

Regression tests preserve opaque non-ASCII header bytes, repeated value order,
status, and sensitivity flags, reject an invalid unknown Connection token after
a long valid list, and serialize the maximum request and response heads. Existing
filtering and upgrade tests still apply. This is source-level lifetime evidence,
not a Verus heap theorem: a library caller can retain other references, and
releasing an allocation does not zeroize its contents or require the allocator
to return pages to the OS.
