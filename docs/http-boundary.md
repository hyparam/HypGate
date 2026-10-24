# HTTP metadata boundary

The trusted runtime now prepares upstream request metadata. No sockets, TLS,
request bodies, response bodies, or disk effects are implemented in this layer.
The boundary is tested Rust, not an additional Verus proof.

Clients use `POST /routes/<selector>` with one `Authorization: Bearer <gateway-token>`
header. Scheme matching is case-insensitive; duplicate credentials, malformed token
syntax, absolute-form URLs, queries, escaped selectors, extra path components, and
noncanonical decimal selectors are rejected. Authorization is still decided by
the verified tenant-scoped policy. Capacity exhaustion returns an unavailable error.

The resulting private-constructor `PreparedRequest` owns the admitted routed request
and its capacity lease. Its URI is the configured HTTPS endpoint, Host comes from
that endpoint's authority, and its credential is loaded from the same policy
snapshot. It has no public cloning, mutation, or raw-request extraction API.
The future transport must consume this object and retain it through response work.

Only Content-Type, Accept, Anthropic-Version, Anthropic-Beta, and OpenAI-Beta are
copied from client headers. Connection-nominated headers are removed. Gateway
Authorization, caller API keys, cookies, proxy headers, forwarding headers, and
framing headers are discarded; the root-authorized credential is injected afterward.
Upload Content-Encoding, Upgrade, and Trailer are rejected. Duplicate Content-Type
or Anthropic-Version headers are rejected. The HTTP library must generate framing
from the actual body stream, not discarded client metadata.

The adapter requests identity response encoding. If an upstream nevertheless sends
encoded bytes, it must forward them unchanged with Content-Encoding; there is no
automatic decompression. Response metadata is limited to Content-Type,
Content-Encoding, Cache-Control, Retry-After, Request-Id, and X-Request-Id, excluding
Connection-nominated fields. A Connection nomination of Content-Encoding is rejected
to avoid misrepresenting encoded bytes. Cookies, credential headers, and Location
are excluded. A future transport must preserve status and return redirects without
following them; this metadata code cannot itself establish no-redirect behavior.

Header maps are capped at 100 values and 32 KiB of name/value bytes. These are
post-parsing checks: the future server must also cap header allocation in its parser.
Malformed upstream metadata must become a gateway failure, not successful output.
Errors contain categories only. Body content remains opaque and may contain or
echo secrets; header filtering is not arbitrary content secrecy.

Six boundary tests cover fixed destination/credential binding, caller header
overrides, duplicate/malformed authentication, forbidden paths and methods,
Connection nominations, header limits, admission cleanup, and response filtering.
All 24 workspace tests passed on 2026-10-23. No live provider was contacted.
Next: network dispatch, exact body forwarding through the stream core, and logging.

## Metadata ownership and allocation

The production server consumes request `Parts` through `prepare_request_parts`;
the transport consumes response `Parts` through `prepare_response_parts`. These
synchronous boundaries finish and destroy the original metadata, including
extensions, before the caller can await DNS, response output, or body streaming.
The borrowed preparation functions remain available for library callers, who own
and must budget their original input metadata separately.

Filtering copies each allowed HeaderValue's visible bytes with `from_bytes`, then
preserves its sensitive/redaction flag. It does not clone shared input backing.
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

Connection-header processing validates every comma-separated token, including
unknown names, but retains only distinct names relevant to the allowlist: at most
five for requests and six for responses. A repeated/irrelevant token list cannot
create an arbitrarily long retained options vector. Parsing one token still uses
HeaderName validation scratch; the 32 KiB input limit bounds its visible bytes.

Regression tests supply small headers backed by 256 KiB owners and metadata
extension drop probes. Both original owners must be destroyed while prepared
output remains live. Tests preserve opaque non-ASCII header bytes, repeated value
order, status, and sensitivity flags, and reject an invalid unknown Connection
token after a long valid list. Existing filtering and upgrade tests still apply.
This is source-level lifetime evidence, not a Verus heap theorem. Hyper or a
library caller can retain other references, and releasing an allocation does not
zeroize its contents or require the allocator to return pages to the OS.
