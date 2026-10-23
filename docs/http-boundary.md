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
