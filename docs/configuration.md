# Static configuration boundary

The runtime parses two separate JSON inputs: an operator-controlled root policy
and an untrusted candidate route selection. `GatewayConfig::from_json` receives an
operator-controlled secret resolver; the executable resolves named environment
variables. See [running](running.md) for the command-line interface.
Never permit a caller to supply root policy or the secret resolver.

## Root policy format

The root object has exactly these fields:

- `identities`: records containing `tenant` (u64) and `sha256` (64 hexadecimal
  characters encoding the hash of a high-entropy gateway token).
- `destinations`: fixed HTTPS endpoint strings, indexed from zero. For example,
  `https://api.openai.com/v1/responses` or
  `https://api.anthropic.com/v1/messages`. Each includes its fixed native API path
  and is limited to 8,192 ASCII bytes, including scheme and authority. Oversized
  endpoints are rejected before credential resolution.
- `credentials`: records containing `tenant`, `kind` (`bearer` or `api_key`), and
  `env` (the name passed to the secret resolver). Secret values are not JSON fields.
- `grants`: records containing `tenant`, `selector`, `origin` (destination index),
  and `credential` (credential index).
- `limits`: `requests` and `chunk_bytes`, both positive integers.
- `logging`: `strict` or `availability`.

The candidate object contains only `routes`, whose entries use exactly the grant
record format. Every selected tuple must occur in the root grants and must satisfy
the verified tenant, identity, and handle constraints. An empty route selection
is allowed and grants no forwarding authority. No fallback or URL override exists.

Input is bounded to one MiB per JSON document before parsing. Unknown and duplicate
object fields are rejected. Limits allow at most 65,536 request slots and one MiB
per chunk, with their product at most 128 MiB. This is a logical payload allowance,
not a total memory guarantee or a recommended deployment setting.

## Destination and credential binding

Destination validation is the verified `gateway_core::destination::parse`. It
accepts exactly the texts of the form HTTPS, a conventional ASCII DNS name or
bracketed IPv6 address, an optional nonzero port, and a fixed path; both
directions are proved, so every such text is accepted and userinfo, fragments,
queries, backslashes, control characters, encoded authorities, ambiguous hosts,
and paths starting with two slashes are rejected. The authority, host, port, and
path the runtime uses are proved to be exactly the substrings of the configured
text, and the verified writer puts that path in the request line. No client path is joined onto
this endpoint. New API paths need explicitly granted endpoints; this initial
interface does not support dynamic query parameters.

Admission hashes the supplied raw gateway token with the verified SHA-256
(`gateway_core::sha256`, proved against its FIPS 180-4 spec), invokes the verified
policy admission path, then resolves the authorized handles within that same
immutable configuration. A private-constructor `RoutedRequest` owns the admitted
request and borrows its destination and credential; callers cannot replace them.
Tokens are bounded to 512 bytes. Token entropy and secure provisioning are operator
obligations; this is not a password authentication mechanism.

Bearer credentials produce an `authorization` header; API-key credentials produce
`x-api-key`. Loaded values must be nonempty visible ASCII without spaces, at most
8,192 bytes. HTTP header values are marked sensitive. Credentials and routed
requests have no Debug implementation, and configuration errors contain only
categories, never input strings or secret values. Secret memory is not zeroized.

## Evidence and remaining work

Six configuration unit tests cover native provider endpoint/credential bindings,
invalid authentication, forbidden routes, hostile destinations, invalid limits and
digests, cross-tenant credentials, malformed schemas, and secret/header injection.
See [contributing](../CONTRIBUTING.md) for validation commands. Live Anthropic
Messages and OpenAI Responses exchanges, JSON and SSE, passed through these
bindings on 2026-10-25; the [HypAware setup](hypaware.md#smoke-test-record)
records the run.

JSON parsing is verified (`gateway_core::json`), and so is the schema walk
(`gateway_core::config_schema`: which keys each object may hold, once each,
which are required, and of what kind; the reader accepts exactly that shape and
returns the fields the file holds), and so are the rules on values
(`gateway_core::config_values`: a digest is 64 hex digits decoding to 32
bytes, a secret name is 1 to 128 alphanumeric or underscore bytes, a
credential or token is visible ASCII within its limit, and the header value
built from a credential, with its `Bearer ` prefix, holds no control byte, so
no line break can enter a request head; the shipping limits and state
directory are within their ranges). Destination validation is verified, as is
the check that a bracketed host is an IPv6 address (`gateway_core::ipv6`, the
RFC 4291 text grammar as the standard library reads it) and the check that
every configuration string is UTF-8 (`gateway_core::utf8::is_valid`). SHA-256
hashing is verified against the core FIPS 180-4 specification.
Secret resolution and the runtime mapping are trusted and tested, not
formally verified. The core theorem still concerns
normalized route handles. The HTTP adapter consumes `RoutedRequest`; the verified
header projection strips client credential headers and constructs Host from the
fixed destination, while disabling redirects/proxies/retries and retaining request
ownership during effects are adapter obligations. Authentication header parsing
lives in the [HTTP boundary](http-boundary.md). DNS and TLS validation, disk logging, and
network-level IP restrictions are not implemented here. Approved destinations may
resolve to private IPs: this is origin confinement, not an SSRF/IP-range theorem.

## Verified normalized resource limits

The JSON adapter calls `resource::validate_limits` in the production core.
Its result is true exactly when requests are between 1 and 65,536, chunk size is
between 1 and 1,048,576 bytes, and their mathematical product is at most
134,217,728 bytes (128 MiB). Guarded conversion and multiplication are proved safe;
zero, excessive individual limits, and excessive combined allowance are rejected.
The adapter still rejects these configurations before loading provider secrets.
Tests cover exact boundaries, one-over-boundary values, and maximum machine integers.

This preserves the existing configuration policy. It does not establish that
process RSS is below 128 MiB: the allowance covers one payload chunk per admitted
request. HTTP/TLS/log buffers, allocator overhead, and other runtime state require
separate accounting. JSON parsing and the use of the validated values to construct
the runtime registry remain trusted bindings.

## Configuration storage and startup scratch

Let I be the number of identities, A the selected route count, D the destination
count, and C the credential count. The immutable configuration retains:

- I identity structs with a 32-byte digest vector each.
- A route structs. Root-grant structs, origin count, and credential-owner indices
  are kept only as erased proof snapshots after successful core validation.
- D parsed URI values and their backing strings, with at most 8,192 input bytes
  per destination.
- C credential structs and header values. Each value holds at most 8,199 bytes
  including the seven-byte bearer prefix (API keys need at most 8,192).
- The request registry, with R `u64` slot entries and fixed-size metadata. The
  server's separate worker registry has another R entries.

If U denotes the total retained URI component bytes, a conservative logical
variable-content subtotal is **32 × I + U + 8,199 × C** bytes, in addition to the
struct arrays and registry entries. Counts are fixed after construction and
bounded by the input documents; accepted decoded strings cannot expand beyond
their JSON representation, apart from URI default-path representation. This is
not a retained-allocation theorem: URI/HeaderValue shared backing, vector spare
capacity, allocator rounding, and object metadata require separate accounting.
The one-MiB input limit is not a one-MiB total configuration-memory limit.

The executable scopes both source JSON vectors to configuration construction, so
they are dropped before TLS, logger, listener, and server creation. Each file read
accepts at most one MiB plus a sentinel byte before the parser's size check.
Destination input strings are consumed during URI conversion, rather than retained
through all credential loading. Identity/grant/candidate input vectors are consumed
by normalization and validation; source grants and credential-owner vectors drop
when core validation returns because their resulting policy fields are ghost-only.
Successful construction owns all runtime data and borrows neither source JSON.

Parsing can temporarily hold source documents, deserialized structs/strings, and
normalized output simultaneously. The per-credential resolver can allocate its
returned String before its 8,192-byte length is checked; caller-owned buffers and
custom resolver behavior are outside the gateway's allocation guarantees. The CLI
also inherits process environment storage, which is neither zeroized nor accounted
by the per-request payload theorem. Failure-path cleanup relies on Rust ownership.
