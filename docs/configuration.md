# Static configuration boundary

The runtime reads one operator-controlled JSON file, conventionally named
`config.json`. `GatewayConfig::from_json` receives that file's bytes and an
operator-controlled secret resolver; the executable resolves named environment
variables. Never let a request caller supply configuration or the secret resolver.

## Configuration format

The configuration has these required fields (and an optional
[`shipping`](cloud-shipping.md) section):

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

Every entry in `grants` is active. Each binds a tenant and route selector to
one destination and credential. The verified builder rejects invalid references,
ambiguous routes, and credentials owned by another tenant. Empty grants allow
health checks but no forwarding. No fallback or URL override exists.

Configuration changes require a restart.

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
8,192 bytes. Credentials and routed
requests have no Debug implementation, and configuration errors contain only
categories, never input strings or secret values. Secret memory is not zeroized.

## Validation and scope

The verified core checks JSON syntax, schema, destination grammar, credential
values, and tenant bindings before provider secrets are loaded. The runtime
selects every configured grant for the core's policy builder. Tests cover invalid
references, cross-tenant credentials, malformed input, and header injection;
see [contributing](../CONTRIBUTING.md) for validation commands and the
[proof index](proof-index.md) for exact contracts.

Approved destinations may resolve to private IPs. Destination confinement does
not enforce network-level IP restrictions; DNS, TLS, environment access, and
runtime effects retain their documented trust assumptions.

The one-MiB input limit and the 128-MiB request-payload allowance are not total
process-memory limits. Loaded configuration retains identity digests, route
bindings, parsed destination byte vectors, and credential bytes. Parsing and
secret resolution also need temporary allocations; source JSON is dropped before
server startup. See [resource composition](resource-composition.md) for memory
accounting and its assumptions.
