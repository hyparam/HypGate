# Security contract

The security properties the gateway must have, and where each one stands. Core
authorization, normalized configuration, streaming, resource, and upstream-mediation
properties are checked by Verus. Production body writes pass the checked
`ResolvedRoute::write_bytes` gate ([ownership composition](ownership-composition.md)),
and the [end-to-end audit](end-to-end-audit.md) traces that mediation through every
effect site and failure exit. Hyper, TLS, DNS, and the OS remain trusted adapters,
and there is no single mechanized theorem over the async runtime. The
[authorization notes](authorization-core.md) give the exact boundary.

## Threat and policy boundary

Treat request bodies, headers, URI components, route selectors, and candidate
configuration as untrusted. Keep the operator's root security policy separate:
it grants principals/tenants access to approved origins and credential handles.
Configuration may select within those grants, never enlarge them. A proof cannot
establish that an arbitrary administrator-supplied root policy expresses the
administrator's intended security policy. Root-policy provisioning, authentication
evidence, and secret loading need explicit trust assumptions.

Start with static policy snapshots, fixed routes, no redirects, no fallback, and
no automatic request replay. No general RBAC system or provider-body interpretation
is required to enforce a simple principal-to-route permission relation. The identity
and credential ownership mechanism must be settled before exposing an endpoint.

## Required properties

| Property | Obligation | Current status |
| --- | --- | --- |
| Authorization | Every upstream dispatch is justified by an authenticated principal's grant for that route and policy snapshot. Unknown identities, missing grants, and validation errors produce no dispatch. | Digest identity and tenant-scoped token issuance proved; HTTP authentication is tested; production dispatch is bound through the checked `ResolvedRoute::write_bytes` gate, with Hyper/TLS/DNS delivery trusted. |
| Tenant isolation | A principal cannot select another tenant's credential, route grant, request state, or private audit destination. Async completion cannot attach to another live request. | Local owner/ticket checks and authenticated token tenant binding proved; cross-owner lifecycle composition is checked (`cleanup_before_reuse`); audit-file access control remains an operator obligation. |
| Credential confinement | Only the credential handle authorized for the tenant and exact origin may reach the secret-bearing transport operation. Gateway authentication material is never forwarded upstream; credential headers are excluded from client-visible metadata, audit metadata, and diagnostics. | Authorized handles satisfy tenant ownership and exact root grants; secret loading and header filtering are tested; the transport consumes only the resolved route's credential, with header serialization trusted to Hyper. |
| Routing integrity | Effective scheme, host, port, and route template come from validated policy, not arbitrary request fields, provider response headers, ambient proxy settings, or unvalidated configuration. | Normalized origin handles confined to root grants; fixed HTTPS endpoint parsing is tested; socket/TLS naming derives from the resolved destination, with URI parsing, DNS, and TLS name checks trusted. |
| Security failure is closed | Authentication, authorization, destination validation, and credential selection failures never permit upstream dispatch. | Invalid core authentication/configuration cannot yield authority; dispatch mediation is audited at the source level in the end-to-end audit. Distinct from logging policy. |
| Logging policy | Strict mode gates write ranges on durable acknowledgments. Availability-first mode may forward without complete audit coverage but still requires all security checks. | Exact durable receipts gate stream bytes; ordered recovery is proved under explicit storage/read/checksum assumptions. Linux ext4 failure/process-death tests passed; physical persistence remains trusted. |
| Configuration confinement | For every candidate configuration, validation either rejects it or constructs routes whose tenant, origin, and credential bindings satisfy the root grants. | Proved for normalized tenant, selector, origin, and credential handles; textual configuration parsing is implemented and tested, not proved. |

These properties cover gateway-controlled effects. An opaque body may contain a
user-supplied secret, and an upstream may echo data it received. Preserving and
logging raw bodies cannot also guarantee that no secret value ever appears in a
body. Credential confinement must not be advertised as arbitrary content secrecy,
timing noninterference, or security against a malicious approved provider.

## Make dispatch require verified evidence

The core issues a private-constructor `AuthorizedRequest` through verified,
synchronous admission that combines authenticated identity, validated
configuration, and root policy. Bind the token to the tenant, unique request
identity, immutable policy snapshot, exact destination, and credential handle.
Currently the token binds a nonzero request ID; uniqueness and resource ownership
require composition with the registry. Destinations and credentials are handles;
the configuration layer preserves their immutable mapping to actual endpoints
and secrets in a routed request, and the transport consumes only that wrapper.
See [configuration](configuration.md) for tested parser scope and remaining obligations.
Do not implement public deserialization, arbitrary constructors, or unrestricted
cloning for the token.

The transport entry point consumes that token; it must not accept separate raw
destination or credential overrides. Route/credential fields are not mutable after
authorization. Request-body stream handles and completion capabilities must remain
bound to the authorized request. Invalid input must not produce a token.

Rust visibility and ownership help prevent accidental bypass in safe code; they
do not prevent trusted transport code from opening its own socket. Keep all outbound
connections in one reviewed module, enumerate every dispatch path, and test that
none bypasses the token boundary. Verus proves token issuance and core transitions;
module structure, dependency review, and adapter checks support complete mediation.
If policy reload is added later, specify revocation and in-flight snapshot semantics
before implementing it; do not silently reinterpret old tokens under new policy.

Resource admission is separate: a capacity reservation or write ticket does not
authenticate a caller or authorize a destination. Use distinct types and names.

## Validate configuration before it becomes policy-bearing state

Validation should reject unsupported schemes, userinfo, malformed/ambiguous origins,
unknown tenants or credentials, duplicate/contradictory bindings, out-of-policy
destinations, and invalid limits. Resolve a route selector against a validated
table; never treat it as a URL. Construct outbound authority/Host from the chosen
route, strip inappropriate hop-by-hop headers, and prevent headers or path joining
from overriding the origin. Disable automatic redirects and ambient proxy discovery.

The URI parser, DNS resolver, TLS peer validation, connection pool, and HTTP request
builder must honor the exact origin binding. Origin confinement alone is not an
IP-range/SSRF theorem: if network-range restrictions are required, enforce them on
resolved connections as well and specify DNS/rebinding behavior. Test these adapter
obligations without claiming the parser or networking libraries are verified.

No fallback is in scope. If later introduced, each destination needs its own grant
and correctly scoped credential; a fallback cannot inherit authority merely because
an earlier request was allowed.

## Synchronous proofs, asynchronous execution

Keep authentication evidence validation, route admission, policy decisions, write
reservation, and completion transitions in a synchronous state machine. The async
shell supplies events and executes only its allowed actions. It must preserve owner,
generation, policy, and destination bindings across awaits, cancellations, errors,
partial writes, and shutdown.

Cancellation cannot retract bytes already submitted to the OS. Known completion
may still be recorded; an unknown outcome cannot justify replay. Bound outstanding
effects and resource lifetimes, and define every error transition before connecting
the core to an executor. Fairness, I/O progress, and deadline behavior need separate
assumptions and tests; state-machine safety does not imply availability.

## Trusted computing base and evidence

For each theorem, publish its exact scope and preconditions. The current trust
boundary includes Verus and its translation/solver, vstd specifications, rustc/LLVM,
standard-library implementations, allocation behavior, and platform execution.
Runtime dependencies include the adapter, Tokio, Hyper, rustls, OS sockets/filesystem,
DNS/PKI, secret provisioning, and authentication bindings. None is automatically
verified by adding Verus contracts to the core.

The optional [cloud shipper](cloud-shipping.md) adds one trusted component: a
thread in the same process that reads the audit log and uploads to one
configured HypAware server with a credential that server issued. Every
decision about what to send is made by the verified shipper machine, whose
requests carry a path and a body but no host and whose only body containing
the operator token is a bootstrap; the verified driver loop feeds it, and the
thread performs those requests against the client built from the configured
server under an `egress::Egress` permit, the same permit type the provider
transport requires. Every other socket, lookup, listener, file write, and
secret read in the runtime is denied by `clippy.toml` and the audited sites
are pinned by `scripts/check_effect_sites.sh`. The token is confined by
ownership and module structure, not by a process boundary: it is read once at
startup, moved into the machine, and never placed in the gateway
configuration, on the request path, or in the log. The shipper has no handle
to admission, routes, credentials, or the logger, so it cannot enlarge grants
or change destinations; the HypAware server's ledger and dedup behavior are
trusted for exactly-once storage, never for any security property above.

Track each external contract separately: what is assumed, why it is reasonable,
which component fulfills it, and what tests exercise it. Do not replace an unproved
security obligation with an `assume` and then describe the result as a proof of it.

Dispatching traffic required checked admission/token-issuance properties and
negative tests for unknown identities, cross-tenant credentials, host/header
overrides, unsafe configuration, redirects, and every error path; those are in place
and mapped in the [end-to-end audit](end-to-end-audit.md). Provider compatibility tests and
fault injection supplement these proofs; they do not substitute for them.
