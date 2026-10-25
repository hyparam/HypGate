# Verified authorization core

The verified policy, authentication, and authorization core. The source is [policy.rs](../crates/gateway-core/src/policy.rs).

## Checked boundary

The operator provisions identity digests, root grants, origin count, and credential
ownership. Candidate routes are untrusted. Validation rejects unknown tenants,
invalid origin or credential indices, cross-tenant credentials, routes outside the
root grants, and duplicate tenant/selector bindings. Identity digests must contain
32 bytes; duplicate tenants or digests are rejected. A successful validation result
preserves the supplied root snapshot in ghost state and satisfies all of these
constraints. Root grants, origin count, and credential-owner indices are needed
at validation time but not during runtime dispatch, so the validated `Policy`
stores them as erased `Ghost` fields. Runtime policy storage retains only the
identity table and selected routes. Validation still checks the actual input
vectors before producing these snapshots; no assumed grant or ownership facts
replace those checks. Authentication and authorization contracts are unchanged. Deliberate mutations
that replace either ghost snapshot with an empty sequence are rejected by the
proofs, in addition to mutations that bypass grant and credential validation.

Authentication matches an input digest against the immutable identity table.
Authorization then selects only that tenant's configured route and rejects a zero
request ID. Private-constructor `Authenticated` and `AuthorizedRequest` tokens
borrow the actual policy snapshot; they cannot be constructed or cloned by callers.
Verified accessors return the authorized origin, credential, tenant, and request ID.
The root grant includes the exact tenant, selector, origin, and credential tuple.

## Assumptions and remaining obligations

The runtime configuration layer hashes gateway tokens with SHA-256 before
authentication. This hashing and its cryptographic security are not verified.
HTTP authentication header parsing is tested in the [HTTP boundary](http-boundary.md);
secure token provisioning remains an operator obligation. Digest comparison
scans every byte but carries no constant-time theorem. Tests use synthetic digests.

Origins and credentials are numeric handles, not URLs or secrets. The transport
consumes the routed wrapper and uses the same immutable mapping snapshot, without
accepting independent destination or credential overrides; see the
[end-to-end audit](end-to-end-audit.md) for implementation and test evidence.
Fixed endpoint URI validation and secret loading are tested in the
[configuration layer](configuration.md). DNS, TLS, and proxy/redirect disabling
remain adapter obligations; header filtering and credential injection are proved in
`headers`. Root-policy intent is a trusted input;
candidate configuration cannot enlarge that policy.

Nonzero request IDs are not inherently unique. Composition with the resource
registry enforces uniqueness within its instance, and the verified initial
stream constructor binds the token and resource key. The runtime owns the
request/stream lifetime; its release composition is checked in the
[ownership composition](ownership-composition.md). The registry bounds logical
slots and payload allowances, not total process memory. The checked chain ends at
`ResolvedRoute::write_bytes`; the socket write and disk syscall themselves are
trusted.

## Evidence

Source-contract mappings are in the [proof index](proof-index.md); current check,
test, and mutation totals are maintained in the [README](../README.md). Policy tests
include 108 candidate configurations plus invalid identities and authorization
failures.

Seven authorization mutations exercise
unauthenticated identity acceptance, cross-tenant routing, expanded root grants,
cross-tenant credentials, unknown origins, wrong origin accessors, and ambiguous
identities. A mutation counts only when a proof obligation fails, not when the
source merely fails to compile. Reproduction commands are in the [README](../README.md).
