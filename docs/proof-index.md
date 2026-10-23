# Proof index and composition boundary

The production proofs live beside executable Rust in `crates/gateway-core/src`.
Cargo compiles these sources into the gateway; Verus checks their contracts.
A specification function defines a property, an invariant describes valid states,
and executable function postconditions establish what a transition preserves or
changes. Most guarantees are established by these postconditions, not by a separate
file of named lemmas. Ghost histories are erased from the executable.

Read each `requires` clause before interpreting an `ensures` clause. Runtime code
in `gateway-runtime` is ordinary Rust and must supply valid states and truthful
external events. Checking the core does not mechanically verify those call sites.
The [adapter audit](adapter-audit.md) records tested bindings to network and disk
operations. Tests and proof mutations complement the contracts but do not enlarge
their formal scope.

## Claims and their checked sources

| Claim | Checked definitions and operations | Remaining binding or assumption |
| --- | --- | --- |
| Candidate routes cannot expand root grants or select another tenant's credential | [policy.rs](../crates/gateway-core/src/policy.rs): `allowed`, `Policy::valid`, `Policy::validate` | Root-policy intent, JSON parsing, and mapping handles to concrete URLs/secrets are trusted. |
| Issued authority belongs to an authenticated tenant and configured route | Same module: `Policy::authenticate`, `Authenticated::authorize`, `AuthorizedRequest::valid`, verified accessors | Token provisioning and SHA-256 are trusted. Actual dispatch through the wrapper is audited/tested, not formally proved. |
| Normalized request/chunk limits fit the configured combined allowance without arithmetic overflow | [resource.rs](../crates/gateway-core/src/resource.rs): `validate_limits` | Covers one chunk per slot; parser binding and total process memory remain separate. |
| Live resource IDs are distinct within one registry and stale release cannot free a replacement | [resource.rs](../crates/gateway-core/src/resource.rs): `ResourceAdmission::valid`, `acquire`, `capacity`, `release` | Keys must remain scoped to their registry. Runtime ownership controls when release occurs. |
| Initial stream ownership matches a live reservation and authority, with one creation per key | Same module: `authorized_stream`, `RequestKey::stream_claimed` | This covers construction, not the lifetime of every later async effect. Trusted code could bypass this path using lower-level constructors. |
| Active-count snapshots exactly count occupied slots and never exceed the slot limit | Same module: `occupied`, `usage` | The runtime lock supplies a coherent snapshot. Slots are not total memory, connections, or outstanding disk jobs. |
| Completed byte history is an unchanged ordered prefix of accepted input | [stream.rs](../crates/gateway-core/src/stream.rs): `StreamChunk::valid`, `pending_bytes`, `complete`, `advance`, `discard_completed` | The adapter must submit the returned slice once and report the actual accepted count. This does not prove peer receipt. |
| Strict-mode submitted ranges do not exceed the acknowledged durable prefix | Same module: `valid`, `acknowledge`, `prepare`, `fail_log` | The runtime `Request::audit_current` holds an exclusive request borrow across logging and acknowledges only the current chunk after logger success; raw numeric acknowledgment is not exposed by the runtime request API. The logger must truthfully report durability. Journal/stream acknowledgment composition is not yet a theorem. |
| Cancellation blocks new submissions while allowing completion accounting for an issued write | Same module: `cancel`, `prepare`, `pending_bytes`, `complete` | Async cancellation must drop or stop the corresponding operation. No-replay behavior of transport/proxy is structural and tested. |
| Ready core operations do not arbitrarily refuse progress | `resource.rs`: rejection postconditions of `acquire`, `authorized_stream`, `release`; `stream.rs`: rejection/success postconditions of `acknowledge`, `prepare`, `complete`, `advance`, `discard_completed`; `journal.rs`: exact success conditions of `begin`, `record_written`, `sync_succeeded`, `acknowledge` | Scheduler fairness, lock availability, finite input, allocation success, and I/O progress are external. Exhausted IDs intentionally reject work. |
| Log acknowledgment follows complete-write and sync state transitions | [journal.rs](../crates/gateway-core/src/journal.rs): `Journal::valid`, `begin`, `record_written`, `sync_succeeded`, `acknowledge`, `fail` | The disk worker must bind successful syscalls and immutable frame bytes to these events. Tickets stay within one journal/file. |
| Acknowledged bytes survive if the storage model preserves the synced prefix | Same module: `acknowledged_prefix_survives` | Preservation of synced bytes is an explicit precondition, not a proved filesystem or power-loss property. |
| Header encode/decode roundtrips and payload framing preserves exact supplied bytes | [framing.rs](../crates/gateway-core/src/framing.rs): `valid`, `encoding`, `decoded`, `encode`, `decode`, `encode_payload` | SHA-256 calculation/comparison, session-header parsing, and syscall bindings remain trusted. Header identities are structural data, not authentication evidence. |
| Recovery advances across complete bounded extents and defaults to stopped on a read attempt | Same module: `frame_end`, `Cursor::begin`, `Cursor::accept` | The runtime must truthfully report bytes read, validate checksums before acceptance, and drop the local ticket on failure. Tickets cannot cross readers. Full scanner refinement remains open. |

## End-to-end boundaries that remain unproved

There is no single theorem establishing that every byte reaching a provider has
an authorized tenant, correct credential, and durable audit record under every
async interleaving and physical crash. The missing steps include complete mediation
of network effects, stream-to-journal acknowledgment correspondence, scanner
refinement, and the storage contract. The [security contract](security-contract.md)
and [storage contract](storage-crash-contract.md) specify those boundaries.

There is also no whole-process memory theorem. Logical slot/chunk bounds are
verified; retained vector capacities, HTTP frame limits, queues, worker lifetimes,
and deadlines have runtime checks/tests. TLS/HTTP backing allocations, allocator
behavior, OS caches, and full resource-release composition remain outside that
proof. [Benchmarks](benchmarks.md) measure one workload rather than proving bounds.

Availability mode changes audit coverage after logging failure. Its authorization
path is the same runtime path as strict mode, but their complete noninterference
is not formally proved. Neither mode promises secrecy of arbitrary opaque body
contents, protection against a malicious approved provider, or exactly-once remote
execution. Origin confinement is not a resolved-IP-range/SSRF theorem.

## Verification trust and reproduction

The trusted verification stack includes Verus, its translation/solver, vstd
specifications, rustc/LLVM, and standard-library/platform behavior. The production
core introduces no `assume` or `external_body` escape. This does not remove trusted
specifications supplied by vstd. The runtime additionally trusts Tokio, Hyper,
rustls, cryptography, DNS/PKI, the OS/filesystem, root-policy provisioning, and
external TLS termination/proxy behavior.

Use the pinned toolchain and commands in the [README](../README.md). The
[mutation runner](../scripts/check_mutations.py) verifies the unmodified core
first, then checks isolated deliberately broken variants. A mutant must fail a
proof obligation; syntax/type failures do not count as successful rejection.
[CI](../.github/workflows/ci.yml) also runs executable tests and proxy-policy tests.
Verification-check totals are not counts of independent security guarantees.
