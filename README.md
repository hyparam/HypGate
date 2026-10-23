# Verified Gateway

Research toward a minimal LLM gateway: forward request bodies unchanged, stream
responses back, and record traffic to disk. No provider API translation.

Status: a runnable prototype with Verus-checked authorization, configuration,
streaming, and resource invariants. The network and disk adapters are tested;
end-to-end formal guarantees and production hardening remain incomplete.

## Important properties we aim to prove

These are the project's proof targets, not a claim that the whole gateway already
satisfies them formally. “Core proved” means a synchronous model or transition is
checked by Verus, conditional on the documented adapter contracts.

| Property | Intended guarantee | Evidence today |
| --- | --- | --- |
| Authorization and fail-closed security | Every upstream dispatch requires an authenticated tenant's grant; authentication or policy failures cannot authorize forwarding, in either logging mode. | Core token issuance proved; HTTP binding tested. Complete mediation remains a trusted adapter obligation. |
| Tenant and credential isolation | Requests, completions, and credentials cannot cross tenant/request boundaries; gateway authentication material never becomes an upstream credential. | Core tenant/credential-handle and ticket checks proved; secret/header handling tested. Composed isolation and audit access controls remain open. |
| Routing and configuration confinement | Candidate configuration and request fields cannot expand operator grants or change the authorized destination/credential binding. | Normalized configuration and route selection proved; URI, DNS, TLS, and actual dispatch remain trusted/tested. |
| Byte integrity and ordering | Forwarded body bytes form an unchanged, ordered prefix of the input, across chunks and partial writes, without skipped or duplicated advancement. | Core byte-prefix and completion properties proved; async HTTP integration tested. Peer receipt is not proved. |
| Strict audit-before-forwarding | Every submitted body range in strict mode is covered by a durable log acknowledgment for that request and chunk. | Core gate proved conditional on truthful acknowledgments; disk sync adapter tested. Filesystem crash guarantees remain open. |
| Crash-safe recovery | Recovery exposes only complete records, and acknowledged records survive every crash in the specified storage model. | Journal acknowledgment ordering and conditional synced-prefix survival proved; header encoding/decoding, frame extents, and scanner cursor transitions proved; scanner I/O tested. Process-kill recovery tested and storage assumptions documented; scanner refinement and power-loss validation remain open. |
| Cancellation and no replay | Cancellation prevents new submissions; uncertain effects, crashes, or failover never trigger automatic replay of a possibly executed generation. | Core cancellation/stale-event checks proved; transport has no replay path. Async cancellation and recovery composition remain unproved. |
| Resource bounds and safe release | Slots, buffers, queues, and outstanding operations stay within explicit budgets; capacity cannot be reused while work retaining it remains alive. | Logical slot limits and ID isolation proved; ownership, queues, and deadlines tested. Full allocation accounting and composed release proofs remain open. |
| Logging-mode separation | Availability mode may lose audit coverage but cannot relax authorization, routing, or tenant isolation; logging failure cannot create unbounded replacement work. | Core logging-mode transitions proved; bounded logger and failure handling tested. End-to-end composition remains open. |
| Honest completion and conditional progress | Failed/truncated streams cannot masquerade as successful completion; under stated scheduler and I/O assumptions, admitted work terminates or times out and releases resources. | EOF/error behavior and deadlines tested. Liveness and whole-system shutdown/resource-release proofs remain open. |

Verus does not verify Tokio, Hyper, rustls, the OS, DNS/PKI, or the filesystem for us.
Availability also depends on deployment: an external load balancer must route around
a failed gateway instance, and interrupted generations are not transparently replayed.
The [security contract](docs/security-contract.md) and progress notes below specify
the assumptions and limits; these targets do not promise secrecy of arbitrary
opaque body contents or survival of permanent storage loss.

## Implementation progress

The [implementation milestones](docs/implementation-plan.md) are the active plan,
starting with a bounded chunk interface and verified partial-write accounting.
The [first streaming-core increment](docs/streaming-core-progress.md) records the
current interface, checked behavior, and remaining milestone-one work.
The [security contract](docs/security-contract.md) separates proved core properties
from remaining adapter obligations. The [authorization notes](docs/authorization-core.md)
describe digest authentication, tenant-scoped tokens, and configuration confinement.
The [runtime ownership layer](docs/runtime-ownership.md) binds authorized requests
to capacity leases. Initial stream creation is now verified against the authority
and live slot; async ownership and release composition remain tested Rust.
The [configuration boundary](docs/configuration.md) now parses root policy and
candidate routes, loads credentials, and binds admitted requests to fixed endpoints.
The [HTTP metadata boundary](docs/http-boundary.md) validates gateway authentication
and prepares fixed upstream requests with filtered headers.
The [async transfer driver](docs/async-transfer.md) connects the stream core to Tokio
reads/writes and an explicit durable-log contract, with cancellation tests.
The [disk logger](docs/disk-logging.md) now implements that contract with a bounded
worker, sync acknowledgments, and an incremental recovery scanner; crash proofs remain open.
The [journal proof](docs/journal-proof.md) checks acknowledgment ordering and byte-prefix
survival conditional on the storage preserving synced bytes.
The [framing proof](docs/framing-proof.md) checks header roundtrips, bounded payload
lengths, and exact frame extents in the serializer and recovery scanner.
The [HTTPS upstream transport](docs/https-transport.md) now forwards opaque bodies
over real TLS through the stream core. The [runnable gateway](docs/running.md)
connects the inbound server, authorization, streaming, and disk logging.
The [deployment example](docs/deployment.md) adds TLS termination and readiness-based
standby routing with proxy retries disabled.
The [local benchmark](docs/benchmarks.md) measures both logging modes through TLS
and real disk logging, with explicit workload and memory-accounting limits.
The [adapter audit](docs/adapter-audit.md) maps runtime trust obligations to effect
paths and tests, including concurrent tenants and client disconnects.

See [language and verification research](docs/verification-research.md) for the
candidate comparison, agreed scope, proposed proof obligations, and next experiment.

See [experiment results and implementation plan](docs/experiment-results.md) for
the initial comparison, Verus proof, limitations, and reproduction instructions.

The [viability follow-up](docs/viability-followup.md) records byte-level Verus proofs
and the decision to continue with Rust and Verus. Perennial research is retained
for reference; its experimental code was removed and remains in Git history at
commit `7869347`.

## Development

The production core lives in `crates/gateway-core`; the superseded experiment
code is retained only in Git history (see the research notes). Cargo builds and Verus checks
use the same source. Install Rust 1.99.1 and Verus release
`0.2026.10.18.7d82994` (commit `7d829946231d6413a398f6e4160cdfe951261dad`),
and put the release's `verus` and `cargo-verus` binaries on PATH.
The workspace pins vstd and commits Cargo.lock.

```sh
cargo test --workspace --locked
cargo verus verify -p gateway-core --locked -- --triggers-mode silent
VERUS=/path/to/verus python3 scripts/check_mutations.py
```

Validation on 2026-10-23: 54 core verification checks passed, 73 workspace tests
passed, and all 37 deliberate mutations failed their proof obligations.
These counts are checks, not a count of independent security guarantees.

[GitHub Actions CI](.github/workflows/ci.yml) runs on pushes, pull requests, and
manual dispatch. Separate Linux jobs run locked workspace tests and the production
core's Verus proofs plus all mutation checks. Rust comes from rust-toolchain.toml;
the Verus release archive is SHA-256 pinned, and checkout is commit-pinned.
Jobs have read-only repository permissions and bounded execution times.
