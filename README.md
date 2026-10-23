# Verified Gateway

Research toward a minimal LLM gateway: forward request bodies unchanged, stream
responses back, and record traffic to disk. No provider API translation.

Status: a runnable prototype with Verus-checked authorization, configuration,
streaming, and resource invariants. The network and disk adapters are tested;
end-to-end formal guarantees and production hardening remain incomplete.

## Why verify an AI gateway?

For companies that depend on AI, the gateway is among their most critical pieces
of infrastructure. It sits in the hot path of every AI request routed through it:
if the gateway goes down, that AI work stops until failover or recovery. It also
handles highly sensitive data, including proprietary code, customer information,
internal prompts, and provider credentials. A compromise can expose that data or
turn a shared gateway into a path across tenant boundaries.

These risks are concrete. LiteLLM documented a
[March 2026 supply-chain compromise](https://docs.litellm.ai/blog/security-townhall-updates)
affecting its published Python packages, and a
[second compromise on October 21, 2026](https://docs.litellm.ai/blog/security-incident-oct-21-2026)
that distributed credential-stealing malware in version 1.107.0 through PyPI and
official container registries. These incidents highlight the trust placed in gateway
software and the importance of securing how it is built and delivered.

Formal verification can help make this critical infrastructure more trustworthy:
prove authorization, isolation, byte integrity, and resource invariants across all
states covered by explicit models, rather than relying only on tested examples.
This project keeps the gateway small enough to make those proofs practical.
Proofs complement fault testing, operational redundancy, and secure builds; they
do not by themselves prevent a compromised release pipeline from shipping different
code. The proof targets and remaining trust assumptions are listed below.

## Run it

Install Rust through rustup; this repository selects the pinned toolchain. Create
`root.json` and `routes.json` from the [configuration example](docs/running.md#configuration-example),
set your gateway-token digest, and supply `PROVIDER_KEY` through your environment.
Then run:

```sh
cargo build --release --locked --bin soundgate
mkdir -m 700 logs
target/release/soundgate root.json routes.json logs/session-001.log
```

The server listens on `127.0.0.1:8080`; check it with
`curl --fail http://127.0.0.1:8080/healthz`. Send native provider requests to
`POST /routes/7` with `Authorization: Bearer <gateway-token>` and the provider's
normal headers and JSON body. Use a **new log filename on every start**; logs
contain request and response bodies. Remote access needs a
[TLS reverse proxy](docs/deployment.md). See [running the gateway](docs/running.md)
for provider configuration, scanning logs, and shutdown behavior.

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
| Crash-safe recovery | Recovery exposes only complete records, and acknowledged records survive every crash in the specified storage model. | Journal acknowledgment ordering and conditional synced-prefix survival proved; header/payload encoding, header decoding, frame extents, and scanner cursor transitions proved; scanner I/O tested. Process-kill recovery tested and storage assumptions documented; scanner refinement and power-loss validation remain open. |
| Cancellation and no replay | Cancellation prevents new submissions; uncertain effects, crashes, or failover never trigger automatic replay of a possibly executed generation. | Core cancellation/stale-event checks proved; transport has no replay path. Async cancellation and recovery composition remain unproved. |
| Resource bounds and safe release | Slots, buffers, queues, and outstanding operations stay within explicit budgets; capacity cannot be reused while work retaining it remains alive. | Logical slot limits, ID isolation, and combined payload bound under an explicit stream-to-slot mapping proved; ownership, queues, and deadlines tested. Full allocation accounting and composed release proofs remain open. |
| Logging-mode separation | Availability mode may lose audit coverage but cannot relax authorization, routing, or tenant isolation; logging failure cannot create unbounded replacement work. | Core logging-mode transitions proved; bounded logger and failure handling tested. End-to-end composition remains open. |
| Honest completion and conditional progress | Failed/truncated streams cannot masquerade as successful completion; under stated scheduler and I/O assumptions, admitted work terminates or times out and releases resources. | Core admission/release and conditional streaming progress proved; EOF/error behavior and deadlines tested. Async liveness and whole-system shutdown/resource-release proofs remain open. |

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
The [proof index](docs/proof-index.md) maps advertised guarantees to exact source
contracts and the assumptions still required for composition.
The [security contract](docs/security-contract.md) separates proved core properties
from remaining adapter obligations. The [authorization notes](docs/authorization-core.md)
describe digest authentication, tenant-scoped tokens, and configuration confinement.
The [runtime ownership layer](docs/runtime-ownership.md) binds authorized requests
to capacity leases. Initial stream creation is now verified against the authority
and live slot, and stream retirement consumes the matching owned stream before
releasing its slot. Async ownership and external-effect lifetimes remain tested Rust.
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

Validation on 2026-10-23: 71 core verification checks passed, 90 workspace tests
passed, the opt-in TLS proxy/gateway process-failover test and six load/fault workloads passed, and all 65
deliberate mutations failed their proof obligations.
These counts are checks, not a count of independent security guarantees.

[Automated checks](.github/workflows/ci.yml) reproduce the tests and proofs on Linux.
