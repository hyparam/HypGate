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
| Strict audit-before-forwarding | Every submitted body range in strict mode is covered by a durable log acknowledgment for that request and chunk. | Core gate and exact journal-receipt/stream binding proved; disk sync adapter tested. Filesystem crash guarantees remain open. |
| Crash-safe recovery | Recovery exposes only complete records, and acknowledged records survive every crash in the specified storage model. | Journal acknowledgment ordering and conditional synced-prefix survival proved; header/payload encoding, header decoding, frame extents, and scanner cursor transitions proved; scanner I/O tested. Process-kill recovery tested and storage assumptions documented; conditional scanner steps proved; acknowledged-prefix reconstruction proved under preserved-byte/read/checksum assumptions. Linux ext4 error/process-death tests passed; physical power-loss validation remains open. |
| Cancellation and no replay | Cancellation prevents new submissions; uncertain effects, crashes, or failover never trigger automatic replay of a possibly executed generation. | Core cancellation/stale-event checks proved; transport has no replay path. Async cancellation and recovery composition remain unproved. |
| Resource bounds and safe release | Slots, buffers, queues, and outstanding operations stay within explicit budgets; capacity cannot be reused while work retaining it remains alive. | Logical slot limits, ID isolation, and combined payload bound under an explicit stream-to-slot mapping proved; fixed disk-FIFO order, slot capacity, permanent closure, and actual queued-frame byte bound proved; HTTP mailbox occupancy and endpoint closure proved; ownership and deadlines tested. Conditional allocation composition and shutdown/release arguments are documented; mechanized async refinement remains open. |
| Logging-mode separation | Availability mode may lose audit coverage but cannot relax authorization, routing, or tenant isolation; logging failure cannot create unbounded replacement work. | Core logging-mode transitions proved; bounded logger and failure handling tested. Submission and lifecycle composition are checked under the documented adapter assumptions. |
| Honest completion and conditional progress | Failed/truncated streams cannot masquerade as successful completion; under stated scheduler and I/O assumptions, admitted work terminates or times out and releases resources. | Core admission/release and conditional streaming progress proved; EOF/error behavior and deadlines tested. Permanent worker closure and drain rank are proved; the conditional shutdown/resource argument is documented. Mechanized async liveness verification remains open. |

Verus does not verify Tokio, Hyper, rustls, the OS, DNS/PKI, or the filesystem for us.
Availability also depends on deployment: an external load balancer must route around
a failed gateway instance, and interrupted generations are not transparently replayed.
The [security contract](docs/security-contract.md) and the documents indexed below
specify the assumptions and limits; these targets do not promise secrecy of arbitrary
opaque body contents or survival of permanent storage loss.

## Documentation

All six [implementation milestones](docs/implementation-plan.md) are complete under
their documented assumptions; the [milestone 6 exit audit](docs/milestone-6-exit-audit.md)
is the latest record of what is proved, tested, and still trusted.

Guarantees and proofs:

| Document | Purpose |
| --- | --- |
| [Proof index](docs/proof-index.md) | Maps each advertised guarantee to its source contracts and composition assumptions |
| [Security contract](docs/security-contract.md) | Threat boundary, required properties and their status, trusted computing base |
| [Authorization core](docs/authorization-core.md) | Digest authentication, tenant-scoped tokens, configuration confinement |
| [Framing proof](docs/framing-proof.md) | Header roundtrips, bounded payloads, frame extents in the serializer and scanner |
| [Journal proof](docs/journal-proof.md) | Acknowledgment ordering and conditional synced-prefix survival |
| [Recovery proof](docs/recovery-proof.md) | Scanner cursor transitions and acknowledged-prefix reconstruction |
| [Shutdown proof](docs/shutdown-proof.md) | Verified drain rank and the conditional shutdown/resource release argument |
| [Storage crash contract](docs/storage-crash-contract.md) | Storage assumptions, process-death experiments, milestone 3 exit audit |
| [Resource accounting](docs/resource-accounting.md) | Source-level inventory of application buffers and queues |
| [Resource composition](docs/resource-composition.md) | Budget ownership and the conditional requested-allocation bound |
| [Dependency resources](docs/dependency-resources.md) | Pinned Hyper/rustls/Tokio retained-allocation audit |
| [DNS resources](docs/dns-resources.md) | DNS lookup ownership, threads, and shutdown |

Runtime and adapters:

| Document | Purpose |
| --- | --- |
| [Runtime ownership](docs/runtime-ownership.md) | Binding authorized requests to capacity leases and owned streams |
| [Worker lifetimes](docs/worker-lifetimes.md) | Worker credits and task destruction order |
| [Configuration](docs/configuration.md) | Root policy and candidate route parsing, credential loading, endpoint binding |
| [HTTP boundary](docs/http-boundary.md) | Inbound authentication and fixed upstream request preparation |
| [Async transfer](docs/async-transfer.md) | Tokio body driver and the durable-log contract |
| [HTTPS transport](docs/https-transport.md) | Upstream TLS exchange and handshake isolation |
| [Disk logging](docs/disk-logging.md) | Bounded disk worker, sync acknowledgments, recovery scanner |
| [HTTP ownership](docs/http-ownership.md) | HTTP owner counts derived from the worker and connection registries |
| [HTTP buffer lifetimes](docs/http-buffer-lifetimes.md) | HTTP body buffers, mailbox credit, and cancellation |
| [Audit buffer lifetimes](docs/audit-buffer-lifetimes.md) | Audit queue credit, worker ownership, and receipt delivery |

Operations:

| Document | Purpose |
| --- | --- |
| [Running the gateway](docs/running.md) | Configuration example, provider setup, log scanning, shutdown |
| [Deployment](docs/deployment.md) | TLS termination, standby routing, clean-environment reproduction |
| [Operational limits](docs/operational-limits.md) | Every fixed and configurable limit and what happens when it is reached |
| [Benchmarks](docs/benchmarks.md) | Latency, throughput, overload, and memory measurements |

Audits:

| Document | Purpose |
| --- | --- |
| [Implementation milestones](docs/implementation-plan.md) | Milestone table with status and a link to each exit audit |
| [Milestone 1 exit audit](docs/milestone-1-exit-audit.md) | Verified streaming core criteria and evidence |
| [Adapter audit](docs/adapter-audit.md) | Milestone 2 trust obligations mapped to effect paths and tests |
| [Availability audit](docs/availability-audit.md) | Milestone 4 criteria, validation results, scheduler/I/O assumptions |
| [End-to-end audit](docs/end-to-end-audit.md) | One request traced through every effect site, failure exit, and shutdown |
| [Milestone 6 exit audit](docs/milestone-6-exit-audit.md) | Composed ownership and submission proofs and the remaining trusted joins |

History:

| Document | Purpose |
| --- | --- |
| [Historical plan](docs/history/implementation-plan.md) | Checkpoint-by-checkpoint plan with the counts current at each checkpoint |
| [Streaming core progress](docs/history/streaming-core-progress.md) | First streaming-core and authorization increment |
| [Verification research](docs/history/verification-research.md) | Language and verifier comparison that chose Rust and Verus |
| [Experiment results](docs/history/experiment-results.md) | Initial feasibility experiments and reproduction notes |
| [Viability follow-up](docs/history/viability-followup.md) | Byte-level Verus proofs and the decision to drop Perennial |

The historical experiment code (`experiments/`) was removed from the tree and
remains only in Git history at commit `7869347`.

## Development

The production core lives in `crates/gateway-core`. Cargo builds and Verus checks
use the same source. Install Rust 1.99.1 and Verus release
`0.2026.10.18.7d82994` (commit `7d829946231d6413a398f6e4160cdfe951261dad`),
and put the release's `verus` and `cargo-verus` binaries on PATH.
The workspace pins vstd and commits Cargo.lock.

```sh
cargo test --workspace --locked
cargo verus verify -p gateway-core --locked -- --triggers-mode silent
VERUS=/path/to/verus python3 scripts/check_mutations.py
```

Opt-in load, memory, benchmark, and failover workloads (the last needs HAProxy and
OpenSSL on PATH; results are discussed in the [benchmarks](docs/benchmarks.md),
[availability audit](docs/availability-audit.md), and [deployment](docs/deployment.md) notes):

```sh
cargo test -p gateway-runtime --locked --lib sustained_overload -- --ignored --nocapture
cargo test -p gateway-runtime --locked --lib isolated_gateway_memory_in_both_logging_modes -- --ignored --nocapture
cargo test -p gateway-runtime --locked --lib isolated_gateway_memory_soak -- --ignored --nocapture
cargo test -p gateway-runtime --release --locked server::tests::benchmark -- --ignored --nocapture --test-threads=1
SOUNDGATE_HAPROXY=/path/to/haproxy cargo test -p gateway-runtime --locked proxy_gateway_process_failover -- --ignored --nocapture
```

Validation on 2026-10-24: 288 core verification checks passed, 249 workspace tests and seven compile-fail doctests
passed, and all 252 deliberate mutations failed their proof obligations. The opt-in TLS proxy/gateway
process-failover test and six load/fault workloads passed on 2026-10-23.
Two ten-minute overload runs and the final 100-wave-per-mode isolated memory soak
also passed; measurements and limits are in the benchmark notes.
These counts are checks, not a count of independent security guarantees.

[Automated checks](.github/workflows/ci.yml) are configured to reproduce the tests and proofs on Linux.
Current GitHub Actions runs cannot start because of an account billing/spending-limit
restriction; the local milestone-6 checks passed, but remote CI is not green.
`bash scripts/check_deployment.sh` reproduces the documented deployment from a clean
checkout, and `deploy/Dockerfile` repeats the build, tests, proofs, and that check in
a digest-pinned container; see [clean-environment reproduction](docs/deployment.md#clean-environment-reproduction).
