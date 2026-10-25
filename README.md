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

## What the gateway guarantees

Three statements an operator can hold the gateway to. Each is a theorem over a
verified state machine joined to the outside world by a small, enumerated set
of trusted adapters. [PROOFS.md](PROOFS.md) states each one precisely, names
its premises, lists every finer-grained property proved beneath it, and tracks
the work that still narrows the trusted part.

**Your traffic goes only where you said.** Request bodies reach only the
provider a root grant names, with that grant's credential; audit records go only
to the local log file; and, only if a `shipping` section is configured, log
contents go to the one HypAware server it names, with a credential that server
issued. No other socket exists in the binary. The provider half is proved
through a single write gate (`ResolvedRoute::write_bytes`) that every body byte
passes; the shipper half is being moved into the same shape: a verified machine
whose only outgoing requests carry a path but no host, so the destination is a
type, not a string.

**What was logged is what is shipped, once and in order.** Every exchange in the
log is grouped, bounded, and uploaded in emission order; an upload is counted
only when the server acknowledges the exact batch it was sent; a restart
replays from the file and reproduces identical identities, so the server's
dedup stores each exchange once. The assembler, cursor, batch limits, and
identity injectivity are proved today; the conservation theorem that no
exchange is dropped between them is the next step.

**There is no crash state.** The verified core cannot panic, overflow, or index
out of bounds, and every reachable shipper state has a next action with a
bounded wait; the shipper runs on its own thread with no handle to admission,
routing, or the logger, so its failure changes metrics and nothing else; and a
process kill at any point resumes to a state consistent with the log. Progress
and recovery theorems for the shipper are in progress; the gateway's own
crash-safe recovery is proved under the storage contract.

What Verus does not verify for us: Tokio, Hyper, rustls, the OS, DNS and PKI,
the filesystem under power loss, the HypAware server honoring its ledger, and
provider-specific JSON parsing. Each is a named premise of a theorem, not an
unstated gap.

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
| [Cloud shipping](docs/cloud-shipping.md) | HypAware shipper thread: protocol, configuration, proved and trusted parts |
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

Validation on 2026-10-25: 383 core verification checks passed, 288 workspace tests and seven compile-fail doctests
passed, and all 332 deliberate mutations failed their proof obligations. The opt-in TLS proxy/gateway
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
