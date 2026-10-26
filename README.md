# LogGate - Formally Verified AI Gateway

LogGate is a small LLM gateway with a machine-checked core. It forwards request
bodies to your provider unchanged, streams responses back, writes every
exchange to an audit log on disk, and optionally ships that log to
[HypAware](https://hypaware.ai) for analysis. No provider API translation, no
plugins, no other network destinations.

What makes it different: the code that decides what the gateway does is
proved correct with [Verus](https://github.com/verus-lang/verus). Other
gateways are tested on examples. LogGate's core is proved for every input, and
the code that talks to the network and disk is kept small and audited.

## Three guarantees

### 1. Data only goes where you configured

Requests go to the provider you set up, using the key you set up. Logs go to
the log file on disk. If you turn on shipping, logs go to your HypAware server
and nowhere else. There is no other network connection in the binary.

### 2. Correctness

The gateway is a faithful pass-through with a faithful record.

- **Bodies pass through unchanged.** The provider gets the client's request body
  byte for byte, and the client gets the provider's response byte for byte, in
  order. Only the headers change: the gateway swaps in the provider credential
  and sets Host.
- **Every exchange is recorded completely.** Each request gets a start record
  with the time, route, and destination; every request body chunk; the response
  status; every response body chunk; and a completion record with the outcome
  and byte counts. The logged bytes are the forwarded bytes.
- **Records are ordered and attributed.** Within a request, records appear in
  the order the bytes flowed, with chunks numbered from one. Every record names
  the authenticated tenant and the request, and chunks cannot cross requests.
- **Nothing is forwarded before it is on disk.** In strict mode a byte reaches
  the provider or the client only after its record is written and synced. If
  the log cannot be written, the request fails instead of going unrecorded.
- **A crash loses nothing that was acknowledged.** Kill the process at any
  point and every synced record is still there. Recovery reports only complete
  records and never rewrites or truncates the file.
- **Failures are reported honestly.** A provider error, timeout, or client
  disconnect ends the request with a completion record naming the cause. A
  truncated stream is an error, never a clean completion.
- **The whole log reaches HypAware once, in order.** An upload counts only when
  the server confirms the exact batch. After a restart the gateway resends only
  what was unconfirmed, with the same identities, so the server stores each
  exchange once.

Strict mode is the guarantee. Availability mode is an opt-out that keeps
forwarding after the log fails and counts each unrecorded request as a gap.

### 3. It cannot crash

The verified core cannot panic, overflow, or read out of bounds. If the
process is killed at any moment, it restarts in a state that matches the log.
Shipping runs on its own thread, so if it fails, the gateway keeps serving
requests.

These are theorems about the verified core, plus a short list of things we
trust and do not prove: Tokio, rustls, the OS, DNS, TLS certificates, the
filesystem under power loss, the HypAware server, and provider JSON parsing.
The HTTP/1.1 parser and writer are verified core code; no HTTP library is
linked ([codec](docs/http1-codec.md)). [PROOFS.md](PROOFS.md) states each guarantee exactly and lists every
assumption.

## Why verify an AI gateway?

The gateway sits in the path of every AI request and sees your most sensitive
data: proprietary code, customer information, internal prompts, and provider
credentials. If it goes down, AI work stops. If it is compromised, that data
leaks, and a shared gateway becomes a path across tenant boundaries.

This has happened. LiteLLM documented a
[March 2026 supply-chain compromise](https://docs.litellm.ai/blog/security-townhall-updates)
of its published Python packages, and a
[second compromise on October 21, 2026](https://docs.litellm.ai/blog/security-incident-oct-21-2026)
that shipped credential-stealing malware through PyPI and official container
registries.

Tests check the examples someone thought of. Proofs cover every input the model
describes. Keeping the gateway small is what makes the proofs practical. Proofs
do not replace fault testing, redundancy, or secure builds, and they cannot stop
a compromised release pipeline from shipping different code.

## Status

A runnable prototype. The core's authorization, configuration, streaming,
shipping, HTTP/1.1 codec, and resource invariants are Verus-checked. The
network and disk adapters are tested, and live exchanges with Anthropic and
OpenAI, streamed and not, have been run through the gateway and shipped to
HypAware Cloud ([smoke record](docs/hypaware.md#smoke-test-record)).
Production hardening remains incomplete.

## Run it

Install Rust through rustup; this repository selects the pinned toolchain. Create
`root.json` and `routes.json` from the [configuration example](docs/running.md#configuration-example),
set your gateway-token digest, and supply `PROVIDER_KEY` through your environment.
Then run:

```sh
cargo build --release --locked --bin loggate
mkdir -m 700 logs
target/release/loggate root.json routes.json logs/session-001.log
```

The server listens on `127.0.0.1:8080`; check it with
`curl --fail http://127.0.0.1:8080/healthz`. Send native provider requests to
`POST /routes/7` with `Authorization: Bearer <gateway-token>` and the provider's
normal headers and JSON body. Use a **new log filename on every start**; logs
contain request and response bodies. Remote access needs a
[TLS reverse proxy](docs/deployment.md). See [running the gateway](docs/running.md)
for provider configuration, scanning logs, and shutdown behavior.

## Documentation

[PROOFS.md](PROOFS.md) states the guarantees. These pages back them up:

| Document | Purpose |
| --- | --- |
| [Proof index](docs/proof-index.md) | Maps each advertised guarantee to its source contracts and composition assumptions |
| [End-to-end audit](docs/end-to-end-audit.md) | One request traced through every effect site, failure exit, and shutdown |
| [Ownership composition](docs/ownership-composition.md) | How the ownership and submission proofs compose through the runtime, and the trusted joins |
| [Security contract](docs/security-contract.md) | Threat boundary, required properties and their status, trusted computing base |
| [Authorization core](docs/authorization-core.md) | Digest authentication, tenant-scoped tokens, configuration confinement |
| [Framing proof](docs/framing-proof.md) | Header roundtrips, bounded payloads, frame extents in the serializer and scanner |
| [Journal proof](docs/journal-proof.md) | Acknowledgment ordering and conditional synced-prefix survival |
| [Recovery proof](docs/recovery-proof.md) | Scanner cursor transitions and acknowledged-prefix reconstruction |
| [Shutdown proof](docs/shutdown-proof.md) | Verified drain rank and the conditional shutdown/resource release argument |
| [Storage crash contract](docs/storage-crash-contract.md) | Storage assumptions, process-death experiments, and the evidence behind the recovery claims |
| [Resource accounting](docs/resource-accounting.md) | Source-level inventory of application buffers and queues |
| [Resource composition](docs/resource-composition.md) | Budget ownership and the conditional requested-allocation bound |
| [HTTP/1.1 codec](docs/http1-codec.md) | The verified head parser and writer, framing selection, and chunked coding; the adapter and what stays trusted |
| [Dependency resources](docs/dependency-resources.md) | Pinned rustls/Tokio retained-allocation audit and the codec's own buffers |
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
| [HypAware setup](docs/hypaware.md) | Operator walkthrough: tokens, shipping config, checking rows on the server, live smoke test record |
| [Thread context](docs/thread-context.md) | Runtime entry as a typed permit: the sites, what is proved, typed, and trusted |
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
cargo clippy -p gateway-runtime --locked
bash scripts/check_effect_sites.sh
```

The clippy run enforces the panic-free standard on the cloud-shipping
adapters (`crates/gateway-runtime/src/shipping`): unwrap, expect, panic,
indexing, and unchecked arithmetic are denied there. It also denies every
socket, name lookup, listener, file write, and secret read outside the
audited effect sites (`clippy.toml`); the script fails if that set of sites
changes.

Opt-in load, memory, benchmark, and failover workloads (the last needs HAProxy and
OpenSSL on PATH; results are discussed in the [benchmarks](docs/benchmarks.md)
and [deployment](docs/deployment.md) notes):

```sh
cargo test -p gateway-runtime --locked --lib sustained_overload -- --ignored --nocapture
cargo test -p gateway-runtime --locked --lib isolated_gateway_memory_in_both_logging_modes -- --ignored --nocapture
cargo test -p gateway-runtime --locked --lib isolated_gateway_memory_soak -- --ignored --nocapture
cargo test -p gateway-runtime --release --locked server::tests::benchmark -- --ignored --nocapture --test-threads=1
LOGGATE_HAPROXY=/path/to/haproxy cargo test -p gateway-runtime --locked proxy_gateway_process_failover -- --ignored --nocapture
```

Validation on 2026-10-25: 737 core verification checks passed, 303 workspace tests including seven compile-fail
doctests passed, all 439 deliberate mutations failed their proof obligations, and the runtime passed its
panic and effect-site lints. The opt-in TLS proxy/gateway
process-failover test and six load/fault workloads passed on 2026-10-23.
Two ten-minute overload runs and the final 100-wave-per-mode isolated memory soak
also passed; measurements and limits are in the benchmark notes.
These counts are checks, not a count of independent security guarantees.

[Automated checks](.github/workflows/ci.yml) reproduce the tests and proofs on Linux
for every pull request and every push to `master`.
`bash scripts/check_deployment.sh` reproduces the documented deployment from a clean
checkout, and `deploy/Dockerfile` repeats the build, tests, proofs, and that check in
a digest-pinned container; see [clean-environment reproduction](docs/deployment.md#clean-environment-reproduction).
