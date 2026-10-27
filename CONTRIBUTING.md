# Contributing

## Code layout

HypGate has two crates. Keep policy decisions in the core and external effects
in the runtime; moving a decision into an adapter removes it from verification.

- `crates/gateway-core`: Verus contracts and executable policy, HTTP codecs,
  audit journal, resource accounting, and shipping state machines.
- `crates/gateway-runtime`: blocking network, TLS, disk, and thread adapters.
  The binary composes these adapters; `cli.rs` parses commands and `scan.rs`
  renders audit metadata.
- `docs`: operator guides, proof boundaries, and measured workload results.
- `scripts`: effect-site checks, proof mutations, and deployment/storage fixtures.
- `deploy`: the HAProxy configuration and reproducible deployment container.

Core modules retain stable paths because proof mutations and the proof index
refer to them directly. The crate root groups them by responsibility. Before
changing a contract, read its entry in [the proof index](docs/proof-index.md).
When adding an external effect, update the pinned effect sites and
[the end-to-end audit](docs/end-to-end-audit.md) together.

## Local checks

Use the pinned tools and validation commands in the
[README](README.md#development). Changes to executable behavior need regression
tests; changes to verified contracts also need Verus and mutation checks.

## Release checks

Run the Linux CI workflow before tagging a release. It includes Verus, deliberate
proof mutations, storage faults, proxy failover, overload, memory soak, and clean
container deployment; a local unit-test pass does not replace those checks.
Review [operational limits](docs/operational-limits.md) and
[the storage contract](docs/storage-crash-contract.md) when changing defaults.

Build the executable with `cargo build --release --locked --bin hypgate`.
The workspace crates are implementation components with `publish = false`;
this repository currently distributes the gateway as source. Release artifacts
must include the [MIT license](LICENSE). Keep versions in the workspace manifest
and report validation against the exact release commit.

The [CI workflow](.github/workflows/ci.yml) runs on pull requests and pushes to
`master`. `bash scripts/check_deployment.sh` checks the documented deployment;
`deploy/Dockerfile` repeats the build, tests, proofs, and deployment in a pinned
container.
