# Verified Gateway

Research toward a minimal LLM gateway: forward request bodies unchanged, stream
responses back, and record traffic to disk. No provider API translation.

Status: a Rust Cargo library with Verus-checked authorization, configuration,
streaming, and resource invariants. No HTTP gateway or end-to-end guarantees yet.

The [implementation milestones](docs/implementation-plan.md) are the active plan,
starting with a bounded chunk interface and verified partial-write accounting.
The [first streaming-core increment](docs/streaming-core-progress.md) records the
current interface, checked behavior, and remaining milestone-one work.
The [security contract](docs/security-contract.md) separates proved core properties
from remaining adapter obligations. The [authorization notes](docs/authorization-core.md)
describe digest authentication, tenant-scoped tokens, and configuration confinement.
The [runtime ownership layer](docs/runtime-ownership.md) binds authorized requests
to capacity leases; this composition is tested Rust, not yet a Verus theorem.

See [language and verification research](docs/verification-research.md) for the
candidate comparison, agreed scope, proposed proof obligations, and next experiment.

See [experiment results and implementation plan](docs/experiment-results.md) for
the initial comparison, Verus proof, limitations, and reproduction instructions.

The [viability follow-up](docs/viability-followup.md) records byte-level Verus proofs
and the decision to continue with Rust and Verus. Perennial research is retained
for reference; its experimental code was removed and remains in Git history at
commit `7869347`.

## Development

The production core lives in `crates/gateway-core`; Cargo builds and Verus checks
use the same source. Install Rust 1.99.1 and Verus release
`0.2026.10.18.7d82994` (commit `7d829946231d6413a398f6e4160cdfe951261dad`),
and put the release's `verus` and `cargo-verus` binaries on PATH.
The workspace pins vstd and commits Cargo.lock.

```sh
cargo test --workspace --locked
cargo verus verify -p gateway-core --locked -- --triggers-mode silent
VERUS=/path/to/verus python3 scripts/check_mutations.py
```

Validation on 2026-10-23: 34 core verification checks passed, six integration tests
passed, and all 19 deliberate mutations failed their proof obligations.
These counts are checks, not a count of independent security guarantees.
