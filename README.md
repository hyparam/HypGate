# Verified Gateway

Research toward a minimal LLM gateway: forward request bodies unchanged, stream
responses back, and record traffic to disk. No provider API translation.

Status: early experiments; a small offset-based Rust core has machine-checked
invariants. No production gateway or end-to-end guarantees yet.

See [language and verification research](docs/verification-research.md) for the
candidate comparison, agreed scope, proposed proof obligations, and next experiment.

See [experiment results and implementation plan](docs/experiment-results.md) for
the Verus proof, Go tests, limitations, and reproduction instructions.

The [viability follow-up](docs/viability-followup.md) adds byte-level Verus proofs,
checked Perennial policy theorems, and an updated recommendation.
