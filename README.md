# Verified Gateway

Research toward a minimal LLM gateway: forward request bodies unchanged, stream
responses back, and record traffic to disk. No provider API translation.

Status: early Rust and Verus experiments with machine-checked policy and byte-level
invariants. No production gateway or end-to-end guarantees yet.

See [language and verification research](docs/verification-research.md) for the
candidate comparison, agreed scope, proposed proof obligations, and next experiment.

See [experiment results and implementation plan](docs/experiment-results.md) for
the initial comparison, Verus proof, limitations, and reproduction instructions.

The [viability follow-up](docs/viability-followup.md) records byte-level Verus proofs
and the decision to continue with Rust and Verus. Perennial research is retained
for reference; its experimental code was removed and remains in Git history at
commit `7869347`.
