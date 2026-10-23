# Initial experiments and implementation plan

Date: 2026-10-23. These experiments compare a small offset-based policy core,
not whole gateways. Rust and Verus are now the active implementation path.

The Verus prototypes have also been removed: the production proofs now live in
[crates/gateway-core](../crates/gateway-core/src/lib.rs), with mutation checks in
[scripts/check_mutations.py](../scripts/check_mutations.py). The original Verus
experiment sources and runners remain in Git at `efe687426377ebfd39a1bbe7968fe176eac9817c`.

This records the first experiment. The [follow-up](viability-followup.md) now
includes checked Perennial theorems and byte-level Verus proofs.
Perennial results below are historical. Its code was removed after evaluation;
use a separate checkout of commit `7869347` to revisit those experiments.

## Executed results

| Experiment | Result | What it establishes |
| --- | --- | --- |
| Verus core verification | 6 functions verified, 0 errors | Creation and five transitions preserve declared invariants for all inputs satisfying their preconditions. |
| Compile and run the same Verus source | Both policy scenarios passed | Verified functions can be compiled and exercised in this environment. The ordinary Rust demonstration main is tested, not itself verified. |
| Remove durability guard | Rejected by Verus | Proof detects forwarding beyond the durable offset in strict mode. |
| Remove buffer capacity guard | Rejected by Verus | Proof detects violation of the pending-byte capacity. |
| Keep strict stream open after logger failure | Rejected by Verus | Proof detects failure to close strict mode. |
| Go reachable-state exploration | 320 availability-first states and 102 strict states; all passed | Exhaustive exploration within capacity 2 and received-byte lifetime cap 6, with operation arguments 0 through 7. Not an unbounded proof. |
| Go availability and overflow cases | Passed | Logger failure permits further forwarding in availability-first mode; offset wraparound is rejected. |
| Goose translation at pinned Perennial revision | Succeeded without ignored errors | Candidate Go core was accepted by the translator; generated Rocq source remains in Git history. This was not a checked correctness theorem or a Rocq compilation result. |

Verus version: `0.2026.10.18.7d82994`, arm64 macOS release; required Rust:
`1.99.1-aarch64-apple-darwin`. Go version: `go1.27.3 darwin/arm64`.
The Verus compiler emitted a macOS SDK filesystem-event warning, but compilation
and execution succeeded. Tools were downloaded into a temporary directory rather
than replacing the user's default toolchain.

## Scope of the proof

The state contains received, durable, and sent byte offsets, a capacity, a fixed
logging policy, and failure/closure flags. The invariant states:

- Sent and durable offsets do not exceed received bytes.
- Received minus sent does not exceed capacity.
- In strict mode, sent does not exceed durable.
- In strict mode, logger failure implies closure.

The core checks overflow, admission capacity, invalid acknowledgments, sends past
available bytes, and strict sends past durable bytes. Availability-first mode
allows sending after logging failure; cancellation closes either mode.

An acknowledgment is a trusted input. There is no disk operation, crash model,
byte-content representation, request identity, HTTP handler, TLS connection,
concurrent scheduler, or actual queue in this experiment. Buffer bounds here are
offset invariants, not whole-process memory bounds. Fields are public for this
experiment; production code must prevent callers from fabricating state.

In particular, none of these results proves stream isolation, byte equality,
durable logging, recovery, availability, absence of all panics in an executable,
or resistance to a malicious adapter. No `assume` or external proof stubs were
added to the Verus core. Caller validity and acknowledgment semantics are explicit
boundaries. A sequence of valid transitions preserves the invariant by induction;
deployment must ensure all relevant actions use those transitions.

## Reproduction

Install the pinned Verus release and its required Rust toolchain using the
[official instructions](https://github.com/verus-lang/verus/blob/main/INSTALL.md).
Use a separate historical checkout of `efe687426377ebfd39a1bbe7968fe176eac9817c` for the
commands below; the experiment runner is no longer in the active tree. Set
`VERUS` to its executable path, then run:

```sh
python3 experiments/verus/check.py
```

The Python runner verifies and compiles the source, runs the executable, and checks
that all three mutations produce proof failures rather than incidental build errors.
It uses a temporary directory for generated binaries and mutated sources.

Historical Go reproduction requires a separate checkout of commit `7869347` first.
From that checkout, run `go test -v ./...` in `experiments/perennial`. To reproduce
the Goose translation, install the pinned translator and run from that checkout's
root (with Go and the installed Goose binary on PATH):

```sh
go install github.com/mit-pdos/perennial/goose/cmd/goose@3e3e0a484d61d0a15b578f5d5887ead84f145d71
goose -dir experiments/perennial -out experiments/perennial/generated .
```

## Perennial investigation

Examined Perennial commit `3e3e0a484d61d0a15b578f5d5887ead84f145d71`.
Its current OPAM definition requires Rocq runtime 9.1 through before 9.3 (or dev),
Rocq stdlib, coqutil, record-update, stdpp, Iris, and named propositions, with pinned
dependencies. Its Go module requires Go 1.26. The current repository includes
Goose; older standalone Goose instructions should not be assumed compatible.

The machine initially had no Go, Rocq, OPAM, or Nix available; Docker was installed
but its daemon was unavailable. A temporary Go toolchain was sufficient to run
the candidate core and tests. At this initial stage, no Perennial/Rocq theorem had
been checked; the follow-up records the later successful proofs.
This is an environment and setup-cost observation, not evidence that the framework
cannot verify this program.

Perennial offers a capability absent from the current Verus experiment: reasoning
about persistent state and recovery across crashes through its program logic.
However, its disk model must match the intended filesystem implementation. We
must not import a theorem based on atomic block writes and silently assume it
applies to arbitrary file appends and fsync.

## Next implementation stages

1. **Strengthen the core before networking.** Add actual byte sequences and two
   request identities, then prove body-prefix preservation and isolation. Make
   state private and require typed, single-use action permits so that the adapter
   cannot accidentally send arbitrary ranges. Define partial-send, cancellation,
   and timeout outcomes. Extend invariant preservation to resource accounting.
2. **Specify crash semantics in Verus.** Model volatile append, durable commit,
   crash, and recovery for a minimal log. Make the filesystem assumptions explicit;
   a model alone is not a proof of actual fsync. Perennial is archived as an option
   to revisit if the storage proof warrants a different framework.
3. **Build one adapter behind the selected core.** Use fixed configured origins,
   no automatic redirects or request retries, opaque body bytes, bounded queues,
   and explicit deadlines. For Rust, evaluate Hyper/Tokio/rustls integration;
   supported APIs and proof boundaries need checking before commitment.
4. **Implement the disk contract.** Choose framed records, durable acknowledgment
   semantics, startup recovery, and file/directory synchronization rules for the
   target OS. Strict mode gates sends on durable acknowledgment. Availability-first
   mode bounds logger waiting and reports dropped coverage through independent
   diagnostics when possible. A permanently stuck filesystem operation must not
   lead to unbounded worker creation; assess process isolation for the logger.
5. **Exercise failure behavior.** Inject process death, torn tails, disk-full and
   stalled writes, disconnects, slow readers, and concurrent streams. Add health
   and readiness behavior for the external load balancer, bounded draining, and
   no automatic replay of interrupted generations. Measure latency and memory.

Implementation gate: prove the required core properties in Verus, compile that core
into the gateway, and keep the trusted adapter small enough to audit. The follow-up
records the evidence behind selecting this path and retaining Perennial only as
research for a possible future revisit.

Open decisions: deployment OS/filesystem, exact logging contents, authentication
and credential ownership, limits, timeout policy, and acceptable strict-mode
latency. Operator-selectable logging behavior and external failover are already
agreed and need no reconfirmation.

Sources: [Perennial pinned dependency definition](https://github.com/mit-pdos/perennial/blob/3e3e0a484d61d0a15b578f5d5887ead84f145d71/perennial.opam),
[current Goose source](https://github.com/mit-pdos/perennial/tree/3e3e0a484d61d0a15b578f5d5887ead84f145d71/goose),
and [language survey](verification-research.md).
