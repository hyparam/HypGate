# Language and verification research

Research date: 2026-10-23. Recommendations are provisional. This is a source review,
not a benchmark or a successful verification experiment.

## Agreed scope

- Minimal forwarding, response streaming, and disk logging; no translation between
  provider APIs, model orchestration, or billing machinery.
- Operators select whether logging failure stops forwarding or allows it to
  continue with degraded audit coverage. These modes need different guarantees.
- Availability matters because the gateway is on the critical path of AI requests.
- An external load balancer handles failover between gateway instances.
- Language and prover are still open decisions.

## Recommendation

Start the evaluation with **Rust plus Verus**, with **Rust plus Aeneas/Lean** and
**Go plus Perennial/Rocq** as the strongest alternatives for different priorities.
Creusot deserves a Rust comparison experiment if Verus integration proves awkward.
Bend 2 is relevant and should not be confused with the earlier Bend/HVM project,
but its current HTTP/TLS and tooling gaps make it a higher-risk production choice.

The decisive experiment should verify a real bounded forwarding state machine,
including logging failure and cancellation, and compile that same core into a
small streaming executable. A proof of a detached model alone does not establish
that the deployed gateway follows it.

## Candidate comparison

| Candidate | What it provides | Fit and principal cost |
| --- | --- | --- |
| Rust + Verus | Specifications and deductive proofs attached to executable Rust, using SMT automation | Leading practical candidate for byte/order invariants, bounded buffers, and lifecycle rules. Supports a Rust subset; networking libraries, compiler, runtime, and I/O contracts remain trusted unless separately addressed. |
| Rust + Creusot | Rust contracts translated through Coma to Why3 verification conditions | Credible alternative with a different Rust integration and proof workflow. Its repository cites verified algorithms in a Kafka broker, a relevant precedent, not proof of an entire broker. |
| Rust + Aeneas + Lean | Translates Rust through Charon into functional definitions with theorem-prover backends | Attractive for Lean-checked proof artifacts while retaining Rust. Current documentation lists concurrency and unsafe code as limitations; suited first to a sequential core. Translation and external models need explicit trust accounting. |
| Go + Goose + Perennial/Rocq | Program logic for concurrent code, crashes, persistent state, and recovery, built on Iris | Most directly aligned with deeper crash-consistency proofs. Specialized Go subset, substantial proof work, and syscall models; does not automatically verify Go's HTTP stack or deployed storage hardware. |
| Dafny | Verification-oriented language with SMT automation and executable compilation targets | Good for a small state machine and inductive invariants. Integration with the production networking layer adds a boundary to maintain. |
| Lean directly | Programming language and interactive theorem prover with kernel-checked proof terms | Strong option for mathematical specifications and a pure executable core. Writing a model in Lean and separately implementing it in Rust leaves a correspondence obligation. Aeneas is one route to reduce manual duplication. |
| F*/Low* | Dependent types, SMT automation, and effectful verification; Low* can compile to C | Serious option when verified low-level components and protocol work dominate. More specialist integration work than the proposed Rust core. |
| Bend 2 | Affine dependent types, laws, proofs, native compilation, and optional rechecking with a kernel formalized in Lean | Real verification features, but a young compiler and small library ecosystem. Missing HTTP/TLS libraries are especially costly for this project. |
| Kani | Model checking of Rust harnesses, including panic/overflow checks and assertions | Useful supplement for finite helpers and bounded scenarios. Harness assumptions, loop bounds, reachability, and supported language features determine coverage; not a blanket proof of an indefinitely running async gateway. |
| TLA+ / TLC | Behavioral specification and finite-state model checking of concurrent systems | Useful for failure interleavings, backpressure, and shutdown design. Does not itself establish that the production implementation refines the model. |

## What Bend actually offers

The current Bend site advertises laws and proof checking. The repository explains
that Bend 2 differs from Bend 1 and HVM; evaluating only the older parallel
language would miss the current proposal.

The guide describes `--verdict` as a second check through a small kernel with a
proof in Lean. This is different from claiming the whole compiler, runtime, I/O
stack, or resulting native binary has been verified. The guide explicitly says
the translation into the kernel has no proof. The README also states that backend
semantics can differ from Bend semantics and that the default checker may have
bugs. These are disclosed trust boundaries, not evidence that all Bend proofs fail.

The current README lists no TLS or HTTP library, no tactics or proof search, a
small base library, and limited tooling. Foreign implementations can supply missing
I/O capabilities, but then those implementations and their contracts become part
of the gateway's trusted boundary. GPU parallelism does little to resolve this
gateway's dominant problems: streaming I/O, cancellation, backpressure, and disk
durability.

Conclusion: consider Bend for a proof prototype or reconsider when its ecosystem
changes; do not choose it for the first production gateway solely on its proof or
performance marketing. All candidates require explicit specifications: no language
can prevent bugs that the specifications omit.

## Proposed architecture and guarantees to evaluate

Keep HTTP/TLS handling in a narrow adapter and make the verified core decide the
allowed actions. It should own request identities, byte offsets, buffer credits,
logging mode, and lifecycle transitions. The adapter must execute only authorized
actions and report their outcomes without inventing acknowledgments. This adapter
is a critical trust boundary, not an incidental wrapper.

Proof candidates, in approximate priority order:

1. **Stream fidelity and isolation.** Every emitted body is an ordered prefix of
   the corresponding received body; successful completion implies equality. No
   duplicated, reordered, or cross-request bytes. This is body-byte fidelity, not
   preservation of TLS records, HTTP chunk boundaries, or header serialization.
2. **Destination and credential confinement.** Forward only to an admitted,
   configured destination. Request data and redirects must not select arbitrary
   origins or send a credential to another origin. Credential headers must not
   enter audit metadata or diagnostics. Raw opaque bodies can themselves contain
   secrets, so an unconditional claim that logs contain no secrets is impossible.
3. **Strict audit mode.** Before a body range is submitted to the outbound
   transport, that exact range and its request identity have a durable log
   acknowledgment. Mere buffered writes do not establish crash durability.
4. **Availability-first audit mode.** Logging failure cannot consume unbounded
   queue space or indefinitely delay forwarding. Audit gaps must be represented
   and reported when reporting is possible; a crash can destroy volatile gap
   notifications, so this mode cannot promise a complete durable history of gaps.
5. **Bounded resources.** Enforce connection, buffer, queue, header, and record
   limits with checked arithmetic. Backpressure must reach the reader. Core bounds
   do not prove whole-process memory bounds if libraries allocate outside them.
6. **Lifecycle correctness.** Terminal transitions occur at most once, resources
   are released, cancellation does not leak work, and shutdown stops admission
   before draining. Error paths must preserve the same invariants as success paths.
7. **Recovery correctness.** Under a declared filesystem crash model, recovery
   preserves acknowledged records and does not mistake incomplete records for
   complete ones. Checksums detect corruption under stated assumptions; they are
   not a mathematical guarantee against arbitrary corruption or malicious edits.
8. **Conditional progress.** With explicit scheduler fairness and I/O assumptions,
   an admitted request progresses or terminates. Deadlines and resource bounds
   must cover a stalled logger and upstream. A proof cannot guarantee uptime when
   the machine, scheduler, or storage stops responding.

Logging and delivery are different facts. A durable record can exist even when
the client never received its bytes. A successful socket write is not proof that
the client application consumed them. A crash mid-generation leaves an uncertain
outcome; replaying that request can duplicate execution or charges. Automatic
replay should therefore be excluded from the initial design unless stronger
provider-specific semantics are established.

Independent instances let the external load balancer route new requests around a
failed instance. They do not make an existing stream survive process death. Shared
logging infrastructure can introduce a common failure point even with many gateway
instances. Local logs on a lost machine also require a distinct recovery policy.

## First experiment and decision criteria

Implement one small core with two concurrent request identities, bounded chunk
buffers, partial sends, logging acknowledgments, logging failure, cancellation,
and shutdown. Use arbitrary byte sequences and inductive invariants for the core
proof; a two-request finite exploration is supplementary evidence, not an all-size
concurrency theorem.

For each serious candidate, record: implementation size, proof size, verification
time, unsupported constructs, assumptions, and the amount of unverified adapter
code. Compile and exercise the same verified functions. Deliberately introduce
cross-stream output, forwarding before persistence in strict mode, and credit
leaks; the checks should reject these mutations without strengthening assumptions.

Then test the actual adapter under disconnects, slow consumers, disk-full errors,
stalled disk writes, process kills, and torn log tails. Measure forwarding latency
and memory use under load. Keep the distinction between formal proofs, bounded
model checking, fault-injection tests, and performance measurements visible.

At the time of this initial survey no candidate had been run. Subsequent
[experiment results](experiment-results.md) record the first executable proof and
Go tests; neither experiment establishes gateway latency or end-to-end correctness.

## Sources

Primary documentation reviewed; links to moving branches may change after this date.

- [Bend website](https://bend-lang.com/)
- [Bend README, including limitations](https://github.com/bendlang/bend/blob/main/README.md)
- [Bend guide and verdict boundary](https://github.com/bendlang/bend/blob/main/guide/GUIDE.md)
- [Verus overview and explicit non-goals](https://verus-lang.github.io/verus/guide/overview.html)
- [Creusot architecture and projects](https://github.com/creusot-rs/creusot)
- [Aeneas architecture, backends, and limitations](https://github.com/AeneasVerif/aeneas)
- [Perennial crash-safety framework and publications](https://github.com/mit-pdos/perennial)
- [Dafny](https://dafny.org/)
- [Lean](https://github.com/leanprover/lean4)
- [F* and Low*](https://fstar-lang.org/)
- [Kani](https://model-checking.github.io/kani/)
- [Kani loop bounds](https://model-checking.github.io/kani/tutorial-loop-unwinding.html)
- [TLA+ and its tools](https://lamport.azurewebsites.net/tla/tla.html)
- [User's preliminary research](https://chatgpt.com/share/6adb9d09-79f0-83ea-8e9b-4047491df33f)

The shared conversation was read for context. Its incident reports and claims about
the absence of existing gateways were not independently established by this survey
and are not used as evidence for the language recommendation.
