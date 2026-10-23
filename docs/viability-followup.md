# Follow-up: implementation and proof viability

Date: 2026-10-23. This extends the [first experiments](experiment-results.md).
It is a feasibility study, not a production gateway or a performance benchmark.

Decision after evaluation: continue with Rust and Verus. Perennial's experimental
code has been removed; its results and tradeoffs remain here for reference. To
revisit or reproduce it, use a separate checkout of commit `7869347`, which contains
the Go source, generated code, proofs, and runners.

## Verus: move from counters to bytes

`experiments/verus/bytes.rs` owns a bounded byte vector and tracks its request
identity, durable offset, and output position. Its fields are private. Four
operations are verified: construction, durable acknowledgment, returning the next
byte, and logger failure. The byte-return contract states that every successful
call returns exactly the byte at the previous output position and advances by one.
An erased ghost history proves that the accumulated returned bytes equal the
corresponding prefix of the input vector; it consumes no runtime history buffer.
Wrong-identity calls cannot change state. Strict mode cannot advance beyond the
durable offset; a closed chunk cannot emit a byte.

Results: **4 functions verified, 0 errors**; the compiled, interleaved two-request
example passed. Three mutated implementations were rejected: replacing output
with zero, removing the request-identity check, and removing the durability gate.
The source contains no assumed lemmas or external-body escapes.

This is stronger evidence than the first offset experiment: the executable code
returns actual payload bytes. It is still deliberately small. It owns one chunk,
rejects oversized chunks at construction, and assumes a trustworthy
durability acknowledgment. It does not prove uniqueness of request identities,
correct binding of sockets to identities, safe reuse across chunks, disk durability,
or behavior of a concurrent HTTP adapter. Its one-byte interface is an experiment,
not the proposed production forwarding API. A production design should issue
bounded slice permits and handle partial writes without per-byte calls.
The vector already exists when the constructor checks its size: bounding allocation
requires the adapter to read into bounded buffers, not just call this constructor.

Verus-specific friction encountered: private state requires public specification
views in public contracts; this keeps representation private but adds specification
API work. The previous experiment already encountered release-specific mutable
reference syntax. Pinning the toolchain and testing upgrades is necessary.

Reproduce with the release pinned in the first results:

```sh
VERUS=/path/to/verus python3 experiments/verus/check_bytes.py
```

## Perennial: move from translation to program proofs

The follow-up uses the same pinned Perennial revision as the first experiment.
The generated proof support adds field ownership and update rules to the already
translated Go implementation. `policy_proof.v` covers these concrete operations:
cancellation sets the closed field without changing others; logging failure marks
the failure and closes strict mode while preserving the availability-first mode's
previous closure state. A third theorem proves that sending on a closed stream
returns false and leaves its state unchanged, for any count. These are program-logic statements about the generated Go
code, not separately handwritten state-machine models.

Results: **all three theorems compiled with Rocq, with completed Qed proofs**.
The generated ownership-support file also compiled. No `Admitted`, `Axiom`, or
proof-skipping compilation mode was added to our proof. This establishes exact
policy-operation behavior under the framework's semantic assumptions; it does not
prove the full original core invariant, crash recovery, or byte preservation in Go.

`Print Assumptions` reports `go.type_eq_dec` and `go.signature_eq_dec` for each
theorem. Both are upstream admitted equality-decision instances in
`new/golang/defn/prelang.v`. Their statements concern deciding equality of Go types
and signatures; they do not assume the desired gateway properties. They are still
part of the trust boundary and must be disclosed. The theorems are also explicitly
parameterized by Go/package/FFI semantics, so this assumption printout is not a
complete list of deployment trust dependencies.

The negative experiment also passed: removing cancellation's store caused
`wp_Cancel` to fail with an incomplete proof. The original code was restored and
all three theorems checked again successfully.

The temporary environment uses OPAM 2.6.1, OCaml 5.3.0, Rocq 9.2.0, Rocq stdlib
9.1.0, and the upstream pinned Iris/Perennial dependencies. It uses the existing
Homebrew GMP library and a locally built pkgconf 2.5.1. No default user toolchain
was replaced. The proof-setup helper produced a skeleton using outdated API names
and `Admitted` placeholders; that skeleton was not used as verification evidence.
The custom proof follows the current upstream tutorial instead.

Building this environment exposed more setup work than Verus's downloadable
binary. That is a local cold-start observation, not a fair measure of steady-state
proof development or the framework's ability to verify crash recovery.

After the cold build, changes to our proof required only rebuilding its own file.
The nontrivial proof adjustment was preserving the strict-mode case equality while
simplifying a record update so the heap ownership assertion matched the result.
This is manageable, but requires familiarity with Rocq and Iris proof mode beyond
ordinary Go development. The generated support and proof-skeleton helpers are
different: the support compiled; the skeleton needed replacement.

The following historical commands require a checkout of this project at `7869347`;
the runners no longer exist on the active branch. Separately, prepare a dedicated
writable checkout of the pinned upstream Perennial revision:
install dependencies from its `perennial.opam`, activate that OPAM environment,
set `PERENNIAL_ROOT` to the checkout, then run:

```sh
python3 experiments/perennial/check_policy.py
```

The script stages the generated code, generated ownership support, and policy proof
into the checkout and builds the specific proof target with its dependencies.
No files are copied when their contents are unchanged. For the negative check,
also put the pinned Goose translator and Go on PATH and run:

```sh
python3 experiments/perennial/check_mutation.py
```

That runner generates a version with cancellation's store removed, checks for
failure in the policy proof, then restores and rechecks the original code.

## Decision criteria

| Question | Verus | Perennial |
| --- | --- | --- |
| Does the proof follow executable code? | Yes: contracts on the compiled Rust functions | Through generated Go semantics and separately checked program proofs |
| Where does proof maintenance live? | Alongside Rust, with SMT-friendly specifications | Go source, generated semantic/ownership support, and Rocq proof scripts |
| What is trusted beyond the theorem? | Verus translation, solver, Rust compiler, external contracts, runtime | Goose translation and semantic assumptions, Rocq kernel, Go compiler, external contracts, runtime |
| How do we reach actual crash consistency? | Build explicit persistence/recovery specifications and prove adapter obligations | Use a framework designed for crash reasoning, with a compatible disk model |
| Does either prove deployed availability today? | No | No |

Do not equate an offset acknowledgment with an actual durable write in either
stack. Filesystem crash semantics, stuck I/O, record recovery, and the boundary
between durable logging and network submission are the next substantive storage
questions. A durable local log also does not survive permanent loss of its host.

Crash consistency and availability are separate. A recovery theorem can show that
surviving records remain valid; it does not prevent the process from dying, make
fsync finish, or reconnect an interrupted generation. Both paths still need bounded
queues and worker counts, explicit timeout handling, readiness/draining behavior,
and the agreed external load balancer. Merely using Perennial does not establish
liveness; a Rust memory-safety guarantee does not establish crash consistency.

The implementation should use one main proof stack. Combining both in the gateway
would add maintenance and cross-language contracts before demonstrating a need.

## Recommendation after this step

**Use Rust plus Verus as the active implementation path.** It has now checked
both policy counters and an executable byte-preserving chunk abstraction, including
negative checks that catch deliberately broken implementations. Its proof workflow
has been more direct for the properties this minimal forwarding gateway needs.
Next, integrate a bounded slice-based core with a minimal real streaming adapter,
keeping source-to-socket and disk-acknowledgment contracts explicit.

**Retain Perennial research for a possible revisit if verified persistent storage
becomes the main deliverable.** It was a demonstrated proof path here, not merely a
translator we managed to run. Its crash logic is a reason to invest further, but
our three policy theorems do not yet demonstrate that benefit. A deciding storage
experiment would prove recovery preserves acknowledged records using a specified
disk model, then identify how a real filesystem adapter meets that model.

This is not an apples-to-apples benchmark: Verus's new properties concern bytes;
Perennial's new properties concern exact state updates and rejection after closure.
The results support a workflow recommendation, not claims about maximum provable
scope, performance, or superiority of either proof foundation. No production
latency or throughput measurements were made.
