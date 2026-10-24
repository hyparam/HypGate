# Milestone 1 exit audit

Audited on 2026-10-23 against the seven exit criteria in the implementation plan,
including the sealed raw-stream APIs, and re-audited on 2026-10-24 after the
resource composition. **Milestone 1 is closed under the explicit assumptions in
the [resource composition](resource-composition.md).** Six criteria are covered
within the synchronous core's stated preconditions; the resource-accounting
criterion is covered conditionally on the runtime-correspondence, pinned
dependency, and allocator/OS assumptions listed there. This does not move
unfinished work to another milestone or treat adapter assumptions as proved
runtime behavior; the assumptions remain visible obligations.

| Exit criterion | Evidence and scope | Status |
| --- | --- | --- |
| Compiled executable core and checked proofs cover every public transition | Cargo compiles the same `gateway-core` sources checked by the unfiltered `cargo verus verify -p gateway-core` invocation: 183 checks pass. Production core sources contain no `assume` or external-body escape. The proof index identifies contracts and external interfaces; runtime adapters and vstd contracts remain trusted. Raw stream construction/claim/release is crate-private, so external code must use OwnedStream. | Covered for the core |
| Partial, zero-progress, invalid, and stale completions have specified behavior | `StreamChunk::{prepare,pending_bytes,complete}` specifies exact matching owner/generation, permitted byte ranges, accepted partial counts, and unchanged state on rejection. Streaming/composition tests and deliberate completion defects exercise the compiled path. A reported write count still assumes truthful I/O. | Covered for the core |
| Cancellation prevents new writes while accounting for an already issued write | `cancel` closes the stream; `prepare` and `pending_bytes` refuse further submissions. `complete` can account for the matching already-issued range without granting a new range. OwnedStream preserves those contracts. Actual future cancellation and effect termination are separate adapter obligations. | Covered for the core |
| Multiple chunks and requests preserve ordering and cannot mix identities | Chunk rollover preserves the byte-prefix history, request ownership, and monotonic offsets; tickets bind owner and generation and reject exhaustion. OwnedStream consumes its unique key and cannot expose a mutable or owned raw stream externally. Numeric identities remain scoped to a registry, which the runtime lease must bind correctly. | Covered within one correctly bound registry |
| Queue, buffer, and outstanding-operation limits have explicit accounting | Verified admission, owned stream/read bounds, fixed audit FIFO/closure and actual queued-frame byte bound, and the conditional buffer subtotal cover the visible payload. The [resource composition](resource-composition.md) maps every theorem category and cancellation tail to its production owner, assigns every budget to one instance, and sums the dependency inventories into a requested-allocation bound that `budget.rs` computes. Descriptor sizes, allocator/OS behavior, and the async correspondence are explicit assumptions. | Covered conditionally |
| Mutation tests reject corruption, cross-request writes, duplicate advancement, capacity violations, and strict-mode forwarding before durability | All 139 mutations are rejected by proof obligations; the script verifies the unmodified library first. Named defects include wrong owner/generation, full-write substitution, omitted payload/receipt storage, queue overwrite/reopening, and advancing beyond durability. Mutations test the strength of specified contracts, not the completeness of the threat model. | Covered for listed defect classes |
| Verified admission issues private authorization tied to identity/policy/origin/credential; candidate configuration cannot expand root grants | Policy validation, authentication, and tenant-scoped authorization establish those relationships. AuthorizedRequest construction is private and its policy borrow binds the immutable snapshot. Runtime dispatch consumes PreparedRequest; concrete URI/DNS/TLS/secret binding remains trusted and tested. | Covered at the verified admission boundary |

The current workspace has 179 passing regular tests and five compile-fail doctests.
All five CI jobs passed at `154ef03`, the closing commit, in
[run 40068082114](https://github.com/platypii/LogGate/actions/runs/40068082114):
183 production proof checks, all 139 rejected mutations, Rust tests, Linux ext4,
proxy failover, and the 100-wave memory soak.
The raw-construction, raw-claim, and raw-release negative examples require the
private-method diagnostic; existing examples prohibit mutable stream extraction
and completing a read while its mutable buffer borrow remains live. Low-level
adversarial stream tests now run inside the core crate, retaining their coverage
without reopening the external API.

## Closure evidence for criterion five

The three items that previously blocked closure are discharged in the
[resource composition](resource-composition.md), which the earlier increments
recorded in this section now support:

1. **Runtime ownership correspondence.** A table maps each category of
   `Buffers::accounted_payload_bound` (chunks, readers, output queues, queued
   log, encoding snapshot, active log, receipts, headers) to the production
   owner type, the event that inserts it, the event that removes it, and the
   mechanism that enforces its count. Cancellation tails are enumerated so no
   snapshot entry is dropped from the sum. The verified transitions, Rust field
   drop order, and the lifetime regressions support that table; a mechanized
   async refinement is not claimed and is the first listed assumption.
2. **Allocation accounting beyond logical payloads.** The HTTP, TLS deframer,
   transcript, HelloRetryRequest, queued-ciphertext, peer-chain, session,
   verifier, metadata, DNS, configuration, stack, and cache inventories are
   summed into B(R, K, C, Q). The queued-ciphertext window composes the control
   audit with the production drain guard. `gateway-runtime/src/budget.rs`
   computes the figure with checked arithmetic, pins the documented constants
   and the executable example (about 441.1 MB for R = 32, K = 16 KiB, C = 128,
   Q = 16), and the executable prints it at startup. Objects whose sizes are
   private ABI facts are listed with bounded counts as assumptions.
3. **Lifetime and instance scopes.** Every budget is assigned to one owner
   (`GatewayConfig`, `Gateway`, a `serve` invocation, `HttpsTransport`,
   `DiskLog`, an admitted exchange, an inbound connection task) with its
   lifetime and the tails that outlive callers. Instances compose additively;
   no path reclaims resources because a caller timed out.

The composed figure is a conservative requested-allocation ceiling under seven
explicit assumptions: runtime correspondence, pinned dependency source,
allocator/OS behavior, fixed-size descriptors, one instance of each owner,
the protocol scope, and honest effects. It is far above measured RSS by design,
because it charges every owner at its replacement peak simultaneously. Closing
the milestone on this basis does not certify total process memory; it certifies
that no queue, buffer, or outstanding operation in the production path is
unaccounted within those assumptions.

See the [resource inventory](resource-accounting.md),
[runtime ownership](runtime-ownership.md), [audit ownership](audit-buffer-lifetimes.md),
[dependency audit](dependency-resources.md), and [proof index](proof-index.md).
