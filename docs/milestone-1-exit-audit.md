# Milestone 1 exit audit

Audited on 2026-10-23 against the seven exit criteria in the implementation plan,
including the sealed raw-stream APIs. **Milestone 1 remains open.** Six criteria
are covered within the synchronous core's stated preconditions; the complete
resource-accounting criterion is partial. This does not move unfinished work to
another milestone or treat adapter assumptions as proved runtime behavior.

| Exit criterion | Evidence and scope | Status |
| --- | --- | --- |
| Compiled executable core and checked proofs cover every public transition | Cargo compiles the same `gateway-core` sources checked by the unfiltered `cargo verus verify -p gateway-core` invocation: 175 checks pass. Production core sources contain no `assume` or external-body escape. The proof index identifies contracts and external interfaces; runtime adapters and vstd contracts remain trusted. Raw stream construction/claim/release is crate-private, so external code must use OwnedStream. | Covered for the core |
| Partial, zero-progress, invalid, and stale completions have specified behavior | `StreamChunk::{prepare,pending_bytes,complete}` specifies exact matching owner/generation, permitted byte ranges, accepted partial counts, and unchanged state on rejection. Streaming/composition tests and deliberate completion defects exercise the compiled path. A reported write count still assumes truthful I/O. | Covered for the core |
| Cancellation prevents new writes while accounting for an already issued write | `cancel` closes the stream; `prepare` and `pending_bytes` refuse further submissions. `complete` can account for the matching already-issued range without granting a new range. OwnedStream preserves those contracts. Actual future cancellation and effect termination are separate adapter obligations. | Covered for the core |
| Multiple chunks and requests preserve ordering and cannot mix identities | Chunk rollover preserves the byte-prefix history, request ownership, and monotonic offsets; tickets bind owner and generation and reject exhaustion. OwnedStream consumes its unique key and cannot expose a mutable or owned raw stream externally. Numeric identities remain scoped to a registry, which the runtime lease must bind correctly. | Covered within one correctly bound registry |
| Queue, buffer, and outstanding-operation limits have explicit accounting | Verified admission, owned stream/read bounds, fixed audit FIFO/closure and actual queued-frame byte bound, conditional buffer subtotal, and source inventories cover substantial parts. Complete runtime-to-snapshot correspondence and allocation composition remain unresolved, as detailed below. | **Partial: blocks closure** |
| Mutation tests reject corruption, cross-request writes, duplicate advancement, capacity violations, and strict-mode forwarding before durability | All 131 mutations are rejected by proof obligations; the script verifies the unmodified library first. Named defects include wrong owner/generation, full-write substitution, omitted payload/receipt storage, queue overwrite/reopening, and advancing beyond durability. Mutations test the strength of specified contracts, not the completeness of the threat model. | Covered for listed defect classes |
| Verified admission issues private authorization tied to identity/policy/origin/credential; candidate configuration cannot expand root grants | Policy validation, authentication, and tenant-scoped authorization establish those relationships. AuthorizedRequest construction is private and its policy borrow binds the immutable snapshot. Runtime dispatch consumes PreparedRequest; concrete URI/DNS/TLS/secret binding remains trusted and tested. | Covered at the verified admission boundary |

The current workspace has 150 passing regular tests and five compile-fail doctests.
The raw-construction, raw-claim, and raw-release negative examples require the
private-method diagnostic; existing examples prohibit mutable stream extraction
and completing a read while its mutable buffer borrow remains live. Low-level
adversarial stream tests now run inside the core crate, retaining their coverage
without reopening the external API.

## Remaining work for criterion five

1. **Complete runtime ownership correspondence.** The owner-map lemmas preserve
   initialization, reservation, claim, replacement, and retirement. Their global
   bound still takes a complete snapshot as a premise. The runtime must account
   for every live owner, encoding frame, delivered receipt, channel endpoint, and
   cleanup tail at each relevant transition. Rust privacy and field drop order
   support that argument but are not a mechanically checked async refinement.
   The actual frame queue now supplies queued count and structural validity to the
   subtotal and enforces its configured payload limit. The core also charges one
   encoding reservation against Q, and the combined theorem explicitly includes its
   byte snapshot. Production uses the verified reserved encoder, and typed
   composition derives actual body/frame lengths. Production enqueue hides the
   callback/core reference and consumes a private single-use encoding permit. The
   queue module, synchronization, and snapshot completeness remain trusted. Startup binding to K and
   the other snapshots remain explicit premises.
   Sealing raw constructors removes one external bypass; it does not prove
   registry identity, destructor timing, or snapshot completeness.
2. **Finish allocation accounting beyond logical payloads.** The disk queue now
   requests a fixed Q-slot vector with verified unchanged slot count. Audit encoding
   requests P + 65 frame bytes plus 33 header scratch bytes; boundary tests check
   reported capacity and unchanged allocation across sealing. These are allocation
   requests and regression evidence, not a proof of allocator overhead. HTTP channels now use one fixed slot and bounded registered wakers, removing
   linked-block growth/reuse overlap; Hyper parser/output backing capacity,
   metadata collections, TLS handshake/cache active owners, task/waker storage,
   and allocator/OS storage remain outside the subtotal. The dependency audit
   distinguishes known control-object counts and stack reservations from unresolved
   peak allocations. No RSS plateau substitutes for these obligations.
3. **Compose the lifetime scopes.** Connection budgets are per server invocation;
   aborted invocation tails can outlive that parent. Worker/request budgets belong
   to their registries, DNS jobs to their transport, and audit jobs to their logger.
   A complete bound must state the instance/lifetime assumptions and count those
   tails before combining categories. It cannot reclaim an operation's resources
   merely because its caller timed out.

The next closure review should discharge these items against the actual production
owners and the combined theorem, then rerun the required checks. It should not
close the milestone by counting additional lemmas, passing more examples, or
renaming an unresolved resource obligation.

See the [resource inventory](resource-accounting.md),
[runtime ownership](runtime-ownership.md), [audit ownership](audit-buffer-lifetimes.md),
[dependency audit](dependency-resources.md), and [proof index](proof-index.md).
