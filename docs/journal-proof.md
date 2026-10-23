# Journal acknowledgment proof

The production core's [journal.rs](../crates/gateway-core/src/journal.rs) is used
by the disk worker for every framed record. It tracks one pending append and
written, durable, and acknowledged offsets relative to the already-synced session
header. Full byte history is ghost state, erased in the executable; runtime journal
memory is constant-size.

## Checked properties

`begin` reserves a nonempty range with checked arithmetic and rejects another
pending append. A private-constructor ticket identifies the range. `record_written`
accepts only its matching ticket and exact frame length, appends exactly the supplied
bytes to ghost history, and preserves stable/acknowledged prefixes. `sync_succeeded`
advances the stable prefix only when no append is pending. `acknowledge` advances
only from the preceding acknowledged boundary to a ticket's end within the stable
prefix. Duplicate/stale acknowledgments are rejected. `fail` permanently prevents
further successful append, completion, sync, and acknowledgment transitions.

The invariant orders acknowledged, durable, and complete-written offsets, and
equates ghost-history length with the complete-written offset. Every executable
transition preserves it and the specified byte-prefix relationships.

`acknowledged_prefix_survives` is a conditional crash lemma: for any recovered byte
sequence containing the stable prefix unchanged, the entire acknowledged prefix
also exists unchanged. Preservation of the stable prefix is an explicit theorem
precondition, not a proved filesystem property. Scanner acceptance/refinement is
a separate obligation; the lemma does not assume or prove scanner correctness.

## Runtime correspondence and limits

The worker reserves before writing, calls `record_written` after `write_all` succeeds
with that immutable frame, and calls `sync_succeeded` only after `sync_all` succeeds.
It sends a positive result only after `acknowledge` succeeds. Any failed operation
closes the journal and poisons logger health. A failed syscall may leave an unknown
physical suffix; no later record is written or acknowledged through that journal.

These event bindings are trusted Rust, exercised by the disk fault tests. Verus
does not verify syscalls or worker control flow. The worker exclusively owns one
file and journal; tickets never leave it. The public core alone cannot distinguish
tickets from different journal instances with identical offsets. File/session
ownership is an adapter obligation. Storage must preserve previously synced bytes.

This proves acknowledgment ordering and conditional byte-prefix survival, not
complete crash-safe logging. [Header and frame-extent proofs](framing-proof.md),
a documented [storage contract](storage-crash-contract.md), and process-kill
experiments now exist. Full scanner refinement, storage-stack validation, and
record-identity/stream-ack composition remain open. No `assume` or external-body escape was introduced.

## Validation

The combined core passes 48 Verus checks and all 61 workspace tests pass. All 29
deliberate mutations fail proof obligations. Four journal mutations remove the sync
gate, replace a pending append, accept the wrong frame length, or regress the stable
prefix. CI checks the same production sources and pinned toolchain.
