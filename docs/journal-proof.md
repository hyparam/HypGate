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

The worker reserves before writing, then calls `record_durable` only after both
`write_all` and `sync_all` succeed for that immutable frame. This verified operation
composes `record_written`, `sync_succeeded`, and `acknowledge`. Success proves that
the new acknowledged and stable histories equal the previous complete history
followed by exactly the supplied frame bytes. It rejects stale tickets, incorrect
lengths, failed journals, and an unacknowledged earlier record without changing state.
The worker sends a positive result only after this operation succeeds. If writing
or syncing fails, the model retains its earlier prefix and the journal is failed;
physical bytes beyond that prefix may exist but cannot authorize an acknowledgment. Any failed operation
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

The current totals are recorded in the README. Journal tests cover exact-length
commit, duplicate and stale tickets, failure, and refusal to skip an earlier
unacknowledged record. Mutations additionally remove the composed sync, remove the
acknowledgment, or bypass the prior-acknowledgment check and must fail verification.
The earlier mutations still check sync gating, pending append replacement, incorrect
frame length, and stable-prefix regression. CI uses the production sources.
