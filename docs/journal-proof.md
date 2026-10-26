# Journal acknowledgment proof

The production disk worker uses [AuditJournal](../crates/gateway-core/src/audit_journal.rs),
which wraps the [journal state machine](../crates/gateway-core/src/journal.rs) and
permits only canonical-frame commits. It tracks one pending append and
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

The worker reserves before writing, then calls `commit_frame` only after both
`write_all` and `sync_all` succeed for that immutable frame. This verified operation
uses `record_durable` to compose `record_written`, `sync_succeeded`, and
`acknowledge`. The queued immutable `RecordFrame` binds that byte sequence to its
canonical metadata, payload, and checksum. Success proves that
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
experiments now exist, including Linux ext4 ENOSPC, EROFS, and process-death
validation. Receipt delivery across threads and journal/session ownership remain trusted. No `assume` or external-body escape was introduced.

The wrapper's ghost frame sequence proves that acknowledged bytes are exactly
those frames concatenated in commit order. Its conditional reconstruction theorem
connects that sequence to actual verified scanner steps; see the
[recovery proof](recovery-proof.md). This assumes preserved synced bytes, correct
checksums, successful scanner initialization, no read errors, and offsets fitting
in `u64`. It does not retain past frame allocations at runtime.

## Durable receipts and stream authorization

`commit_frame` consumes the sealed frame and issues a private-constructor
`DurableFrame` only after successful journal acknowledgment. Its ghost prefix and
owned frame capture exactly the journal's acknowledged history at issuance.
The worker sends this receipt through the job's oneshot instead of a boolean.
`AuditLog::append` returns the receipt, and `BodyCopy::finish_audit` passes it to
verified `OwnedStream::acknowledge_receipt` while the loop retains exclusive ownership.

The stream checks canonical tenant/request/chunk/direction metadata and exact
payload bytes, not merely their length or a digest. Success proves that the receipt's
acknowledged history contains that canonical current record and advances the
stream's durable offset to the complete chunk length. All other stream state is
preserved. Invalid receipts leave core state unchanged; the runtime cancellation
guard closes the request on rejection, in either logging mode. Exact acceptance
conditions also rule out arbitrary refusal of an otherwise valid receipt.

This composes journal acknowledgment with the stream gate under the journal's
truthful write/sync event assumptions. It does not prove an external logger actually
performed I/O: custom implementations can invoke the journal's event API, just as
other trusted adapters can. Receipt origin and file/session scope remain bound by
the production logger's ownership. Equal record bytes in separate journals do not
establish the same physical log. Checksum cryptography remains trusted for recovery,
but receipt-to-stream byte equality does not assume collision resistance.

Receipts retain one frame until consumed or canceled. The additional memory is
accounted for in the [resource inventory](resource-accounting.md). Runtime tests
return receipts with wrong tenant, request, chunk, direction, same-length bytes,
and payload length, and check that none permits forwarding or reusing the request.

## Validation

The current totals are recorded in the README. Journal tests cover exact-length
commit, duplicate and stale tickets, failure, and refusal to skip an earlier
unacknowledged record. Mutations additionally remove the composed sync, remove the
acknowledgment, or bypass the prior-acknowledgment check and must fail verification.
The earlier mutations still check sync gating, pending append replacement, incorrect
frame length, and stable-prefix regression. CI uses the production sources.
