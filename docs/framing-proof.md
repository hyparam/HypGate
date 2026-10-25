# Record framing proof

The production [framing core](../crates/gateway-core/src/framing.rs) is compiled
by Cargo and checked by Verus. The disk serializer and incremental recovery scanner
both call it; the on-disk format is unchanged.

## Checked properties

`encode_session` produces exactly the eight-byte `SGLOG001` version marker and
sixteen supplied session bytes. `decode_session` accepts exactly that 24-byte
prefix when the externally supplied checksum result is true, returns the exact
session identity, and rejects other lengths or versions. Startup and recovery
both call these operations. The fixed-length session checksum is still computed
and compared by trusted SHA-256 code; random-session generation and uniqueness
are not proved, and a checksum is not source authentication.

A valid header has a payload length at most one MiB, a nonzero request ID, and a
record kind of at most 4. Kinds 0 and 1 are the body directions (`body_kind`);
kinds 2 to 4 are the metadata records (`metadata_kind`); `kinds_partition` states
that these two classes are disjoint and together are exactly the valid kinds.
Tenant and chunk IDs may use the full u64 range. These are structural checks,
not authentication or authorization of recorded identities.

The widened kind bound lives only in framing. The body-write path is unchanged:
`StreamChunk::audit_record` and `AuthorizedWrite::{prepare,bytes}` still refuse any
direction above 1, so no body receipt can carry a metadata kind, and
`OwnedStream::receipt_is_body_record` proves the converse for strict-mode
evidence: the receipt's canonical header decodes to the current chunk's header
for the recorded body direction (`encoding_decodes` makes the header encoding
injective), so a metadata record can never stand behind a write ticket.
`AuthorizedWrite::delivers` now states this decoded-kind fact for every byte
range it releases. `audit_record` also refuses chunk 0, the unfilled initial
state, so body records are numbered from 1 and the runtime's metadata records own
chunk 0 without overlap.

`encode` rejects invalid fields and otherwise produces exactly 33 bytes: record
magic, little-endian payload length, tenant/request/chunk IDs, and direction.
Its postcondition proves that specification decoding returns the original fields.
`decode` agrees with the specification on every input, rejects malformed headers,
and proves that every accepted header re-encodes to the identical input bytes.

`encode_payload` rejects a header whose declared payload length differs from the
supplied slice, as well as invalid headers. On success it proves the output is
exactly the canonical header followed by the unchanged complete payload, with
length 33 plus the payload length and at most 1,048,609 bytes. The runtime hashes
these verified bytes, and the verified sealing operation appends the digest. The encoder reserves payload plus
65 bytes so the checksum fits without adapter growth; allocator behavior remains
outside the byte-sequence proof.

`RecordBody::new` owns that canonical encoding behind private fields and exposes
only a borrowed byte view for checksum calculation. `seal` consumes the body and
appends exactly the supplied 32-byte checksum, producing an immutable `RecordFrame`.
Its invariant binds the complete byte vector to canonical header, exact payload,
and exact checksum. Metadata/payload witnesses are ghost state, so the queue still
owns only one vector at runtime. There is no mutable accessor or constructor for
arbitrary sealed bytes. The checksum may be incorrect: cryptographic computation
and its association with the supplied body remain trusted.

The production disk queue now carries `RecordFrame`. The worker writes its byte
view and, after sync, uses `Journal::commit_frame`. On success the checked
acknowledged prefix is exactly the old history followed by this frame's canonical
header, payload, and checksum. Thus framing and journal byte identities compose;
the [journal receipt path](journal-proof.md) now connects this record to stream write authorization.

## Metadata payload codecs

`metadata.rs` holds the payload codecs for kinds 2 to 4, in the same style as the
header: an open specification encoding, a specification decoder, an executable
`encode_*` whose postcondition states that specification decoding returns the
original fields and the exact length, and an executable `decode_*` that agrees
with the specification on every input and re-encodes to the identical bytes.

| Record | Fields | Length | Rejected |
| --- | --- | --- | --- |
| Request start | u64 time, u64 selector, u16 length, destination | 18 + destination, at most 8,210 | destination length 0 or above 8,192; a declared length that does not match the slice |
| Response head | u64 time, u16 status | 10 | status below 100 or above 999; any other length |
| Completion | u64 time, u8 outcome, u64 upload bytes, u64 download bytes | 25 | outcome above 7; any other length |

`request_start_roundtrip`, `response_head_roundtrip`, and `completion_roundtrip`
are the exact-length and specification-roundtrip theorems; `metadata_payloads_bounded`
shows every metadata payload fits the 8,210-byte limit the executable gives the
logger. The codecs check structure only: the clock value, HTTP status, outcome
code, and destination text are supplied by trusted runtime code, and the
destination's ASCII content is enforced by configuration parsing, not here.

`frame_end` advances by exactly 33 header bytes plus payload plus 32 digest bytes.
It rejects oversized payloads, insufficient available bytes, and offset overflow.
The accepted end strictly advances and never exceeds the supplied available extent.

## Recovery cursor

The production scanner now owns a verified `Cursor` instead of independently
updating an offset and stop flag. `begin` preserves the offset, sets the cursor
stopped before any I/O, and issues one private-constructor, non-cloneable ticket.
While stopped, further `begin` calls fail. `accept` consumes the ticket, checks
its starting offset, and uses `frame_end` to advance by exactly one complete
bounded frame. A rejected completion leaves the state unchanged; a successful
completion strictly advances the offset and permits the next read.

The runtime keeps the ticket local to `next_record`. Every EOF, read failure,
malformed header, or checksum error drops it without reopening the cursor.
Only successful exact reads and checksum validation reach `accept`. This makes
failure default to stopping, but the call-site validation remains trusted.
Tickets must stay with their originating reader: identical offsets in separate
cursors do not establish distinct identities. The runtime never exports tickets.
These statements are state/extent proofs, not a theorem that the recovered
records equal the acknowledged journal prefix.

## Runtime binding and trusted boundary

The scanner decodes the fixed-size header before allocating the payload buffer.
It reads the entire payload and digest, validates SHA-256, and only then calls
`frame_end` with the lengths of those successfully read buffers. The serializer
validates record bounds before calling the core payload encoder, then hashes its
result and consumes it through the verified sealing operation. Those call-site bindings remain trusted Rust.

The [verified scanner](recovery-proof.md) composes these operations under an explicit
source contract. Verus does not prove the runtime `Read` implementation, exact-read
adapter, checksum implementation, or correspondence to physical disk.
The extent theorem depends on the caller reporting bytes actually available; it
cannot establish that fact from I/O. Checksums are not authentication against a
writer who can modify the log and recompute them. Standard-library byte conversion
contracts in vstd are part of the verification trust boundary. No new `assume` or
external-body escape is introduced here.

Together with the [journal proof](journal-proof.md), this reduces the remaining
recovery obligation but does not prove that every acknowledged record will be
returned by recovery after a real power failure. The [storage contract](storage-crash-contract.md)
states the separate persistence assumptions.

## Validation

Boundary-value roundtrips and malformed header/extent tests run through ordinary
Cargo, including every kind byte from 0 to 255, destination lengths 0, 1, 8,192,
and 8,193, status and outcome boundaries, and every truncation and bit flip of a
metadata record. Three cursor mutations reopen a stopped scanner, advance before
validation, or regress its offset. Two payload mutations omit the body or remove
its length check. Framing mutations switch the request field to tenant bytes,
remove the payload bound, accept incomplete extents, skip a frame byte, accept an
unknown kind in the encoder or decoder, or drop the kind byte. Guard mutations
widen the body-direction checks in `audit_record`, `prepare`, and `bytes` to the
metadata kinds, or let a body record use chunk 0. Thirty-one codec mutations
remove each length check and corrupt each field of each metadata payload in the
encoder and the decoder; all are rejected.
Current check, test, and mutation totals are maintained in the [README](../README.md);
counts describe checks, not independent guarantees.
