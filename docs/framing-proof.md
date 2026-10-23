# Record framing proof

The production [framing core](../crates/gateway-core/src/framing.rs) is compiled
by Cargo and checked by Verus. The disk serializer and incremental recovery scanner
both call it; the on-disk format is unchanged.

## Checked properties

A valid header has a payload length at most one MiB, a nonzero request ID, and a
direction of zero or one. Tenant and chunk IDs may use the full u64 range. These
are structural checks, not authentication or authorization of recorded identities.

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
view and, after sync, uses `Journal::record_durable_frame`. On success the checked
acknowledged prefix is exactly the old history followed by this frame's canonical
header, payload, and checksum. Thus framing and journal byte identities compose;
the [journal receipt path](journal-proof.md) now connects this record to stream write authorization.

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

Verus does not prove the file-header parser, `Read` implementation, exact-read
helper, checksum implementation, scanner loop, or correspondence to physical disk.
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
Cargo. Three cursor mutations reopen a stopped scanner, advance before validation, or
regress its offset. Two payload mutations omit the body or remove its length check. Four framing mutations switch the request field to tenant bytes, remove the
payload bound, accept incomplete extents, and skip a frame byte; all are rejected.
The complete core passes 55 verification checks, 75 workspace tests pass, and all
39 proof mutations are rejected. Counts describe checks, not independent guarantees.
