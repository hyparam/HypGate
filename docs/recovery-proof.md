# Conditional scanner refinement

The production scanner is now `gateway_core::recovery::Scanner`. Ordinary Rust
`LogReader` supplies only a sequential-read/checksum adapter and converts the
verified record into the public direction enum and record type. Parsing, failure
state, and accepted-prefix advancement run through the Verus-checked code.

## Explicit source contract

`Source` models a stable byte sequence and a current position relative to scanner
construction. A successful exact read returns precisely the next requested bytes
and advances by that length. EOF means no bytes remain; an incomplete read means
fewer than the requested bytes remain. I/O errors may consume an unknown suffix
but cannot move backward. The abstract I/O-error count increases exactly on an I/O
error, so the scanner cannot claim an I/O failure without such an event. Checksum
validation agrees with the source's abstract digest function on header plus payload.

The runtime `ReadSource` implementation is **trusted**, not verified. Its two
methods loop over `std::io::Read`, retry interruptions, and compute SHA-256. These
contracts are assumptions about the adapter, the standard library, and the input;
they are not proofs of filesystem reads, cryptography, or stable physical storage.
The source snapshot excludes concurrent modification or append during this proof.
EOF is observed through a zero-byte read; other read errors are classified as I/O
errors, including an underlying callback directly returning `UnexpectedEof`.

## Checked scanner behavior

Successful initialization verifies the session/version prefix and its checksum,
returns the exact source session identity, and starts record recovery at byte 56.
Each record attempt closes the cursor before any fallible read. A stopped scanner
returns no more records and cannot advance its accepted boundary.

Every returned record has valid decoded metadata, exact payload length, and bytes
equal to the corresponding slice of the modeled source. The accepted end is
exactly the previous accepted end plus header, payload, and checksum sizes. The
complete extent lies within the source and fits in `u64`; the source checksum
predicate holds for that exact extent. The session identity does not change.

EOF or error leaves the preceding accepted boundary unchanged and the scanner
stopped. EOF without reading is justified by an already stopped scanner or the
source ending at the boundary. Corruption/incompleteness cannot be claimed for a
complete, structurally valid, checksum-valid record at that boundary. An I/O error
requires an increase in the source's error count. Thus a valid next record must be
returned if reads complete without I/O errors. This is conditional functional
progress, not a bound on scheduling, interrupted reads, or syscall latency.

## Record kinds

The scanner is kind-agnostic: it decodes the 33-byte header with the same
verified `framing::decode`, so a record of kind 2, 3, or 4 is returned exactly like
a body chunk, with its payload bytes unchanged for the metadata codecs, and a
header with kind 5 or above is `Corrupt` at that boundary. `recovered_kind_in_range`
states that every returned header has a kind of at most 4 and is either a body or
a metadata kind; `recover_metadata_frame_step` instantiates the frame-recovery
step for a canonical metadata frame and adds that the recovered kind is the
encoded metadata kind, not a body kind. `reconstruct_acknowledged` is unchanged
and covers mixed sequences because it quantifies over arbitrary canonical frames.
The runtime maps the recovered kind byte to its `RecordKind` name with a total
conversion and decodes metadata payloads with the verified codecs after
recovery; a structurally valid record whose metadata payload does not decode is
returned and reported as such, not treated as corruption of the file.

## Evidence and remaining logging obligations

The production-path tests still cover truncation/corruption, exact payloads,
fragmented/interrupted reads, an injected I/O error at every record byte, unchanged
valid offsets, and no further reads after failure. Proof mutations change the
header read extent, substitute returned payload, or bypass record/session checksum
results. The wrong-extent mutation initially exposed an overly permissive error
contract; justified rejection is now part of the checked contract.

## Ordered acknowledged-prefix reconstruction

The production writer now owns `AuditJournal`, which exposes only reservation,
canonical-frame commit, and permanent failure. Its erased frame sequence is kept
in order, and its invariant equates acknowledged/stable bytes to the concatenation
of those frames. Lower-level raw journal operations cannot bypass this wrapper.
No past frame buffers are retained at runtime; the sequence is ghost state.

`canonical_frame_is_complete` connects canonical encoding to the scanner's
complete-record predicate. `recover_frame_step` combines that fact with the actual
`scanner_step` postcondition: a live scanner at the frame boundary, with no new
I/O error, must return that exact header and payload and advance to its end.
`reconstruct_prefix` inducts over an arbitrary finite record sequence and scanner
trace, proving that every result is the corresponding record in the same order.
It also proves that the final accepted offset is exactly the prefix end.
`AuditJournal::reconstruct_acknowledged` supplies the production journal invariant
and starts the trace after the 56-byte session header.

The theorem assumes successful scanner initialization and one completed
`next_record` call per acknowledged frame; it does not assume those calls return
success. It proves success from preserved prefix bytes, correct frame checksums,
representable `u64` offsets, and no read errors. A later uncertain suffix may
exist and may fail scanning; it cannot change the reconstructed acknowledged
prefix. The checksum predicate is explicit and shared with the source model.

Physical persistence, syscall truth, stable-source behavior, SHA-256, and the
adapter implementation remain trusted. This is not an initial-open or scheduling
liveness theorem, power-loss certification, or protection against malicious log
rewriting. Linux ext4 validation and the evidence summary are recorded in the
[storage contract](storage-crash-contract.md#evidence-summary).
