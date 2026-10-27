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

## Whole-file emission

`records_from(data, start)` is the maximal run of complete records from a
position: each record that is whole and checksum-valid, up to the first byte that
is not. The scanner carries a ghost sequence of the records it has returned.
While live, that sequence plus the records remaining from the cursor equals the
records from the start; once stopped, it is a prefix of them. `next_record`
proves `emission_step`: a returned record extends the sequence by exactly that
header and payload, and a clean stop (end of file, or a tail that is not a
complete record) leaves the sequence equal to the whole run. So the loop that
calls `next_record` until it returns nothing has, at that point, seen every
recoverable record once and in order, and nothing else. After an I/O error the
sequence is still a prefix of the run.

`lemma_records_resume` covers the shipper's reopen: if a file is read to its
clean stop and later extended by appends, the records of the extension from the
start equal the records already read plus the records of the extension from that
stop. A reader reopened at its last valid end therefore continues the same run
without repeating or skipping a record. That the file grows only by appends is a
premise about the writer, not a theorem here.

## Record kinds

The scanner is kind-agnostic: it decodes the 33-byte header with the same
verified `framing::decode`, so a record of kind 2, 3, or 4 is returned exactly like
a body chunk, with its payload bytes unchanged for the metadata codecs, and a
header with kind 5 or above is `Corrupt` at that boundary. `reconstruct_acknowledged`
covers mixed sequences because it quantifies over arbitrary canonical frames.
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

## Rotated-session composition

`gateway_core::session_recovery::SessionScanner` is the production driver used
by `SessionReader`, `scan`, and both shipping modes. It owns the existing verified
`recovery::Scanner`, all file-selection decisions, header/session comparisons,
resume offsets, retries, and terminal failure state. The runtime only opens the
specified path, captures its descriptor length, reads within that snapshot,
seeks to the specified offset, and converts the resulting record type. There is
no parallel Rust implementation of the traversal algorithm.

The model gives each segment immutable eventual contents. An opened snapshot is
a prefix of those contents; future appends do not change earlier bytes. `Files`
records which segments have been observed. Once the successor with the matching
checksummed header has been observed, reopening its predecessor returns that
predecessor's complete sealed contents. A mere foreign file or filename collision
does not meet this condition. This is the explicit correspondence assumption
between filesystem effects and the writer's protocol, not an assumption that
the reader already recovered the right records. `SeekSource` reports whether a
seek succeeded within the snapshot. `Scanner::restart` preserves the validated
session and constructs a fresh scanner at the core-selected record boundary.

Three inductive invariants establish the composition:

- The emitted sequence plus records remaining at the current cursor equals all
  recoverable records in preceding files plus the current file's records.
- The current offset is reachable from byte 56 solely by consuming complete,
  checksummed records. Each crossed file has a matching checked session header
  and its scanner stop equals its physical end; no damaged tail can be skipped.
- A retained scanner is live, at exactly the saved offset, under the same session,
  over a prefix snapshot of the selected file.

`next_record` extends the emitted sequence by exactly the returned header and
payload, or leaves it unchanged. `recovered_prefix` derives the ordered-prefix
property and the completeness of every crossed file. `recovered_to_end` derives
complete recovery through the current file when the cursor reaches its actual
end. Both theorems apply to the same struct and methods the runtime executes;
proof histories are erased and retain no prior records in memory.

At snapshot EOF the driver opens only the immediately numbered successor and
validates its header. It then reopens and rechecks the predecessor before crossing.
Without that recheck, a writer could append its final record between the earlier
EOF and discovery of the successor. If the refreshed predecessor yields a record,
it is returned first; if it has a damaged tail, the driver stays there. Only a
clean EOF in the sealed snapshot permits advancing to byte 56 of the successor.
Incomplete tails and next headers can be retried without moving the saved cursor.
Corruption or I/O failure permanently stops all later effects, including opens.

Tests rotate at the exact successor-open boundary, cover every truncation of a
sample trailing record and successor header, and check foreign sessions, corrupt
tails, I/O failures, empty segments, live growth, shipping replay, and real-file
snapshot refresh. Eight deliberate defects must fail verification, including
omitting the sealed-predecessor recheck and restarting from the wrong offset.
Filesystem truthfulness, immutable earlier bytes, session uniqueness, and the
writer's seal protocol remain assumptions. A missing successor is EOF, so no
claim is made that an operator has not removed a file; there is no manifest.
