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

## Evidence and remaining logging obligations

The production-path tests still cover truncation/corruption, exact payloads,
fragmented/interrupted reads, an injected I/O error at every record byte, unchanged
valid offsets, and no further reads after failure. Proof mutations change the
header read extent, substitute returned payload, or bypass record/session checksum
results. The wrong-extent mutation initially exposed an overly permissive error
contract; justified rejection is now part of the checked contract.

This establishes conditional per-step scanner refinement. A complete argument
that scanning reconstructs every acknowledged frame still needs composition across
the journal's sequence of records and the recovered snapshot, including the
checksum/storage assumptions. The initial-open error path is not a proved liveness
guarantee. No theorem here proves physical persistence, resistance to malicious
log rewriting, or authenticity/uniqueness of random session identifiers.
