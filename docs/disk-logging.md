# Bounded disk logger and recovery scanner

The disk worker runs the verified `BatchJournal` and `BatchWorker` state machines.
The [framing core](framing-proof.md) verifies header encoding and decoding, frame
extents, and recovery cursor transitions. Filesystem operations, checksums, and the
complete scanner loop are tested rather than verified. The production HTTP server
uses this logger.

`DiskLog::create` creates a new operator-selected file and never overwrites or
appends to an existing path. On Unix the requested mode is 0600. Startup writes a
versioned file header with a random 128-bit session identifier, calls `sync_all`,
and syncs the parent directory before starting the worker. The parent directory
must already exist and be operator-controlled. Startup itself is synchronous.
Directory syncing makes the current implementation a Unix-oriented prototype;
supported deployment filesystems and their crash guarantees still need validation.

## Audit durability policy

The optional root field `"durability"` accepts `"durable"` (the default) or
`"buffered"`. It is independent of `"logging": "strict" | "availability"`.
Both durability modes wait for complete writes; only durable mode waits for a
per-batch sync before returning receipts. Strict mode requires a successful
receipt under the configured policy before forwarding body bytes; availability
mode continues with counted gaps after logging failure. Buffered mode does not
ignore write failures or turn logging into a background enqueue acknowledgment.

Buffered receipts establish exact written bytes, session identity, and ordering,
but do not establish stable storage. A system crash or power loss may discard
acknowledged records, including records for already-forwarded traffic. There is
no periodic-sync interval or bounded loss window, and shutdown does not promise
a final sync. Startup headers and directory entries, and rotation predecessor
sealing and successor creation, still sync in both modes.

`AuditReceipt` explicitly records its strength. `BatchJournal` preserves the
selected policy; `BatchWorker::run` proves written-prefix membership for all
successful receipts and stable-prefix membership for durable receipts only.
`JournalBinding` rejects buffered receipts for durable requests, even when session
and bytes match. `OwnedStream::durable_receipt_evidence` ties accepted evidence
to this requirement. The older `Journal` and `AuditJournal` crash theorems remain
durable-only models; they do not give buffered acknowledgments crash survival.

## Automatic rotation

The executable uses `DiskLog::create_rotating_with_durability`. It starts at the supplied path
and creates `PATH.000001`, `PATH.000002`, and so on. Each segment has the same
56-byte format header and immutable session ID. The original library constructors
remain single-file APIs. No existing file is overwritten, renamed, or deleted.

Defaults are 128 MiB per segment (including its header) or 24 hours since the
segment opened, whichever is reached first. Override them with
`--log-max-bytes N` (greater than 56) and `--log-max-age-seconds N` (positive).
The monotonic age is checked on append, so an idle logger creates no empty files.
Rotation happens before a complete frame that would exceed the size target;
a single oversized frame is allowed intact in an otherwise empty segment.
Thus a segment is bounded by the larger of the target and one maximum frame
plus the 56-byte header. Requests may span segments, but individual frames never do.

The same worker closes the old file only after syncing it and durably creating
the next header and parent directory entry. The record is then written and
synced before acknowledgment in durable mode, under the existing append deadline. A collision,
creation, write, or sync failure permanently poisons logging health, with the
existing strict/availability behavior; there is no fallback, retry, or replacement
worker. At rotation there are at most two open audit segment files plus a
short-lived parent-directory handle, independent of segment count.

`log_rotation::RotatingStorage` is the production, verified implementation of
`disk_worker::Storage`. Its proof establishes overflow-safe size decisions,
sequential segment indices, unchanged session identity, exact append-only logical
history across rotation, sync-before-success, and no further effects after a
failure. The logical history excludes segment headers. `SegmentIo` is the
explicit trusted interface: creating a segment preserves earlier bytes and
durably establishes the header/directory entry; append writes the offered bytes;
sync makes the logical history durable. `segment_protocol` now proves the actual
primitive-effect trace: every successor creation attempt immediately follows a
successful seal of its predecessor; later appends never target that predecessor,
and failed effects admit no later effects. The old-file sync is issued by the
verified core through `seal`, rather than hidden inside runtime `create_next`.
Runtime path construction, elapsed time, syscalls, header-file/directory durability,
and the correspondence of physical files to that history remain trust assumptions.
See the [storage contract](storage-crash-contract.md).

`SessionReader`, used by `scan` and both shipping modes, follows consecutive
segments from the original path, checking each header's checksum and session ID.
It crosses a file boundary only at clean record EOF, never past a torn or corrupt
record. After discovering a matching successor, it reopens the sealed predecessor
and consumes any records added since its earlier snapshot before crossing. This
closes the race between seeing EOF and discovering rotation. Each file snapshot
is bounded by its descriptor's captured length; later appends are read on refresh.
Live reads can retry an incomplete tail or next header. Corruption and
I/O errors stop the reader. Scan output includes `segment` (zero for the original
file); `valid_end` is an offset within that physical file. `LogReader` remains a
single-file scanner. `SessionReader` now delegates traversal to the verified
`session_recovery::SessionScanner`. Its `recovered_prefix` theorem establishes
that records are emitted exactly once in file order and every crossed file has
a matching checked header and a complete record boundary at its end.
`recovered_to_end` establishes completeness when the cursor reaches the actual
end of the current file. The core `snapshot::Snapshot` proves exact read
accumulation, captured-length bounds, EOF versus incomplete-tail classification, and seek bounds/cursor updates
over primitive short-read and seek effects. Snapshot length acquisition and the
physical effects remain trusted. A missing next file is EOF: there is no manifest or proof
that an operator has not removed a segment. Preserve the complete consecutive
set, including the original path, until shipping and any required replay finish.

One worker thread owns the active file. Cloned logger handles share its bounded queue.
Each append reserves a queue slot before copying its record. The worker takes
up to 16 records already queued and writes each intact record. Durable mode then
calls `sync_all` once for the group before returning any positive acknowledgment;
buffered mode acknowledges complete writes without this sync. It never waits
to fill a batch, so an isolated durable record is synced immediately. A write or sync
failure rejects the whole group. Rotation can add predecessor-sealing syncs.
The production `BatchWorker` core verifies that sequence and retains an independent
active credit from dequeue through completion delivery. Only a private token
matching its file session and generation permits another dequeue; see
[audit-buffer ownership](audit-buffer-lifetimes.md#verified-active-worker-ownership).
There is no retry after write or sync failure. Such failures poison logger health,
and later appends fail. A full queue parks the caller until the worker frees a slot; queued records
retain FIFO order, but waiting producers have no scheduling-order guarantee; nothing is reserved or encoded while it waits, and a canceled
waiter leaves nothing behind. The acknowledgment deadline covers the wait, so a
worker that stops freeing slots is treated like one that stops acknowledging.
The worker owns an exit guard that marks logging unhealthy even when a panic
unwinds the thread after its append caller was canceled. A closed queue also
poisons health on observation. This prevents a dead worker from leaving strict
readiness healthy merely because no caller survived to report the failure.
Normal shutdown closes admission and also leaves health false. The guard handles
Rust unwinding, not process aborts or machine failure; those stop health serving
altogether and require external failure detection.

An acknowledgment deadline bounds caller waiting. Expiration poisons health and
does not spawn a replacement worker. A syscall already in progress may later finish;
its record may be durable even though its caller received no acknowledgment. A
canceled caller likewise can leave a logged but unsent record. Nothing replays it.
One stuck worker can remain alive indefinitely, but queue and worker buffers remain
bounded. Operators must not repeatedly construct replacements in the same process.

Queue capacity ranges from 1 to 1,024 records; each payload is at most one MiB.
The executable sets the payload limit to the larger of `chunk_bytes` and 8,210
bytes, the longest metadata payload, so a small body chunk never refuses the
request-start record. Retained log frames are bounded by queue capacity plus one
active worker frame, each with 65 bytes of framing. This excludes caller buffers, allocator overhead,
and filesystem caches. The acknowledgment deadline must be positive and no more
than 300 seconds. Dropping all logger handles closes the queue; a responsive worker
drains and exits. `shutdown` closes admission atomically across all clones, drains
already-admitted jobs, and joins the worker only after its thread has finished.
It polls for the worker to finish under a caller-selected deadline and joins it
only once it has; it never blocks past the deadline in a join of a running
thread. Server shutdown invokes it
with a two-second deadline after request workers stop. A timeout marks logging
unhealthy and returns an error; the existing worker can remain blocked until the
syscall returns or the process exits. A later shutdown call can join that same
worker. Successful shutdown means the worker exited, not that every previous
append succeeded; append results and audit health retain that distinction.

Admission and closure share a short mutex-protected section containing bounded
record encoding and enqueueing, with no filesystem operations. This
prevents a retained sender/permit from keeping admission alive after closure.
The thread handle and queue are shared across clones; shutdown is irreversible.
Tests block sync, queue a second record, close admission, reject later records,
then release sync and check both frames and worker joining. A separate test
expires shutdown while sync is blocked and checks eventual joining without a
replacement worker. A worker-panic test cancels the waiting caller before injecting a sync panic,
then checks unhealthy state without waiting for an append deadline, later append
refusal, and a reported join error. These are runtime tests, not formal shutdown proofs.

## Format and scanner

The 56-byte file header contains eight-byte magic `SGLOG001`, a 16-byte random
session ID, and a SHA-256 digest of the preceding 24 bytes. Each record contains
four-byte magic `SGR1`, a little-endian u32 payload length, u64 tenant/request/chunk
IDs, one record-kind byte, payload, and a 32-byte SHA-256 digest of its header and
payload. Request IDs must be nonzero. Session plus request ID identifies a request
only when a single admission registry supplies that log. The runtime must enforce
that composition; the logger accepts caller-supplied IDs. The format is still under
development; nothing has been deployed, so the kinds below were added without a
version bump.

| Kind | Meaning | Chunk | Payload (little-endian) |
| --- | --- | --- | --- |
| 0 | Upload body chunk | 1 and up | Forwarded request body bytes |
| 1 | Download body chunk | 1 and up | Forwarded response body bytes |
| 2 | Request start | 0 | u64 Unix time in ms, u64 route selector, u16 destination length, destination bytes (1 to 8,192; the configured `https://...` text) |
| 3 | Response head | 0 | u64 Unix time in ms, u16 HTTP status (100 to 999) |
| 4 | Completion | 0 | u64 Unix time in ms, u8 outcome, u64 accepted upload bytes, u64 accepted download bytes |

Body chunks are numbered from 1 by the verified stream, which never issues an
audit record for the unfilled chunk 0 (proved); metadata records use chunk 0.
A request's records appear in the order start, upload chunks, response head,
download chunks, completion, interleaved with other requests' records. Request
headers and response headers are never recorded.

Completion outcome codes: 0 success; 1 upstream connect, TLS, or HTTP failure;
2 upstream timeout; 3 upload failure; 4 download failure; 5 client disconnect or
cancellation, including shutdown; 6 strict-mode logging refusal; 7 metadata or
other failure. The [end-to-end audit](end-to-end-audit.md#metadata-records-and-outcome-codes)
maps every exit of an exchange to one code. Wall-clock values come from the
system clock, clamped to `u64` milliseconds; they order records within one
process only as well as that clock does and are not verified.

`LogReader` scans incrementally with at most one bounded record allocation. It
reports the byte offset after the last fully validated record. It distinguishes
incomplete tails, corruption, and I/O errors, then stops permanently rather than
searching ahead for another magic sequence. It never edits a file or replays traffic.
EOF exactly at a record boundary is a valid prefix; the scanner cannot infer whether
later records were lost. Checksums detect accidental corruption under cryptographic
assumptions, not malicious rewriting or adversarial checksum collisions.

## Evidence and remaining obligations

Tests cover real-file acknowledgment and permissions, refusal to overwrite,
strict transfer payload identity, every truncation position in a record and file
header, single-bit changes at every record byte, excessive lengths, partial writes,
injected disk-full and sync errors, blocked sync deadlines, and queue saturation.
Scanner I/O tests inject a transient non-EOF error at every byte of a following
record, including header, payload, checksum, and the next record boundary. They
check the exact retained prefix offset and that subsequent scanner calls never
read the underlying source again, even though the source could recover. Separate
tests interleave interruptions with fragmented reads at sizes from one byte to
128 bytes and check unchanged recovered payloads and offsets. Workspace test totals
are maintained in the [README](../README.md). These are tests, not a filesystem crash
theorem. Process-kill tests and the conditional journal-prefix and scanner theorems
are recorded in the [storage contract](storage-crash-contract.md). Six abrupt
QEMU guest power-cut trials also preserved every observed acknowledgment after
reboot. These discard guest RAM and kernel caches while the host storage remains
powered. Software crash validation is complete for this tested configuration;
physical storage durability is a deployment assumption.

Durability assumes the OS/filesystem/storage stack honors successful sync calls
and that the parent directory was already durable. Permanent disk loss, malicious
operators, concurrent external file modification, and unavailable storage hardware
are outside this assumption. Raw bodies can contain secrets; file permissions do
not substitute for retention, encryption, or operator access policy. The
metadata codecs are verified; the values they carry (clock, status, outcome, byte
counts, destination text) are supplied by trusted runtime code and tested, and a
missing completion record means the logger was unhealthy or the process died.

Journal identity is explicit in the checked core: append tickets and durable
receipts carry the immutable file-session ID. The worker refuses a journal from
another session before any write or sync. Production initializes both owners
from the same random file-header session. Uniqueness of that session and its
correspondence to the actual file remain trusted. Each request establishes its immutable `JournalBinding` before its first
append. Later logger identity changes and receipts from another session are
rejected; exact record matching is still required. Selecting the intended initial
logger and its correspondence to the file remain trusted. The authorized-write
composition through `ResolvedRoute::write_bytes` is checked; see the
[ownership composition](ownership-composition.md).

## Narrowed effect boundary

The production snapshot adapter no longer supplies the whole `Source` contract
as an unchecked runtime implementation. `snapshot::Snapshot` implements both
`Source` and `SeekSource` in verified code over `FileRead`: one bounded short read,
one absolute seek, and checksum comparison. Its exact-read loop has a decreasing
remaining-byte count. It keeps one buffer, asks for no bytes beyond the captured
length, and derives the EOF/error classification and cursor from actual replies.
A read failure can leave the physical position uncertain, so subsequent reads
fail until a successful seek reestablishes it. Primitive syscall termination,
interruption handling, bytes, lengths, seek results, and checksums remain trusted
bindings. The generic single-file `LogReader` retains its existing `ReadSource`
adapter; production multi-file scanning/shipping uses the verified snapshot.

The proof of writer effect ordering does not prove OS cache visibility or the
path-to-file mapping. Recovery still assumes a fresh open sees the full sealed
predecessor after a matching successor is observed, and that external actors do
not modify or remove prior bytes. File naming, clock sampling, and CLI parsing
remain tested runtime code. No manifest is added: a missing successor can still
look like end-of-log. These limits are unchanged rather than silently promoted
to proved properties.
