# Bounded disk logger and recovery scanner

Status: the [journal acknowledgment state machine](journal-proof.md) is now formally
verified and used by the disk worker. The [framing core](framing-proof.md) verifies
header encoding/decoding, frame extents, and recovery cursor transitions. Filesystem operations, checksums, and
the complete scanner loop remain tested rather than verified. The production HTTP server integrates this logger.

`DiskLog::create` creates a new operator-selected file and never overwrites or
appends to an existing path. On Unix the requested mode is 0600. Startup writes a
versioned file header with a random 128-bit session identifier, calls `sync_all`,
and syncs the parent directory before starting the worker. The parent directory
must already exist and be operator-controlled. Startup itself is synchronous.
Directory syncing makes the current implementation a Unix-oriented prototype;
supported deployment filesystems and their crash guarantees still need validation.

One worker thread owns the file. Cloned logger handles share its bounded queue.
Each append reserves a queue slot before copying its record; the worker performs
`write_all` followed by `sync_all` before returning a positive acknowledgment.
The production `DiskWorker` core verifies that sequence and retains an independent
active credit from dequeue through completion delivery. Only a private token
matching its file session and generation permits another dequeue; see
[audit-buffer ownership](audit-buffer-lifetimes.md#verified-active-worker-ownership).
There is no retry after write or sync failure. Such failures poison logger health,
and later appends fail. A full queue parks the caller, in arrival order, until the
worker frees a slot; nothing is reserved or encoded while it waits, and a canceled
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
Retained log frames are bounded by queue capacity plus one active worker frame,
each with 65 bytes of framing. This excludes caller buffers, allocator overhead,
and filesystem caches. The acknowledgment deadline must be positive and no more
than 300 seconds. Dropping all logger handles closes the queue; a responsive worker
drains and exits. `shutdown` closes admission atomically across all clones, drains
already-admitted jobs, and joins the worker only after its thread has finished.
It polls completion asynchronously with a caller-selected deadline; it never
blocks the executor in a join of a running thread. Server shutdown invokes it
with a two-second deadline after request workers stop. A timeout marks logging
unhealthy and returns an error; the existing worker can remain blocked until the
syscall returns or the process exits. A later shutdown call can join that same
worker. Successful shutdown means the worker exited, not that every previous
append succeeded; append results and audit health retain that distinction.

Admission and closure share a short mutex-protected section containing bounded
record encoding and enqueueing, with no await or filesystem operations. This
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
IDs, one direction byte (zero upload, one download), payload, and a 32-byte SHA-256
digest of its header and payload. Request IDs must be nonzero. Session plus request
ID identifies a request only when a single admission registry supplies that log.
The runtime must enforce that composition; the logger accepts caller-supplied IDs.

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
128 bytes and check unchanged recovered payloads and offsets. All 70 workspace
tests pass. These are tests, not a filesystem crash theorem. Real process-kill experiments and the conditional journal-prefix theorem now exist;
see the [storage contract](storage-crash-contract.md). Scanner refinement and
power-loss/storage-stack validation remain milestone-three requirements.

Durability assumes the OS/filesystem/storage stack honors successful sync calls
and that the parent directory was already durable. Permanent disk loss, malicious
operators, concurrent external file modification, and unavailable storage hardware
are outside this assumption. Raw bodies can contain secrets; file permissions do
not substitute for retention, encryption, or operator access policy. The current
format records body chunks, not completion/abort events or HTTP status metadata.


Journal identity is now explicit in the checked core: append tickets and durable
receipts carry the immutable file-session ID. The worker refuses a journal from
another session before any write or sync. Production initializes both owners
from the same random file-header session. Uniqueness of that session and its
correspondence to the actual file remain trusted. Each request establishes its immutable `JournalBinding` before its first
append. Later logger identity changes and receipts from another session are
rejected; exact record matching is still required. Selecting the intended initial
logger and its correspondence to the file remain trusted. Full authorized-write
composition is a separate unfinished milestone 6 obligation.
