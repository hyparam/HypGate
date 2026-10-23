# Bounded disk logger and recovery scanner

Status: the [journal acknowledgment state machine](journal-proof.md) is now formally
verified and used by the disk worker. The [framing core](framing-proof.md) verifies
header encoding/decoding and frame extents. Filesystem operations, checksums, and
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
There is no retry after write or sync failure. Such failures poison logger health,
and later appends fail. Queue saturation fails immediately without poisoning the
whole logger; the request's logging policy decides whether forwarding may continue.

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
drains and exits. Explicit coordinated shutdown and worker joining remain open.

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
These are tests, not a filesystem crash theorem. Real process-kill experiments and the conditional journal-prefix theorem now exist;
see the [storage contract](storage-crash-contract.md). Scanner refinement and
power-loss/storage-stack validation remain milestone-three requirements.

Durability assumes the OS/filesystem/storage stack honors successful sync calls
and that the parent directory was already durable. Permanent disk loss, malicious
operators, concurrent external file modification, and unavailable storage hardware
are outside this assumption. Raw bodies can contain secrets; file permissions do
not substitute for retention, encryption, or operator access policy. The current
format records body chunks, not completion/abort events or HTTP status metadata.
