# Storage crash contract and experiments

The journal theorem is conditional on this external storage contract:

1. One worker exclusively owns an append-only regular file in an operator-controlled,
   already-durable parent directory. No external process modifies or replaces it.
2. Successful writes preserve the stable prefix. Partial/failed writes may leave
   unknown suffix bytes but cannot corrupt previously stable bytes.
3. Successful `sync_all` makes preceding complete writes and file length durable.
   Startup also syncs the new file header and parent directory entry.
4. After a modeled crash, recovered bytes contain the stable prefix unchanged.
   Unsynced suffixes may survive, disappear, or be incomplete. Hardware honors
   flushes; permanent loss, bit rot, malicious rewriting, and lying devices are
   outside the model.

The journal also proves exact acceptance conditions for append reservation,
complete-write recording, sync recording, and acknowledgment: valid events cannot
be arbitrarily refused by the state machine. This does not guarantee syscall
success, worker scheduling, or correspondence between journal and stream tickets.

These are assumptions, not Verus-verified filesystem properties. The prototype uses
Unix file permissions and directory syncing; it has not certified a filesystem
against power loss. Deployment must validate the actual filesystem, mount/storage
configuration, and hardware against this contract. Live-OS tests do not establish
it for network filesystems, ephemeral volumes, or another storage stack.

The scanner emits only complete, checksum-valid records and stops at the first
incomplete/corrupt tail, reporting the preceding valid offset. The production
scanner now calls verified `Cursor::accept_record` to bind header decoding, exact
payload length/content, successful checksum-result input, and cursor advancement.
An unsuccessful acceptance preserves the stopped cursor and prior offset. The
contracts also prove acceptance of a valid complete record when its ticket matches,
the supplied checksum result is successful, and its end offset fits in `u64`.
Rejection must identify a malformed header, payload-length mismatch, failed
checksum result, wrong cursor/ticket state, or offset overflow. These are finite
core transitions, not a promise that reads or checksum computation finish. File
reads, checksum computation, session parsing, and conversion to the public runtime
record remain trusted; full scanner refinement remains open. Checksums defend against accidental corruption, not malicious changes.
EOF exactly at a record boundary cannot reveal whether later records were lost.

Restart creates a new file and session ID. It never appends to an existing file,
silently truncates uncertain suffixes, or replays generations. Logged bytes do not
prove provider/client receipt or generation completion; logged-but-unsent data is
allowed.

## Process-death experiments

The integration tests in `crates/gateway-runtime/tests/crash.rs` run the actual
DiskLog writer in a child process. The child reports acknowledgment after append
completes. The parent kills it without cleanup, then scans its file and checks
payloads and tenant/request/chunk identities.

One case pauses immediately after the first acknowledgment and is killed there.
The other is killed after three acknowledgments while further appends may race
with termination. Recovery must include all observed acknowledgments; additional
complete records and an incomplete tail are permitted. Tests also assert read-only
scanning, refusal to reuse the old path, and a new session ID after restart.

The OS/page cache survives these process-crash tests. They do not simulate power
loss, force every kernel-write interleaving, or prove sync semantics. Exhaustive
synthetic tail truncation, corruption, disk-full/sync-error injection, and blocked
sync tests provide separate evidence.

`crates/gateway-runtime/src/server/tests/process_crash.rs` additionally kills a real
gateway runtime subprocess after a client receives a response prefix from a TLS
provider. The client must observe a truncated-body error, and scanning the strict
log must recover the exact request and observed response prefix with matching
identities. Starting a fresh gateway produces a new log session, leaves the old
log unchanged, and makes no upstream connection during the observation window.
This exercises the runtime in a test binary with a fixture CA, not the CLI binary;
it does not establish absence of replay for arbitrary future executions.
An opt-in test in the same module uses the example HAProxy configuration with
fixture TLS and two gateway runtime child processes. It kills the primary after
a response prefix, checks truncated client framing and the primary audit prefix,
observes no upstream replay during health detection, then sends a distinct new
request through the standby and checks its exact audit bytes in a separate session.
CI runs this test with the distribution HAProxy package. This remains a local
process-failure experiment; host/power-loss tests remain open.
