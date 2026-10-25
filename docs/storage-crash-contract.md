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
scanner calls verified `Cursor::accept_record` to bind header decoding, exact
payload length/content, successful checksum-result input, and cursor advancement.
An unsuccessful acceptance preserves the stopped cursor and prior offset. The
contracts also prove acceptance of a valid complete record when its ticket matches,
the supplied checksum result is successful, and its end offset fits in `u64`.
Rejection must identify a malformed header, payload-length mismatch, failed
checksum result, wrong cursor/ticket state, or offset overflow. These are finite
core transitions, not a promise that reads or checksum computation finish. File
reads, checksum computation, session randomness/uniqueness, and conversion to the public runtime
record remain trusted. The [scanner refinement](recovery-proof.md) proves
per-step source correspondence under explicit adapter contracts; ordered
acknowledged-prefix reconstruction is proved under its explicit read/checksum
and preserved-byte assumptions. The named ext4 validation below covers live-OS errors and process death. Checksums defend against accidental corruption, not malicious changes.
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

## Named filesystem validation

`scripts/check_storage.sh` creates a private 64 MiB ext4 loopback image on Linux,
with `data=ordered,barrier=1`, and removes it after testing. It never formats a host
device. The Ubuntu 24.04 CI storage job records the kernel, mount options, and
e2fsprogs version. The storage job passed on 2026-10-23 in
[CI run 40039148167](https://github.com/hyparam/LogGate/actions/runs/40039148167),
commit `7b9ce21`: Linux `6.17.0-1022-azure`, e2fsprogs `1.47.0`, observed mounts
`rw,relatime,data=ordered` and then `ro,relatime,data=ordered`. Barriers were requested
explicitly; their default enabled state is omitted from the displayed mount options.
Both storage tests and all three crash-test harness cases passed.

The fixture fills that image until actual ENOSPC, checks that a failed append
preserves the acknowledged prefix, and checks sticky failure even after space is
freed before logger shutdown. It runs the real writer process-death tests on the
same filesystem, then remounts it read-only and requires EROFS at logger startup.
Recovery remains read-only and restart uses a fresh file/session. These tests
exercise live-OS storage errors and process death; they do not establish power-loss
durability or certify the backing device's flush behavior.

## Evidence summary

What the proofs and experiments above establish for each recovery claim. None of
it is an unconditional durability claim.

| Claim | Evidence and scope | Status |
| --- | --- | --- |
| Partial records cannot masquerade as complete records | Verified `Scanner::next_record` requires the exact complete extent and checksum predicate. `every_torn_record_tail_stops_at_the_last_complete_record` tests every cut of a sample frame and session header; corruption tests reject every single-byte mutation of a sample frame without resynchronization. This excludes malicious checksum forgery and assumes truthful source reads. | Covered under source/checksum contract |
| Acknowledged records survive every modeled crash point | `Journal::acknowledged_prefix_survives` preserves acknowledged bytes for every recovered sequence satisfying the stable-prefix crash contract. `AuditJournal::reconstruct_acknowledged` proves ordered exact reconstruction under successful initialization, completed error-free reads, correct checksums, and representable offsets. Production commits only after `write_all` and `sync_all`; startup syncs both header and parent directory. Syscall correspondence and persistence remain trusted. | Covered under storage/adapter contract |
| Process-kill, torn-tail, write-error, and disk-full experiments match the contract | Writer child-process kills after acknowledgment and during later appends; exhaustive sample-tail cuts; injected write/sync failures and blocked sync; private Linux ext4 fixture for actual ENOSPC, EROFS, and writer process death. | Regular tests and Linux ext4 fixture passed |
| Recovery never automatically replays a possibly executed generation | `LogReader` only reads; `DiskLog::create` requires a new path and session. Gateway process-kill and proxy failover tests check truncated responses, preserved audit prefixes, no observed replay, and new-request routing to standby. No retry/replay path exists in the recovery adapter. The observation window is test evidence, not an unbounded runtime liveness proof. | Covered by implementation inspection and tests |
| Both operator modes document guarantees and failure behavior | `async-transfer.md` and `running.md` describe strict durable byte gating, availability-mode audit gaps, suppressed later appends, deadlines, and volatile diagnostics. Transfer tests exercise both modes; stalled-sync workloads cover bounded queues and continued availability forwarding. Strict mode may establish a connection/send headers before body logging fails. | Covered; process resource composition is in [resource composition](resource-composition.md) |

These conditional proofs and adapter experiments are complete. This does not mean power-loss certification, verified kernel/filesystem
code, permanent-device-loss tolerance, or durable audit-gap reporting.
