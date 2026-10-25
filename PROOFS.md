# What is proved

## Overview

The gateway is a small Rust program in two parts. `crates/gateway-core` holds
every decision the gateway makes: who may send what where, which bytes are
forwarded, what is written to the audit log, what is shipped to the cloud and
when. Verus checks that crate against written contracts, so its functions
cannot panic, overflow, index out of bounds, or violate their stated
postconditions on any input. `crates/gateway-runtime` holds the plain Rust
that touches the world: sockets, TLS, files, threads, clocks, JSON. It is
tested, audited, and kept as thin as we can make it, but it is not verified.

A guarantee in this document is therefore always a theorem about the core
joined to the world by named premises about the runtime. The premises are
listed with each guarantee; the [proof index](docs/proof-index.md) maps every
theorem to its source contracts, and the [end-to-end audit](docs/end-to-end-audit.md)
enumerates every effect site in the runtime that a premise relies on. Tests
and deliberate proof mutations (`scripts/check_mutations.py`) show the
contracts are not vacuous; they do not enlarge the formal scope.

Three guarantees follow. Each gives the claim, what is proved today, and the
premises about the runtime that join the proof to the world.

## Guarantee 1: your traffic goes only where you said

**Statement.** A request body reaches only the provider that a root grant
names for its tenant, carrying that grant's credential. An audit record is
written only to the configured log file. Log contents leave the machine only
if the root policy has a `shipping` section, and then only to the single
HypAware server it names, authenticated by a credential that server issued in
exchange for the operator's token. The binary contains no other network
destination.

**Proved today.**

- Every provider body byte passes one gate, `ResolvedRoute::write_bytes`,
  which releases a byte range only when the request's authority, route,
  tenant, credential index, direction, and (in strict mode) durable audit
  receipt all match. Candidate configuration cannot enlarge root grants or
  pick another tenant's credential. The concrete destination and credential
  come from the authorized table indices and nothing else.
- The shipper's enrollment machine refuses to upload without an unexpired
  server-issued credential; a revoked service account stops it for good.
- Every outgoing shipper request is chosen by the verified machine
  (`shipper::Machine::next`): it names a path and a body but no host, so the
  only destination any body can reach is the client built from the configured
  server. A bootstrap body is the escaped operator token, a refresh body is
  empty, an ingest body is queued rows, and no other action, checkpoint, or
  state carries the token.
- The operator token is read once and moved into the machine; the gateway
  configuration, request path, and log never hold it.
- Both outbound socket sites take one permit type, `egress::Egress`. A
  provider permit is minted by the verified core only for the destination the
  request's route resolved to (`Egress::provider`); a cloud permit only from
  the parsed `shipping` section's server, which does not exist when shipping
  is off. Every other call to connect, resolve, listen, write a file, or read
  a secret is denied by `clippy.toml`, and `scripts/check_effect_sites.sh`
  fails if the set of allowed sites changes.

**Premises.** HTTP serialization, DNS, TLS, and the system resolver behave as
specified (no IP-range policy, so not an SSRF theorem); the runtime passes
the gate's bytes to the socket it opened under the permit and the machine's
requests to the client it built from the configured server; `send_request`
and `write_all` sites are still enumerated by review rather than lint.

## Guarantee 2: correctness, starting with no data loss

**Statement.** Nothing is silently lost, altered, or duplicated between the
provider, the audit log, and HypAware. In strict mode a body byte is released
to the socket only after its audit record has a durable receipt, so the log is
complete for everything the provider or client saw; a logging failure fails the
request rather than skipping the record, and availability mode counts every
gap it allows. Forwarded bytes are an unchanged, ordered prefix of the input.
Every acknowledged record survives a crash in the storage model, and recovery
exposes only complete records. Every exchange recorded in the audit log is
grouped from its records in file order, bounded in retained size with
truncation recorded, projected into rows whose identities are a function of
the log alone, and uploaded in emission order. An exchange is counted as
delivered only when the server acknowledges the exact batch it was sent in. A
restart replays the log and resends at most what was unacknowledged, with
identical identities, so the server's dedup stores each exchange once. A
truncated stream is never reported as a clean completion.

**Proved today.**

- Strict mode gates every body range on an exact durable receipt for that
  request, chunk, direction, and payload (`ResolvedRoute::write_bytes`,
  `StreamChunk::{prepare,pending_bytes,complete}`); the logging-mode
  transitions keep authorization identical in availability mode.
- Forwarded bytes are an ordered, unchanged prefix of the input across chunks
  and partial writes, with no skipped or duplicated advancement; cancellation
  prevents new submissions and a failed or truncated stream cannot complete as
  success.
- Acknowledged records survive every crash in the storage model
  (`Journal::acknowledged_prefix_survives`), and the acknowledged prefix is
  reconstructed in order under the read and checksum contracts
  (`AuditJournal::reconstruct_acknowledged`).
- The scanner returns only complete, checksum-valid records and resumes at a
  validated offset in the same session.
- The assembler keeps open exchanges bounded and unique per request, retains
  an ordered prefix of each body within the cap, records truncation, and
  emits each exchange exactly once.
- A batch holds at most 5,000 rows and 4 MiB; the upload cursor advances
  only to the end of the in-flight batch, only on an acknowledgment naming
  its exact id or an explicit poison; abandonment and restore never advance it.
- Exchange, message, part, and batch identities are injective in their inputs.
- Conservation (`shipper::Machine`): every emitted exchange comes back as a
  numbered token that is accepted only in emission order; the queue is always
  the unresolved suffix of the ghost history of projections; an ingest body is
  exactly the concatenation of the next queued exchanges under the batch id
  for that range; an acknowledgment pops exactly those exchanges and a poison
  exactly one; nothing else moves progress.

- The driver loop (`shipping_driver::drive`) is verified against the
  machine: every emitted token is projected and queued in the same step,
  every send is followed by exactly one reply, records are admitted only
  while wanted and with checked headers, and a checkpoint can only carry the
  machine's own progress.
- Replay (`exchange_assembler::emitted_requests`, `Machine::replay_numbering`):
  which exchange is emitted when is a function of the record kinds and
  request ids alone, proved on every assembler step; the machine's ghost
  emission sequence equals that function of its inputs, and every queued or
  resolved projection at position j came from the exchange numbered
  skip + j. A restart that starts the cursor at the checkpointed count
  therefore skips exactly the exchanges the earlier run resolved, and a
  resent exchange carries the same request id, so its part ids are identical.
  A checkpoint can only carry the machine's resolved count, which advances
  only on an acknowledgment or a poison, so a crash before the checkpoint is
  written causes a resend, never a skip.

**Premises.** The storage contract (synced bytes survive, see the
[storage contract](docs/storage-crash-contract.md)); the disk adapter reports
write and sync outcomes truthfully; hex encoding; the server honors its batch
ledger and part-id dedup; the projection of an exchange's provider JSON into text and usage is
faithful (tested against recorded bodies, not proved); the runtime's `Effects`
implementation performs what it is asked (sends to the configured server,
returns the log's records in order, writes the checkpoint it is given); the
scanner reads the same file on restart (the checkpoint names the session).

## Guarantee 3: there is no crash state

**Statement.** The verified core cannot panic. Every reachable shipper state
has a next action, and every wait it asks for is between one second and five
minutes; the single terminal state is a revoked credential, and it is
reported. The shipper shares no executor, pool, or handle with request
handling, so its failure changes metrics and nothing else. A process kill at
any point resumes, after recovery, to a state consistent with the log and
with what the server already holds.

**Proved today.**

- Absence of panics, overflow, and out-of-bounds access in every core
  function, by construction of the verifier.
- Recovery exposes only complete records; acknowledged records survive any
  crash in the specified storage model; retry delays are bounded.
- Slots, buffers, and queues stay within explicit budgets, and capacity
  cannot be reused while work retaining it is alive.
- The shipper machine is total: every operation has no precondition beyond a
  valid state and the caller's turn-taking; every wait it asks for is 1 to 300
  seconds; pending work with a usable credential is sent or poisoned at once;
  a revoked credential is the only absorbing state and is reported.
- Tested: a shipper thread that panics is contained by `catch_unwind` and
  the thread boundary; the gateway keeps forwarding, stays ready, and shuts
  down, and only the shipping metrics and the shipper handle report it
  (`shipping_thread_panic_changes_only_metrics`). A crash after every single
  machine step of a seven-exchange run, followed by a restart from the
  checkpoint, leaves the server with exactly the uninterrupted run's rows
  (`a_crash_at_any_step_resends_only_the_unacknowledged_exchanges_and_the_server_stores_each_once`).

**Premises.** The storage contract (synced bytes survive); Tokio cancellation
reaches the futures; the shipping adapters are panic-free, which clippy
denies on unwrap, expect, panic, indexing, and unchecked arithmetic enforce
(`cargo clippy -p gateway-runtime`), and the thread boundary contains any
panic that does occur; the clock is monotone enough for the enrollment
windows.

The gateway's own async cancellation and whole-process memory are documented
rather than mechanized; the table below records where.

## Where the proofs live

- `crates/gateway-core/src/shipper.rs`: the shipper state machine, which owns
  the assembler, cursor, enrollment, queue, backoff, and batching. Theorems:
  conservation, batch fidelity, token containment, bounded waiting, progress,
  totality.
- `crates/gateway-core/src/shipping_driver.rs`: the loop that drives the
  machine, checked against its contracts over an effect trait with no
  decisions in the runtime side.
- `crates/gateway-core/src/egress.rs`: the single permit type both socket
  sites require. With shipping disabled no cloud permit can be built.
  `clippy.toml` denies every other socket, lookup, listener, file-write, and
  secret-read call, and `scripts/check_effect_sites.sh` pins the audited sites.
- `crates/gateway-core/src/exchange_assembler.rs`: the replay theorem.
  Emission numbering is a function of record kinds and request ids, so a
  restart from a checkpoint skips exactly the resolved exchanges.
- `crates/gateway-runtime/src/shipping`: the trusted adapters, held to a
  panic-free standard by clippy and run under `catch_unwind`.

## Specific properties proved

The finer-grained targets behind the three guarantees. “Core proved” means a
synchronous model or transition is checked by Verus, conditional on the
documented adapter contracts. The [proof index](docs/proof-index.md) names the
checked definitions for each row.

| Property | Intended guarantee | Evidence today |
| --- | --- | --- |
| Authorization and fail-closed security | Every upstream dispatch requires an authenticated tenant's grant; authentication or policy failures cannot authorize forwarding, in either logging mode. | Core token issuance proved; HTTP binding tested; every production body write passes the checked `ResolvedRoute::write_bytes` gate, and every other socket, lookup, and file-write site is denied by lint. The socket write itself is trusted. |
| Tenant and credential isolation | Requests, completions, and credentials cannot cross tenant/request boundaries; gateway authentication material never becomes an upstream credential. | Core tenant/credential-handle and ticket checks proved; cross-owner lifecycle composition checked; secret/header handling tested. Audit-file access control is an operator obligation. |
| Routing and configuration confinement | Candidate configuration and request fields cannot expand operator grants or change the authorized destination/credential binding. | Normalized configuration and route selection proved; URI, DNS, TLS, and actual dispatch remain trusted/tested. |
| Byte integrity and ordering | Forwarded body bytes form an unchanged, ordered prefix of the input, across chunks and partial writes, without skipped or duplicated advancement. | Core byte-prefix and completion properties proved; async HTTP integration tested. Peer receipt is not proved. |
| Strict audit-before-forwarding | Every submitted body range in strict mode is covered by a durable log acknowledgment for that request and chunk. | Core gate and exact journal-receipt/stream binding proved; disk sync adapter tested. Filesystem crash guarantees remain open. |
| Crash-safe recovery | Recovery exposes only complete records, and acknowledged records survive every crash in the specified storage model. | Journal acknowledgment ordering and conditional synced-prefix survival proved; header/payload encoding, header decoding, frame extents, and scanner cursor transitions proved; scanner I/O tested. Process-kill recovery tested and storage assumptions documented; conditional scanner steps proved; acknowledged-prefix reconstruction proved under preserved-byte/read/checksum assumptions. Linux ext4 error/process-death tests passed; physical power-loss validation remains open. |
| Cancellation and no replay | Cancellation prevents new submissions; uncertain effects, crashes, or failover never trigger automatic replay of a possibly executed generation. | Core cancellation/stale-event checks proved; transport has no replay path. Async cancellation and recovery composition remain unproved. |
| Resource bounds and safe release | Slots, buffers, queues, and outstanding operations stay within explicit budgets; capacity cannot be reused while work retaining it remains alive. | Logical slot limits, ID isolation, and combined payload bound under an explicit stream-to-slot mapping proved; fixed disk-FIFO order, slot capacity, permanent closure, and actual queued-frame byte bound proved; HTTP mailbox occupancy and endpoint closure proved; ownership and deadlines tested. Conditional allocation composition and shutdown/release arguments are documented; mechanized async refinement remains open. |
| Logging-mode separation | Availability mode may lose audit coverage but cannot relax authorization, routing, or tenant isolation; logging failure cannot create unbounded replacement work. | Core logging-mode transitions proved; bounded logger and failure handling tested. Submission and lifecycle composition are checked under the documented adapter assumptions. |
| Cloud shipping | The optional HypAware shipper cannot affect authorization, forwarding, or readiness; it never modifies the log; every request it sends is chosen by a verified machine and names no host; no exchange is dropped between the log and the acknowledged batch; delivery is at least once with idempotent batch and row identities, so the server stores each exchange once. | Isolation is structural and tested; tailing, exchange assembly bounds, batch limits, upload progress, identity injectivity, enrollment transitions, and the machine's conservation, request shape, and bounded waiting are core proved; HTTPS, parsing, projection, and the server's ledger/dedup are trusted and tested. See [cloud shipping](docs/cloud-shipping.md). |
| Honest completion and conditional progress | Failed/truncated streams cannot masquerade as successful completion; under stated scheduler and I/O assumptions, admitted work terminates or times out and releases resources. | Core admission/release and conditional streaming progress proved; EOF/error behavior and deadlines tested. Permanent worker closure and drain rank are proved; the conditional shutdown/resource argument is documented. Mechanized async liveness verification remains open. |

Verus does not verify Tokio, Hyper, rustls, the OS, DNS/PKI, or the filesystem
for us. Availability also depends on deployment: an external load balancer
must route around a failed gateway instance, and interrupted generations are
not transparently replayed. The [security contract](docs/security-contract.md)
specifies the assumptions and limits; these targets do not promise secrecy of
arbitrary opaque body contents or survival of permanent storage loss.
