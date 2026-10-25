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

Three statements summarize what the proofs buy an operator. Each is followed
by what is proved today and what is still being moved under the theorem.

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

**Premises.** HTTP serialization, DNS, TLS, and the system resolver behave as
specified (no IP-range policy, so not an SSRF theorem); the effect-site table
in the end-to-end audit is complete; the runtime passes the gate's bytes to
the socket it opened for that route and the machine's requests to the client
it built from the configured server.

**In progress.** "No other socket" is still a reviewed table; phase 3 makes
it a lint-enforced structural fact and gives the provider writer and the
cloud client one shared permit type.

## Guarantee 2: what was logged is what is shipped, once and in order

**Statement.** Every exchange recorded in the audit log is grouped from its
records in file order, bounded in retained size with truncation recorded,
projected into rows whose identities are a function of the log alone, and
uploaded in emission order. An exchange is counted as delivered only when the
server acknowledges the exact batch it was sent in. A restart replays the log
and resends at most what was unacknowledged, with identical identities, so the
server's dedup stores each exchange once.

**Proved today.**

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

**Premises.** Hex encoding; the server honors its batch ledger and part-id
dedup; the projection of an exchange's provider JSON into text and usage is
faithful (tested against recorded bodies, not proved); the runtime's `Effects`
implementation performs what it is asked (sends to the configured server,
returns the log's records in order, writes the checkpoint it is given).

**In progress.** Phase 4 adds the replay theorem.

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

**Premises.** The storage contract (synced bytes survive); Tokio cancellation
reaches the futures; the shipping adapters are panic-free, which clippy
denies on unwrap, expect, panic, indexing, and unchecked arithmetic enforce
(`cargo clippy -p gateway-runtime`), and the thread boundary contains any
panic that does occur; the clock is monotone enough for the enrollment
windows.

**In progress.** Panic-injection and kill-at-every-step tests for the
shipper (phase 5).

## Plan to close the gaps

Each phase is one logical commit on the `hypaware-shipping` branch.

1. **Verified shipper machine (core).** Done. One state machine owning the
   assembler, cursor, enrollment, queue, backoff, and batching. Operations:
   admit a record, enqueue its projection, choose the next action, absorb a
   reply. Theorems: conservation, batch fidelity, token containment, bounded
   waiting, progress, totality (`crates/gateway-core/src/shipper.rs`).
2. **Verified driver over an effect trait.** Done. The loop itself is
   checked against the machine's contracts; the runtime implements read,
   send, sleep, checkpoint, and now with no decisions in them
   (`crates/gateway-core/src/shipping_driver.rs`). Clippy denies on unwrap,
   expect, panic, indexing, and unchecked arithmetic in the shipping adapters.
3. **One egress permit.** A single verified type that both the provider
   writer and the cloud client require; with shipping disabled the cloud
   variant is uninhabited. Disallowed-method lints and a CI script pin the
   only socket and file-write sites.
4. **Replay theorem.** Emission is a deterministic function of the record
   sequence; restoring a checkpoint and replaying yields the unacknowledged
   suffix with identical part ids; a checkpoint never claims more than was
   acknowledged, so a crash can cause a resend but never a skip.
5. **No crash state, tested.** Panic injection and kill-at-every-step runs
   against the scripted server; readiness, admission, and disk acknowledgment
   unchanged while the shipper dies.
6. **Documentation.** This file, the proof index, the end-to-end audit, and
   the security contract updated to point at the theorems.

## Specific properties proved

The finer-grained targets behind the three guarantees. “Core proved” means a
synchronous model or transition is checked by Verus, conditional on the
documented adapter contracts. The [proof index](docs/proof-index.md) names the
checked definitions for each row.

| Property | Intended guarantee | Evidence today |
| --- | --- | --- |
| Authorization and fail-closed security | Every upstream dispatch requires an authenticated tenant's grant; authentication or policy failures cannot authorize forwarding, in either logging mode. | Core token issuance proved; HTTP binding tested. Complete mediation remains a trusted adapter obligation. |
| Tenant and credential isolation | Requests, completions, and credentials cannot cross tenant/request boundaries; gateway authentication material never becomes an upstream credential. | Core tenant/credential-handle and ticket checks proved; secret/header handling tested. Composed isolation and audit access controls remain open. |
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
