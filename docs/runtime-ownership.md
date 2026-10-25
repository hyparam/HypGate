# Runtime admission and ownership

`gateway-runtime::admission` is the first trusted runtime layer. It is ordinary
safe Rust, not Verus-verified code. It calls the verified policy, registry, and
stream transitions; their proofs do not automatically verify this composition.

An `Admission` owns an immutable policy and a mutex-protected registry. `admit`
authenticates a digest, reserves a slot, authorizes a tenant-scoped route using the
new request ID, and calls verified `OwnedStream::claim`, which uses `authorized_stream` for its
initially empty stream. A denied route
returns its reservation. Registry poisoning rejects new requests.

The returned `Request` privately owns its authorization token, stream, and lease.
There is no stream extraction or mutable reference to the core. The lease owns
a verified `OwnedStream` pair and consumes it through `OwnedStream::retire` while holding the
registry mutex, before another admission can reuse the slot. Cancellation closes the stream
but retains the lease until the request is dropped. Unwinding also drops the lease;
process abort does not promise cleanup. Deliberately forgetting a request leaks its
credit rather than allowing unsafe reuse.

Runtime write tickets additionally borrow their admission instance. Pointer identity
rejects tickets from another registry even when both registries issue the same
numeric request ID. The borrowed payload cannot outlive its request; stale tickets
can outlive the request but cannot expose bytes or advance a replacement request.

## Verified initial composition

`ResourceAdmission::authorized_stream` requires a valid authorization token and
registry. It rejects a key whose request ID differs from the token, whose slot is
not live, or whose initial stream has already been claimed. The key has a private,
non-cloneable claimed bit. Successful construction proves stream validity, matching
owner/token/key IDs, empty payload, the registry's per-request capacity, and the
requested logging mode. The key's identity and slot remain unchanged. A failed
construction leaves the key unchanged, allowing the correct token to be used later.
The runtime creates its stream through `OwnedStream::claim`, which consumes the key
and uses this path after policy authorization.

This is an initial composition theorem, not a proof of the whole Rust wrapper.
Keys must remain scoped to their registry; identical numeric slots and IDs in
independent registries are not globally distinct. The runtime lease binds that
identity by ownership. Raw `StreamChunk::new`, `authorized_stream`, and
`release_stream` are now crate-private. External callers, including the runtime
crate, must construct and retire streams through the consuming `OwnedStream` API.
Async effects, release timing, and whole-process budgets remain separate obligations. No proof claims that a slot cannot be released while an
independently retained stream exists; the runtime wrapper prevents that extraction.

## Verified stream retirement

`ResourceAdmission::release_stream` consumes a stream by value and succeeds exactly
when the key has claimed a stream, its ID matches the stream owner, and the registry
still owns the key. Success clears only that slot and decreases occupancy by one;
rejection leaves the registry unchanged. Both outcomes consume the supplied stream.
The runtime lease uses this operation through `OwnedStream::retire` for constructed
streams, retaining reservation-only
`release` for reservations that failed before stream construction. Storage is
dropped inside the locked operation; no async I/O occurs under the lock.

This proves the synchronous ownership check and registry transition. It does not
prove that external async effects have stopped, distinguish equal numeric IDs in
separate registries, or verify every privileged call inside the core crate.
External code can no longer use raw constructors to synthesize another stream
with the same owner; runtime encapsulation still binds each owner to its registry. Reservation-only `release` now rejects every claimed
key without changing registry state; the lower-level slot-clearing primitive is
private and used only by the two verified release paths. This removes the direct
non-consuming release bypass, but does not yet prove the global stream-to-slot map.
Composition tests cover valid retirement, mismatched owners, unclaimed streams,
and stale keys, and verify that a claimed slot stays occupied when reservation-only
release is attempted. A dedicated mutation removes that guard and must fail its
proof; the existing mutations check the owner accessor and acceptance conditions.

## Admission progress within the synchronous core

The registry now specifies the reasons for rejection, not only the safety of
successful operations. `acquire` returns no key only when the monotonic ID space
is exhausted or every slot is occupied. Its finite scan records that every
previously visited slot is occupied. Thus a free slot with IDs remaining produces
a reservation. `authorized_stream` returns no stream only for an already-claimed
key, a mismatched authorization ID, or a key not owned by this registry. `release`
returns false only for an unowned key; a valid owned key must release its slot.

Mutation checks replace each operation with unconditional refusal and require
proof rejection. These are synchronous non-rejection/termination properties under
the core preconditions, not scheduler fairness, mutex availability, memory-allocation
success, or network/storage liveness. Poisoned runtime locks still fail closed.
Identifier exhaustion intentionally disables further admissions rather than reusing
IDs. Runtime cleanup must still reach a release operation; the theorem cannot force a caller
to drop a forgotten or indefinitely retained request.

## Verified occupancy snapshot

`ResourceAdmission::usage` scans the slot vector and proves its returned active
count equals the recursively specified number of nonzero slots and never exceeds
the returned slot limit. Its loop records the exact occupied count for the visited
prefix and terminates after the finite registry length. This is a read-only
snapshot; it neither reserves slots nor predicts whether a later request succeeds.
The constructor proves zero occupied slots. A recursive `occupied_update` lemma
then establishes that a successful `acquire` increases occupancy by exactly one,
and a successful `release` decreases it by exactly one. Rejected operations leave
the registry unchanged. These contracts compose count changes across arbitrary
valid synchronous call sequences; they do not prove when async owners drop leases.

The runtime takes this snapshot under the admission mutex. `/metrics` reports
`loggate_requests_active`, `loggate_requests_limit`, and
`loggate_admission_healthy`. If the mutex is poisoned, it reports admission health
zero and omits occupancy gauges instead of inventing zero utilization. Readiness
also returns 503 in both logging modes after poisoning, while liveness stays 200
so operators can distinguish an unusable registry from an unresponsive process.
A fault-injection test poisons the actual mutex and checks readiness, metrics,
authorized-request refusal, no upstream connection, and clean worker shutdown. Snapshot
cost is linear in configured slots (configuration caps them at 65,536). The counts
exclude unauthenticated connections, disk jobs, and dependency allocations, so they
must not be presented as a whole-process memory measurement or liveness guarantee.

## Evidence and remaining gaps

Eight runtime integration tests cover authentication/route failures, slot exhaustion,
drop and panic cleanup, cancellation with a pending write, strict durability gating,
oversized chunks, stale completions, concurrent admission, and cross-registry tickets.
The tests also reject short or empty vectors whose spare allocation exceeds the
chunk budget, without changing the live chunk or its pending ticket.

This wrapper bounds the number of retained streams and each stream's logical payload
length. Before passing a new vector to the core, it also checks `Vec::capacity`
against the request budget. Rejected vectors are dropped without changing stream
state. This is a trusted Rust check: the current Verus model describes lengths,
not allocated capacities. It bounds retained vector capacity, not memory allocated
by the caller before admission or physical allocator overhead. The production
transfer driver releases completed storage before allocating the next buffer.
HTTP/TLS buffers, logger queues, and total process memory remain separate obligations.
The admission mutex protects only admission and release; no I/O occurs under it.

The eventual transport must own the request for the lifetime of every effect and
must not detach work that survives its lease. Repeated borrowed views still do not
authorize repeated submissions. Logging acknowledgments remain trusted events:
`audit_current` obtains metadata and bytes together through verified
`StreamChunk::audit_record`, then binds the awaited logger result to the exclusively
borrowed current chunk. It is the runtime request's only acknowledgment path. The logger returns a
private journal receipt, and verified `acknowledge_receipt` compares its canonical
metadata and exact payload to the current stream before advancing durability.
A mismatched receipt closes the runtime request, including in availability mode.
The constructor proves that tenant comes from the supplied authority, request ID
matches the stream owner, chunk ID and payload length match current stream state,
and borrowed bytes equal the current payload. It rejects mismatched authority,
closed/failed streams, oversized records, and invalid directions. Numeric request
IDs still require the runtime to keep authority and stream in the same admission
instance; this check cannot authenticate an arbitrary independently supplied token. A direct cancellation
test covers both logging modes, rejects further writes/chunks, and retains the
lease until request drop. A custom `AuditLog` implementation must still truthfully
report durability; the type boundary cannot prove a syscall or an external callback.
Numeric request IDs are local to one admission instance and process lifetime;
persistent log identities need a boot/session namespace. Network dispatch must
consume the owned request and use the same immutable origin/secret snapshot as its
authorization policy. The [configuration layer](configuration.md) now supplies those
immutable mappings and owns the request in a routed wrapper. The HTTP transport consumes this routed wrapper through response completion.

One stream currently serializes chunks. Concurrent upload/download would require
separately owned directional streams and explicit shared budget accounting; it
must not be implemented by duplicating the current stream under the same owner.


## Conditional combined payload theorem

The registry-wide payload theorem lives in `owned_accounting` and is described
under [registry-wide bound including pending reads](#registry-wide-bound-including-pending-reads).
An earlier version stated the same bound over bare stream snapshots; production
only ever maps `OwnedStream` values, so that duplicate map and its preservation
lemmas were removed.

The theorem composes the synchronous slot and chunk bounds under the stated
ownership mapping. It does not prove that every async transition maintains that
mapping, or that dropping a request stops every external effect. Numeric owners
remain scoped to their registry. It also excludes vector spare capacity, HTTP/TLS
backing storage, log queues, allocator overhead, and OS caches. The runtime
ownership boundary and load tests support those separate obligations without
turning this into a whole-process memory theorem.

## Ownership-map preservation

The core proves preservation rules for the ghost owner-to-slot map, rather than
requiring every later snapshot's validity independently:

- `ResourceAdmission::new` establishes a valid all-empty map.
- The actual `acquire` postcondition preserves every previously valid map. Its
  proof derives that the newly reserved slot had no retained owner, since it was
  free; other owners remain unchanged.
- `OwnedStream::claim` proves that installing the returned owner at its key's
  slot preserves the map.
- `replace_owner` covers subsequent owner snapshots with valid state, unchanged
  key, and capacity within the slot's allowance. The executable stream
  transitions specify these facts, including chunk rollover and cancellation.
- Successful `release_stream` and reservation-only `release` prove that clearing
  the released slot's map entry preserves the map. Failed releases leave the
  registry unchanged. Clearing a map entry describes dropping the owner, not
  permission to keep an independent copy alive.

Together these rules allow induction over core lifecycle events and application
of `registry_owned_payload_bound` after each event. Deliberate defects test
reservation of a live mapped slot, replacement with the wrong owner, omitted
read bytes, oversized replacements, and retained payload after retirement.

This is still a conditional resource proof. The ghost map is a specification
snapshot, not a runtime registry of buffers. Safe Rust lease encapsulation must
faithfully implement its insertion/replacement/removal events and enforce one
stream per key. Formal composition of that async ownership boundary, additional
queue/receipt allocations, and dependency backing storage remains open. No new
runtime collection or retained historical payload is introduced.

## Verified owned stream in the production lease

`gateway_core::owned_stream::OwnedStream` privately owns both the request key and
its stream. `claim` consumes a reservation and either returns the valid pair or
returns the unchanged key with a specified rejection reason. Successful creation
binds the stream owner, authority request, live key, capacity, and logging mode.
There is no key extraction, stream extraction, cloning, or mutable stream accessor.
Its read-only stream borrow cannot outlive the pair or replace its stream.

Every mutating stream operation used by the runtime goes through a verified
method that preserves the pair invariant and retains the exact underlying
behavioral contract: rollover, discard, prepare, partial completion, cancellation,
logging failure, and durable-receipt acknowledgment. `retire` consumes the pair,
clears exactly its live slot, and preserves the ownership map with that stream
removed. The owned read buffer replaces the driver's former allocation; it does not add
a second per-request payload buffer.

The runtime lease now stores either an unclaimed reservation or this owner. Its
Drop implementation holds the same registry mutex while retiring the owner; no
raw stream/key re-pairing is performed by the async adapter. A panic during the
synchronous reservation-to-owner transfer can leak a slot until restart, but cannot
return credit while retaining the stream. Normal rejection restores the reservation
for Drop to release. Poisoning continues to close admission.

The constructor/transition/retirement proofs reduce the trusted ownership surface;
they do not verify Tokio scheduling, mutex identity, cancellation/drop execution,
or all allocation lifetimes. Lower-level construction/release is confined to the
core crate; registry namespaces remain externally scoped. These limits prevent
claiming a complete global async ownership proof. The composition test covers failed
claim, capacity, partial writes, rollover, cancellation, retirement, and slot reuse;
compile-fail doctests reject raw construction, raw claim/release, mutation through
the read-only accessor, and completion while a read-buffer borrow remains live.
The raw API tests explicitly require the private-method diagnostic. Four
mutations check skipped retirement, altered bytes, ignored cancellation, and denied
valid write progress.

## Verified read-buffer ownership

`OwnedStream` now owns the pending read vector as well as its stream. Its invariant
bounds their combined logical length by the request capacity and requires an empty
stream body whenever a read buffer exists. `payload_bound` exposes that theorem.
`begin_read` discards only completed stream storage before allocating the next
buffer; it rejects a second pending buffer and specifies exact acceptance.
`finish_read` checks the reported length, truncates to that prefix, and moves the
same allocation into the stream. EOF frees the read buffer without advancing the
chunk; canceled or invalid completion cannot authorize forwarding. Valid completion
has an exact acceptance contract and preserves byte history and owner identity.
Retirement explicitly drops any pending read buffer before releasing its slot.

The async driver now calls `Request::read_next`; it no longer owns a separately
allocated chunk. That helper borrows the owner's mutable slice through the awaited
read. Rust slices cannot resize their underlying vector. Because vstd's mutable
slice projection represents future contents abstractly, the accessor's proof states
preservation conditional on unchanged slice length; Rust/AsyncRead correspondence
at that boundary remains trusted. No new assumed specification or external-body
escape was added. Vec backing capacity and allocator behavior are still outside
Verus's logical-length model; allocation uses `with_capacity` before zero-filling.

Tests exercise partial fill, rejection of an oversized count, EOF, cancellation,
rollover, and refusal of a second read or external chunk while a buffer is pending.
Mutations retain an old chunk while allocating, substitute the completed prefix,
or deny a valid read completion and must fail verification.

## Registry-wide bound including pending reads

`owned_accounting::registry_owned_payload_bound` lifts the production owner's
`payload_bound` to a registry-wide total. The ghost owner map is indexed by slot;
each present owner must be valid, belong to that live registry slot, and retain
its configured capacity. Its projected buffer is the stream body concatenated
with the pending read bytes. This concatenation is erased specification data,
not a runtime allocation; the owner invariant makes at most one side nonempty.

The theorem proves that the total is at most live-slot occupancy times per-request
capacity, hence at most the configured request limit times capacity. With the
validated configuration budget, that logical total is at most 128 MiB. It also
supplies the `bounded` chunk-category predicate consumed by the combined buffer
subtotal theorem, so pending async reads are included in that category.

The actual registry constructor establishes the empty owner map. Acquisition
preserves it, `OwnedStream::claim` proves insertion of its returned owner, and
successful release/retirement proves removal. The `replace_owner` lemma lifts
mutating owner transitions using their preserved key/capacity and valid-state
postconditions. A coverage lemma and five mutations check live-slot reservation,
wrong-owner replacement, omitted read bytes, oversized replacements, and retained
payload after retirement.

The runtime must still maintain a complete single-registry map of its live owners;
this is not a proof of all Tokio scheduling or global allocation lifetimes. The
mutable-read-slice length obligation and dependency/allocator exclusions remain.
