# Runtime admission and ownership

`gateway-runtime::admission` is the first trusted runtime layer. It is ordinary
safe Rust, not Verus-verified code. It calls the verified policy, registry, and
stream transitions; their proofs do not automatically verify this composition.

An `Admission` owns an immutable policy and a mutex-protected registry. `admit`
authenticates a digest, reserves a slot, authorizes a tenant-scoped route using the
new request ID, and calls the verified `authorized_stream` constructor for its
initially empty stream. A denied route
returns its reservation. Registry poisoning rejects new requests.

The returned `Request` privately owns its authorization token, stream, and lease.
There is no stream extraction or mutable reference to the core. Field destruction
disposes of the stream before returning its slot. Cancellation closes the stream
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
The runtime creates its stream through this path after policy authorization.

This is an initial composition theorem, not a proof of the whole Rust wrapper.
Keys must remain scoped to their registry; identical numeric slots and IDs in
independent registries are not globally distinct. The runtime lease binds that
identity by ownership. The core still exposes lower-level constructors for other
verified callers, so arbitrary trusted embedding code could bypass this path.
Drop order, async effects, release timing, and whole-process budgets remain
separate obligations. No proof claims that a slot cannot be released while an
independently retained stream exists; the runtime wrapper prevents that extraction.

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
IDs. Runtime cleanup must still reach `release`; the theorem cannot force a caller
to drop a forgotten or indefinitely retained request.

## Verified occupancy snapshot

`ResourceAdmission::usage` scans the slot vector and proves its returned active
count equals the recursively specified number of nonzero slots and never exceeds
the returned slot limit. Its loop records the exact occupied count for the visited
prefix and terminates after the finite registry length. This is a read-only
snapshot; it neither reserves slots nor predicts whether a later request succeeds.

The runtime takes this snapshot under the admission mutex. `/metrics` reports
`soundgate_requests_active`, `soundgate_requests_limit`, and
`soundgate_admission_healthy`. If the mutex is poisoned, it reports admission health
zero and omits occupancy gauges instead of inventing zero utilization. Readiness
also returns 503 in both logging modes after poisoning, while liveness stays 200
so operators can distinguish an unusable registry from an unresponsive process.
A fault-injection test poisons the actual mutex and checks readiness, metrics,
authorized-request refusal, no upstream connection, and clean worker shutdown. Snapshot
cost is linear in configured slots (configuration caps them at 65,536). The counts
exclude unauthenticated connections, disk jobs, and dependency allocations, so they
must not be presented as a whole-process memory measurement or liveness guarantee.

## Evidence and remaining gaps

Seven runtime integration tests cover authentication/route failures, slot exhaustion,
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
the disk adapter must correlate request and chunk identity before invoking them.
Numeric request IDs are local to one admission instance and process lifetime;
persistent log identities need a boot/session namespace. Network dispatch must
consume the owned request and use the same immutable origin/secret snapshot as its
authorization policy. The [configuration layer](configuration.md) now supplies those
immutable mappings and owns the request in a routed wrapper. The HTTP transport consumes this routed wrapper through response completion.

One stream currently serializes chunks. Concurrent upload/download would require
separately owned directional streams and explicit shared budget accounting; it
must not be implemented by duplicating the current stream under the same owner.
