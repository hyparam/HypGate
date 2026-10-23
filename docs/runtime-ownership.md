# Runtime admission and ownership

`gateway-runtime::admission` is the first trusted runtime layer. It is ordinary
safe Rust, not Verus-verified code. It calls the verified policy, registry, and
stream transitions; their proofs do not automatically verify this composition.

An `Admission` owns an immutable policy and a mutex-protected registry. `admit`
authenticates a digest, reserves a slot, authorizes a tenant-scoped route using the
new request ID, and constructs exactly one initially empty stream. A denied route
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
