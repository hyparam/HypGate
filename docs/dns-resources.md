# DNS work ownership and shutdown

Hostname resolution is a blocking system call that no caller can interrupt.
A connection thread that stops waiting at its exchange deadline does not stop
a started lookup, so returning the request's credit at the deadline does not by
itself bound DNS work across repeated timeouts. Production never resolves a
hostname on the connection thread itself; it waits, under the deadline, for a
lookup on the bounded pool below and connects only to the addresses it returns.

## Separate bounded lifetime

Each `HttpsTransport` owns one resolver with four dedicated threads and a separate
32-slot `ResourceAdmission` registry. Acquisition precedes constructing/enqueueing
a lookup job; excess work is refused immediately. The bounded channel also has
32 slots. Active, queued, and unadopted replies share the same 32-credit limit, rather than each
having 32 additional credits. No replacement threads are spawned for slow lookups.

Each job uses shared `credited_job::CreditedJob` and retains its original registry
key in a verified `TaskCredit` through lookup execution and capture destruction.
Successful results move that credit into `Reply`; sending is not permission to
return the slot. An unread reply remains charged even after its worker finishes.
Dropping a job or reply enters verified cleanup, destroys its owned value, then
reports cleanup complete; a panic during that wrapper cleanup strands capacity.
The Verus contracts establish empty initialization, capacity refusal, exact
acquire/release occupancy changes, and refusal to release running/cleaning credits.
Mutex serialization, private key ownership, Rust destruction, and channel behavior
are trusted runtime bindings. The resolver wrapper itself is not Verus-verified.

`HttpsTransport::connect`, the driver's `connect` effect, adopts a successful
reply while exclusively borrowing its admitted request. `Request::adopt_background` locks that request's own registry
and calls `TaskCredit::handoff_to` with its actual `OwnedStream`. The checked
transition requires a completed-work reply credit and a live, non-closed admitted
owner, records its exact ID, and only then permits background release. The adapter
moves the unchanged result into the borrowing request before further network
I/O. A canceled/poisoned request cannot adopt; the reply destroys the result under
its original credit. Core keys remain scoped by private runtime registry owners.

A caller whose deadline passes drops its `Pending` receiver, not the
queued/running job. Workers skip queued jobs whose requester has left. A lookup
already started may finish
and discard its result; it keeps its credit until actual completion. Lookup panics
are caught after job cleanup, so they close the reply without permanently losing
a pool worker. Process abort, stack overflow, and a permanently blocked system
lookup are outside this recovery mechanism.

## Addresses and routing

IPv4/IPv6 literals bypass DNS workers. For hostnames, the system resolver retains
its ordinary hosts-file/NSS/DNS behavior. The adapter copies at most 64 returned
socket addresses into a fresh vector and rejects a 65th; it does not retain a
large backing allocation from the system iterator. The source iterator and its
storage drop inside the worker. Empty results fail when TCP connection is tried.

The bounded address vector is passed to `TcpStream::connect_timeout` one socket
address at a time, each attempt bounded by the exchange deadline's remaining
time, so no second hostname lookup can start. It is released after the TCP
attempt, before TLS/body streaming. TLS still authenticates the original configured
hostname and HTTP uses the same authorized Host and credential. This changes no
root grants and adds no HTTP retry/replay. Trying multiple resolved socket addresses
before sending HTTP is the existing TCP connection behavior.

DNS saturation, lookup failure, panic, and excessive address count become the
existing connection error (502 before client response headers). The exchange's
existing deadline includes queue wait and lookup time. DNS saturation does not
make process health fail and literal-IP routes remain usable. There is no claim
that hostname traffic progresses while all four resolver threads are stuck.

## Allocation inventory and shutdown

Per transport instance, separately from per-request payloads:

- Four dedicated worker threads request 2 MiB stacks each (8 MiB requested stack
  size total); OS stack rounding, committed pages, thread-local data, and kernel
  thread objects are not represented by that number.
- At most 32 credited queued/running jobs, each with a hostname, port, reply sender,
  lookup closure, registry key, and Arc reference. Production DNS hostnames are
  bounded to 253 bytes by configuration validation. Job/queue metadata, allocator
  slack, and receiver synchronization are additional fixed-count objects.
- One 32-entry `u64` registry and its mutex, plus one bounded channel and shared
  receiver. The production closure captures no request payload or provider secret.
- Each completed reply or connection attempt retains at most 64 socket addresses.
  Replies waiting for consumption retain background credits; adopted vectors
  belong to the admitted request until the TCP attempt finishes. Canceled replies
  destroy their vectors before returning their credits.
- Up to four system-resolver invocations can allocate internally. libc/NSS lookup
  buffers and external resolver modules are not bounded by the 64-address output
  cap. This remains a dependency allocation assumption, not a whole-process theorem.

Resolver workers are ordinary detached OS threads. Dropping the resolver closes
its sender; workers exit once outstanding system calls return and remaining
unwanted jobs are discarded. A permanently blocked lookup can outlive server
drain, but cannot hold process exit open. Multiple transport instances multiply these budgets; repeatedly constructing
new transports while abandoning stuck old instances is outside the executable's
single-transport lifecycle and must be budgeted by library callers.

## Tests

`transport::resolver::tests` exercises four started lookups plus one queued lookup,
lets every requester stop waiting, rejects 16 additional jobs, confirms IPv6
literals still work, then releases the original workers and checks the queued
lookup nobody waited for was never executed and capacity is reusable.
Deliberately returning lookup credit before executing the blocking operation
makes this regression test fail. Further tests cover a panicking lookup followed
by successful reuse of the same one-worker pool, exact 64-address acceptance,
excess rejection, and detachment from an oversized source allocation. Existing TLS, deadline, cancellation, overload, and CLI tests
exercise the integrated transport. These are deterministic adapter tests, not a
proof that every operating-system resolver terminates or bounds its own memory.

Shared `credited_job` tests additionally cover unread/delivered reply retention,
departed requesters, queued and reply destructor panics, and exact value adoption
into live versus canceled requests. Core tests exercise absent/canceled target
owners and repeated handoff. Four reply/handoff mutations reject missing target
liveness, a wrong target ID, transfer before work finishes, and release of an
unread result; the seven cleanup
mutations still reject early release and invalid lifecycle transitions.
