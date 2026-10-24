# HTTP ownership and cancellation audit

The production gateway now derives its HTTP owner counts from the same verified
registries that admit and release workers and connections. The HTTP cleanup-tail
row of milestone 6 is complete under the adapter assumptions below. The completed
[lifecycle composition audit](milestone-6-exit-audit.md) connects this row to request,
disk, DNS, and TLS ownership.

## Actual owners and charges

| Payload owner | Checked issuance | Runtime retention and cleanup |
| --- | --- | --- |
| Inbound detached reader copy, at most 32 KiB | `WorkerRegistry::issue(INPUT_READER)` | `Gateway::handle` calls `WorkerHttp::input`. `Reader::drop` destroys the body and detached `ReadBuffer` before completing its permit. |
| Upstream detached reader copy, at most 32 KiB | `WorkerRegistry::issue(OUTPUT_READER)` | `HttpsTransport::run` calls `WorkerHttp::output`. The same explicit reader cleanup retains the charge through partial reads and cancellation. |
| Upload mailbox, at most 16 KiB | `WorkerRegistry::issue(UPLOAD_CHANNEL)` | `WorkerHttp::upload` attaches one shared charge to both endpoints. The last endpoint returns it after mailbox cleanup; a cleanup panic is recorded and strands the permit even if the other endpoint drops normally later. |
| Client-response sender and any sender-only mailbox tail, at most 16 KiB | `WorkerRegistry::issue(RESPONSE_WRITER)` | `Gateway::handle` attaches the charge before spawning the writer. `Writer::drop` destroys the sender before completing its permit. |
| Client-response receiver and receiver cleanup, at most 16 KiB | `ResponseRegistry::issue` | `ConnectionResponses::channel` binds the permit to the receiver. `ChannelBody::drop` destroys the receiver and its pending cleanup before returning the permit. |

`ReadBuffer` proves bounded loading and preserves the full detached backing charge
through partial consumption. Production output uses `OutputFrame` and
`HttpMessage`; their checked projections and consuming extraction cap each data
frame at 16 KiB. `Mailbox` and `Cleanup` preserve the pending message through
closure and extraction until reported destruction completes.

The client mailbox may be charged to both sender and receiver. This is an
intentional upper bound: a worker can finish while its connection still drains
the response, and a canceled connection can leave a sender cleanup tail. If one
endpoint disappears, the other still covers any shared mailbox payload. The
upload charge instead spans both endpoints of a single worker-owned channel.
Dequeued frames retained by Hyper are dependency allocations, accounted for in
[dependency resources](dependency-resources.md), not additional application
mailbox entries hidden in this bound.

## Checked count and lifecycle preservation

`http_worker::WorkerRegistry` wraps the existing closeable worker admission
registry and stores four issued/active bits per actual slot. Every admission
creates a fresh generation. Each role can be issued once, completion consumes its
non-cloneable permit without resetting issuance, and task release retires the
issuer permanently. Stale issuers cannot act on a replacement generation.
Allocation, completion, closure, and release preserve unrelated active roles.
Any outstanding role prevents task release, even after its future cleanup has
completed; failed worker release closes admission and strands the slot.

`http_connection::ResponseRegistry` provides the corresponding one-response
connection lifecycle. Both registries maintain the invariant that every active
role belongs to an occupied slot. Their count theorems derive bounds from their
actual arrays, with no independently supplied owner-count premise.

`http_accounting::http_owner_bounds` composes those production invariants:

- The two reader counts total at most twice the worker limit.
- Client receivers plus response-writer tails plus upload channels total at most
  the connection limit plus twice the worker limit.
- Their charged payload subtotal is at most `2R × 32 KiB + (C + 2R) × 16 KiB`.
- Coverage clauses prevent omitting a category while proving a smaller subtotal.

These are upper bounds, so an empty-but-live reader/channel may still be charged.
No extra admission pool or new concurrency limit was introduced. Registry state
and its permits remain live through shared Rust ownership after cancellation;
leaked owners or failed cleanup cannot make their slots reusable.

## Production correspondence and trusted assumptions

The registry transitions and arithmetic are checked by Verus. The private Rust
adapters bind each permit to exactly one listed owner, preserve its registry
identity, serialize transitions under that registry's mutex, and report completion
only after the corresponding destructor returns normally. These Rust ownership,
Arc lifetime, mutex, and truthful destruction joins remain trusted. The upload
panic flag prevents a later normal endpoint destructor from hiding an earlier
cleanup panic. Poisoned registries are never recovered to return capacity.

The gateway always calls `exchange_with_http` with its worker's context. The
public embedding API `HttpsTransport::exchange` still accepts arbitrary byte
readers/sinks and has no gateway worker context; embedders must supply their own
lifetime/count correspondence. It is outside this gateway-wide bound. The fixed
runtime reader capacity and output-frame limits are part of the reviewed adapter
mapping. Hyper/Tokio/TLS internals, allocator capacity, wakers, and total process
RSS remain governed by their separate assumptions and accounting.

## Evidence

Core tests exercise all four roles, duplicate/invalid issuance, independent
completion, stale generations, closure, and retained-role release rejection.
Runtime tests cover both partially consumed readers, both upload endpoint drop
orders, payload destruction while the global charge remains active, and an
upload cleanup panic followed by normal destruction of the surviving sender.
The actual worker wrapper rejects reuse when any HTTP owner escapes task cleanup.
Existing worker/connection cancellation tests now use the credited reader and
response-writer paths; the queued response still drains under connection credit
after worker cancellation. The locked gateway suite also covers normal exchanges,
deadlines, shutdown, blocked logging, and canceled requests through this path.

Validation at this checkpoint: 293 Verus checks, 247 tests including the added
targeted escaped-owner regression, six compile-fail doctests, and 248 rejected
mutations. Mutations cover duplicate/stale/foreign issuance, wrong roles, missing
charges, premature release, and omitted aggregate payload categories.
