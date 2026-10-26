# HTTP ownership and cancellation audit

The production gateway derives its HTTP owner counts from the same verified
registries that admit and release workers and connections, under the adapter
assumptions below. The [ownership composition](ownership-composition.md) connects
these counts to request, disk, DNS, and TLS ownership.

## Actual owners and charges

| Payload owner | Checked issuance | Runtime retention and cleanup |
| --- | --- | --- |
| Inbound body reader and its 32 KiB read buffer | `WorkerRegistry::issue(INPUT_READER)` | `Gateway::run_exchange` calls `WorkerHttp::input`. `Reader::drop` destroys the body reader before completing its permit. |
| Upstream body reader and its 32 KiB read buffer | `WorkerRegistry::issue(OUTPUT_READER)` | `HttpsTransport::run` calls `WorkerHttp::output`. The same explicit reader cleanup retains the charge through partial reads and cancellation. |
| Upload writer, one framed chunk of at most 16 KiB plus framing | `WorkerRegistry::issue(UPLOAD_CHANNEL)` | `HttpsTransport::run` calls `WorkerHttp::upload_writer` around the chunked writer on the TLS stream. `Charged::drop` or `into_inner` destroys the writer before completing its permit. |
| Client-response writer, one framed chunk of at most 16 KiB plus framing | `WorkerRegistry::issue(RESPONSE_WRITER)` | `serve_connection` calls `WorkerHttp::response_writer` around the server's `Output` before the exchange. `Charged::drop` destroys the output before completing its permit. |
| Connection credit | `ResourceAdmission::acquire` with a `TaskCredit` | `ConnectionSlots::acquire` in the accept loop; the credit is spent by `leased::run` on the connection thread and released when the thread's work returns. There is no separate response permit: the response is written by the same thread. |

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
A frame being framed as a chunk is the chunked writer's allocation on the
connection thread, accounted for in
[dependency resources](dependency-resources.md#chunk-framing-buffers), not an
additional application queue entry hidden in this bound; there is no queue.

## Checked count and lifecycle preservation

`http_worker::WorkerRegistry` wraps the existing closeable worker admission
registry and stores four issued/active bits per actual slot. Every admission
creates a fresh generation. Each role can be issued once, completion consumes its
non-cloneable permit without resetting issuance, and task release retires the
issuer permanently. Stale issuers cannot act on a replacement generation.
Allocation, completion, closure, and release preserve unrelated active roles.
Any outstanding role prevents task release, even after the work has returned;
failed worker release closes admission and strands the slot.

`http_connection::ResponseRegistry` provides a corresponding one-response
connection lifecycle; the runtime no longer uses it, since the connection
thread writes the response itself, and its connection credits are a plain
`ResourceAdmission`. Both registries maintain the invariant that every active
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
mapping. TLS internals, allocator capacity, thread stacks, and total process
RSS remain governed by their separate assumptions and accounting.

## Evidence

Core tests exercise all four roles, duplicate/invalid issuance, independent
completion, stale generations, closure, and retained-role release rejection.
Runtime tests cover both partially consumed readers and both writer roles held
until destruction or `into_inner`. The actual worker wrapper refuses reuse and
closes admission when any HTTP owner escapes the work. The locked gateway suite
also covers normal exchanges,
deadlines, shutdown, blocked logging, and canceled requests through this path.

Current validation totals are maintained in the [README](../README.md). Mutations cover duplicate/stale/foreign issuance, wrong roles, missing
charges, premature release, and omitted aggregate payload categories.
