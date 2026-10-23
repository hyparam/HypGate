# Milestone 1: multi-chunk streaming and resource admission

Status: implementation started; milestone 1 is not complete.

`experiments/verus/stream.rs` replaces per-byte iteration with an immutable owned
chunk, a borrowed slice view, and one outstanding write reservation. The older
experiments remain as research baselines. This is not an HTTP adapter or a packaged
production library yet.

`experiments/verus/admission.rs` adds `ResourceAdmission`, a bounded slot registry
with opaque request keys, monotonically allocated owner IDs, and a configured
per-request payload allowance. This is resource accounting, not caller authorization;
the [security contract](security-contract.md) specifies that separate boundary.

## Write lifecycle

1. Acquire a resource key, then construct a stream with its owner and capacity limit.
   Oversized input is rejected; the caller must also bound allocation before this call.
2. Supply truthful owner- and chunk-tagged durable-prefix acknowledgments. Strict mode can
   reserve only acknowledged bytes; availability-first mode can reserve received bytes.
3. Prepare a nonempty range up to the requested maximum. This returns an opaque
   owner/generation ticket and leaves the completed offset unchanged. A second
   reservation is rejected while one is outstanding.
4. Borrow the ticket's exact input slice for one transport write. The core neither
   copies the payload nor iterates byte by byte. Rust borrowing keeps the chunk
   immutable while this view is borrowed.
5. Report the transport's accepted-byte count with the ticket. Only that prefix
   advances; an unsent suffix can be reserved again with a new generation. Zero
   progress releases the reservation without advancing. Invalid counts and stale
   or wrong-owner tickets are rejected without changing state.
6. Advance to the next chunk only after all current bytes complete and no write is
   outstanding. Enforce the original capacity, increment the chunk number, clear
   its durable offset, and retain the write-generation counter. Old acknowledgments
   and tickets cannot advance the new chunk. The erased cumulative history spans
   chunk boundaries without retaining old payloads at runtime.
7. Dispose of the request's work and return its resource key. The registry rejects
   duplicate/stale release and allocates a new ID when reusing the slot.

Cancellation blocks new reservations and new payload views, but a previously
issued write may already have reached the transport. Its known completion can
still be recorded. Strict logging failure follows the same closure rule;
availability-first logging failure permits forwarding and rejects further log
acknowledgments in this initial terminal-failure model.

If transport failure leaves the accepted count unknown, cancel and discard the
chunk rather than fabricate a count or replay the range. The adapter must enforce
that policy. Likewise, zero-progress retries need a deadline; the core does not
prove liveness or force a blocking syscall to return.

## Checked properties and tests

Validation on 2026-10-23: Verus reported **15 verified checks, 0 errors** for the
combined streaming and registry code (including loop checks). Compiled scenarios
passed; eight streaming and four registry mutations were rejected by proof failures.

All public executable operations have Verus contracts. The invariant bounds the
completed, reserved, and durable offsets; strict reservations remain within the
durable prefix. An erased ghost history equals the completed prefix of the original
input across chunks. Public contracts state identity, policy, and unaffected-state
preservation. The registry preserves its fixed slot count and per-request allowance,
keeps occupied IDs distinct, and allocates above every currently occupied ID without
wrapping. Returning a stale key cannot evict a replacement request.

The compiled scenario covers oversized and empty chunks, zero limits, invalid log
acknowledgments, partial writes, duplicate/stale/wrong-owner completions, interleaved
owners, cancellation during a reservation, strict logging failure, and zero progress
in availability-first mode, rollover including empty chunks, stale chunk log events,
admission exhaustion, slot reuse, and stale releases. These scenarios test ordinary Rust calling the verified
methods; the scenario's main function is not itself verified.

The streaming mutation runner rejects bypassing durability, accepting the
wrong owner, accepting a stale generation, claiming a partial write was complete,
returning the wrong slice, ignoring cancellation, replacing unfinished data, and
accepting a stale log acknowledgment. The registry runner rejects ID reuse,
evicting a live request, changing the configured budget, and stale release.
The runners distinguish failed proof obligations from incidental compiler errors.

With the Verus/Rust versions pinned in [the experiment results](experiment-results.md):

```sh
VERUS=/path/to/verus python3 experiments/verus/check_stream.py
VERUS=/path/to/verus python3 experiments/verus/check_admission.py
```

## Boundaries and remaining work

The adapter must submit each reservation at most once, use its exact byte slice,
and report write counts and durable acknowledgments honestly. The core cannot
observe socket or disk effects. Multiple calls to the borrowed-view method are
possible; that method is not a linear network-send capability. No new `assume` or
external-body escape was added to the experiment; the standard Verus slice/Vec
specifications and compiler remain trusted.

IDs are unique within one registry's allocation history. Keys are scoped to that
registry; two independently constructed registries can issue the same ID. The
adapter must use one shared registry and one stream instance per issued owner.
The current public constructors still allow bypassing that discipline. The next
ownership wrapper must enforce the relationship, rather than treating this as a
proved whole-gateway isolation property. Request IDs, chunk numbers, and write
generations reject exhaustion rather than wrapping.

The registry bounds logical active slots and offers a fixed allowance per slot.
With one retained chunk per slot, their nominal aggregate payload allowance is
request limit times per-request limit. This is not an allocator-memory theorem:
Vec capacity, incoming replacement buffers, HTTP/TLS buffers, log queues, and
metadata are not accounted for. In particular, constructing a replacement Vec can
temporarily retain both old and new allocations. A managed reservation/ownership
layer must charge these resources and must prevent releasing a key while its
request's buffers or work remain alive. The current demonstration disposes of the
request before release, but the registry does not own or enforce that disposal.

Still required for milestone 1: enforce registry-to-stream ownership, account for
all queued and in-flight allocations, prove composed resource release on error,
and implement the distinct security admission/token boundary. Then extract a
production library and connect its contract to the streaming adapter in milestone 2.
