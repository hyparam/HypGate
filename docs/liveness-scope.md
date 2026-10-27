# Mechanized liveness: scope

What it would take to close the "mechanized liveness remains open" item in the
README. This is a scoping note, not a proof.

## Where termination is already checked

Verus requires a `decreases` measure on every exec loop unless the function
opts out with `#[verifier::exec_allows_no_decreases_clause]`. The core crate
had about 260 measures and exactly eight opt-outs, all in the driver modules,
when this note was written; the table marks the ones since closed.
Everything else in the core (codec, JSON, config, exchange machines, queues)
already terminates by proof. The runtime crate is trusted Rust and is not
checked either way.

## The eight unmeasured loops

| Loop | What bounds it | Class |
|------|----------------|-------|
| `body_reader::read_request_head` | `fill_head` strictly grows the buffer and never past `MAX_BYTES`; the parser returns `Incomplete` only below `MAX_BYTES` | A: done, measure `MAX_BYTES - buffer.len()` |
| `body_reader::read_status_head` | Same | A: done |
| `body_reader::BodyReader::read` | Buffered half: each `Framing` step consumes one byte, so `buffer.len() - pos` decreases. Refill half: needs a bound on framing bytes the chunked decoder consumes between data steps (chunk-size line and trailers are already size-capped, but the decoder does not expose a budget) | B: needs a decoder ghost budget, no new trust |
| `shipping_driver::flush` | Each `Some` from `Machine::flush` evicts one open exchange, and numbering, enqueueing, and settling leave the open count alone | A: done, measure `open_count` |
| `shipping_driver::pump` | `wants_records` is false once the queue is full or the log ends or fails. A log of unbounded no-op records (bad headers go to `log_failed` and stop it, but admitted records that open nothing do not) is not bounded by the machine | C: needs a finite-log fuel on `Effects::read` |
| `exchange_driver::final_head` | Loops on 1xx interim heads with no cap | C: either cap interim heads (behavior change, recommended) or assume the upstream eventually sends a final head |
| `serve_driver::accept_loop` | Exits only on trigger or accept failure. A service loop; termination is the wrong theorem | D: reactive loop |
| `shipping_driver::drive` | Exits on stop, revoke, or drained. Same | D |

Class A: a measure exists in the current contracts. Class B: a measure exists
but a verified component must expose it. Class C: termination is false without
an assumption about the environment; the assumption can be a small spec change
(a cap) or a ghost fuel on an effect. Class D: the loop is meant to run until
told to stop.

## What the liveness theorem would say

Three layers, each conditional on the one below.

1. Body termination. Every class A, B, and C loop terminates. For C this is
   under a stated fuel: the log is finite, the upstream sends at most N interim
   heads. After this, every call into the core from the runtime returns.
2. Per-exchange liveness. `exchange_driver::drive` returns and the exchange
   reaches a terminal lifecycle state with its credit released, given that
   every `Effects` call returns. The exchange machine already proves this
   shape for the trace; what is missing is only layer 1.
3. Service liveness. For the two class D loops: each iteration terminates,
   each iteration appends at least one step to the trace, and the loop exits
   within one iteration after the trigger is observed. That is the honest
   statement; "the server eventually stops" additionally needs the trusted
   scheduler and the deadline-bounded socket calls to deliver the trigger.

## The assumptions that stay trusted

- Every socket, TLS, and disk call returns within its deadline or errors. The
  verified deadline driver already makes this honest for mediated calls; the
  accept call, DNS, and the handshake remain to be checked against it.
- The OS scheduler eventually runs each thread.
- Interim-head cap and finite-log fuel, if taken as assumptions rather than
  enforced.

These cannot be proved inside Verus. They belong in the trust list next to
effect truthfulness.

## Suggested order

1. Class A (three loops, half a day): remove the opt-outs with measures.
2. `final_head` cap: add `MAX_INTERIM_HEADS`, refuse beyond it, then measure.
3. Class B: add a framing budget to `BodyDecoder`, measure `read`.
4. `pump` fuel: a ghost remaining-records count on the shipping `Effects`.
5. Class D: state and prove the per-iteration progress theorem; update
   `docs/shutdown-proof.md` so the conditional termination argument cites it.
6. README: replace "mechanized liveness remains open" with the conditional
   statement and the remaining trusted assumptions.
