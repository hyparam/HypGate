# Mechanized liveness: scope and status

What "mechanized liveness" means for this code base, how far the proofs now
take it, and what stays an assumption about the environment.

## Where termination is checked

Verus requires a `decreases` measure on every exec loop unless the function
opts out with `#[verifier::exec_allows_no_decreases_clause]`. When this note
was first written the core crate had about 260 measures and exactly eight
opt-outs, all in the driver modules. Six of the eight now carry a measure. The
two that remain are service loops, each reduced to a verified terminating
step inside a loop of one `match`. Everything else in the core (codec, JSON,
config, exchange machines, queues) terminates by proof. The runtime crate is
trusted Rust and is not checked either way.

## The eight loops

| Loop | What bounds it now | How it was closed |
|------|--------------------|-------------------|
| `body_reader::read_request_head` | `fill_head` strictly grows the buffer and never past `MAX_BYTES`; the parser returns `Incomplete` only below it | Measure `MAX_BYTES - buffer.len()` |
| `body_reader::read_status_head` | Same | Same |
| `body_reader::BodyReader::read` | Chunk size lines, with any extension, are capped at `MAX_SIZE_LINE` (1024) bytes, and the chunked decoder exposes a `framing_budget` that every framing step lowers | Grammar cap, then a lexicographic measure: the budget, then whether the buffer is spent |
| `shipping_driver::flush` | Each `Some` from `Machine::flush` evicts one open exchange; numbering, enqueueing, and settling leave the open count alone | Measure `open_count` |
| `shipping_driver::pump` | Reads at most `PUMP_BATCH` (1024) records a round, so a stop request is seen within a bounded batch whatever the log holds | Batch cap, measure `PUMP_BATCH - count` |
| `exchange_driver::final_head` | At most `MAX_INTERIM_HEADS` (8) interim heads; one more is `Fault::Http`, answered 502 | Cap, measure `MAX_INTERIM_HEADS - interim` |
| `serve_driver::accept_loop` | Each round is `accept_step`, verified to terminate and to record at least one trace step; a round that sees the flag set ends the loop | Service loop: opt-out kept on a one-`match` loop |
| `shipping_driver::drive` | Each round is `drive_step`, verified to terminate (its read and flush loops are measured); a round that sees `stop_requested` ends the loop | Service loop: opt-out kept on a one-`match` loop |

Three of the closures changed behavior, each a cap that bounds a peer's
ability to keep the gateway busy without progress: interim heads, chunk
extension length, and records per pump round. Each has a test at the cap and
one past it, and a mutation that loosens the cap by one is rejected by proof.

## What is proved

1. Body termination. Every call into the verified core from the runtime
   returns, provided each `Effects` or `Source` call it makes returns. There
   is no fuel and no fairness assumption inside the core.
2. Per-exchange liveness. `exchange_driver::drive` returns and the exchange
   reaches a terminal lifecycle state with its credit released, given that
   every effect returns. The exchange machine proves the shape of the trace;
   layer 1 supplies the termination of the loops around it.
3. Service liveness, per round. For the two service loops: each round
   terminates, the accept round appends at least one step to the trace, and
   the loop ends within one round of observing its stop signal. "The server
   eventually stops" additionally needs the environment to deliver the signal
   and to return from the blocking call the round is in.

## The assumptions that stay trusted

- Every socket, TLS, and disk call returns within its deadline or errors. The
  verified deadline driver makes this honest for mediated calls; the accept
  call is woken by the loopback self-connection at shutdown, and DNS and the
  TLS handshake sit behind their own timeouts.
- The OS scheduler eventually runs each runnable thread.
- The shutdown signal and the shipper's stop flag are delivered.

These cannot be proved inside Verus. The first is made auditable instead:
[blocking sites](blocking-sites.md) lists every call in the runtime that can
block a thread, what unblocks it, its bound, its test, and the one kernel
fact it rests on, and `scripts/check_blocking_sites.py` fails CI when a
blocking call appears without a row. The others are stated with the effect
assumptions in the [shutdown proof](shutdown-proof.md#conditional-termination-argument)
and the [shipping trust assumptions](cloud-shipping.md#trust-assumptions).
