# Benchmarking the gateway

Measure on the storage, hardware, and configuration you plan to deploy. The
[benchmark fixture](../crates/gateway-runtime/src/server/tests/benchmark.rs)
uses the production gateway, a local TLS provider, and real disk logging. It
checks response and audit bytes, released capacity, and clean shutdown while
reporting throughput, first-byte and completion latency, and inter-frame gaps.

## Reproduction

Use the pinned Rust toolchain and locked dependencies:

```sh
cargo test -p gateway-runtime --release --locked server::tests::benchmark -- --ignored --nocapture --test-threads=1
```

To run only the healthy strict-mode baseline, replace the test filter with
`server::tests::benchmark::strict_tls_disk`. Run workloads one at a time and
record the commit, OS, hardware, filesystem, logging mode, and configuration
alongside the emitted JSON. Repeat runs to expose variability.

## Broader workloads

The fixture covers both logging modes with healthy traffic, paced peers,
concurrency sweeps, large uploads, long streams, audit-queue contention, and
permanent logging failure. The baseline uses 32 requests in batches of eight,
8 KiB uploads, 64 KiB responses, and 16 KiB core chunks. Each request opens a new
upstream TLS connection; the local provider is not a model of LLM generation.

With the default durable policy, both logging modes wait for durable logging while the log is healthy. Availability mode
changes behavior after a logging failure; compare failure behavior separately
from healthy throughput. See [operational limits](operational-limits.md) for
capacity limits and their failure behavior.

## Group commit

In durable mode, the disk worker writes up to 16 already-queued records in FIFO order and syncs
once before delivering receipts. There is no timer delay to fill a batch.
Rotation can add predecessor-sealing syncs. A lone record still needs its own
sync; concurrent records can share one. Measure queue contention and latency on
your own storage before choosing request capacity and chunk size.

## Isolated gateway process memory

The TLS benchmark process includes provider and client fixtures, so its RSS is
not gateway-only memory. Use the separate child-process fixture:

```sh
cargo test -p gateway-runtime --locked --lib isolated_gateway_memory_in_both_logging_modes -- --ignored --nocapture --test-threads=1
cargo test -p gateway-runtime --locked --lib isolated_gateway_memory_soak_in_both_logging_modes -- --ignored --nocapture --test-threads=1
```

The short workload runs three waves per mode; the soak runs 100. Both check exact
payloads and recovered audit contents, released capacity, and shutdown. RSS
samples exclude the parent provider/client fixtures. Sampling can miss peaks;
finite runs establish neither leak freedom nor a universal memory bound. See
[resource composition](resource-composition.md) for the separate logical budget
and its assumptions.

## Overload and failure checks

```sh
cargo test -p gateway-runtime --locked --lib sustained_overload -- --ignored --nocapture --test-threads=1
```

The overload fixture holds requests open while rejecting excess work, checks
health and readiness, then verifies capacity reuse. `HYPGATE_OVERLOAD_SECONDS`
controls the duration per mode; the default is five minutes.

Regular workspace tests also cover stalled logging, truncated responses,
deadlines, and shutdown with blocked disk work. See
[contributing](../CONTRIBUTING.md) for checks and [deployment](deployment.md) for
proxy failover.

## Interpreting measurements

Latency includes inbound connection setup, upload, upstream TLS, and logging.
Storage sync latency, scheduling, TLS work, and fixture pacing all affect the
result. Small closed-loop samples do not establish an open-loop saturation rate
or stable tail latency. A successful sync benchmark does not prove physical
storage durability; the [storage contract](storage-crash-contract.md) still
applies. No release performance threshold is specified.

## Optional buffered durability comparison

Run `cargo test -p gateway-runtime --release --locked durability_comparison -- --ignored --nocapture --test-threads=1`.
This alternates durable and buffered root configuration at concurrency 1, 8,
and 32 for three repetitions. Both use strict logging, real writes, exact
response/audit checks, 8 KiB uploads, and 64 KiB downloads. Each sample uses four
closed-loop batches; these short local TLS runs are not production capacity estimates.

On the development arm64 machine running macOS 27.0.1, the implementation run produced these medians
of three samples (p95 columns are medians of each run's p95):

| Concurrency | Durability | Requests/second | First-byte p95, ms | Completion p95, ms |
| --- | --- | ---: | ---: | ---: |
| 1 | Durable | 25.53 | 19.83 | 33.73 |
| 1 | Buffered | 609.15 | 1.38 | 1.82 |
| 8 | Durable | 105.82 | 37.26 | 64.65 |
| 8 | Buffered | 1240.61 | 5.37 | 6.83 |
| 32 | Durable | 361.88 | 46.52 | 74.16 |
| 32 | Buffered | 1548.50 | 17.42 | 20.43 |

At concurrency 32, buffered throughput was 4.3 times durable throughput, with
first-byte p95 down from 46.5 to 17.4 ms. Buffered acknowledgments do not promise
crash survival; see [durability policy](disk-logging.md#audit-durability-policy).
The benchmark validates clean-operation recovery, not power-loss durability.
