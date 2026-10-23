# Local TLS and disk baseline

The opt-in [benchmark fixture](../crates/gateway-runtime/src/server/tests/benchmark.rs)
runs the production gateway, HTTPS transport, stream core, and disk logger. It
uses 32 requests in four closed-loop batches of eight concurrent clients, each
uploading 8 KiB and downloading 64 KiB. Core chunks are 16 KiB, the log queue has
16 slots, and every record uses the normal write-and-sync acknowledgment path.
Each request opens a new upstream TLS connection; there is no pooling. The local
provider returns its body immediately, so this is not an LLM token-generation model.

The fixture checks exact client response bytes, zero failed exchanges/audit gaps,
released workers, and recovery totals for each request in both directions. It
reports JSON with request throughput, first-response-byte and completion p50/p95,
and log size. Timing begins before inbound connection setup and includes upload,
upstream TLS, logging, and response processing. Throughput includes the brief
between-batch worker cleanup, but excludes final server shutdown and log scanning.
Percentiles use nearest rank over 32 samples; this is a small baseline, not a
statistically stable tail-latency estimate or an overload test.

## Reproduction

Run with the pinned Rust toolchain and locked dependencies:

```sh
cargo test -p gateway-runtime --release --locked server::tests::benchmark -- --ignored --nocapture --test-threads=1
```

For process memory accounting, first build the library test executable with
`cargo test -p gateway-runtime --release --locked --lib --no-run`. Cargo prints its
path. Run that executable directly under `/usr/bin/time -l` on macOS or
`/usr/bin/time -v` on Linux, using these arguments for one mode at a time:

```text
--exact server::tests::benchmark::strict_tls_disk --ignored --nocapture --test-threads=1
--exact server::tests::benchmark::availability_tls_disk --ignored --nocapture --test-threads=1
```

Do not measure the Cargo build when reporting gateway memory. The test process
still includes the local provider, clients, TLS certificate generation, test
harness, and recovery scan; its peak RSS is not isolated gateway RSS. It excludes
filesystem cache outside the process and does not establish a resource bound.
The tests are ignored in normal CI and can be run explicitly; ordinary workspace
checks compile them so interface changes cannot silently break the harness.

## Observed baseline, 2026-10-23

Release build, Rust 1.99.1, Apple M3 Max, 128 GiB RAM, macOS 27.0.1, local temporary
storage, single-thread Tokio runtime plus the normal disk worker. Each row is one
separate measured process; these are observations, not performance guarantees.

| Logging mode | Requests/sec | First byte p50 / p95 (ms) | Complete p50 / p95 (ms) | Process peak RSS (bytes) |
| --- | ---: | ---: | ---: | ---: |
| Strict | 33.16 | 88.46 / 107.49 | 226.63 / 248.12 | 11,059,200 |
| Availability, healthy log | 32.96 | 88.01 / 105.00 | 227.86 / 247.97 | 10,911,744 |

Both runs produced 2,373,912-byte logs with all 32 requests recovered. Both modes
wait for healthy logging in the current implementation. Availability mode changes
behavior after a logging error; it is not a nonblocking logging optimization.
The small differences here do not demonstrate that either mode is faster.
Successful local sync calls retain the documented storage-contract assumptions;
this workload does not test power-loss durability.

Remaining measurements include stalled/failed logging, slow clients/providers,
long-running streams, increasing concurrency, admission overload, repeated runs,
isolated gateway memory, deployment-proxy overhead, and supported Linux storage.
These remain milestone-four/five work. No load or memory theorem follows from this
small baseline, and no release performance threshold has been set.
