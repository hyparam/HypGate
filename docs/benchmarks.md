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
log size, sampled peak admission occupancy, and forwarded/rejected counts. Timing begins before inbound connection setup and includes upload,
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
The default workspace invocation skips these ignored tests but compiles them. CI
explicitly runs the two permanent-failure cases; timing workloads remain opt-in.

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

## Extended fault and paced-peer workloads

The same fixture now has six opt-in runs: healthy, paced peers, and permanent log
failure, each in strict and availability mode. The healthy fixture now streams
provider output through 16 KiB frames; the earlier baseline table predates this
fixture change and is retained as historical evidence, not a direct comparison.

Paced-peer runs use 4 MiB responses generated in 16 KiB pieces with a 2 ms delay
before each piece. Clients delay 5 ms between reads of HTTP body frames, whose
sizes are determined by the transport. This is an imposed workload, not a gateway
throughput ceiling or proof that every buffer is saturated. Payloads are checked
incrementally without retaining whole response bodies in the client fixture.

Failure runs poison the real disk logger after the first eight requests drain.
Strict mode must reject the remaining 24 requests with 503 before provider
connection; availability mode must complete them with 24 reported audit gaps.
Only the first batch may appear in either log. This tests permanent failure,
not a permanently blocked syscall (which has separate fault-injection tests).

All runs sample active admission at 1 ms intervals, check it never exceeds eight,
require zero active requests and no workers afterward, verify exact payloads, and
scan every logged request's byte totals. Sampling can miss transient values;
the core count invariant is separately proved. Percentiles include successful
requests only; rejected requests are counted separately. Rates distinguish all
attempts from forwarded requests. No process-memory bound follows from slot counts.

Observed on the same local machine on 2026-10-23, release build, one run per row:

| Workload | Mode | Forwarded / rejected | Audit gaps | Elapsed (s) | Successful completion p95 (ms) |
| --- | --- | ---: | ---: | ---: | ---: |
| Healthy streamed fixture | Strict | 32 / 0 | 0 | 1.259 | 319.62 |
| Healthy streamed fixture | Availability | 32 / 0 | 0 | 1.433 | 371.84 |
| Paced 4 MiB responses | Strict | 32 / 0 | 0 | 59.557 | 18,076.18 |
| Paced 4 MiB responses | Availability | 32 / 0 | 0 | 54.908 | 13,939.35 |
| Log fails after batch one | Strict | 8 / 24 | 0 | 0.366 | 363.80 |
| Log fails after batch one | Availability | 32 / 0 | 24 | 0.383 | 360.63 |

All six runs sampled a peak of eight active requests and finished with zero active
requests and workers. Paced runs each recovered 135,284,888-byte logs; failure runs
recovered only the first eight complete requests. These single samples include
local scheduling and disk variability and do not establish comparative performance.
The two permanent-failure workloads also run in the normal CI test job; slow-peer
and healthy timing workloads remain opt-in.

A separate strict paced-peer process run under `/usr/bin/time -l` completed in
56.22 seconds with a peak RSS of 15,368,192 bytes, zero audit gaps, and all 32
requests recovered. This includes provider/client fixtures and the recovery scan,
excludes kernel filesystem cache, and is one observation rather than a memory bound.
The repeated workload's completion p95 was 14,571.22 ms, illustrating run variability.

## Repeated admission overload

The ordinary CI test in `server/tests/overload.rs` holds eight real TLS exchanges
open, then sends four waves of 32 concurrent excess requests in each logging mode.
All 128 must return 503 while liveness, readiness, and metrics remain reachable.
Occupied slots stay at eight and provider connections stay at eight: rejected
requests must not reach the provider. Releasing the held streams must preserve
all response bytes, return occupancy to zero, and permit a fresh successful request.
Recovery must contain exactly the nine admitted requests with exact upload and
download bytes, and final worker, failure, and audit-gap counts must be zero.

The test passes locally and runs in the regular workspace suite. It stays below
the separate inbound connection cap to isolate request admission; it is a bounded
burst experiment, not a long-duration soak, latency SLA, or whole-memory theorem.
Incomplete-connection overload is exercised separately by the server tests.

Remaining measurements include stalled logging under sustained load,
long-running streams, increasing concurrency, long-duration overload, repeated runs,
isolated gateway memory, deployment-proxy overhead, and supported Linux storage.
These remain milestone-four/five work. No load or memory theorem follows from this
small baseline, and no release performance threshold has been set.
