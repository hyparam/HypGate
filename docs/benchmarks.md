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

## Broader workloads

The fixture now takes a profile (request count, concurrency, upload and download
sizes, provider and client pacing) and reports client-observed inter-frame gaps,
completed and failed counts, and payload throughput in addition to the earlier
fields. Six new opt-in runs cover a concurrency sweep, half-minute paced streams,
1 MiB uploads, and 128 requests at 32 concurrent contending for the 16-record
audit queue, each in both logging modes.
The `Release workloads` CI job runs every opt-in workload in release mode on
Ubuntu 24.04 and prints the JSON rows. The [operational limits](operational-limits.md)
tabulate every limit these workloads approach.

All numbers below are from one local machine (Apple M3 Max, macOS 27.0.1, release
build, local temporary storage) on 2026-10-24, with other processes idle, after
the audit queue was changed to make appends wait for a slot instead of refusing. They are
observations of this fixture, not performance guarantees or a controlled
comparison between modes.

### Concurrency sweep

Four closed-loop batches at each level, 8 KiB uploads and 64 KiB responses, three
separate runs per level and mode. Sixteen is the audit queue depth; at 32, half of
the concurrent appends are waiting for a slot at any moment.

| Concurrency | Mode | Requests/s (3 runs) | First byte p95 ms (3 runs) | Completion p95 ms (3 runs) | Frame gap p99 ms (max of runs) |
| ---: | --- | --- | --- | --- | ---: |
| 1 | Strict | 24.7 / 24.7 / 24.6 | 16 / 16 / 16 | 44 / 43 / 43 | 5.3 |
| 1 | Availability | 22.0 / 23.2 / 23.9 | 20 / 16 / 16 | 51 / 46 / 42 | 5.7 |
| 2 | Strict | 25.1 / 19.5 / 25.7 | 29 / 28 / 28 | 82 / 176 / 81 | 54.6 |
| 2 | Availability | 24.7 / 25.0 / 25.4 | 30 / 29 / 29 | 83 / 82 / 82 | 10.4 |
| 4 | Strict | 25.2 / 17.3 / 26.0 | 54 / 179 / 54 | 163 / 376 / 160 | 48.5 |
| 4 | Availability | 25.3 / 25.1 / 25.3 | 55 / 57 / 57 | 162 / 162 / 163 | 20.0 |
| 8 | Strict | 24.9 / 17.4 / 25.8 | 111 / 109 / 106 | 335 / 905 / 312 | 538.9 |
| 8 | Availability | 25.1 / 18.0 / 26.4 | 110 / 111 / 107 | 324 / 783 / 304 | 504.4 |
| 16 | Strict | 25.9 / 24.8 / 25.8 | 207 / 217 / 204 | 629 / 648 / 644 | 82.0 |
| 16 | Availability | 26.5 / 25.2 / 26.5 | 200 / 222 / 206 | 610 / 656 / 611 | 77.1 |
| 32 | Strict | 24.9 / 25.5 / 22.8 | 483 / 413 / 1,038 | 1,364 / 1,287 / 1,838 | 177.7 |
| 32 | Availability | 26.0 / 25.1 / 22.7 | 416 / 460 / 414 | 1,297 / 1,322 / 1,891 | 859.3 |

Throughput stays near 25 requests per second at every level while completion
latency grows linearly with concurrency, and the client-observed gap between
16 KiB frames grows from about 4 ms at one request to about 68 ms at sixteen and
about 137 ms at 32. Both modes write and sync every 16 KiB record on one disk
worker, so each frame waits behind one synced write per concurrent stream: roughly
4 ms per record on this storage, about 230 synced records per second at this
payload mix. Adding concurrency therefore adds latency rather than throughput once
the disk worker is busy, and crossing the queue depth changes nothing but the place
where a frame waits. Single requests occasionally stalled for half a second to
0.8 s in one of the three runs (strict at two, four, and eight; availability at
eight and 32), which is why three runs are reported rather than one.

### Long streams, large uploads, and queue contention

| Workload | Mode | Completed / failed | Audit gaps | Elapsed s | Payload MiB/s | First byte p95 ms | Completion p50 / p95 ms | Frame gap p50 / p99 / max ms |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Healthy 64 KiB (eight concurrent) | Strict | 32 / 0 | 0 | 1.316 | 1.71 | 111 | 312 / 345 | 36.1 / 40.0 / 40 |
| Healthy 64 KiB (eight concurrent) | Availability | 32 / 0 | 0 | 1.332 | 1.69 | 121 | 312 / 345 | 35.0 / 45.5 / 59 |
| 1 MiB uploads, 16 KiB responses (eight concurrent) | Strict | 32 / 0 | 0 | 9.052 | 3.59 | 2,262 | 2,240 / 2,294 | 31.9 / 44.1 / 44 |
| 1 MiB uploads, 16 KiB responses (eight concurrent) | Availability | 32 / 0 | 0 | 9.115 | 3.57 | 2,298 | 2,254 / 2,330 | 32.0 / 36.1 / 36 |
| Paced 4 MiB responses (eight concurrent) | Strict | 32 / 0 | 0 | 58.503 | 2.19 | 117 | 13,765 / 17,383 | 34.0 / 144.2 / 765 |
| Paced 4 MiB responses (eight concurrent) | Availability | 32 / 0 | 0 | 58.738 | 2.18 | 105 | 14,314 / 16,286 | 34.0 / 141.5 / 830 |
| Eight 32 MiB streams, 16 KiB per 15 ms | Strict | 8 / 0 | 0 | 109.603 | 2.34 | 117 | 109,585 / 109,603 | 33.9 / 44.5 / 669 |
| Eight 32 MiB streams, 16 KiB per 15 ms | Availability | 8 / 0 | 0 | 108.935 | 2.35 | 134 | 108,918 / 108,935 | 33.1 / 43.1 / 706 |
| 32 concurrent requests, 128 total | Strict | 128 / 0 | 0 | 5.469 | 1.65 | 483 | 1,279 / 1,447 | 147.0 / 196.1 / 197 |
| 32 concurrent requests, 128 total | Availability | 128 / 0 | 0 | 5.198 | 1.73 | 449 | 1,225 / 1,353 | 141.0 / 159.5 / 168 |
| Log fails after batch one | Strict | 8 / 0 (24 rejected) | 0 | 0.324 | 1.74 | 111 | 304 / 322 | 34.9 / 38.0 / 38 |
| Log fails after batch one | Availability | 32 / 0 | 24 | 0.361 | 6.23 | 108 | 5 / 340 | 0.1 / 39.9 / 40 |

Every response was byte-exact and every request's audit records summed to its
exact upload and download sizes; no run had a failed exchange, and all ended with
zero active requests and workers and a clean shutdown. The long-stream logs were
270,099,333 and 270,099,853 bytes, with 24,587 and 24,595 client-observed frames.

The eight 32 MiB streams were paced to finish in about 31 s, but took about 109 s
in both modes: 16,384 records of 16 KiB passed through the single disk worker at
about 150 synced records per second, or 2.3 MiB/s of logged payload, and the
client-observed frame gap settled at 34 ms, the same gap the sweep shows for eight
concurrent streams. The 1 MiB uploads ran at about 230 synced records per second.
Sustained payload throughput is therefore bounded by the synced-record rate of the
log device times the chunk size; a larger `chunk_bytes` (up to 1 MiB) raises the
bytes per sync, and faster storage raises the rate, as the Linux runner results
below show. Both logging modes pay this
cost while the log is healthy; availability mode only differs after a failure.
The rare 700 to 800 ms maximum gaps in the paced runs are single stalls of the
local disk or scheduler, not a steady-state behavior.

At 32 concurrent requests, twice the audit queue depth, every append beyond the
16 slots waits in arrival order for the worker to free one. Both modes completed
all 128 requests with exact bytes, no failed exchange, and no audit gap; the cost
is latency, not failure. The frame gap roughly doubles from the 16-concurrent level
(about 140 ms against 68 ms), first-byte p95 reaches about 450 ms, and completion
p95 about 1.4 s, while throughput stays near 25 requests per second: the same one
synced write per concurrent stream, now partly spent waiting for a slot. A waiting
append charges nothing until its slot is reserved, and the two-second
acknowledgment deadline covers the wait, so a disk that stops freeing slots fails
the append and closes health the same way a late acknowledgment does. Before this
change the queue refused an append when full, and the same workload at commit
`c81b35f` failed 62 of 128 strict requests with 502 or an aborted body and recorded
60 audit gaps in availability mode.

### The same workloads on the Ubuntu CI runner

The `Release workloads` job at `b5fffbd`
([run 40078196998](https://github.com/platypii/LogGate/actions/runs/40078196998),
2026-10-24 UTC) ran every workload above on a GitHub-hosted Ubuntu 24.04 runner.
Thirteen passed; the strict 32-concurrent run failed in the client fixture because
the audit queue then refused appends when full, which it no longer does. The
runner's synced writes are far faster than this laptop's, so the same code
behaves differently:

| Concurrency | Mode | Requests/s (3 runs) | Completion p95 ms (3 runs) | Frame gap p99 ms (max) |
| ---: | --- | --- | --- | ---: |
| 1 | Strict | 11.9 / 11.9 / 11.9 | 84 / 85 / 85 | 41.0 |
| 2 | Strict | 23.5 / 23.5 / 23.5 | 86 / 86 / 86 | 39.5 |
| 4 | Strict | 45.4 / 45.6 / 45.4 | 89 / 88 / 89 | 38.6 |
| 8 | Strict | 86.4 / 86.2 / 86.8 | 93 / 93 / 92 | 38.1 |
| 16 | Strict | 156.1 / 158.9 / 155.8 | 103 / 101 / 103 | 35.0 |

Availability rows were within a few percent of strict at every level. There,
throughput scales linearly with concurrency and completion stays near 85 to 100 ms
regardless of level, so the single-threaded TLS and HTTP work, not the disk, sets
the per-request time. The eight 32 MiB streams finished in 32.97 s (strict) and
32.95 s (availability), matching their 15 ms pacing with a 20 ms p99 frame gap, and
the 1 MiB uploads completed in 1.14 and 1.20 s (about 1,800 synced records per
second). A hosted virtual disk may acknowledge a sync before data reaches durable
media, so this speed is not evidence of durability; the storage contract's
assumptions still apply. The laptop and runner differ in hardware, OS, and
filesystem, so these are two separate observations rather than a comparison of
the gateway's performance.

### Not measured

CPU utilization, allocator and kernel memory under these workloads, HTTP/1
keep-alive (none is used), proxy overhead through HAProxy, provider-side pacing
that resembles real token generation, hostile inputs at the header and handshake
limits, and any machine other than this laptop and the Ubuntu CI runner. No
release performance threshold has been set.

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

Stalled logging under load, long-running streams, increasing concurrency,
long-duration overload, repeated runs, isolated gateway memory, and Linux storage
are now measured in the sections above and below. Deployment-proxy overhead is
not. No load or memory theorem follows from these measurements, and no release
performance threshold has been set.

## Stalled disk under concurrent traffic

The regular-CI `stalled_log_under_load_preserves_health_deadlines_and_mode_policy`
test runs the production server and TLS transport with eight request slots, a
two-record logger queue, and a one-second acknowledgment deadline. A test sink
blocks the existing disk worker inside its first sync. The test waits until both
queue slots are occupied, then completes a batch of eight requests followed by a
second batch of eight while the disk worker remains blocked.

Health and metrics remain reachable during the stall. After the deadline, all
request slots and exchange workers return to zero. Strict mode fails the first
eight requests without sending any body bytes and rejects the next eight with
503; its readiness becomes 503. The first batch may open TLS connections and send
HTTP headers before body logging, so this is not a no-connection or no-header
claim. Availability mode completes all sixteen requests with exact response bytes
and records sixteen audit gaps; readiness remains 200. Both modes retain exactly
two queued jobs and one blocked worker. A write-call counter remains one throughout
and after releasing/joining the worker: no replacement, replay, or later queued
write occurs once health has failed.

This is deterministic fault injection into a synchronous writer, not an actual
filesystem hang, long-duration soak, memory measurement, or proof of OS scheduling
and syscall cancellation. It complements the smaller disk-worker timeout tests.

## Isolated gateway process memory

`server::tests::memory::isolated_gateway_memory_in_both_logging_modes` launches a
separate gateway runtime child. The provider, clients, and RSS sampler run in the
parent and are excluded from the measured PID. The child is the debug test binary
using a fixture CA, not the release CLI. It runs one Tokio runtime thread and the
real disk worker, with eight request slots, 16 KiB chunks, a 16-record disk queue,
and a 128-connection limit.

Each mode runs three waves of eight requests. Providers stream 1 MiB per response
in 16 KiB frames, paced by 2 ms sleeps; clients delay 3 ms between received frames.
The fixture checks exact response bytes, all 24 requests' audit byte totals and
response contents, no audit gaps or failed exchanges, zero active requests/workers,
and graceful server/logger shutdown. It reads logs after shutdown without storing
all response payloads. RSS is sampled about every 50 ms; Linux additionally reads
`VmHWM` from the child's proc status. macOS reports sampled RSS only, which can miss
brief peaks. Run it with:

```sh
cargo test -p gateway-runtime --locked --lib isolated_gateway_memory_in_both_logging_modes -- --ignored --nocapture
```

CI runs this fixture on Ubuntu 24.04 and emits JSON with baseline, sampled peak,
kernel high-water mark where available, settled RSS after each wave, and sample
count. This is a measurement, not an asserted universal memory limit. Three waves
do not establish long-duration stability or leak freedom. Settled RSS can include
allocator caches, TLS sessions, and retained dependency capacities. The workload
does not exercise maximum header sizes, handshake attacks, all configured request
limits, or kernel/filesystem memory. The [dependency audit](dependency-resources.md)
remains relevant even when the observed resident set is small.

Local macOS arm64 result on 2026-10-23 (debug test profile, 21.74 seconds for both
modes combined; 181 periodic samples per mode, plus final sampling):

| Mode | Baseline RSS bytes | Sampled peak RSS bytes | Settled RSS bytes after waves 1 / 2 / 3 |
| --- | ---: | ---: | --- |
| Strict | 6,914,048 | 12,746,752 | 12,402,688 / 12,615,680 / 12,746,752 |
| Availability | 6,914,048 | 12,763,136 | 12,435,456 / 12,632,064 / 12,763,136 |

Both runs passed all correctness and shutdown checks. RSS rose between waves;
these samples do not establish a plateau. Linux CI evidence is recorded below.

Ubuntu 24.04 CI at `aec3985` also passed both modes in the Rust test job of
[run 40043901306](https://github.com/platypii/LogGate/actions/runs/40043901306),
2026-10-24 UTC. Linux reports the child's kernel RSS high-water mark through the
end of the workload:

| Mode | Baseline RSS bytes | Kernel peak RSS bytes | Settled RSS bytes after waves 1 / 2 / 3 |
| --- | ---: | ---: | --- |
| Strict | 10,301,440 | 14,168,064 | 13,824,000 / 14,102,528 / 14,168,064 |
| Availability | 10,293,248 | 14,147,584 | 13,905,920 / 14,028,800 / 14,147,584 |

The Linux and macOS runs differ in OS, machine, and storage timing; their values
are separate workload observations, not a controlled platform performance comparison.

### Repeated isolated gateway memory workload

The separate ignored test `isolated_gateway_memory_soak_in_both_logging_modes`
uses the same fixture for 100 waves per mode: 800 requests and 800 MiB of response
payload per gateway child. It checks every response and recovered audit record,
then checks zero active requests/workers and graceful shutdown. Each mode has a
600-second timeout. A dedicated CI job runs this test, leaving the short baseline
in the regular Rust test job. Run it locally with:

```sh
cargo test -p gateway-runtime --locked --lib isolated_gateway_memory_soak -- --ignored --nocapture
```

JSON includes wave count, elapsed milliseconds, and all settled RSS samples.
The extended workload exercises repeated allocation and cleanup; it does not
establish leak freedom or a whole-process memory bound, and does not replace
hostile-input, long-duration overload, or production release measurements.

Local macOS arm64 results on 2026-10-23 (debug test profile): both modes
passed all 800 requests, recovered audit checks, and clean shutdown checks.
The complete test took 722.19 seconds. Per-mode elapsed time includes setup and
final audit validation; RSS sampling ends before gateway shutdown.

| Mode | Elapsed seconds | Baseline RSS bytes | Sampled peak RSS bytes | Final 20 settled samples, bytes | Periodic samples |
| --- | ---: | ---: | ---: | ---: | ---: |
| Strict | 359.508 | 6,914,048 | 13,434,880 | All 13,434,880 | 6,008 |
| Availability | 362.660 | 6,897,664 | 13,025,280 | All 13,025,280 | 6,046 |

These observed plateaus are specific to this workload and sampling interval.
The dedicated Ubuntu 24.04 soak job at `4816c00` passed both modes in
[run 40048074140](https://github.com/platypii/LogGate/actions/runs/40048074140)
on 2026-10-24 UTC, before the subsequent worker-registry change:

| Mode | Elapsed seconds | Baseline RSS bytes | Kernel peak RSS bytes | Final 20 settled RSS range, bytes |
| --- | ---: | ---: | ---: | ---: |
| Strict | 109.103 | 10,289,152 | 14,696,448 | 14,540,800–14,684,160 |
| Availability | 99.533 | 10,371,072 | 14,426,112 | 14,336,000–14,401,536 |

Linux settled samples varied; this is not the flat sequence seen in the macOS
run. Both are bounded-duration observations, not a proven memory ceiling.

After introducing the bounded HTTP plaintext-read adapter on 2026-10-23, the
short three-wave macOS fixture passed again in both modes (24 requests and
24 MiB of response payload per mode). Strict mode took 11.160 seconds with
12,910,592 bytes sampled peak RSS; availability mode took 11.704 seconds with
12,877,824 bytes sampled peak RSS. Exact responses, audit coverage, released
credits, and shutdown passed. This is a short regression check, not a rerun of
the 100-wave soak or evidence of a universal allocation bound.

The fixed audit-FIFO implementation subsequently passed all six release-mode
healthy/slow-peer/failed-log workloads (124.23 seconds total), including exact
payload/audit checks and the expected mode-specific failure behavior. Its short
isolated memory fixture also passed: strict sampled peak RSS was 13,008,896 bytes
and availability sampled peak was 12,926,976 bytes across three waves per mode.
The strict memory run overlapped the load workload, so these timings are not a
controlled performance comparison. The queue's fixed slot-count claim comes from
its source and checked contracts, not these RSS samples.

After the fixed HTTP mailbox, queued Hyper output, configured destination cap,
and parser-owner audit, the Ubuntu 24.04 100-wave soak at `b72c839` passed in
[run 40061075707](https://github.com/platypii/LogGate/actions/runs/40061075707)
on 2026-10-24 UTC. Each mode completed 800 requests, exact response/audit checks,
and clean shutdown. The gateway alone was sampled; these are debug-profile
measurements, not a controlled performance comparison with previous runs.

| Mode | Elapsed seconds | Baseline RSS bytes | Kernel peak RSS bytes | Final 20 settled RSS range, bytes | Periodic samples |
| --- | ---: | ---: | ---: | ---: | ---: |
| Strict | 93.927 | 11,493,376 | 15,400,960 | 15,396,864–15,400,960 | 1,449 |
| Availability | 90.055 | 11,366,400 | 15,388,672 | 15,196,160–15,319,040 | 1,372 |

Both remained within this workload's observed range through the final waves.
This does not establish leak freedom, adversarial-input bounds, or allocator/OS
memory limits; the dependency and lifetime accounting obligations still apply.

After the TLS drain-before-write safeguard, both healthy release TLS/disk
workloads passed locally at `75190d0` on 2026-10-23. Each forwarded 32 requests
at concurrency eight, with 8 KiB uploads and 64 KiB responses, zero rejections,
and zero audit gaps. Strict mode completed in 1.302 seconds (24.58 requests/s,
110.72 ms first-byte p95); availability mode completed in 1.314 seconds
(24.35 requests/s, 115.79 ms first-byte p95). Exact payload/audit checks passed.
This validates healthy operation after the scheduling change; it is not a
controlled before/after performance comparison or a latency guarantee.


## Shutdown while the disk worker remains blocked

The regular workspace test
`shutdown_with_blocked_disk_returns_error_without_replacement_or_replay` repeats
the concurrent stalled-log workload in both modes, then signals server shutdown
before releasing the disk gate. Server shutdown must return the logger's timeout
within the test's four-second observation window; the listener must be closed,
request occupancy and worker tracking must be zero, and the same two queued jobs
and one write call must remain. Only then does the fixture release and join the
logger, checking that no queued write or replay occurs. Both modes passed locally
after introducing the bounded TLS handshake pool. The gate models a syscall that
remains blocked through shutdown; it does not prove kernel cancellation behavior.


After moving TLS handshakes onto the bounded dedicated pool, the short isolated
memory fixture passed locally in both modes (macOS arm64, debug profile, three
waves and 24 one-MiB responses per mode). Strict mode completed in 10.911 seconds,
with baseline RSS 7,700,480 bytes and sampled peak 14,434,304 bytes. Availability
mode completed in 11.075 seconds, with baseline 7,667,712 bytes and sampled peak
14,483,456 bytes. Exact response/audit contents, released credits, and graceful
shutdown passed. This run overlapped the sustained overload fixture in another
process, so timing is not a controlled comparison. The initial sandboxed attempt
could not execute the RSS sampler; these measurements came from the successful
unsandboxed rerun. Thread stack reservations are virtual capacity requests, not
an assertion that all stack pages are resident.


## Sustained admission overload and final fault workloads

After TLS scheduling isolation, the ten-minute overload fixture passed locally:
each mode kept eight TLS responses open for five minutes, repeatedly rejected
32-request bursts before provider dispatch, and checked health, readiness, and
metrics during each burst. The fixture then completed all held streams, admitted
a fresh request, checked exact recovered audit bytes, and shut down cleanly.

| Mode | Duration (s) | Excess requests rejected | Maximum observed health request (ms) | Maximum rejected-wave completion (ms) |
| --- | ---: | ---: | ---: | ---: |
| Strict | 300.006 | 362,720 | 22.566 | 25.264 |
| Availability | 300.008 | 356,736 | 27.667 | 32.734 |

The fixture pauses 20 ms between waves. These maxima include local scheduling and
other concurrently running checks, not just gateway processing. There is no
latency SLA assertion. This is sustained admission overload, not saturation of
the distinct inbound-connection cap or an indefinitely running experiment. A
separate CI job reproduces five minutes per mode. The final shutdown changes passed a second full-duration run and the separate
shutdown tests.

The six release-mode workloads also passed after admission closure and shared
worker cancellation were added (114.15 seconds combined). Healthy strict and
availability completion p95 were 355.20 and 350.51 ms. Paced 4 MiB response p95
were 13,984.23 and 14,496.39 ms respectively, with 32 exact responses and no audit
gaps per mode. Permanent logging failure forwarded eight/rejected 24 in strict
mode; availability forwarded all 32 with exactly 24 audit gaps. The process-proxy
failover fixture passed with local HAProxy 3.2.0, verifying truncated interrupted
streams, no automatic replay, and a fresh request handled by standby.


The final repeated overload run after shared worker shutdown changes passed in
600.53 seconds, including all exact-byte, audit, capacity-reuse, and shutdown
checks. It overlapped the isolated memory soak and some proof/mutation checks;
these are local workload observations, not controlled performance comparisons.

| Mode | Duration (s) | Excess requests rejected | Maximum observed health request (ms) | Maximum rejected-wave completion (ms) |
| --- | ---: | ---: | ---: | ---: |
| Strict | 300.020 | 355,584 | 21.303 | 23.663 |
| Availability | 300.024 | 353,696 | 37.210 | 53.027 |

Together the two runs rejected 1,428,736 excess requests, while preserving all
held streams and allowing a fresh admitted request after each overload phase.


The final 100-wave isolated memory soak also passed after shared worker shutdown
and the separate handshake-tail budget were in place. Each gateway child served
800 requests and 800 MiB of response payload; exact responses, recovered audit
contents, zero live request/worker credits, and graceful shutdown all passed.
Both modes together took 785.23 seconds on local macOS arm64, debug profile.

| Mode | Elapsed (s) | Baseline RSS bytes | Sampled peak RSS bytes | Final 20 settled RSS range, bytes | Samples |
| --- | ---: | ---: | ---: | ---: | ---: |
| Strict | 393.180 | 7,782,400 | 15,220,736 | 14,958,592–15,220,736 | 6,604 |
| Availability | 392.024 | 7,766,016 | 14,811,136 | 14,811,136–14,811,136 | 6,664 |

The soak overlapped overload and proof/mutation workloads in other processes.
Samples measure only the gateway child; macOS does not supply the Linux kernel
high-water metric. The final availability samples plateaued, while strict samples
still varied. These finite observations establish neither leak freedom nor a
universal RSS bound. They provide the repeated load measurement required for
milestone 4 alongside the separate sustained-overload latency results.
