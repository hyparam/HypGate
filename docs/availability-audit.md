# Milestone 4 exit audit

Milestone 4 is complete under the explicit assumptions documented here. The
implementation, conditional shutdown argument, fault tests, repeated overload,
and isolated-memory validation have passed. Progress claims retain the scheduler,
destruction, dependency, allocator, and I/O assumptions linked here.

## Exit criteria and current evidence

| Criterion | Production path and evidence | Scope |
| --- | --- | --- |
| Slow clients, slow upstreams, and stalled logging stay within configured budgets | Verified request/worker/connection registries; fixed HTTP mailbox/audit FIFO; separate DNS/TLS job credits; connection/exchange/log deadlines. Both paced 4 MiB workloads, short isolated RSS workload, repeated overload, and concurrent stalled-log tests passed. The first five-minute-per-mode overload run passed over 719,000 excess requests. | Logical capacities and requested-allocation accounting are distinct from measured RSS; see [resource composition](resource-composition.md). Both repeated overload runs and the final 100-wave-per-mode isolated memory soak passed. |
| Disconnects, permanently blocked writes, process death, concurrency, shutdown with outstanding work | Workspace disconnect/drain/abort/kill tests; permanently pending async-write cancellation; disk sync gates; stalled TLS output; concurrent stalled logging; shared-listener cancellation; shutdown while the disk worker remains gated. Six release-mode healthy/paced/failed-log workloads passed. | Fault gates remain blocked through the tested timeout/shutdown, then release for fixture cleanup. They model permanent stalls during service without claiming OS syscall cancellation. |
| Route new traffic around unhealthy instances; report interrupted streams honestly without replay | Strict failed-audit readiness returns 503; availability reports gaps. Graceful closure makes every shared listener unready. The real TLS proxy/two-gateway process-kill test passed with retries disabled and a fresh request on standby. | Interrupted streams fail framing; they are not migrated/retried. Routing around a dead process requires the external proxy/load balancer. |
| State scheduler/I/O assumptions; measure memory and latency under load | The [shutdown proof](shutdown-proof.md) composes verified permanent closure and a decreasing rank with source-level ownership. [Benchmarks](benchmarks.md) report latency, workload, RSS scope, mode, and platform. | Tokio/OS scheduling and finite polls/destructors remain assumptions. Neither ten-plus-two-second drain windows nor observed maxima are a hard real-time guarantee. |

## Completed hardening

TLS handshakes now execute on four dedicated threads with 32 queued/running
credits per transport. A canceled handshake keeps its separate credit and TLS
state until its current poll returns and cleanup runs. No timeout creates a
replacement thread. Five pool regressions cover blocked polls, cancellation,
queued-job skipping, panic recovery, state-before-credit destruction, and runtime
shutdown during blocked work. The allocation inventory separately charges all
32 handshake jobs, including cancellation tails when R is smaller than 32.

`DrainRegistry` is used by production worker admission. Verus checks exact
acquisition/release behavior, permanent closure preserving outstanding keys,
and the finite-release rank. Worker admission through tracker registration is
serialized with closure. Worker future destruction precedes credit release;
tracking removal and release share a mutex, and drain wait synchronizes with it.
This closes the late-registration race across listeners.

One ten-second drain window covers local inbound connections and all shared
workers. Remaining workers are canceled through a shared priority-selected token,
including workers belonging to another listener. The logger gets a two-second
join window; stuck work returns an error and stays separately charged. Other
listeners retain their own socket ownership, but cannot admit new workers after
closure. A graceful restart requires a fresh Gateway/logger. Aborting `serve`
continues to mean asynchronous child cleanup without explicit logger shutdown.

The [conditional proof](shutdown-proof.md) identifies exactly where scheduler,
poll/destructor, timer, mutex, and effect assumptions enter. No assumption merely
asserts that shutdown succeeds. The closure/rank part is mechanically checked;
the async correspondence is a source-level ownership argument with regressions,
not a mechanized verification of Tokio.

## Validation checkpoint

- Production core: 191 verification checks passed, including closure and rank.
- Workspace: 188 tests and five compile-fail doctests passed. Opt-in external
  fixtures are separately exercised as listed here.
- All 144 deliberate mutation cases were rejected against the production core.
  The five drain cases are additionally rerun after strengthening key-preservation
  contracts; this does not count them twice.
- TLS proxy/gateway process-failover test passed with local HAProxy 3.2.0.
- All six release TLS/disk workloads passed: healthy, paced 4 MiB peers, and
  permanent log failure in both modes; exact bytes, audit behavior, and cleanup.
- Short isolated memory workload passed in both modes after TLS isolation.
- Both ten-minute overload runs passed in both modes, rejecting 1,428,736 excess
  requests while preserving active streams, health, exact audit bytes, and reuse.
  The final isolated memory soak passed 100 waves and 800 requests per mode,
  including exact responses/audit records and clean shutdown. RSS and latency
  measurements are recorded in the benchmarks document.

These are current local checks on macOS arm64. CI includes ordinary tests,
proofs/mutations, Linux storage tests, proxy failover, isolated memory, and the
new separate sustained-overload job. Adding that job is not evidence that the
unpublished changes have already passed remote Linux CI. Prior Linux ext4/storage
and memory evidence remains linked in its respective contract and benchmark
notes; no physical-power-loss or universal memory/latency claim is made.

## Reproduction

```sh
cargo test --workspace --locked
cargo verus verify -p gateway-core --locked -- --triggers-mode silent
VERUS=/path/to/verus python3 scripts/check_mutations.py
cargo test -p gateway-runtime --locked --lib sustained_overload -- --ignored --nocapture
cargo test -p gateway-runtime --locked --lib isolated_gateway_memory_soak -- --ignored --nocapture
cargo test -p gateway-runtime --release --locked server::tests::benchmark -- --ignored --nocapture --test-threads=1
SOUNDGATE_HAPROXY=/path/to/haproxy cargo test -p gateway-runtime --locked proxy_gateway_process_failover -- --ignored --nocapture
```

The proxy command requires HAProxy and OpenSSL. macOS RSS sampling needs permission
to inspect the child PID with `ps`. The sustained test holds eight streams for
five minutes in each mode (one minute in CI through `SOUNDGATE_OVERLOAD_SECONDS`), rejects concurrent 32-request waves, probes health
while overloaded, and verifies recovery/reuse afterward. Memory sampling measures
the separate gateway child, excluding the provider/client fixture processes.
