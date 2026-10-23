# Runtime trust-boundary audit

This records the implemented path and its evidence for milestone 2: a minimal
working gateway. It is a code-path audit, not a formal proof of the async runtime
or an independent security review. Milestones 1, 3, 4, and 5 retain their outstanding
composition, recovery, hardening, and release obligations.

## Effect paths

The production source has one upstream TCP-connect site and one HTTP send-request
site, both in `transport.rs`. `HttpsTransport::exchange` consumes PreparedRequest;
that owns RoutedRequest, which owns the core AuthorizedRequest and resource lease.
Only the config/admission path can construct these outside trusted runtime modules.
The endpoint/credential mappings borrow the same immutable configuration as the
authorization policy. Runtime module internals remain trusted; this is not a
sandbox preventing arbitrary embedding code from opening its own sockets.

There is one record-writing worker per DiskLog. Startup writes/syncs the session
header and parent directory in `disk_log.rs`. The worker reserves a journal ticket,
writes that frame and syncs, then uses verified `record_durable_frame` to compose the
write, sync, and acknowledgment transitions for those exact frame bytes. A per-job oneshot binds the result to that append. The transfer
driver uses verified `audit_record` to bind authority, current chunk, and bytes,
never caller headers.

The async server spawns bounded connection tasks and tracked request workers.
A separate semaphore limits all request-worker lifetimes to the configured request
count, including authentication rejection and post-EOF cleanup. It is acquired
before response-channel allocation or spawning; saturation returns 503. A private
lease removes tracking before returning worker credit, including cancellation
before the first task poll. Health/readiness/metrics do not consume worker credit.
Each response body owns an abort guard for its worker; the header-wait path also
holds that guard. Successful body EOF acknowledges the drained application queue
and allows accounting to finish. Connection failure/body drop cancels the worker.
The upstream connection future runs inline with its exchange; the logger is the
only background filesystem worker and is not replaced after a timeout.

## Obligations and evidence

| Trusted obligation | Implementation and exercised evidence |
| --- | --- |
| Raw caller tokens bind to the verified identity | SHA-256 in configuration admission; strict single-bearer parsing in HTTP boundary. Unknown, missing, malformed, and duplicate authentication tests reject requests. |
| Concrete routing matches authorized handles | Immutable configured HTTPS endpoint, trusted Host construction, no caller path/query joining. Negative configuration/header tests and actual TLS credential/destination tests. |
| TLS validates the intended host | rustls with public webpki roots in the executable. Local fixtures trust an explicit test root; an untrusted certificate fails before HTTP credential transmission. DNS/PKI and dependencies remain trusted. |
| Security failure cannot dispatch | Admission precedes connection construction. End-to-end tests observe no provider connection for denied identity/route, and for already-failed strict logging. Both logging modes retain authorization checks. |
| No fallback, redirect following, or request replay | Direct one-exchange Hyper connection with no higher-level redirect/proxy/retry client. A 307 fixture returns without another connection. DNS may try connection addresses before sending a request; generations are not retried. |
| Exact body bytes and truthful completion events | Transfer writes the ticket's borrowed slice once and reports its accepted count. HTTP queues acknowledge accepted bytes, not peer receipt. Partial-write, fragmented-SSE, strict real-file, and full TLS gateway tests. |
| Tenant/request effects remain distinct | Two tenants share a selector and upstream while using distinct credentials. A barrier forces overlapping requests; tests check provider headers, responses, distinct audit request IDs, sequential chunk IDs, and both body directions grouped by tenant. |
| Log acknowledgments correspond to synced frames | Request-scoped `audit_current` binds tenant/request/chunk/bytes to an awaited append before acknowledgment; cancellation closes the stream. Single worker/immutable job/oneshot association and verified journal transitions. Partial-write, sync/disk-full failure, timeout, real-file payload, and process-kill tests. Real storage durability and scanner refinement remain assumptions/open work. |
| Cancellation and failure do not synthesize success | Explicit body end markers, writer-drop errors, post-header transport failure aborts HTTP framing. Provider-truncation tests reject successful EOF; real client disconnects before headers and during a response cancel stalled requests and release their slots without new provider output. The pre-header case also observes upstream TLS socket closure. |
| Request ownership reaches response completion | Lease remains through the sink finish hook and application-queue drain. Admission-contention, worker-drop, client-disconnect, active-response drain, forced stalled-response shutdown, and concurrent-request tests. This is tested ownership, not a complete memory/resource theorem. |

## Incomplete-connection evidence

A real-socket test opens eight incomplete HTTP requests against a two-connection
limit and a short total connection deadline. Excess connections are closed and
accepted stalled connections expire. It checks that no request workers remain,
no upstream connection was made, a subsequent health request succeeds, and an
authorized request slot remains available. This exercises unauthenticated resource
cleanup; it is not a formal connection-count or memory theorem, and does not
simulate a distributed denial-of-service workload.

## Shutdown evidence

Two real HTTP/TLS tests trigger shutdown while a provider response is active.
Both first observe the listening socket close while the gateway task remains alive.
One releases the provider and checks the exact complete response and clean EOF
during the drain. The other keeps the provider blocked beyond the ten-second drain,
with transport and connection deadlines exceeding sixty seconds, so those deadlines
cannot explain termination. It checks bounded server return, a client body error
rather than clean EOF, an empty worker tracker, and restored admission capacity.

These exercise the production drain duration without changing runtime behavior.
They do not prove scheduler fairness, bound an uninterruptible filesystem syscall,
or establish a formal shutdown/resource theorem. The disk logger now closes shared admission, drains, and joins with a separate
two-second server shutdown deadline; a stuck syscall can outlive that deadline.

## Remaining limits

The network/disk adapters, JSON/URI/HTTP parsing, TLS, cryptography, DNS, scheduler,
compiler, standard library, and OS remain in the trusted computing base. Inbound
TLS termination is external; the command binds loopback only. Bodies may contain
secrets and are logged verbatim; header filtering does not establish content secrecy.
Audit files are operator-owned shared logs, not a tenant-facing log retrieval API.

The tests are representative safety/failure checks, not exhaustive interleaving or
load verification. Full process-memory accounting, stuck-I/O/shutdown proofs, power-loss validation,
formal scanner refinement, broader benchmarks/deployment validation, and independent
review remain open. The [resource inventory](resource-accounting.md) records the
source-level budgets and excluded allocations; local benchmarks and proxy/process
failover experiments are recorded separately. Live-provider compatibility
and full duplex/early-response behavior are not certified by the local fixtures.

Current validation totals are maintained in the README. GitHub CI reruns the
workspace tests, production proofs, and deliberate proof mutations.
