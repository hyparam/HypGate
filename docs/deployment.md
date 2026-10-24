# Proxy deployment and failover contract

The [HAProxy example](../deploy/haproxy.cfg) terminates TLS on port 8443 and routes
to a primary gateway on loopback port 8081 and a standby on 8082. Both gateways
need the same intended authorization policy but separate new audit files. Start
them using [the runtime instructions](running.md), with different listen ports.
Provision an operator-managed certificate/private-key PEM, set `SOUNDGATE_TLS_PEM`
to its path, validate with `haproxy -c -f deploy/haproxy.cfg`, then start HAProxy
through the host's service manager. Use a supported, patched HAProxy package.
The example is a deployment starting point, not a hardened or verified proxy.

The public frontend allows only POST route paths; readiness, health, and metrics
remain reachable locally for operators. The backend checks `/readyz` once per
second and requires two failures or successes to change health. Strict logging
failure removes that instance after health-check detection; availability mode
intentionally remains ready despite audit loss. Health checks are approximate
observations, not atomic admission reservations. Saturated instances can still
return 503. The standby activates when the primary is marked unavailable.

`retries 0` and disabled redispatch prevent the proxy from transparently retrying
a failed generation on another instance. No response-status retry policy is
configured. Client SDKs and any outer proxy must also disable automatic generation
retries. A disconnect or timeout leaves execution uncertain: the provider may have
accepted the request even when the client saw no bytes. Do not promise exactly-once
provider execution, and never replay from the audit log. A user may explicitly
initiate a new request after acknowledging that uncertainty.

The proxy streams without requesting whole-body buffering. It has 256 front-end
connection slots, 128 per backend, a one-second queue timeout, two-second connect
timeout, and 320-second client/server inactivity timeouts. Gateway total deadlines
remain authoritative; proxy inactivity timeouts do not establish a total generation
budget. Tune these together and measure memory/latency under representative load.
Connection limits do not by themselves prove an overall memory bound.

## Shutdown and restart

Remove an instance from routing before planned shutdown when your service manager
supports it, then send SIGTERM. The gateway stops accepting, drains connections
for up to ten seconds, cancels remaining request workers, and gives the logger a
separate two seconds to drain and join. Allow additional scheduling margin in the
service-manager stop timeout. A blocked filesystem syscall can outlive the logger
deadline; process termination may leave a partial tail. Preserve the old log and
use the read-only scan command. Every restart needs a new log path; never append
to an old session or truncate it to make startup succeed.

Starting the standby does not resume in-flight work from the primary. New client
requests can use it after health detection. Two processes on one machine tolerate
some process failures, not host, disk, proxy, network, or regional loss. Host-level
redundancy needs another TLS-protected deployment boundary; the executable must
remain loopback-bound. Shared upstream or storage failures can affect both instances.

## Clean-environment reproduction

`scripts/check_deployment.sh` performs the documented operator path from a fresh
checkout with nothing but bash, the pinned Rust toolchain, curl, and openssl. It
builds the release executable with locked dependencies, generates a 32-byte gateway
token and its SHA-256 digest, writes the [documented root policy and candidate
routes](running.md#configuration-example) with only the digest and the upstream
destination substituted, and creates a mode-700 log directory. The destination is a
closed loopback port, so the check makes no provider or external network connection
and needs no real credential; `PROVIDER_KEY` holds a placeholder.

It then checks that startup refuses a non-loopback listen address, a missing provider
credential, and an existing log path without touching that file; that the new audit
log is created with mode 600; that `/healthz`, `/readyz`, and `/metrics` report a
healthy strict-mode instance with 32 request slots; that requests without
credentials, with a wrong token, with a token but no grant, with the wrong method,
or outside `/routes/<n>` receive 401, 401, 401, 405, and 400 and that an authorized
request whose upstream refuses the connection receives 502, is counted once as a
failed exchange, releases its slot, and leaves no audit gap. When HAProxy is on
`PATH` or named by `SOUNDGATE_HAPROXY`, it also starts a standby instance, generates
fixture TLS material, validates and runs the [example configuration](../deploy/haproxy.cfg)
with only ports and the certificate path substituted, checks that the public frontend
exposes only `POST /routes/<n>`, shuts the primary down with SIGTERM, and verifies
that a new request reaches the standby without any replayed exchange. Finally every
gateway must exit with status zero after SIGTERM, and `soundgate scan` must report a
complete, record-free log without changing its bytes.

`deploy/Dockerfile` reproduces the same path inside a container built from the
official Rust 1.99.1 image pinned by digest. The build installs the checksum-pinned
Verus release, builds the executable, runs the workspace tests, and verifies the
production core; running the image executes the deployment check with the
distribution HAProxy. Verus is skipped on architectures without a pinned Linux
binary, so run the image under `linux/amd64` to reproduce the proofs. Mutation
checks remain in CI, which runs the script directly on Ubuntu 24.04 and then builds
and runs the container on every push.

```sh
bash scripts/check_deployment.sh
docker build --file deploy/Dockerfile --tag soundgate-deploy .
docker run --rm soundgate-deploy
```

The check demonstrates provisioning, fail-closed startup, authorization, honest
upstream failure, proxy policy, standby routing, graceful shutdown, and read-only
scanning on a clean machine. It does not exercise a live provider, real certificates,
a service manager, log retention, or host-level redundancy; those remain operator
obligations described above and in [running the gateway](running.md).

## Reproduction and limits

Run `python3 scripts/check_proxy.py --haproxy /path/to/haproxy` with Python 3 and
OpenSSL installed. It creates temporary TLS material and local HTTP fixtures,
validates the exact example with only ports and certificate path substituted,
and checks that neither a truncated response nor a disconnect before headers is
replayed. It then marks the primary
unready and verifies that a new request reaches the standby. It also checks that
metrics are not exposed publicly. No provider credentials or external API calls
are used. Local validation used HAProxy 3.2.0 as a test tool, not a recommended
production patch version. CI exercises the Ubuntu package and reports its version.

The separate `proxy_gateway_process_failover_without_replay` runtime test launches
this configuration with fixture TLS and two real gateway runtime child processes.
It kills the primary mid-response, requires a truncated-body error, observes no
provider connection during the health-detection window, and checks a distinct new
request completes through the standby. Both gateways' strict audit logs are checked
for exact payloads and distinct sessions. Only ports and the certificate path are
substituted; retry and health-check policy are unchanged.

Run it with an installed HAProxy (CI uses the distribution package):

```sh
SOUNDGATE_HAPROXY=/path/to/haproxy cargo test -p gateway-runtime --locked proxy_gateway_process_failover -- --ignored --nocapture
```

The child processes run the gateway runtime in a test binary so a fixture CA can
be supplied; this does not test CLI provisioning or real provider connectivity.
Host/storage/proxy failure, broader load, deployment hardening, and independent
review remain release obligations. HAProxy, TLS termination, and the OS remain
trusted. A finite no-replay observation is test evidence, not a universal theorem.
