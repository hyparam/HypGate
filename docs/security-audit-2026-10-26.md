# Independent source security review — 2026-10-26

**Disposition: do not clear the security release gate.** One confirmed medium-severity
availability defect remains open: TLS trickle input bypasses the absolute deadline.

Reviewed commit: `cfdbdc20975af9ecfd1764c684c68e0f15860232`.
This is a fresh AI-assisted source review, separate from the implementation's
[self-audit](end-to-end-audit.md), with a new adversarial reproduction. It is not
an external security firm's certification or a new proof of the whole runtime.
The release obligations are in [Contributing](../CONTRIBUTING.md#release-checks)
and [Deployment](deployment.md#reproduction-and-limits).

## Scope and method

Reviewed the security contract and followed the production paths for root/candidate
configuration, digest authentication, tenant/route/credential binding, request and
response header filtering, HTTP framing, provider DNS/TCP/TLS, body forwarding,
durable logging, cancellation, shutdown, cloud shipping, and proxy configuration.
Checked the trusted adapters against their stated proof boundaries, rather than
treating successful verification as evidence that those adapters are correct.
Sampled the relevant executable core predicates and transitions; did not manually
re-prove every Verus theorem or audit the compiler, crypto primitives, or OS.

The checkout began with no tracked modifications and an existing untracked
`output/` directory. Other work changed source files during review. Final tests,
proof checks, lint checks, effect-site enumeration, and the reproduction therefore
used a `git archive` of the exact commit above in an isolated temporary directory.
Intermediate failures from the concurrently changing checkout are not findings
against this commit. Later or uncommitted changes are outside this review.

No live provider, cloud account, real credential, or production audit log was used.
The dependency advisory lookup sent only public crate names and versions to OSV.

## SEC-01: TLS reads can outlive the absolute exchange deadline

**Severity:** Medium. **Status:** Confirmed, open, release blocker.
**Category:** CWE-400, resource exhaustion.

**Location:** `crates/gateway-runtime/src/net.rs:64–68`, with the same layering
problem at lines 55–60. Consumers include `transport.rs::HttpsTransport::connect`
and `shipping/client.rs::Client::request`.

`Timed::handshake` sets socket timeouts once, then passes the raw `TcpStream` to
rustls `ClientConnection::complete_io`. In locked rustls 0.23.46, that operation
loops over multiple socket reads while completing the handshake. Each read uses
the same relative timeout. A peer sending partial TLS input before each timeout
can keep the call running after the absolute deadline, without returning to
`Timed::arm`. The outer `while is_handshaking` loop does not fix this because
`complete_io` is itself the blocking loop.

The generic `Timed<StreamOwned<...>>` read/write wrapper has the same architectural
weakness: it arms before a TLS operation, rather than before each underlying
socket operation. Rustls's `Stream::prepare_read` can repeatedly call `complete_io`
to obtain plaintext. The executable reproduction below specifically confirms
the handshake path; application-data trickling needs a separate regression.

**Reproduction:** Run `python3 scripts/check_security_deadline.py` from the repo.
It builds the locked dependency graph, includes production `net.rs` unchanged,
and connects a rustls client to a loopback fixture. The fixture consumes the
ClientHello, starts an incomplete TLS handshake record, and sends one byte every
25 milliseconds for forty iterations. The client has a 150-millisecond deadline.
No valid server certificate or completed TLS handshake is needed.

Observed on the reviewed commit:

```text
deadline=150ms elapsed=1139ms expired=false result=Err(Kind(UnexpectedEof))
TLS trickle bypassed the absolute deadline (including 300ms scheduling allowance)
```

The script exits nonzero because the security assertion fails. The peer closes
after the finite reproduction window; this is not a claim of a measured infinite
hang. The error is also misclassified as EOF/TLS failure rather than a deadline.

**Impact and prerequisites:** An attacker controlling the upstream network path
or selected server can prolong already-authorized exchanges and retain their
worker/request slots past the advertised limit. An on-path attacker can exercise
the handshake case before certificate authentication. Ordinary unauthenticated
gateway clients cannot select arbitrary upstreams through this issue. The cloud
shipper uses the same adapter and can stall its single upload thread. Credential
disclosure, authorization bypass, and unbounded allocation were not demonstrated.
Client disconnect, explicit cancellation, and an outer proxy timeout can still
terminate provider sockets; they do not implement the claimed gateway deadline.

This contradicts the trickle-resistance claim in
[HTTPS transport](https-transport.md) and the exchange/TLS bounds in
[operational limits](operational-limits.md).

**Required remediation:** Enforce the absolute deadline on the raw socket I/O
inside rustls, for example by placing a deadline-checking transport beneath
`StreamOwned`, including handshake I/O. Rechecking only after `complete_io`
returns cannot bound the wait. Preserve cancellation and timeout classification.
Add handshake and post-handshake record-trickle regressions, then exercise the
gateway with all request slots occupied to confirm capacity returns on time.
Cover the cloud client as well. Re-run this audit's reproduction and the required
release checks on the final fixed commit.

## Other reviewed boundaries

No additional exploitable issue was confirmed in these inspected paths:

- Authentication hashes the bounded gateway token; policy validation binds routes
  to tenant-owned credentials and root grants. Prepared requests keep the resolved
  destination and credential under one immutable configuration.
- Request forwarding uses an allowlist and injects the configured Host and one
  provider credential. Gateway Authorization is not forwarded. Destination
  parsing excludes userinfo, non-HTTPS schemes, control bytes, and ambiguous
  authority/path forms. TLS uses the configured host and public trust roots.
- Framing rejects simultaneous Content-Length and Transfer-Encoding, duplicate
  framing fields, and unsupported transfer codings. Provider redirects are not
  followed. The gateway handles one exchange per client connection.
- Strict body forwarding consumes receipts for the corresponding audit record;
  the disk worker performs write, sync, commit, and receipt delivery in order.
  Queue reservations precede frame allocation. Fresh audit files use exclusive
  creation and Unix mode 0600. Partial failures have no provider replay path.
- The cloud adapter has a separate configured destination and enrollment
  credential. The reviewed proxy disables retries and redispatch and keeps
  operator endpoints off the public frontend.

These are bounded review observations, not universal absence-of-vulnerability
claims. Documented trust assumptions remain: private operator-owned state/log
directories, raw sensitive body logging, approved-origin DNS/PKI trust, no
resolved-IP SSRF policy, filesystem durability, and proxy/host hardening.
Cloud DNS resolution is explicitly blocking outside its deadline; this was not
reported as a new defect. State-file read size checks rely on trusted local
files and are not a defense against malicious concurrent local writers.

## Validation and remaining release work

Environment: macOS ARM64, Rust 1.99.1, Verus 0.2026.10.18.7d82994.

| Check against the pinned source | Result |
| --- | --- |
| `cargo test --workspace --locked` | 353 passed, 0 failed; 20 ignored |
| `verus crates/gateway-core/src/lib.rs --crate-type lib --triggers-mode silent` | 1,356 verified, 0 errors |
| `cargo clippy -p gateway-runtime --locked` | Passed; existing style warnings remain |
| `bash scripts/check_effect_sites.sh` | Passed; 8 audited sites, none unaccounted |
| OSV batch lookup of Cargo.lock registry package versions | 90 packages queried, no advisory matches returned |
| New TLS deadline adversarial reproduction | Failed as expected, confirming SEC-01 |

OSV results are a point-in-time advisory lookup, not a dependency source audit,
malware scan, or assurance about unpublished vulnerabilities. Git-sourced vstd
and the verifier are outside that registry lookup.

The complete Linux release workflow was not executed by this review. Proof
mutations, Linux ext4 storage-fault fixtures, HAProxy failover, sustained load and
memory soak, and the clean Linux container remain separate release requirements.
The proof and ordinary-test passes above do not waive those requirements or close
SEC-01. No production implementation was changed by this audit.
