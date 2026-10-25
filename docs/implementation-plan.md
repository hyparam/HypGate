# Implementation milestones

All six milestones are complete under the assumptions documented in their exit
audits. Scope: forward opaque HTTP request bodies and streaming responses, and
log to disk. No provider translation, automatic generation replay, billing, or
plugin system. Operators choose strict durable logging or forwarding with
degraded audit coverage. An external load balancer handles failover between
gateway instances.

| Milestone | Status | Exit audit |
| --- | --- | --- |
| 1. Verified streaming core | Complete under the resource composition assumptions | [Milestone 1 exit audit](milestone-1-exit-audit.md), [resource composition](resource-composition.md) |
| 2. Minimal working gateway | Complete; adapter obligations documented | [Adapter audit](adapter-audit.md) |
| 3. Crash-safe logging | Complete under the storage/read/checksum assumptions; physical power loss not validated | [Storage crash contract](storage-crash-contract.md#milestone-3-exit-audit) |
| 4. Availability hardening | Complete under explicit scheduler/I/O assumptions | [Availability audit](availability-audit.md), [shutdown proof](shutdown-proof.md) |
| 5. Auditable first release | Complete; remote CI currently blocked by an account billing restriction | [End-to-end audit](end-to-end-audit.md), [deployment](deployment.md#clean-environment-reproduction), [benchmarks](benchmarks.md#broader-workloads), [operational limits](operational-limits.md) |
| 6. Async ownership and effect composition | Complete under the adapter assumptions in the audit | [Milestone 6 exit audit](milestone-6-exit-audit.md) |

Completion means every row of the milestone's checklist is checked within its
stated scope; it does not mean the whole gateway is formally verified. The
[security contract](security-contract.md) and each exit audit list the trusted
boundaries that remain: Tokio, Hyper, rustls, DNS/PKI, the OS and filesystem,
Rust destruction and mutex discipline, secret provisioning, and physical
durability. Current validation totals are in the [README](../README.md).

The row-by-row checklists and the checkpoint notes with their then-current
counts are preserved in the [historical plan](history/implementation-plan.md).
The research that chose Rust and Verus is in
[verification research](history/verification-research.md),
[experiment results](history/experiment-results.md), and the
[viability follow-up](history/viability-followup.md).

## Decisions settled during implementation

Inbound authentication uses SHA-256 token digests; provider credentials are
owned per tenant and bound to fixed configured destinations; HTTP/1 only, with
no keep-alive, redirects, or replay; the audit log is a framed append-only file
with one worker and `write_all`/`sync_all` per record; limits are fixed at
startup from validated configuration. Perennial is not an active workstream;
its notes and the historical code revision remain available if storage
verification requirements justify revisiting that decision.
