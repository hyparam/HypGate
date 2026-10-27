# SDK compatibility, retention, and installation

## Scope

Make LogGate easier to adopt without changing its provider-native bodies,
explicit route grants, or strict audit-before-forwarding policy.

## 1. SDK compatibility

Current behavior accepts only `POST /routes/<selector>`. Native request and
response bodies work, but SDKs append endpoint paths to their base URL.

Accept `/routes/<selector><provider-path>` as well as the existing path. The
suffix must equal the selected route's configured destination path; it cannot
choose a different endpoint. Keep selector parsing in the verified core and
reject malformed paths, query parameters, and mismatched endpoints. Document
OpenAI and Anthropic base URLs, gateway authentication, and disabling automatic
SDK retries. Test non-streaming and streaming calls with real Python SDKs
against a local TLS provider fixture, without live credentials.

## 2. Retention

Provide an explicit maintenance command for an archive directory, with a dry run
by default and deletion requiring `--apply`. Operators move closed logs into
that directory only after any required shipping completes. Never prune the live
log directory or shipper state. Use a fixed filename convention, inspect only
regular files, reject symlinks, and select logs by age. Test boundary ages,
unrelated files, symlinks, dry runs, and actual deletion. Document that retention
is deliberate removal of audit evidence, separate from crash durability.

Automatic in-process rotation is a separate change: it needs a session handoff
protocol for the disk worker, shipper, and checkpoints. This release keeps the
existing one-session-per-process storage contract.

## 3. Installation

Provide a local installer that builds with the pinned toolchain and installs the
binary without requiring root by default. Add a minimal runtime container target
separate from the existing validation image, with an unprivileged user and a
private writable log volume. Document loopback networking and TLS termination.
Validate installation into a temporary prefix and run the installed CLI; inspect
the container recipe and build it when Docker is available.

## Validation and delivery

Run workspace tests, core verification, effect-site checks, real-SDK integration,
retention tests, and an installation smoke test. Commit SDK support, retention,
and installation separately. Preserve the README's existing structure and link
to focused guides. Do not publish packages, images, or releases as part of this
work.

## Implemented

- SDK paths retain fixed destination binding and the original route syntax.
  Real OpenAI 3.39.0 and Anthropic 2.3.0 clients pass JSON and SSE tests against a
  local TLS fixture; logged upload/download bytes match the fixture exactly.
- `loggate-retain` previews archive expiry by default and requires `--apply` to
  delete. Age boundaries, unrelated files, invalid headers, symlinks, hard links,
  and directory permissions have automated coverage.
- `scripts/install.sh` installs into a user prefix; installation and the installed
  CLI were checked in a temporary directory. `deploy/Dockerfile.runtime` uses
  pinned builder/runtime bases and an unprivileged user. Docker is not running
  on this machine; image build and CLI smoke checks are wired into Linux CI.
- Local deployment checks pass, including cooperative SIGTERM shutdown. Their
  stale expectation of signal exit status 143 was corrected to clean exit 0.
  HAProxy is not installed here, so its stage remains a Linux CI check.

The serving process still does not rotate or delete logs, and no release or
container image has been published. Full container validation must pass in CI
before release.
