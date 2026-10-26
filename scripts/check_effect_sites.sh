#!/usr/bin/env bash
# Pin the runtime's external effect sites.
#
# clippy.toml disallows every socket, name lookup, listener, file write, and
# secret read in gateway-runtime; each audited site is marked with
# `#[allow(clippy::disallowed_methods)]` and an "Effect site" comment. This
# script fails when that set of marked sites differs from the list below, so a
# new site cannot appear without updating this file and the end-to-end audit.
set -euo pipefail
cd "$(dirname "$0")/.."

expected='crates/gateway-runtime/src/disk_log.rs:create_with_payload_limit
crates/gateway-runtime/src/main.rs:bind
crates/gateway-runtime/src/main.rs:secret
crates/gateway-runtime/src/server.rs:wake_accept
crates/gateway-runtime/src/shipping/client.rs:open_socket
crates/gateway-runtime/src/shipping/state.rs:write_private
crates/gateway-runtime/src/transport.rs:open_socket
crates/gateway-runtime/src/transport/resolver.rs:resolve'

# Each marked site is the function declared on the line after the attribute.
actual=$(grep -rn --include='*.rs' -A1 '#\[allow(clippy::disallowed_methods)\]' crates/gateway-runtime/src \
  | grep -E '\.rs-[0-9]+-' \
  | sed -E 's/^(.*\.rs)-[0-9]+-.*fn ([A-Za-z_0-9]+).*/\1:\2/' \
  | sort)

if [ "$actual" != "$expected" ]; then
  echo "effect sites changed; update scripts/check_effect_sites.sh and docs/end-to-end-audit.md" >&2
  diff <(echo "$expected") <(echo "$actual") >&2 || true
  exit 1
fi

# Every marked site must say what it is for, within the three lines above it.
if ! grep -rn --include='*.rs' -B3 '#\[allow(clippy::disallowed_methods)\]' crates/gateway-runtime/src \
  | awk 'BEGIN { ok = 1; seen = 0 } /^--$/ { if (!seen) ok = 0; seen = 0; next } /Effect site|Escape hatch/ { seen = 1 } END { if (!seen) ok = 0; exit !ok }'; then
  echo "every disallowed-methods allowance needs an 'Effect site' or 'Escape hatch' comment just above it" >&2
  exit 1
fi

# The runtime links no executor: blocking sockets and threads only.
if grep -rn 'tokio' crates/gateway-runtime/src crates/gateway-runtime/tests crates/gateway-runtime/Cargo.toml >&2; then
  echo "the runtime must not depend on an async executor" >&2
  exit 1
fi

# No allowance anywhere else in the runtime, and the lint itself is enforced.
if ! output=$(cargo clippy -p gateway-runtime --locked --quiet 2>&1); then
  echo "$output" | grep -E -A8 '^error' >&2
  exit 1
fi
echo "pinned sites: $(echo "$expected" | wc -l | tr -d ' ') audited, none unaccounted"
