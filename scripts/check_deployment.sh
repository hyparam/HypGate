#!/usr/bin/env bash
# Deploy the documented configuration from a clean checkout and check it end to end.
# Follows README.md, docs/running.md, and docs/deployment.md with only the token
# digest, the upstream destination, and listen ports substituted. Needs bash, the
# pinned Rust toolchain, curl, and openssl; HAProxy is used when available. The
# upstream destination is a closed loopback port, so no provider or external
# network traffic occurs and no real credential is required.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo"
work=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/hypgate-deploy.XXXXXX")
chmod 700 "$work"
pids=()
cleanup() {
    for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
    wait 2>/dev/null || true
    rm -rf -- "$work"
}
trap cleanup EXIT
step() { printf '\n== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
status() { curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$@"; }
expect_status() { # expected description curl-args...
    local expected=$1 what=$2; shift 2
    local actual; actual=$(status "$@")
    [[ "$actual" == "$expected" ]] || fail "$what returned $actual, expected $expected"
    echo "ok: $what -> $actual"
}
free_port() { # a loopback port that currently refuses connections
    local port
    for _ in $(seq 1 100); do
        port=$((RANDOM % 20000 + 30000))
        if ! (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then echo "$port"; return; fi
    done
    fail 'no free loopback port found'
}
file_mode() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }
start_gateway() { # name log-path -> sets $address and appends pid
    local name=$1 log=$2
    PROVIDER_KEY="$provider_key" "$binary" "$work/config.json" "$log" 127.0.0.1:0 \
        2>"$work/$name.err" &
    pids+=("$!")
    eval "${name}_pid=$!"
    local line=
    for _ in $(seq 1 100); do
        line=$(grep -m1 'hypgate listening on ' "$work/$name.err" || true)
        [[ -n "$line" ]] && break
        sleep 0.1
    done
    [[ -n "$line" ]] || fail "$name did not start: $(cat "$work/$name.err")"
    address=${line#hypgate listening on }
    echo "$name listening on $address"
}
stop_gateway() { # name -> SIGTERM and a successful cooperative drain
    local pid; eval "pid=\$${1}_pid"
    kill -TERM "$pid"
    local code=0; wait "$pid" || code=$?
    [[ "$code" == 0 ]] || fail "$1 exited with status $code after SIGTERM: $(cat "$work/$1.err")"
    echo "ok: $1 drained with status 0 after SIGTERM"
}

step 'Environment'
uname -srm
rustup show active-toolchain
cargo --version
curl --version | head -1
openssl version
haproxy=${HYPGATE_HAPROXY:-$(command -v haproxy || true)}
if [[ -n "$haproxy" ]]; then "$haproxy" -v | head -1; else echo 'haproxy not found; proxy stage skipped'; fi

step 'Build the release executable with locked dependencies'
cargo build --release --locked --bin hypgate
binary="$repo/target/release/hypgate"

step 'Provision the documented configuration'
token=$(openssl rand -hex 32)                       # 32 random bytes, bearer-safe
digest=$(printf '%s' "$token" | openssl dgst -sha256 | awk '{print $NF}')
closed=$(free_port)                                 # nothing listens here
provider_key=deployment-check-placeholder-not-a-real-credential
umask 077
cat >"$work/config.json" <<EOF
{
  "identities": [{"tenant": 1, "sha256": "$digest"}],
  "destinations": ["https://localhost:$closed/v1/messages"],
  "credentials": [{"tenant": 1, "kind": "api_key", "env": "PROVIDER_KEY"}],
  "grants": [{"tenant": 1, "selector": 7, "origin": 0, "credential": 0}],
  "limits": {"requests": 16, "chunk_bytes": 16384},
  "logging": "strict"
}
EOF
mkdir -m 700 "$work/logs"
echo "destination https://localhost:$closed refuses connections; digest $digest"

step 'Startup refuses unsafe deployments'
if PROVIDER_KEY=x "$binary" "$work/config.json" "$work/logs/bad.log" 0.0.0.0:0 2>"$work/bad.err"; then
    fail 'non-loopback listen address accepted'; fi
grep -q 'must be loopback' "$work/bad.err" || fail "unexpected error: $(cat "$work/bad.err")"
[[ ! -e "$work/logs/bad.log" ]] || fail 'log created before listen address check'
echo 'ok: non-loopback listen address refused'
if env -u PROVIDER_KEY "$binary" "$work/config.json" "$work/logs/bad.log" 127.0.0.1:0 2>"$work/bad.err"; then
    fail 'missing provider credential accepted'; fi
grep -q 'missing credential' "$work/bad.err" || fail "unexpected error: $(cat "$work/bad.err")"
echo 'ok: missing provider credential refused'
: >"$work/logs/existing.log"
if PROVIDER_KEY=x "$binary" "$work/config.json" "$work/logs/existing.log" 127.0.0.1:0 2>"$work/bad.err"; then
    fail 'existing log path accepted'; fi
grep -q 'new audit log' "$work/bad.err" || fail "unexpected error: $(cat "$work/bad.err")"
[[ ! -s "$work/logs/existing.log" ]] || fail 'existing log was modified'
echo 'ok: existing log path refused and left unchanged'

step 'Start the primary gateway'
start_gateway primary "$work/logs/session-001.log"
primary=$address
[[ "$(file_mode "$work/logs/session-001.log")" == 600 ]] || fail 'audit log is not mode 600'
echo 'ok: audit log created with mode 600'
grep -q 'requested-allocation budget' "$work/primary.err" || fail 'budget line missing'

step 'Health, readiness, and metrics'
[[ "$(curl --fail -s "http://$primary/healthz")" == ok ]] || fail 'healthz'
echo 'ok: /healthz'
expect_status 200 'GET /readyz' "http://$primary/readyz"
metrics=$(curl --fail -s "http://$primary/metrics")
for line in 'hypgate_audit_healthy 1' 'hypgate_admission_healthy 1' 'hypgate_worker_admission_healthy 1' \
    'hypgate_requests_active 0' 'hypgate_requests_limit 16' 'hypgate_failed_exchanges_total 0'; do
    grep -qx "$line" <<<"$metrics" || fail "metrics missing '$line': $metrics"
done
echo 'ok: /metrics reports healthy strict logging and 16 request slots'

step 'Authorization fails closed'
body='{"model":"placeholder","max_tokens":1,"messages":[]}'
expect_status 401 'POST /routes/7 without credentials' -X POST -H 'content-type: application/json' \
    --data "$body" "http://$primary/routes/7"
expect_status 401 'POST /routes/7 with a wrong token' -X POST -H 'content-type: application/json' \
    -H "authorization: Bearer ${token}0" --data "$body" "http://$primary/routes/7"
expect_status 401 'POST /routes/8 (no grant) with the right token' -X POST -H 'content-type: application/json' \
    -H "authorization: Bearer $token" --data "$body" "http://$primary/routes/8"
expect_status 405 'GET /routes/7 with the right token' -H "authorization: Bearer $token" "http://$primary/routes/7"
expect_status 400 'POST /other with the right token' -X POST -H "authorization: Bearer $token" --data "$body" \
    "http://$primary/other"
expect_status 502 'POST /routes/7 authorized, upstream refuses the connection' -X POST \
    -H 'content-type: application/json' -H "authorization: Bearer $token" --data "$body" "http://$primary/routes/7"
# The client receives the response before the worker finishes audit and stream
# cleanup. Wait for its credit to return, but still fail on a leaked slot.
for _ in $(seq 1 100); do
    metrics=$(curl --fail -s --max-time 1 "http://$primary/metrics")
    grep -qx 'hypgate_requests_active 0' <<<"$metrics" && break
    sleep 0.1
done
grep -qx 'hypgate_failed_exchanges_total 1' <<<"$metrics" || fail "failed exchange not counted: $metrics"
grep -qx 'hypgate_requests_active 0' <<<"$metrics" || fail "request slot not released: $metrics"
grep -qx 'hypgate_audit_gap_requests_total 0' <<<"$metrics" || fail "strict mode reported a gap: $metrics"
expect_status 200 'GET /readyz after the failed exchange' "http://$primary/readyz"
echo 'ok: one failed exchange counted, slot released, still ready'

if [[ -n "$haproxy" ]]; then
    step 'TLS proxy with a standby instance'
    start_gateway standby "$work/logs/session-002.log"
    standby=$address
    openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=localhost -addext subjectAltName=DNS:localhost -days 1 \
        -keyout "$work/key.pem" -out "$work/cert.pem" 2>/dev/null
    cat "$work/cert.pem" "$work/key.pem" >"$work/tls.pem"
    chmod 600 "$work/tls.pem"
    proxy_port=$(free_port)
    sed -e "s/bind :8443/bind 127.0.0.1:$proxy_port/" -e "s/127\\.0\\.0\\.1:8081/$primary/" \
        -e "s/127\\.0\\.0\\.1:8082/$standby/" deploy/haproxy.cfg >"$work/haproxy.cfg"
    HYPGATE_TLS_PEM="$work/tls.pem" "$haproxy" -c -f "$work/haproxy.cfg"
    HYPGATE_TLS_PEM="$work/tls.pem" "$haproxy" -db -f "$work/haproxy.cfg" >"$work/haproxy.log" 2>&1 &
    pids+=("$!"); haproxy_pid=$!
    proxy="https://localhost:$proxy_port"
    for _ in $(seq 1 100); do # wait for both backends to pass two readiness checks
        [[ "$(status --cacert "$work/cert.pem" -X POST --data "$body" "$proxy/routes/7")" == 401 ]] && break
        sleep 0.1
    done
    expect_status 401 'proxied POST /routes/7 without credentials' --cacert "$work/cert.pem" -X POST \
        --data "$body" "$proxy/routes/7"
    expect_status 404 'proxied GET /metrics' --cacert "$work/cert.pem" "$proxy/metrics"
    expect_status 404 'proxied GET /readyz' --cacert "$work/cert.pem" "$proxy/readyz"
    expect_status 404 'proxied GET /routes/7' --cacert "$work/cert.pem" "$proxy/routes/7"
    expect_status 502 'proxied authorized POST /routes/7, upstream refuses' --cacert "$work/cert.pem" -X POST \
        -H 'content-type: application/json' -H "authorization: Bearer $token" --data "$body" "$proxy/routes/7"
    echo 'ok: public frontend exposes only POST route paths'

    step 'Primary shutdown routes new requests to the standby'
    stop_gateway primary
    for _ in $(seq 1 100); do # health detection: two failed checks one second apart
        [[ "$(status --cacert "$work/cert.pem" -X POST --data "$body" "$proxy/routes/7")" == 401 ]] && break
        sleep 0.1
    done
    expect_status 401 'proxied POST /routes/7 after primary shutdown' --cacert "$work/cert.pem" -X POST \
        --data "$body" "$proxy/routes/7"
    metrics=$(curl --fail -s "http://$standby/metrics")
    grep -qx 'hypgate_failed_exchanges_total 0' <<<"$metrics" || fail "standby saw a replayed exchange: $metrics"
    echo 'ok: standby serves new requests; no generation was replayed'
    stop_gateway standby
    kill -TERM "$haproxy_pid"; wait "$haproxy_pid" || true
else
    step 'Process termination'
    stop_gateway primary
fi

step 'Scan the audit logs read-only'
for log in "$work"/logs/session-*.log; do
    before=$(openssl dgst -sha256 "$log" | awk '{print $NF}')
    scan=$("$binary" scan "$log")
    summary=$(tail -n1 <<<"$scan")
    grep -q '"status":"complete"' <<<"$summary" || fail "scan of $log: $summary"
    # Refused upstream connections leave a start record and a completion with
    # outcome 1 per authorized request, and never a body record.
    records=$(grep -o '"records":[0-9]*' <<<"$summary" | cut -d: -f2)
    starts=$(grep -c '"kind":"request_start"' <<<"$scan" || true)
    completions=$(grep -c '"kind":"completion"' <<<"$scan" || true)
    failures=$(grep -c '"outcome":1' <<<"$scan" || true)
    if grep -q '"kind":"upload"\|"kind":"download"' <<<"$scan"; then fail "body records in $log: $scan"; fi
    [[ "$records" == $((starts + completions)) && "$starts" == "$completions" && "$completions" == "$failures" ]] \
        || fail "unexpected records in $log: $scan"
    if (( starts > 0 )); then
        grep -q "\"destination\":\"https://localhost:$closed/v1/messages\"" <<<"$scan" || fail "wrong destination in $log: $scan"
    fi
    [[ "$(openssl dgst -sha256 "$log" | awk '{print $NF}')" == "$before" ]] || fail 'scan modified the log'
    echo "ok: $(basename "$log") $summary"
done

step 'PASS'
echo 'clean-environment deployment reproduced: build, provisioning, fail-closed startup, health,'
echo 'authorization, honest upstream failure, process termination, and read-only scan'
[[ -n "$haproxy" ]] && echo 'including TLS termination, public-path policy, and standby routing through HAProxy'
exit 0
