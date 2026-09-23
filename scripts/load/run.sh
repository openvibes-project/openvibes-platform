#!/usr/bin/env bash
# Load test (spec section 8): openvibes-load simulates AGENTS agents, one tick
# every INTERVAL_MS each, against a local openvibes-ingest and PostgreSQL.
# Usage: scripts/load/run.sh [AGENTS] [INTERVAL_MS] [DURATION_S]
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
source "$ROOT/scripts/integration-lib.sh"
export CARGO_NET_GIT_FETCH_WITH_CLI=true
AGENTS=${1:-2000}
INTERVAL_MS=${2:-2000}
DURATION_S=${3:-120}
W=${LOAD_DIR:-$ROOT/target/load/run}
INGEST_PORT=${INGEST_PORT:-28523}
HEALTH_PORT=${HEALTH_PORT:-28580}
if [[ -z "${LOAD_BIN:-}" ]]; then
    (cd "$ROOT" && cargo build --quiet --release --locked -p openvibes-load)
    LOAD_BIN="$ROOT/target/release/openvibes-load"
fi

start_platform
admin token create --expires 1h --uses "$AGENTS" --label load |
    sed -n 's/^token \([A-Za-z0-9_-]\{43\}\)$/\1/p' > "$W/token"
[[ -s "$W/token" ]] || { echo "FAIL: no token" >&2; exit 1; }

echo "--- hardware"
echo "cpu: $(lscpu | sed -n 's/^Model name: *//p'), $(nproc) threads"
echo "memory: $(awk '/MemTotal/ {printf "%.1f GiB", $2 / 1048576}' /proc/meminfo)"
echo "kernel: $(uname -r)"
echo "postgresql: $(postgres --version)"
echo "tcp_tw_reuse: $(cat /proc/sys/net/ipv4/tcp_tw_reuse), ports: $(tr '\t' '-' < /proc/sys/net/ipv4/ip_local_port_range)"
echo "generator, ingest, and PostgreSQL share this host"
echo "--- load: $AGENTS agents, one tick every ${INTERVAL_MS} ms, ${DURATION_S} s measured"
status=0
# shellcheck disable=SC2086  # LOAD_ARGS is a list of extra flags
"$LOAD_BIN" --url "https://127.0.0.1:$INGEST_PORT" --ca "$W/ca/root/root.crt" \
    --token-file "$W/token" --agents "$AGENTS" --interval-ms "$INTERVAL_MS" \
    --duration-s "$DURATION_S" --ingest-pid "$INGEST_PID" \
    --postmaster-pid "$(head -1 "$W/pg/data/postmaster.pid")" --clk-tck "$(getconf CLK_TCK)" \
    ${LOAD_ARGS:-} > "$W/summary.json" 2> "$W/load.log" || status=$?
cat "$W/summary.json"
exit "$status"
