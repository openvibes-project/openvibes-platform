#!/usr/bin/env bash
# Load test (spec section 8): openvibes-load simulates AGENTS agents, one tick
# every INTERVAL_MS each, against a local openvibes-ingest and PostgreSQL.
# Usage: scripts/load/run.sh [AGENTS] [INTERVAL_MS] [DURATION_S]
# PREFILL_FINDINGS=N first stores N synthetic findings spread over the last
# 89 days (a database well into its 90-day retention).
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

# On-disk size of the findings (all partitions, indexes included) and of the
# database, with the row count; printed as one JSON object.
storage() {
    sql "SELECT json_build_object(
        'findings', (SELECT count(*) FROM findings),
        'findings_bytes', (SELECT coalesce(sum(pg_total_relation_size(inhrelid)), 0)
                           FROM pg_inherits WHERE inhparent = 'findings'::regclass),
        'current_findings_bytes', pg_total_relation_size('current_findings'),
        'database_bytes', pg_database_size('openvibes'))"
}

PREFILL_FINDINGS=${PREFILL_FINDINGS:-0}
if ((PREFILL_FINDINGS > 0)); then
    echo "--- prefill: $PREFILL_FINDINGS findings over 89 days"
    started=$SECONDS
    # Same shapes as openvibes-load's findings (and real agent findings):
    # 64-hex ids, 50,000 agents, 20 rules. No agents rows are needed:
    # findings has no foreign key (current_findings is not pre-filled).
    sql "INSERT INTO findings (finding_id, observed_day, observed_at, agent_id, scan_id,
             rule_id, rule_version, severity, confidence, message, evidence, received_at,
             origin, authenticated)
         SELECT 'finding.' || md5(g::text) || md5((-g)::text), d::date, d,
             'agent.' || lpad(to_hex(g % 50000), 8, '0') || '-0000-4000-8000-000000000000',
             'scan.' || (extract(epoch FROM d) * 1000)::bigint,
             'baseline.rule.' || lpad((g % 20)::text, 3, '0'), 1, 'info', 100,
             'Load test finding: a synthetic observation of typical size',
             ARRAY['process.names'], d, 'online', true
         FROM generate_series(1, $PREFILL_FINDINGS) AS g,
             LATERAL (SELECT now() - (g % (89 * 86400)) * interval '1 second' AS d) AS t" >/dev/null
    sql "VACUUM (ANALYZE) findings" >/dev/null
    echo "prefill took $((SECONDS - started)) s"
fi
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
BEFORE=$(storage)
status=0
# shellcheck disable=SC2086  # LOAD_ARGS is a list of extra flags
"$LOAD_BIN" --url "https://127.0.0.1:$INGEST_PORT" --ca "$W/ca/root/root.crt" \
    --token-file "$W/token" --agents "$AGENTS" --interval-ms "$INTERVAL_MS" \
    --duration-s "$DURATION_S" --ingest-pid "$INGEST_PID" \
    --postmaster-pid "$(head -1 "$W/pg/data/postmaster.pid")" --clk-tck "$(getconf CLK_TCK)" \
    ${LOAD_ARGS:-} > "$W/summary.json" 2> "$W/load.log" || status=$?
AFTER=$(storage)
jq -n --argjson before "$BEFORE" --argjson after "$AFTER" '{
    before: $before, after: $after,
    prefilled_bytes_per_finding:
      (if $before.findings > 0 then $before.findings_bytes / $before.findings else null end),
    bytes_per_new_finding:
      (($after.findings - $before.findings) as $n
       | if $n > 0 then ($after.findings_bytes - $before.findings_bytes) / $n else null end)
}' > "$W/storage.json"
cat "$W/summary.json"
echo "--- storage"
cat "$W/storage.json"
exit "$status"
