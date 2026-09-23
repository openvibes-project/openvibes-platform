#!/usr/bin/env bash
# Cross-repo integration (spec section 8): the real agent, built at the
# pinned revision, against openvibes-ingest and Fedora's PostgreSQL, all as
# the current (unprivileged) user under target/integration/run.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
source "$ROOT/scripts/integration-lib.sh"
export CARGO_NET_GIT_FETCH_WITH_CLI=true

W="$ROOT/target/integration/run"
INGEST_PORT=${INGEST_PORT:-28423}
HEALTH_PORT=${HEALTH_PORT:-28480}
PIDS=()
cleanup() {
    local status=$?
    for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
    wait 2>/dev/null || true
    [[ -d "$W/pg/data" ]] && pg_ctl -D "$W/pg/data" -m immediate stop >/dev/null 2>&1 || true
    if ((status != 0)); then
        echo "--- ingest log (tail)"; tail -n 20 "$W/ingest.log" 2>/dev/null || true
        echo "--- agent log (tail)"; tail -n 20 "$W/agent.log" 2>/dev/null || true
    fi
    exit "$status"
}
trap cleanup EXIT
rm -rf "$W"; mkdir -p "$W/pg/run" "$W/ca" "$W/agent/state"; chmod 700 "$W/agent/state"

# Binaries.
if [[ -z "${OPENVIBES_BIN_DIR:-}" ]]; then
    cargo build --quiet --release --locked -p openvibes-ingest -p openvibes-admin
    OPENVIBES_BIN_DIR="$ROOT/target/release"
fi
AGENT_BIN=${AGENT_BIN:-$(build_agent "$ROOT/target/integration/agent")}
admin() { "$OPENVIBES_BIN_DIR/openvibes-admin" --config "$W/admin.toml" "$@"; }

# PostgreSQL (Unix socket only) and the schema.
initdb -D "$W/pg/data" -U openvibes_admin --auth=trust >/dev/null
pg_ctl -D "$W/pg/data" -o "-k $W/pg/run -c listen_addresses=''" -l "$W/pg/log" -w start >/dev/null
createdb -h "$W/pg/run" -U openvibes_admin openvibes
sql() { psql -h "$W/pg/run" -U openvibes_admin -d openvibes -AtX -c "$1"; }
echo "database_url = \"postgresql:///openvibes?host=$W/pg/run&user=openvibes_admin\"" > "$W/admin.toml"
admin migrate >/dev/null
admin maintenance >/dev/null

# Built-in CA: root, intermediate, server certificate for 127.0.0.1.
admin ca init-root --out "$W/ca/root" >/dev/null
admin ca intermediate-request --out "$W/ca/int" >/dev/null
admin ca sign-intermediate --root "$W/ca/root" --csr "$W/ca/int/intermediate.csr" \
    --out "$W/ca/int/intermediate.crt" >/dev/null
admin ca import-intermediate --cert "$W/ca/int/intermediate.crt" \
    --key "$W/ca/int/intermediate.key" --root-cert "$W/ca/root/root.crt" >/dev/null
admin ca issue-server localhost --san 127.0.0.1 --issuer-cert "$W/ca/int/intermediate.crt" \
    --issuer-key "$W/ca/int/intermediate.key" --out "$W/ca/tls" >/dev/null

# Ingest.
cat > "$W/ingest.toml" <<EOF
listen = "127.0.0.1:$INGEST_PORT"
health_listen = "127.0.0.1:$HEALTH_PORT"
server_certificate_file = "$W/ca/tls/localhost.crt"
server_key_file = "$W/ca/tls/localhost.key"
client_ca_file = "$W/ca/int/intermediate.crt"
issuing_certificate_file = "$W/ca/int/intermediate.crt"
issuing_key_file = "$W/ca/int/intermediate.key"
database_url = "postgresql:///openvibes?host=$W/pg/run&user=openvibes_ingest"
EOF
"$OPENVIBES_BIN_DIR/openvibes-ingest" --config "$W/ingest.toml" 2> "$W/ingest.log" &
PIDS+=($!)
wait_for "ingest ready" 30 curl -fsS "http://127.0.0.1:$HEALTH_PORT/ready"

# Agent config with the signed integration bundle.
if [[ -n "${BUNDLE_BIN:-}" ]]; then
    KEY=$("$BUNDLE_BIN" "$W/agent/rules.json")
else
    KEY=$(cd "$ROOT" && cargo run -q --locked -p openvibes-ingest --example integration_bundle -- "$W/agent/rules.json")
fi
cat > "$W/agent/agent.toml" <<EOF
platform_url = "https://127.0.0.1:$INGEST_PORT"
platform_ca_file = "$W/ca/root/root.crt"
state_dir = "$W/agent/state"
enrollment_token_file = "$W/agent/token"
scan_interval_seconds = 86400
[[rule_sets]]
id = "integration"
bundle_file = "$W/agent/rules.json"
trusted_keys = [{ issuer_key_id = "integration.test", public_key = "$KEY" }]
EOF

AGENT_PID=
restart_agent() {
    if [[ -n "$AGENT_PID" ]]; then kill "$AGENT_PID"; wait "$AGENT_PID" 2>/dev/null || true; fi
    "$AGENT_BIN" "$W/agent/agent.toml" 2>> "$W/agent.log" &
    AGENT_PID=$!
    PIDS+=("$AGENT_PID")
}
active_agents() { [[ "$(sql "SELECT count(*) FROM agents WHERE status = 'active'")" == "$1" ]]; }

new_token() {
    admin token create --expires 1h | sed -n 's/^token \([A-Za-z0-9_-]\{43\}\)$/\1/p' > "$W/agent/token"
    chmod 600 "$W/agent/token"
    [[ -s "$W/agent/token" ]]
}
new_token
restart_agent
wait_for "agent enrolled" 20 active_agents 1

FIRST_AGENT=$(sql "SELECT agent_id FROM agents WHERE status = 'active'")
heartbeats_ok() {
    jq -r 'select(.fields.endpoint == "/v1/heartbeat" and .fields.status == 204) | 1' \
        "$W/ingest.log" 2>/dev/null | wc -l
}
more_heartbeats_than() { (($(heartbeats_ok) > $1)); }
wait_for "heartbeat accepted" 20 more_heartbeats_than 0

acked_equals_stored() {
    local pending acked stored
    pending=$(sqlite3 "$W/agent/state/queue.sqlite" "SELECT count(*) FROM pending")
    acked=$(sqlite3 "$W/agent/state/queue.sqlite" "SELECT finding_id FROM acknowledged ORDER BY 1")
    stored=$(sql "SELECT finding_id FROM findings ORDER BY 1")
    [[ "$pending" == 0 && -n "$acked" && "$acked" == "$stored" ]]
}
wait_for "findings delivered exactly once" 20 acked_equals_stored
[[ "$(sql "SELECT count(*) FROM findings")" == 2 ]] || { echo "FAIL: expected 2 findings"; exit 1; }
