#!/usr/bin/env bash
# Cross-repo integration (spec section 8): the real agent, built at the
# pinned revision, against openvibes-ingest and Fedora's PostgreSQL, all as
# the current (unprivileged) user under target/integration/run.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
source "$ROOT/scripts/integration-lib.sh"
export CARGO_NET_GIT_FETCH_WITH_CLI=true

# The agent refuses a state directory with an untrusted ancestor (owned by
# neither root nor the current user), so CI points this at the user's home.
W=${INTEGRATION_DIR:-$ROOT/target/integration/run}
INGEST_PORT=${INGEST_PORT:-28423}
HEALTH_PORT=${HEALTH_PORT:-28480}
AGENT_BIN=${AGENT_BIN:-$(build_agent "$ROOT/target/integration/agent")}
start_platform
# The documented install: migrate and every admin command as a role that
# may create roles but is not a superuser.
[[ "$(sql "SELECT rolsuper FROM pg_roles WHERE rolname = 'openvibes_admin'")" == f ]] ||
    { echo "FAIL: openvibes_admin is a superuser"; exit 1; }
echo "ok: admin role is not a superuser"
mkdir -p "$W/agent/state"; chmod 700 "$W/agent/state"

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
# Stops the agent and forgets its PID, so cleanup never signals a PID the
# kernel may since have given to another process.
stop_agent() {
    [[ -n "$AGENT_PID" ]] || return 0
    kill "$AGENT_PID"; wait "$AGENT_PID" 2>/dev/null || true
    local kept=() pid
    for pid in "${PIDS[@]}"; do [[ "$pid" == "$AGENT_PID" ]] || kept+=("$pid"); done
    PIDS=("${kept[@]}")
    AGENT_PID=
}
restart_agent() {
    stop_agent
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
[[ "$(sql "SELECT count(*) FROM findings WHERE rule_set_id <> 'integration'")" == 0 ]] ||
    { echo "FAIL: a stored finding does not name its rule set"; exit 1; }
echo "ok: findings name their rule set"
[[ "$(sql "SELECT count(*) FROM findings")" == 2 ]] || { echo "FAIL: expected 2 findings"; exit 1; }

BEFORE=$(heartbeats_ok)
restart_agent
wait_for "agent reconnected after restart" 20 more_heartbeats_than "$BEFORE"
wait_for "no finding delivered twice after restart" 10 acked_equals_stored

# Renewal is due at obtained + 2/3 of the lifetime; obtained = 0 makes it due
# now without faking the clock (which would future-date findings).
stop_agent
sqlite3 "$W/agent/state/identity.sqlite" "UPDATE identity SET obtained_at_ms = 0"
restart_agent
certificates() { [[ "$(sql "SELECT count(*) FROM certificates WHERE agent_id = '$FIRST_AGENT'")" == "$1" ]]; }
wait_for "certificate renewed" 15 certificates 2
BEFORE=$(heartbeats_ok)
wait_for "renewed certificate authenticates" 75 more_heartbeats_than "$BEFORE"

# Revoke while the agent is stopped; on restart it scans (interval now 60 s,
# so findings are queued) and then learns of the revocation, so those
# findings must survive until it re-enrolls.
stop_agent
sed -i 's/^scan_interval_seconds = .*/scan_interval_seconds = 60/' "$W/agent/agent.toml"
admin agent revoke "$FIRST_AGENT" >/dev/null
new_token   # the agent reads it only once its identity is gone
restart_agent
revoked_answer() {
    # A command substitution, not a pipe into grep -q: under pipefail an early
    # grep exit can SIGPIPE jq and fail the check even on a match.
    [[ -n "$(jq -r 'select(.fields.status == 403) | 1' "$W/ingest.log")" ]]
}
wait_for "revoked agent told identity_revoked" 75 revoked_answer
queued() { (($(sqlite3 "$W/agent/state/queue.sqlite" "SELECT count(*) FROM pending") > 0)); }
wait_for "findings stay queued while revoked" 5 queued
REVOKED_IDS=$(sqlite3 "$W/agent/state/queue.sqlite" "SELECT finding_id FROM pending ORDER BY 1")
reenrolled() {
    [[ "$(sql "SELECT count(*) FROM agents WHERE status = 'active' AND agent_id <> '$FIRST_AGENT'")" == 1 ]]
}
wait_for "agent re-enrolled with a new token" 75 reenrolled
[[ "$(sql "SELECT status FROM agents WHERE agent_id = '$FIRST_AGENT'")" == revoked ]]
wait_for "no finding lost or duplicated across re-enrollment" 75 acked_equals_stored
# Exactly the findings queued while revoked (not just any later scan) must
# arrive under the new identity.
for id in $REVOKED_IDS; do
    [[ "$(sql "SELECT count(*) FROM findings WHERE finding_id = '$id' AND agent_id <> '$FIRST_AGENT'")" == 1 ]] ||
        { echo "FAIL: finding $id queued while revoked was not delivered under the new identity"; exit 1; }
done
echo "ok: findings queued while revoked delivered under the new identity"
# An expired certificate (a laptop off past its renewal window) cannot renew;
# the agent drops it, keeps its queue, and enrolls again with its token file.
SECOND_AGENT=$(sql "SELECT agent_id FROM agents WHERE status = 'active'")
stop_agent
sqlite3 "$W/agent/state/identity.sqlite" "UPDATE identity SET obtained_at_ms = 0, expires_at_ms = 1"
new_token   # the used single-use token is refused (401); a token with a use left works
restart_agent
third_agent() {
    [[ "$(sql "SELECT count(*) FROM agents WHERE status = 'active'
                AND agent_id NOT IN ('$FIRST_AGENT', '$SECOND_AGENT')")" == 1 ]]
}
wait_for "expired certificate: agent re-enrolled from its token file" 30 third_agent
wait_for "no finding lost or duplicated across expiry re-enrollment" 75 acked_equals_stored
((${#PIDS[@]} == 2)) || { echo "FAIL: tracking ${#PIDS[@]} PIDs, want ingest and the live agent"; exit 1; }

# Rule distribution (SP2): the agent switches from its provisioned bundle to
# fetching from openvibes-distribution. v1 is the exact file it already
# accepted (a re-signed v1 would differ and be refused as a conflict).
start_distribution
bundle() {
    if [[ -n "${BUNDLE_BIN:-}" ]]; then "$BUNDLE_BIN" "$@"
    else (cd "$ROOT" && cargo run -q --locked -p openvibes-ingest --example integration_bundle -- "$@"); fi
}
[[ "$(bundle "$W/v2.json" 2)" == "$KEY" ]] || { echo "FAIL: v2 signed with another key"; exit 1; }
admin rules trust add integration integration.test "$KEY" >/dev/null
admin rules publish "$W/agent/rules.json" >/dev/null
echo "ok: rules v1 published"
stop_agent
sed -i '/^bundle_file = /d; /^\[\[rule_sets\]\]/i distribution_url = "https://127.0.0.1:'"$DIST_PORT"'"' "$W/agent/agent.toml"
distribution_answered() {
    [[ -n "$(jq -r --argjson s "$1" 'select(.fields.endpoint == "/v1/rule-bundle" and .fields.status == $s) | 1' \
        "$W/distribution.log" 2>/dev/null)" ]]
}
restart_agent
wait_for "agent polls distribution (204 for its current v1)" 30 distribution_answered 204
admin rules publish "$W/v2.json" >/dev/null
v2_findings() { sql "SELECT count(*) FROM findings WHERE rule_id = 'integration.v2'"; }
more_v2_than() { (($(v2_findings) > $1)); }
restart_agent
wait_for "agent fetched v2 (200)" 30 distribution_answered 200
wait_for "agent runs v2: its new rule's findings arrive" 75 more_v2_than 0
BEFORE=$(v2_findings)
stop_distribution
restart_agent
wait_for "scans continue on v2 while distribution is down" 75 more_v2_than "$BEFORE"
kill -0 "$AGENT_PID" || { echo "FAIL: agent exited without distribution"; exit 1; }
start_distribution
# The second agent is still active (its certificate expired): take the newest.
THIRD_AGENT=$(sql "SELECT agent_id FROM agents WHERE status = 'active' ORDER BY enrolled_at DESC LIMIT 1")
stop_agent
admin agent revoke "$THIRD_AGENT" >/dev/null
restart_agent
wait_for "distribution tells the revoked agent identity_revoked" 75 distribution_answered 403
((${#PIDS[@]} == 3)) || { echo "FAIL: tracking ${#PIDS[@]} PIDs, want ingest, distribution, agent"; exit 1; }
echo "integration: all checks passed"
