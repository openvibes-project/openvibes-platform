#!/usr/bin/env bash
# Threat alarms end to end (P14, board #89), for the CI job `alarms-e2e` on
# a VM runner with sudo (kernel audit is not reachable from a container):
# the platform (PostgreSQL, ingest, console) from this build's RPMs as the
# current user, and the packaged agent with only CAP_AUDIT_READ and the
# packaged exec audit rule. A fake web server starts a shell three times:
# one alarm, count 3, reaches POST /v1/alarms and reads back from
# GET /api/v1/alarms with its process tree; a `program` suppression made
# through the console API then closes the next one.
# Usage: alarms-e2e.sh RPM_DIR
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
source "$ROOT/scripts/integration-lib.sh"
RPMS=$(realpath "$1")
W=${INTEGRATION_DIR:-$HOME/alarms-e2e}
INGEST_PORT=28423
HEALTH_PORT=28480
CONSOLE_PORT=28490
CONSOLE_HEALTH_PORT=28491
ORIGIN="https://127.0.0.1:$CONSOLE_PORT"
PASSWORD="alarms-e2e-Passw0rd!"
fail() { echo "FAIL: $*" >&2; exit 1; }

# This build's RPMs, unpacked (the runner has no rpm database to use). Only
# the platform's own version; dist may hold other builds.
X=$(mktemp -d)
for package in admin ingest console agent; do
    rpm=$(ls "$RPMS"/openvibes-"$package"-[0-9]*.x86_64.rpm | sort -V | tail -1)
    (cd "$X" && rpm2cpio "$rpm" | cpio -idm --quiet)
done
export OPENVIBES_BIN_DIR="$X/usr/bin"
PATH=$(ls -d /usr/lib/postgresql/*/bin | sort -V | tail -1):$PATH

start_platform # PostgreSQL, schema, CA, ingest (integration-lib.sh)

# Console: direct TLS on 127.0.0.1, its own least-privilege role.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
    -subj /CN=127.0.0.1 -addext subjectAltName=IP:127.0.0.1 \
    -keyout "$W/console.key" -out "$W/console.crt" 2>/dev/null
cat > "$W/console.toml" <<EOF
development_listen = "127.0.0.1:$CONSOLE_PORT"
health_listen = "127.0.0.1:$CONSOLE_HEALTH_PORT"
transport_mode = "direct_tls"
database_url = "postgresql:///openvibes?host=$W/pg/run&user=openvibes-console"
public_origin = "$ORIGIN"
server_certificate_file = "$W/console.crt"
server_key_file = "$W/console.key"
EOF
printf '%s\n' "$PASSWORD" | admin user create --username alex --display-name "Alex Admin" \
    --role admin --password-stdin >/dev/null
"$OPENVIBES_BIN_DIR/openvibes-console" --config "$W/console.toml" 2> "$W/console.log" &
PIDS+=("$!")
wait_for "console ready" 30 curl -fsS "http://127.0.0.1:$CONSOLE_HEALTH_PORT/ready"

# Console session: preauth CSRF → login → the session's own CSRF value.
JAR="$W/cookies"
api() { # METHOD PATH [JSON]
    curl -sS --cacert "$W/console.crt" -b "$JAR" -c "$JAR" -H "Origin: $ORIGIN" \
        -H "Sec-Fetch-Site: same-origin" -H "X-CSRF-Token: ${CSRF:-}" \
        -H 'content-type: application/json' -X "$1" "$ORIGIN$2" ${3:+--data-binary "$3"}
}
CSRF=$(api GET /auth/v1/preauth | jq -r .csrf_token)
[[ $(api POST /auth/v1/login "{\"username\":\"alex\",\"password\":\"$PASSWORD\"}" | jq -r .authenticated) == true ]] ||
    fail "console login"
CSRF=$(api GET /api/v1/session | jq -r .csrf_token)
echo "ok: signed in to the console API"

# The agent: packaged binary, its exec audit rule, one signed alarm rule.
sudo auditctl -R "$X/etc/audit/rules.d/openvibes-agent.rules" >/dev/null
mkdir -p "$W/agent/state"; chmod 700 "$W/agent/state"
SIGN="$RPMS/sign_bundle"; chmod +x "$SIGN"
KEY=$("$SIGN" keygen "$W/agent/signing.key" | tail -1)
cat > "$W/agent/rules.json" <<'RULES'
{"schema_version":1,"rules":[
 {"id":"web-shell","version":1,"title":"Shell from a web server","severity":"high","confidence":80,
  "kind":"process_event",
  "expression":"event['parent.name'] == 'fake-nginx' && event['process.cmdline'].startsWith('sh -c ')",
  "finding_message":"A web server started a shell"}]}
RULES
"$SIGN" sign "$W/agent/signing.key" "$W/agent/rules.json" alarms-e2e 1 e2e.rules 1 \
    "$W/agent/bundle.json" >/dev/null
admin token create --expires 1h | sed -n 's/^token \([A-Za-z0-9_-]\{43\}\)$/\1/p' > "$W/agent/token"
chmod 600 "$W/agent/token"
cat > "$W/agent/agent.toml" <<EOF
platform_url = "https://127.0.0.1:$INGEST_PORT"
platform_ca_file = "$W/ca/root/root.crt"
state_dir = "$W/agent/state"
enrollment_token_file = "$W/agent/token"
collectors = ["processes", "process_events"]
[[rule_sets]]
id = "alarms-e2e"
bundle_file = "$W/agent/bundle.json"
trusted_keys = [{ issuer_key_id = "e2e.rules", public_key = "$KEY" }]
EOF
sudo systemd-run --quiet --collect --unit ov-alarms-e2e-agent --uid "$(id -u)" --gid "$(id -g)" \
    -p AmbientCapabilities=CAP_AUDIT_READ -p CapabilityBoundingSet=CAP_AUDIT_READ \
    -p NoNewPrivileges=yes "$X/usr/bin/openvibes-agent" "$W/agent/agent.toml"
# cleanup (integration-lib.sh) exits with the status it finds in $?: keep
# the script's own.
trap 'status=$?; sudo systemctl stop ov-alarms-e2e-agent 2>/dev/null
      ((status == 0)) || sudo journalctl -u ov-alarms-e2e-agent -o cat --no-pager | tail -20
      (exit "$status"); cleanup' EXIT
agent_log() { sudo journalctl -u ov-alarms-e2e-agent -o cat --no-pager; }
enrolled() { [[ "$(sql "SELECT count(*) FROM agents WHERE status = 'active'")" == 1 ]]; }
wait_for "agent enrolled" 60 enrolled
reading() { agent_log | grep -q 'reading process starts from kernel audit'; }
wait_for "agent reads kernel audit" 30 reading
scanned() { agent_log | grep -q 'scan matched'; }
wait_for "agent took its rules" 60 scanned

# A web server (a copy of bash named fake-nginx) starts a shell three times.
install -m 0755 /bin/bash /tmp/fake-nginx
/tmp/fake-nginx -c 'for i in 1 2 3; do sh -c id >/dev/null; done'
alarm_with_count() { # COUNT: the web-shell alarm at that count
    api GET /api/v1/alarms | jq -e --argjson n "$1" \
        '.items[] | select(.rule_id == "web-shell" and .count == $n)' >/dev/null
}
wait_for "one alarm, count 3, through POST /v1/alarms" 60 alarm_with_count 3
[[ "$(api GET /api/v1/alarms | jq '[.items[] | select(.rule_id == "web-shell")] | length')" == 1 ]] ||
    fail "the three starts did not collapse into one alarm"
ID=$(api GET /api/v1/alarms | jq -r '.items[] | select(.rule_id == "web-shell") | .id')
DETAIL=$(api GET "/api/v1/alarms/$ID")
jq -e '.parent_exe == "/tmp/fake-nginx" and .process.args == ["sh", "-c", "id"]
       and .ancestors[0].exe == "/tmp/fake-nginx" and (.ancestors | length) >= 2
       and .state == "new"' <<<"$DETAIL" >/dev/null ||
    { echo "$DETAIL" | jq . >&2; fail "the alarm's process tree"; }
echo "ok: the alarm reads back from GET /api/v1/alarms/{id} with its process tree"

# "Don't alarm on this program again", then the same program with another
# command line: stored, and closed by the suppression.
SUPPRESSION=$(api POST /api/v1/alarm-suppressions \
    "{\"alarm_id\":\"$ID\",\"scope\":\"program\",\"note\":\"alarms e2e\"}")
jq -e '.scope == "program"' <<<"$SUPPRESSION" >/dev/null ||
    { echo "$SUPPRESSION" >&2; fail "creating a program suppression"; }
/tmp/fake-nginx -c 'sh -c "id -u" >/dev/null'
suppressed() {
    # The list hides suppressed alarms unless asked.
    api GET '/api/v1/alarms?suppressed=true' | jq -e '.items[] | select(.rule_id == "web-shell" and .id != "'"$ID"'"
        and .suppressed_by != null and .state != "new")' >/dev/null
}
wait_for "the next alarm is closed by the program suppression" 60 suppressed
echo "ok: alarms end to end (real agent, real kernel, platform, console API)"
