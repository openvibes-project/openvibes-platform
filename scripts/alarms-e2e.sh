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
RPMS=$(realpath "$1")
SHARED=${INTEGRATION_DIR:-$HOME/alarms-e2e}
W=$SHARED/platform/run # the platform's integration directory
CONSOLE_PORT=28490
CONSOLE_HEALTH_PORT=28491
ORIGIN="https://127.0.0.1:$CONSOLE_PORT"
PASSWORD="alarms-e2e-Passw0rd!"
fail() { echo "FAIL: $*" >&2; exit 1; }
wait_for() { # DESCRIPTION SECONDS COMMAND...
    local desc=$1 seconds=$2 i
    shift 2
    for ((i = 0; i < seconds; i++)); do
        "$@" >/dev/null 2>&1 && { echo "ok: $desc"; return 0; }
        sleep 1
    done
    fail "$desc (after ${seconds}s)"
}
rm -rf "$SHARED"; mkdir -p "$SHARED/agent/state"; chmod 700 "$SHARED/agent/state"

# The platform: this build's RPMs in fedora:44 (Fedora's glibc), on the
# host network so both sides use 127.0.0.1, as an unprivileged user.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
    -subj /CN=127.0.0.1 -addext subjectAltName=IP:127.0.0.1 \
    -keyout "$SHARED/console.key" -out "$SHARED/console.crt" 2>/dev/null
chmod 644 "$SHARED/console.key" # the container's console user reads it (test key)
podman run -d --name ov-alarms-e2e --network host -v "$ROOT:/src:ro,Z" -v "$RPMS:/rpms:ro,Z" \
    -v "$SHARED:$SHARED:z" -e RPMS=/rpms -e SHARED="$SHARED" -e CONSOLE_PORT="$CONSOLE_PORT" \
    -e CONSOLE_HEALTH_PORT="$CONSOLE_HEALTH_PORT" registry.fedoraproject.org/fedora:44 \
    bash /src/scripts/alarms-e2e-platform.sh >/dev/null
cleanup() {
    local status=$?
    sudo systemctl stop ov-alarms-e2e-agent 2>/dev/null || true
    if ((status != 0)); then
        echo "--- platform (tail)"; podman logs --tail 30 ov-alarms-e2e 2>&1 || true
        for log in "$W"/*.log; do [[ -f $log ]] && { echo "--- $(basename "$log") (tail)"; tail -n 20 "$log"; }; done
        echo "--- agent (tail)"; sudo journalctl -u ov-alarms-e2e-agent -o cat --no-pager | tail -20
    fi
    podman rm -f ov-alarms-e2e >/dev/null 2>&1 || true
    exit "$status"
}
trap cleanup EXIT
in_platform() { podman exec ov-alarms-e2e runuser -u ci -- "$@"; }
admin() { in_platform openvibes-admin --config "$W/admin.toml" "$@"; }
sql() { in_platform psql -h "$W/pg/run" -U openvibes-admin -d openvibes -AtX -c "$1"; }
platform_up() { [[ -e $W/ready ]]; }
wait_for "platform up in fedora:44 (ingest and console)" 300 platform_up
printf '%s\n' "$PASSWORD" | podman exec -i ov-alarms-e2e runuser -u ci -- openvibes-admin \
    --config "$W/admin.toml" user create --username alex --display-name "Alex Admin" \
    --role admin --password-stdin >/dev/null

# The agent on the host, from this build's RPM.
X=$(mktemp -d)
(cd "$X" && rpm2cpio "$(ls "$RPMS"/openvibes-agent-[0-9]*.x86_64.rpm | sort -V | tail -1)" |
    cpio -idm --quiet)

# Console session: preauth CSRF → login → the session's own CSRF value.
JAR="$SHARED/cookies"
api() { # METHOD PATH [JSON]
    curl -sS --cacert "$SHARED/console.crt" -b "$JAR" -c "$JAR" -H "Origin: $ORIGIN" \
        -H "Sec-Fetch-Site: same-origin" -H "X-CSRF-Token: ${CSRF:-}" \
        -H 'content-type: application/json' -X "$1" "$ORIGIN$2" ${3:+--data-binary "$3"}
}
CSRF=$(api GET /auth/v1/preauth | jq -r .csrf_token)
[[ $(api POST /auth/v1/login "{\"username\":\"alex\",\"password\":\"$PASSWORD\"}" | jq -r .authenticated) == true ]] ||
    fail "console login"
CSRF=$(api GET /api/v1/session | jq -r .csrf_token)
echo "ok: signed in to the console API"

# The agent: packaged binary, its exec audit rule, one signed alarm rule.
A=$SHARED/agent
sudo auditctl -R "$X/etc/audit/rules.d/openvibes-agent.rules" >/dev/null
SIGN="$RPMS/sign_bundle"; chmod +x "$SIGN" 2>/dev/null || { cp "$SIGN" "$A/sign_bundle"; chmod +x "$A/sign_bundle"; SIGN=$A/sign_bundle; }
KEY=$("$SIGN" keygen "$A/signing.key" | tail -1)
cat > "$A/rules.json" <<'RULES'
{"schema_version":1,"rules":[
 {"id":"web-shell","version":1,"title":"Shell from a web server","severity":"high","confidence":80,
  "kind":"process_event",
  "expression":"event['parent.name'] == 'fake-nginx' && event['process.cmdline'].startsWith('sh -c ')",
  "finding_message":"A web server started a shell"}]}
RULES
"$SIGN" sign "$A/signing.key" "$A/rules.json" alarms-e2e 1 e2e.rules 1 "$A/bundle.json" >/dev/null
admin token create --expires 1h | sed -n 's/^token \([A-Za-z0-9_-]\{43\}\)$/\1/p' > "$A/token"
chmod 600 "$A/token"
[[ -s $A/token ]] || fail "no enrollment token"
cp "$W/ca/root/root.crt" "$A/platform-ca.crt"
cat > "$A/agent.toml" <<EOF
platform_url = "https://127.0.0.1:28423"
platform_ca_file = "$A/platform-ca.crt"
state_dir = "$A/state"
enrollment_token_file = "$A/token"
collectors = ["processes", "process_events"]
[[rule_sets]]
id = "alarms-e2e"
bundle_file = "$A/bundle.json"
trusted_keys = [{ issuer_key_id = "e2e.rules", public_key = "$KEY" }]
EOF
sudo systemd-run --quiet --collect --unit ov-alarms-e2e-agent --uid "$(id -u)" --gid "$(id -g)" \
    -p AmbientCapabilities=CAP_AUDIT_READ -p CapabilityBoundingSet=CAP_AUDIT_READ \
    -p NoNewPrivileges=yes "$X/usr/bin/openvibes-agent" "$A/agent.toml"
agent_log() { sudo journalctl -u ov-alarms-e2e-agent -o cat --no-pager; }
enrolled() { [[ "$(sql "SELECT count(*) FROM agents WHERE status = 'active'")" == 1 ]]; }
wait_for "agent enrolled" 60 enrolled
reading() { agent_log | grep -q 'reading process starts from kernel audit'; }
wait_for "agent reads kernel audit" 30 reading
scanned() { agent_log | grep -q 'scan matched'; }
wait_for "agent took its rules" 60 scanned

# A web server (a copy of bash named fake-nginx) starts a shell three times.
# Run each start only after the previous one reached the platform. This host
# also audits unrelated CI processes, so a burst can overflow the kernel's
# multicast buffer and lose one of the three events under test.
install -m 0755 /bin/bash /tmp/fake-nginx
alarm_count() {
    api GET /api/v1/alarms | jq -e '[.items[] | select(.rule_id == "web-shell")][0].count // 0'
}
for expected in 1 2 3; do
    deadline=$((SECONDS + 60))
    while [[ $(alarm_count "$expected") -lt $expected ]]; do
        ((SECONDS < deadline)) || fail "one alarm, count $expected, through POST /v1/alarms (after 60s)"
        /tmp/fake-nginx -c 'sh -c id >/dev/null'
        # Retry a start if unrelated audited processes caused the kernel to
        # drop it. The next start waits for this count, keeping aggregation
        # deterministic and preventing a burst from overflowing the buffer.
        for _ in {1..80}; do
            [[ $(alarm_count "$expected") -ge $expected ]] && break
            sleep 0.25
        done
    done
done
[[ $(alarm_count 3) == 3 ]] || fail "expected three starts in one alarm"
[[ "$(api GET /api/v1/alarms | jq '[.items[] | select(.rule_id == "web-shell")] | length')" == 1 ]] ||
    fail "the three starts did not collapse into one alarm"
ID=$(api GET /api/v1/alarms | jq -r '.items[] | select(.rule_id == "web-shell") | .id')
DETAIL=$(api GET "/api/v1/alarms/$ID")
jq -e '.parent_exe == "/tmp/fake-nginx" and .process.args == ["sh", "-c", "id"]
       and .ancestors[0].exe == "/tmp/fake-nginx" and (.ancestors | length) >= 2
       and .state == "open"' <<<"$DETAIL" >/dev/null ||
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
        and .suppressed_by != null and .state != "open")' >/dev/null
}
wait_for "the next alarm is closed by the program suppression" 60 suppressed
echo "ok: alarms end to end (real agent, real kernel, platform, console API)"
