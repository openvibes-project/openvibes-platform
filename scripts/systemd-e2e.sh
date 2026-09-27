#!/usr/bin/env bash
# End to end under systemd: documented Fedora install scripted in podman
# fedora:44 with systemd as PID 1. The platform, agent, optional console, and
# optional local LLM RPMs run as their dedicated users. The agent enrolls,
# fetches signed rules, and delivers findings and inventory; the LLM serves a
# tiny test model to `openvibes-admin assistant check` from inside its sandbox.
# Usage: scripts/systemd-e2e.sh RPM_DIR SIGN_BIN [CONSOLE_OLD_RPM CONSOLE_RPM]
#   RPM_DIR  the openvibes-{ingest,distribution,vulns,admin,llm} RPMs and one
#            openvibes-agent RPM (built from the pinned agent revision)
#   SIGN_BIN the agent repository's sign_bundle example, built
#   CONSOLE_OLD_RPM optional prior-version console RPM for upgrade validation
#   CONSOLE_RPM newer production console RPM
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PODMAN=${PODMAN:-podman}
C=ov-platform-e2e
IMAGE=ov-e2e:44
W=$ROOT/target/systemd-e2e
[[ $# == 2 || $# == 4 ]] || { echo "usage: $0 RPM_DIR SIGN_BIN [CONSOLE_OLD_RPM CONSOLE_RPM]" >&2; exit 2; }
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }
in_c() { "$PODMAN" exec "$C" bash -c "$1"; }
wait_for() {
    local desc=$1 seconds=$2 i
    for ((i = 0; i < seconds; i++)); do
        if in_c "$3" >/dev/null 2>&1; then ok "$desc"; return 0; fi
        sleep 1
    done
    fail "$desc (after ${seconds}s)"
}
cleanup() {
    local status=$?
    if ((status != 0)); then
        for unit in openvibes-ingest openvibes-distribution openvibes-vulns openvibes-agent openvibes-console openvibes-llm; do
            echo "--- $unit"
            "$PODMAN" exec "$C" journalctl -u "$unit" --no-pager -n 15 2>/dev/null || true
        done
    fi
    "$PODMAN" rm -f "$C" >/dev/null 2>&1 || true
    exit "$status"
}
trap cleanup EXIT

rm -rf "$W"; mkdir -p "$W"
cp "$1"/openvibes-{ingest,distribution,vulns,admin,llm,agent}-*.rpm "$W/"
(($(ls "$W"/openvibes-agent-*.rpm | wc -l) == 1)) || fail "want exactly one agent RPM in $1"
cp "$2" "$W/sign_bundle"
KEY=$("$W/sign_bundle" keygen "$W/signing.key" | tail -1)
cat > "$W/rules.json" <<'RULES'
{"schema_version":1,"rules":[
 {"id":"host.has.processes","version":1,"title":"Processes are running","severity":"info",
  "confidence":100,"expression":"facts['process.count'] >= 1","finding_message":"The host runs processes"}]}
RULES
"$W/sign_bundle" sign "$W/signing.key" "$W/rules.json" baseline 1 org.rules 7 "$W/bundle.json" >/dev/null
python3 "$ROOT/scripts/tiny-gguf.py" "$W/tiny.gguf"

printf 'FROM registry.fedoraproject.org/fedora:44
RUN dnf -q -y install systemd postgresql-server procps-ng util-linux util-linux-script curl openssl polkit sudo && dnf clean all
' |
    "$PODMAN" build -q -t "$IMAGE" -f - "$W" >/dev/null
"$PODMAN" rm -f "$C" >/dev/null 2>&1 || true
# Rootless --privileged: privileged only inside the container's user
# namespace; it lets systemd apply the units' sandboxes (see the agent's
# scripts/systemd-test.sh).
"$PODMAN" run -d --systemd=always --privileged --name "$C" -v "$W:/test:Z" "$IMAGE" /sbin/init >/dev/null
wait_for "systemd is up" 30 'systemctl is-system-running | grep -qE "running|degraded"'
[[ "$(in_c 'systemd-run --wait -q -p ProtectSystem=strict --pipe bash -c "touch /usr/.probe 2>/dev/null && echo writable || echo blocked"')" == blocked ]] ||
    fail "this container does not enforce systemd sandboxing"
ok "systemd enforces unit sandboxes in this container"

# 1-2. PostgreSQL, the platform RPMs, database and schema.
in_c 'postgresql-setup --initdb && systemctl enable --now postgresql' >/dev/null 2>&1 || fail "postgresql"
in_c 'dnf -q -y install /test/openvibes-ingest-*.rpm /test/openvibes-distribution-*.rpm /test/openvibes-vulns-*.rpm /test/openvibes-admin-*.rpm' \
    >/dev/null 2>&1 || fail "install platform RPMs"
in_c 'runuser -u postgres -- createuser --createrole openvibes-admin &&
      runuser -u postgres -- createdb -O openvibes-admin openvibes &&
      runuser -u openvibes-admin -- openvibes-admin migrate &&
      runuser -u openvibes-admin -- openvibes-admin maintenance' >/dev/null || fail "database"
ok "platform installed, schema migrated"

# Optional C5 package validation. Install only after the platform migrations
# create the least-privilege console database role and schema.
if [[ $# == 4 ]]; then
    cp "$3" "$W/openvibes-console-old.rpm"
    cp "$4" "$W/openvibes-console.rpm"
    in_c '! command -v node >/dev/null && ! command -v npm >/dev/null' || fail "test container unexpectedly has Node.js"
    in_c 'dnf -q -y install /test/openvibes-console-old.rpm' >/dev/null 2>&1 || fail "install prior console RPM"
    in_c 'test "$(rpm -q --qf "%{VERSION}" openvibes-console)" = "$(rpm -qp --qf "%{VERSION}" /test/openvibes-console-old.rpm)" && ! command -v node >/dev/null && ! command -v npm >/dev/null' || fail "console RPM version or runtime dependencies"
    in_c 'set -e
          openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
              -subj "/CN=console.example.invalid" \
              -addext "subjectAltName=DNS:console.example.invalid" \
              -keyout /etc/openvibes/tls/console-key.pem \
              -out /etc/openvibes/tls/console-chain.pem >/dev/null 2>&1
          chown root:openvibes-console /etc/openvibes/tls/console-{key,chain}.pem
          chmod 0640 /etc/openvibes/tls/console-{key,chain}.pem
          cat > /etc/openvibes/console.toml <<TOML
development_listen = "0.0.0.0:443"
health_listen = "127.0.0.1:18482"
transport_mode = "direct_tls"
database_url = "postgresql:///openvibes?host=/run/postgresql&user=openvibes-console"
public_origin = "https://console.example.invalid"
server_certificate_file = "/etc/openvibes/tls/console-chain.pem"
server_key_file = "/etc/openvibes/tls/console-key.pem"
TOML
          chown root:openvibes-console /etc/openvibes/console.toml
          chmod 0640 /etc/openvibes/console.toml
          systemctl enable --now openvibes-console' >/dev/null 2>&1 || fail "configure/start console"
    wait_for "console ready over loopback health" 30 '[[ "$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:18482/ready)" == 204 ]]'
    wait_for "console serves over TLS" 30 '[[ "$(curl -ksS --resolve console.example.invalid:443:127.0.0.1 -o /dev/null -w "%{http_code}" https://console.example.invalid/)" == 200 ]]'
    in_c 'set -e
          curl -ksS --resolve console.example.invalid:443:127.0.0.1 -D /tmp/console.headers -o /dev/null https://console.example.invalid/
          grep -qi "^strict-transport-security: max-age=31536000" /tmp/console.headers
          grep -qi "^content-security-policy:.*frame-ancestors '\''none'\''" /tmp/console.headers
          grep -qi "^x-content-type-options: nosniff" /tmp/console.headers
          pid=$(systemctl show -p MainPID --value openvibes-console)
          grep -q "^Seccomp:[[:space:]]*2$" /proc/$pid/status
          grep -q "^NoNewPrivs:[[:space:]]*1$" /proc/$pid/status' || fail "console headers or systemd sandbox"
    ok "console RPM serves hardened TLS with production headers"

    in_c 'set -e
          password="C5-systemd-upgrade-check-2026!"
          printf "%s\n%s\n" "$password" "$password" |
            script -q -c "runuser -u openvibes-admin -- openvibes-admin user create --username c5-upgrade --display-name C5Upgrade --role admin" /dev/null >/dev/null
          curl -ksS --resolve console.example.invalid:443:127.0.0.1 \
            -c /tmp/c5-cookies -o /tmp/c5-preauth.json \
            https://console.example.invalid/auth/v1/preauth
          csrf=$(sed -n "s/.*\"csrf_token\":\"\\([^\"]*\\)\".*/\\1/p" /tmp/c5-preauth.json)
          test -n "$csrf"
          status=$(curl -ksS --resolve console.example.invalid:443:127.0.0.1 \
            -b /tmp/c5-cookies -c /tmp/c5-cookies \
            -H "Origin: https://console.example.invalid" \
            -H "Sec-Fetch-Site: same-origin" -H "X-CSRF-Token: $csrf" \
            -H "Content-Type: application/json" \
            -d "{\"username\":\"c5-upgrade\",\"password\":\"$password\"}" \
            -o /tmp/c5-login.json -w "%{http_code}" \
            https://console.example.invalid/auth/v1/login)
          test "$status" = 200
          session_hash=$(runuser -u openvibes-admin -- psql -d openvibes -Atqc \
            "SELECT encode(s.session_sha256, '\''hex'\'') FROM console_sessions s JOIN console_users u USING (user_id) WHERE u.username = '\''c5-upgrade'\'' AND s.revoked_at IS NULL ORDER BY s.created_at DESC LIMIT 1")
          test -n "$session_hash"
          printf "%s" "$session_hash" > /tmp/c5-session-hash' || fail "create authenticated upgrade fixture"
    in_c 'touch /var/lib/openvibes-console/c5-upgrade-sentinel &&
          dnf -q -y upgrade /test/openvibes-console.rpm' >/dev/null 2>&1 || fail "upgrade console RPM"
    in_c 'test "$(rpm -q --qf "%{VERSION}" openvibes-console)" = "$(rpm -qp --qf "%{VERSION}" /test/openvibes-console.rpm)" && ! command -v node >/dev/null && ! command -v npm >/dev/null' || fail "console RPM version or runtime dependencies after upgrade"
    in_c 'test -f /var/lib/openvibes-console/c5-upgrade-sentinel &&
          grep -q direct_tls /etc/openvibes/console.toml &&
          test -r /etc/openvibes/tls/console-key.pem' || fail "console upgrade changed local state"
    in_c 'set -e
          session_hash=$(cat /tmp/c5-session-hash)
          session_hash_after=$(runuser -u openvibes-admin -- psql -d openvibes -Atqc \
            "SELECT encode(s.session_sha256, '\''hex'\'') FROM console_sessions s JOIN console_users u USING (user_id) WHERE u.username = '\''c5-upgrade'\'' AND s.revoked_at IS NULL ORDER BY s.created_at DESC LIMIT 1")
          test "$session_hash_after" = "$session_hash"
          runuser -u openvibes-admin -- psql -d openvibes -Atqc \
            "SELECT 1 FROM console_users WHERE username = '\''c5-upgrade'\''" | grep -qx 1
          status=$(curl -ksS --resolve console.example.invalid:443:127.0.0.1 \
            -b /tmp/c5-cookies -o /tmp/c5-session.json -w "%{http_code}" \
            https://console.example.invalid/api/v1/session)
          test "$status" = 200' || fail "console RPM upgrade lost authenticated database state"
    wait_for "console remains ready after RPM upgrade" 30 '[[ "$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:18482/ready)" == 204 ]]'
    wait_for "console remains available over TLS after RPM upgrade" 30 \
        '[[ "$(curl -ksS --resolve console.example.invalid:443:127.0.0.1 -o /dev/null -w "%{http_code}" https://console.example.invalid/)" == 200 ]]'
    ok "console RPM upgrade preserves config, TLS, local account, database session, and authenticated access"

    in_c 'cat > /etc/openvibes/console.toml <<TOML
development_listen = "0.0.0.0:443"
health_listen = "127.0.0.1:18482"
transport_mode = "reverse_proxy"
database_url = "postgresql:///openvibes?host=/run/postgresql&user=openvibes-console"
public_origin = "https://console.example.invalid"
unix_socket_file = "/run/openvibes-console/console.sock"
trusted_proxy_uids = [0]
TOML
          systemctl restart openvibes-console' >/dev/null 2>&1 || fail "configure Unix proxy mode"
    wait_for "console Unix proxy socket" 30 '[[ -S /run/openvibes-console/console.sock ]]'
    wait_for "allowed Unix proxy UID serves shell" 30 \
        '[[ "$(curl -sS --unix-socket /run/openvibes-console/console.sock -H "Host: console.example.invalid" -o /dev/null -w "%{http_code}" http://localhost/)" == 200 ]]'
    in_c 'set -e
          status=$(runuser -u openvibes-console -- curl -sS --unix-socket /run/openvibes-console/console.sock -H "Host: console.example.invalid" -o /dev/null -w "%{http_code}" http://localhost/)
          [[ "$status" == 403 ]]' || fail "reject untrusted Unix proxy UID"
    ok "console Unix proxy accepts only the configured peer UID"
fi

# 3-4, 7. CA: the root (here in the container, normally offline), the
# intermediate, and one server certificate each for ingest and distribution.
in_c 'set -e
      A="runuser -u openvibes-admin -- openvibes-admin"
      openvibes-admin ca init-root --out /root/ca-root >/dev/null
      S=/run/openvibes-ca
      install -d -o openvibes-admin -g openvibes-admin -m 0700 $S
      $A ca intermediate-request --out $S/int >/dev/null
      openvibes-admin ca sign-intermediate --root /root/ca-root --csr $S/int/intermediate.csr \
          --out $S/int/intermediate.crt >/dev/null
      install -o openvibes-admin -m 0644 /root/ca-root/root.crt $S/int/root.crt
      chown openvibes-admin $S/int/intermediate.crt
      $A ca import-intermediate --cert $S/int/intermediate.crt --key $S/int/intermediate.key \
          --root-cert $S/int/root.crt >/dev/null
      for name in localhost rules.localhost; do
          $A ca issue-server $name --san 127.0.0.1 --issuer-cert $S/int/intermediate.crt \
              --issuer-key $S/int/intermediate.key --out $S/tls >/dev/null
      done
      install -m 0644 $S/int/intermediate.crt /etc/openvibes/pki/intermediate.crt
      install -o openvibes-ingest -g openvibes-ingest -m 0600 $S/int/intermediate.key /var/lib/openvibes-ingest/intermediate.key
      install -m 0644 $S/tls/localhost.crt /etc/openvibes/tls/ingest.crt
      install -o openvibes-ingest -g openvibes-ingest -m 0600 $S/tls/localhost.key /etc/openvibes/tls/ingest.key
      install -m 0644 $S/tls/rules.localhost.crt /etc/openvibes/tls/distribution.crt
      install -o openvibes-distribution -g openvibes-distribution -m 0600 $S/tls/rules.localhost.key /etc/openvibes/tls/distribution.key
      rm -r $S' || fail "CA"
ok "CA and server certificates installed"

# 5-7. Services.
in_c 'systemctl enable --now openvibes-ingest openvibes-distribution' >/dev/null 2>&1 || fail "start services"
wait_for "ingest ready" 30 'curl -fsS http://127.0.0.1:18480/ready'
wait_for "distribution ready" 30 'curl -fsS http://127.0.0.1:18481/ready'

# Vulnerabilities (VM): the service runs offline (its mirror list points at
# a closed loopback port, so checks fail and are recorded, and KEV, EPSS,
# NVD, EUVD are turned off); an offline feed
# says bash is fixed in 999.0, above the container's bash. It is imported
# before the agent enrolls, so the vulnerability can only open through the
# service's re-match when the agent's inventory arrives.
# An offline KEV file then marks the advisory's CVE as exploited.
cat > "$W/updateinfo-test.xml" <<'FEED'
<?xml version="1.0" encoding="UTF-8"?>
<updates>
  <update from="test" status="stable" type="security" version="2.0">
    <id>FEDORA-TEST-bash</id>
    <title>bash-999.0-1.fc44</title>
    <issued date="2026-09-25 00:00:00"/>
    <severity>Important</severity>
    <description>Test advisory for CVE-2026-99999.</description>
    <references/>
    <pkglist><collection short="F44"><name>Fedora 44</name>
      <package name="bash" version="999.0" release="1.fc44" epoch="0" arch="x86_64"><filename>bash-999.0-1.fc44.x86_64.rpm</filename></package>
    </collection></pkglist>
  </update>
</updates>
FEED
in_c "sed -i -e 's|^metalink_url = .*|metalink_url = \"http://127.0.0.1:9/metalink?release={release}\&arch={arch}\"|' \
             -e 's#^\(kev\|epss\|nvd\|euvd\|osv\)_url = .*#\1_url = \"\"#' /etc/openvibes/vulns.toml &&
      systemctl enable --now openvibes-vulns" >/dev/null 2>&1 || fail "start vulns"
wait_for "vulns service ready" 30 'curl -fsS http://127.0.0.1:18483/ready'
in_c 'runuser -u openvibes-admin -- openvibes-admin feeds import /test/updateinfo-test.xml --source fedora-44-x86_64' >/dev/null ||
    fail "feeds import"
printf '{"vulnerabilities":[{"cveID":"CVE-2026-99999","dateAdded":"2026-09-25","knownRansomwareCampaignUse":"Known"}]}' \
    > "$W/kev-test.json"
in_c 'runuser -u openvibes-admin -- openvibes-admin feeds import /test/kev-test.json --source kev' >/dev/null ||
    fail "kev import"
ok "offline feed and KEV imported"

# Rules: trust the signing key and publish the signed bundle.
in_c "set -e
      runuser -u openvibes-admin -- openvibes-admin rules trust add baseline org.rules -- \"$KEY\"
      runuser -u openvibes-admin -- openvibes-admin rules publish /test/bundle.json" >/dev/null 2>&1 ||
    fail "publish rules"
ok "rules trusted and published"

# The agent, as its first-run steps say.
TOKEN=$(in_c 'runuser -u openvibes-admin -- openvibes-admin token create --expires 1h' |
    sed -n 's/^token \([A-Za-z0-9_-]\{43\}\)$/\1/p')
[[ -n "$TOKEN" ]] || fail "no token"
in_c 'dnf -q -y install /test/openvibes-agent-*.rpm' >/dev/null 2>&1 || fail "install agent"
in_c "install -m 0644 /root/ca-root/root.crt /etc/openvibes-agent/platform-ca.crt &&
      printf '%s\n' '$TOKEN' > /run/token &&
      install -o openvibes_agent -g openvibes_agent -m 0600 /run/token /etc/openvibes-agent/token && rm /run/token" ||
    fail "agent files"
[[ "$(in_c 'stat -c "%a %U" /etc/openvibes-agent/token')" == "600 openvibes_agent" ]] ||
    fail "token file is not 0600 openvibes_agent"
in_c "cat > /etc/openvibes-agent/agent.toml <<TOML
state_dir = \"/var/lib/openvibes-agent\"
platform_url = \"https://localhost\"
platform_ca_file = \"/etc/openvibes-agent/platform-ca.crt\"
enrollment_token_file = \"/etc/openvibes-agent/token\"
distribution_url = \"https://127.0.0.1\"
[[rule_sets]]
id = \"baseline\"
trusted_keys = [{ issuer_key_id = \"org.rules\", public_key = \"$KEY\" }]
TOML
systemctl enable --now openvibes-agent" >/dev/null 2>&1 || fail "start agent"

# Every service runs sandboxed: seccomp filter and no_new_privs in force.
for unit in openvibes-ingest openvibes-distribution openvibes-vulns openvibes-agent; do
    in_c "pid=\$(systemctl show -p MainPID --value $unit);
          grep -q '^Seccomp:[[:space:]]*2\$' /proc/\$pid/status &&
          grep -q '^NoNewPrivs:[[:space:]]*1\$' /proc/\$pid/status" ||
        fail "$unit: seccomp filter or no_new_privs not in force"
done
ok "ingest, distribution, vulns, and agent run with seccomp and no_new_privs"
SQL='runuser -u openvibes-admin -- psql -d openvibes -AtX -c'
wait_for "agent enrolled" 60 "[[ \$($SQL \"SELECT count(*) FROM agents WHERE status = 'active'\") == 1 ]]"
wait_for "agent fetched its rules from distribution (200)" 120 \
    'journalctl -u openvibes-distribution -o cat | grep -q "\"endpoint\":\"/v1/rule-bundle\".*\"status\":200"'
wait_for "findings from the published rule set in PostgreSQL" 120 \
    "[[ \$($SQL \"SELECT count(*) FROM findings WHERE rule_set_id = 'baseline' AND rule_id = 'host.has.processes'\") -ge 1 ]]"
wait_for "the agent's inventory is stored (protocol P8)" 120 \
    "[[ \$($SQL \"SELECT count(*) FROM host_packages\") -gt 100 ]]"
wait_for "the vulns service re-matched the host: bash vulnerable" 60 \
    "[[ \$($SQL \"SELECT count(*) FROM vulnerabilities WHERE advisory_id = 'FEDORA-TEST-bash' AND fixed_at IS NULL\") == 1 ]]"
in_c 'runuser -u openvibes-admin -- openvibes-admin vulns list' | grep -q 'FEDORA-TEST-bash.*bash .* -> .*999.0-1.fc44' ||
    fail "vulns list does not show the bash vulnerability"
in_c 'runuser -u openvibes-admin -- openvibes-admin vulns list' | grep -q 'FEDORA-TEST-bash.*exploited (KEV, ransomware)' ||
    fail "vulns list does not show the KEV mark"
ok "openvibes-admin vulns list shows it, marked exploited (KEV)"

# 7b. File import (P3b): a local-only agent's export becomes an imported host
# whose inventory the vulns service matches like an enrolled one.
in_c 'install -d -m 0700 /run/local-state /run/exports &&
      printf "state_dir = \"/run/local-state\"\n" > /run/local.toml &&
      openvibes-agent export /run/local.toml /run/exports' >/dev/null 2>&1 || fail "local-only export"
in_c 'chmod 0755 /run/exports && chmod 0644 /run/exports/*.json &&
      runuser -u openvibes-admin -- openvibes-admin import /run/exports' | grep -q 'inventory accepted' ||
    fail "import of the export files"
IMP=$(in_c "$SQL \"SELECT agent_id FROM agents WHERE status = 'imported'\"")
[[ "$IMP" == import.* ]] || fail "no imported host"
wait_for "the vulns service matched the imported host: bash vulnerable" 60 \
    "[[ \$($SQL \"SELECT count(*) FROM vulnerabilities WHERE agent_id = '$IMP' AND advisory_id = 'FEDORA-TEST-bash' AND fixed_at IS NULL\") == 1 ]]"
in_c 'runuser -u openvibes-admin -- openvibes-admin agent list --imported' | grep -q "^$IMP  imported" ||
    fail "agent list --imported"
ok "openvibes-admin import stores a local-only export as a matched imported host"

# 7c. Operators (admin TUI PR 1): a member of openvibes-operators restarts a
# unit through polkit and reads its log through the root helper, without a
# password; a non-member cannot, and neither can reach other units. The
# full-screen TUI itself is covered by its snapshot tests; this checks the
# rights it relies on.
in_c 'useradd -m -G openvibes-operators alice && useradd -m bob' || fail "operator users"
in_c 'runuser -u alice -- systemctl --no-ask-password restart openvibes-vulns.service' ||
    fail "operator restart through polkit"
wait_for "vulns ready after the operator's restart" 30 'curl -fsS http://127.0.0.1:18483/ready'
in_c 'runuser -u bob -- systemctl --no-ask-password restart openvibes-vulns.service' >/dev/null 2>&1 &&
    fail "a non-operator restarted a unit"
in_c 'runuser -u alice -- systemctl --no-ask-password restart systemd-journald.service' >/dev/null 2>&1 &&
    fail "an operator restarted a unit outside the allow-list"
in_c 'runuser -u alice -- systemctl --no-ask-password enable openvibes-llm.service' >/dev/null 2>&1 &&
    fail "an operator enabled a unit without a password"
# sudo's rules are checked as root with `sudo -l -U USER COMMAND` (exit 0
# only if the policy allows it without a password): on the CI runner's
# rootless podman, setuid does not take effect, so sudo run by alice never
# becomes root and PAM cannot read /etc/shadow. The helper is then run as
# root, as sudo would run it.
allowed() { in_c "sudo -n -l -U $1 $2" >/dev/null 2>&1; }
allowed alice '/usr/bin/openvibes-admin helper logs openvibes-vulns.service 5' ||
    fail "operators may not read logs through the helper"
allowed alice '-u openvibes-admin /usr/bin/openvibes-admin status' ||
    fail "operators may not run openvibes-admin as openvibes-admin"
allowed bob '/usr/bin/openvibes-admin helper logs openvibes-vulns.service 5' &&
    fail "a non-operator may read logs"
allowed bob '-u openvibes-admin /usr/bin/openvibes-admin status' &&
    fail "a non-operator may run openvibes-admin as openvibes-admin"
allowed alice '/usr/bin/openvibes-admin helper config-write ingest' &&
    fail "operators may run helper verbs beyond logs"
in_c '/usr/bin/openvibes-admin helper logs openvibes-vulns.service 5' | grep -q . ||
    fail "the helper, as root, reads a unit's log"
in_c '/usr/bin/openvibes-admin helper logs systemd-journald.service 5' >/dev/null 2>&1 &&
    fail "the helper read a unit outside the allow-list"
in_c 'runuser -u openvibes-admin -- /usr/bin/openvibes-admin status' >/dev/null ||
    fail "openvibes-admin status as openvibes-admin"
ok "operators restart units through polkit; sudo lets them read logs and use the admin CLI; others cannot"

# 8. openvibes-llm (assistant AS5): refuses to start without a verified
# model, serves the tiny test model on loopback behind its API key, runs
# sandboxed, and refuses a model file changed after installation.
LLM=http://127.0.0.1:18430
in_c 'dnf -q -y install /test/openvibes-llm-*.rpm' >/dev/null 2>&1 || fail "install openvibes-llm"
in_c 'systemctl start openvibes-llm' >/dev/null 2>&1 && fail "openvibes-llm started without a model"
in_c 'journalctl -u openvibes-llm -o cat | grep -q "OPENVIBES_LLM_MODEL is not set"' ||
    fail "openvibes-llm did not say that no model is installed"
ok "openvibes-llm refuses to start without a model"
SHA=$(sha256sum "$W/tiny.gguf" | cut -d' ' -f1)
in_c "runuser -u openvibes-admin -- openvibes-admin assistant model install /test/tiny.gguf --sha256 $SHA --alias tiny" \
    >/dev/null || fail "model install"
[[ "$(in_c 'stat -c "%a" /var/lib/openvibes-llm/models/tiny.gguf')" == 444 ]] || fail "installed model is not read-only"
in_c 'systemctl reset-failed openvibes-llm; systemctl enable --now openvibes-llm' >/dev/null 2>&1 || fail "start openvibes-llm"
wait_for "openvibes-llm ready" 60 "curl -fsS $LLM/health"
in_c "pid=\$(systemctl show -p MainPID --value openvibes-llm);
      [[ \$(stat -c %U /proc/\$pid) == openvibes-llm ]] &&
      grep -q '^Seccomp:[[:space:]]*2\$' /proc/\$pid/status &&
      grep -q '^NoNewPrivs:[[:space:]]*1\$' /proc/\$pid/status &&
      grep -q '^CapEff:[[:space:]]*0*\$' /proc/\$pid/status &&
      [[ \$(systemctl show -p IPAddressDeny --value openvibes-llm) == *0.0.0.0/0* ]]" ||
    fail "openvibes-llm: not its own user, or seccomp, no_new_privs, no capabilities, or the IP deny list not in force"
ok "openvibes-llm runs as its own user with seccomp, no_new_privs, no capabilities, loopback only"
CHAT='{"model":"tiny","messages":[{"role":"user","content":"hello"}],"max_tokens":4}'
[[ "$(in_c "curl -s -o /dev/null -w '%{http_code}' -H 'content-type: application/json' -d '$CHAT' $LLM/v1/chat/completions")" == 401 ]] ||
    fail "openvibes-llm answered without the API key"
in_c "curl -fsS -H \"authorization: Bearer \$(cat /etc/openvibes/llm-api-key)\" -H 'content-type: application/json' \
      -d '$CHAT' $LLM/v1/chat/completions | grep -q '\"choices\"'" || fail "openvibes-llm did not answer with the API key"
ok "openvibes-llm answers only with its API key"
# The console reads the key as its own credential; here openvibes-admin gets
# a private copy for the check.
in_c "install -o openvibes-admin -m 0600 /etc/openvibes/llm-api-key /run/llm-key &&
      printf '[assistant]\nenabled = true\n[assistant.backend]\nurl = \"$LLM/v1\"\nmodel = \"tiny\"\napi_key_file = \"/run/llm-key\"\n' > /run/console.toml &&
      chmod 0644 /run/console.toml &&
      runuser -u openvibes-admin -- openvibes-admin assistant check --file /run/console.toml > /run/check.out 2>&1" ||
    { in_c 'cat /run/check.out' || true; fail "assistant check against openvibes-llm"; }
in_c 'grep -q "models listed 1 (configured model listed)" /run/check.out && grep -q "^first token" /run/check.out' ||
    fail "assistant check output"
ok "openvibes-admin assistant check passes against openvibes-llm"
in_c 'f=/var/lib/openvibes-llm/models/tiny.gguf; chmod 0644 $f && printf x >> $f && chmod 0444 $f &&
      systemctl restart openvibes-llm' >/dev/null 2>&1 && fail "openvibes-llm started with a changed model file"
in_c 'journalctl -u openvibes-llm -o cat | grep -q "does not match OPENVIBES_LLM_MODEL_SHA256"' ||
    fail "openvibes-llm did not report the changed model"
ok "openvibes-llm refuses a model file changed after installation"
echo "systemd-e2e: all checks passed"
