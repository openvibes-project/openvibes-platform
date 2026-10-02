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
        for unit in openvibes-ingest openvibes-distribution openvibes-vulns openvibes-agent openvibes-console openvibes-llm openvibes-signer; do
            echo "--- $unit"
            "$PODMAN" exec "$C" journalctl -u "$unit" --no-pager -n 15 2>/dev/null || true
        done
    fi
    "$PODMAN" rm -f "$C" >/dev/null 2>&1 || true
    exit "$status"
}
trap cleanup EXIT

rm -rf "$W"; mkdir -p "$W"
cp "$1"/openvibes-{ingest,distribution,vulns,admin,llm,agent,signer}-*.rpm "$W/"
(($(ls "$W"/openvibes-agent-*.rpm | wc -l) == 1)) || fail "want exactly one agent RPM in $1"
cp "$2" "$W/sign_bundle"
KEY=$("$W/sign_bundle" keygen "$W/signing.key" | tail -1)
cat > "$W/rules.json" <<'RULES'
{"schema_version":1,"rules":[
 {"id":"host.has.processes","version":1,"title":"Processes are running","severity":"info",
  "confidence":100,"expression":"facts['process.count'] >= 1","finding_message":"The host runs processes"}]}
RULES
# Valid for 30 days: a bundle expiring within 7 is reported as
# rule_set_expiring (P12), and the agent must show as healthy below.
"$W/sign_bundle" sign "$W/signing.key" "$W/rules.json" baseline 1 org.rules 30 "$W/bundle.json" >/dev/null
# Version 2 of the same rule never matches: the P13 check below ends it.
sed -e 's/"version":1/"version":2/' -e "s/>= 1/< 0/" "$W/rules.json" > "$W/rules-v2.json"
"$W/sign_bundle" sign "$W/signing.key" "$W/rules-v2.json" baseline 2 org.rules 30 "$W/bundle-v2.json" >/dev/null
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

# 1-7. As the install script will: install openvibes-admin, then Setup
# without screens (admin TUI spec §6.6) from the RPMs in /test: PostgreSQL,
# the platform packages, database, schema, quick CA, server certificates
# for localhost and 127.0.0.1, services, readiness. The console and the
# agent are installed further down (upgrade check, and the vulnerability
# must open through the re-match); the container has no firewalld.
in_c 'dnf -q -y install /test/openvibes-admin-*.rpm' >/dev/null 2>&1 || fail "install openvibes-admin"
SETUP='openvibes-admin setup --quick --components ingest,distribution,vulns --hostname localhost \
       --san 127.0.0.1 --repo-dir /test --allow-unsigned-local'
in_c "$SETUP --root-key-out /root/ca-root.key" > "$W/setup.out" 2>&1 || { cat "$W/setup.out"; fail "setup --quick"; }
grep -q '^Readiness: done' "$W/setup.out" || { cat "$W/setup.out"; fail "setup did not finish"; }
grep -q '^Firewall: skipped' "$W/setup.out" || fail "firewall step should be skipped without firewalld"
[[ "$(in_c 'stat -c "%a %U" /var/lib/openvibes-ingest/intermediate.key /root/ca-root.key')" == $'600 openvibes-ingest\n600 root' ]] ||
    fail "CA key files have the wrong owner or mode"
in_c '! test -e /run/openvibes-ca' || fail "CA staging directory left behind"
# Re-running is safe: every step is already done and nothing is redone.
in_c "$SETUP --root-key-out /root/ca-root-2.key" > "$W/setup2.out" 2>&1 || { cat "$W/setup2.out"; fail "second setup --quick"; }
! grep -qE ': (to do|failed|waiting)' "$W/setup2.out" || { cat "$W/setup2.out"; fail "second run redid a step"; }
in_c '! test -e /root/ca-root-2.key' || fail "second run created another root"
ok "platform installed and set up by setup --quick (and re-run safely)"

# The rule signer (board #107) under its unit: seeded as its user, it
# starts sandboxed with no network, and only its socket group reaches it.
in_c 'dnf -q -y install /test/openvibes-signer-*.rpm' >/dev/null 2>&1 || fail "install openvibes-signer"
SITE_TRUST=$(in_c 'runuser -u openvibes-signer -g openvibes-signer-clients -- openvibes-signer seed --min-version 1')
grep -q '^site-alarms site.key ' <<<"$SITE_TRUST" || fail "signer seed printed no trust line"
SITE_KEY=$(awk '$1 == "site" { print $3 }' <<<"$SITE_TRUST")
in_c 'systemctl start openvibes-signer' || fail "start openvibes-signer"
wait_for "the signer listens on its socket" 30 'test -S /run/openvibes-signer/sign.sock'
[[ "$(in_c 'stat -c "%a %U:%G" /run/openvibes-signer /run/openvibes-signer/sign.sock /var/lib/openvibes-signer/site.key')" == \
    $'750 openvibes-signer:openvibes-signer-clients\n660 openvibes-signer:openvibes-signer-clients\n600 openvibes-signer:openvibes-operators' ]] ||
    fail "signer socket or key has the wrong owner or mode"
[[ "$(in_c 'grep -E "^(NoNewPrivs|Seccomp):" /proc/$(systemctl show -p MainPID --value openvibes-signer)/status | tr -s "\t " " "')" == \
    $'NoNewPrivs: 1\nSeccomp: 2' ]] || fail "signer runs without no_new_privs and seccomp"
in_c 'useradd -M outsider && useradd -M insider -G openvibes-signer-clients' || fail "add test users"
in_c '! runuser -u outsider -- test -r /run/openvibes-signer/sign.sock' || fail "a non-member reaches the signer socket"
in_c 'runuser -u insider -- test -w /run/openvibes-signer/sign.sock' || fail "a member of openvibes-signer-clients cannot reach the socket"
# status.json (written on the first tick) reaches operators, not others,
# under the unit's UMask=0077.
wait_for "the signer wrote status.json" 10 'test -s /var/lib/openvibes-signer/status.json'
[[ "$(in_c 'stat -c "%a %U:%G" /var/lib/openvibes-signer/status.json')" == "640 openvibes-signer:openvibes-operators" ]] ||
    fail "status.json is $(in_c 'stat -c "%a %U:%G" /var/lib/openvibes-signer/status.json'), want 640 openvibes-signer:openvibes-operators"
ok "the signer runs sandboxed and only its socket group reaches it"

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
      systemctl restart openvibes-vulns" >/dev/null 2>&1 || fail "restart vulns offline"
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
in_c "install -m 0644 /etc/openvibes/pki/root.crt /etc/openvibes-agent/platform-ca.crt &&
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

# The site's own rules end to end (board #107): a console user publishes a
# rule set through the signer (which checks the password itself), the
# platform serves it, and an agent with the site lines reports findings.
cat > "$W/site.json" <<'RULES'
{"schema_version":1,"rules":[
 {"id":"site.processes","version":1,"title":"Our own check","severity":"info",
  "confidence":100,"expression":"facts['process.count'] >= 1","finding_message":"Written by the site"}]}
RULES
in_c "set -e
      printf '%s\n' 'a long enough publisher password' |
          runuser -u openvibes-admin -- openvibes-admin user create --username publisher \
              --display-name Publisher --role operator --password-stdin
      usermod -aG openvibes-signer-clients openvibes-admin
      runuser -u openvibes-admin -- openvibes-admin rules trust add site site.key -- '$SITE_KEY'" >/dev/null 2>&1 ||
    fail "site publisher, socket group and trust"
out=$(in_c "printf 'wrong password, long enough\n' | runuser -u openvibes-admin -- openvibes-admin rules publish-site \
    --user publisher --set site --password-stdin /test/site.json" 2>&1) && fail "published with a wrong password"
[[ "$out" == *"wrong username or password"* ]] || fail "wrong password: $out"
in_c "printf 'a long enough publisher password\n' | runuser -u openvibes-admin -- openvibes-admin rules publish-site \
    --user publisher --set site --password-stdin /test/site.json" > "$W/publish-site.out" 2>&1 ||
    { cat "$W/publish-site.out"; fail "publish-site"; }
in_c 'journalctl -u openvibes-signer -o cat | grep -q "\"audit\":\"rules.sign\".*\"result\":\"signed\""' ||
    fail "the signer's journal has no audit line for the signature"
in_c "cat >> /etc/openvibes-agent/agent.toml <<TOML
[[rule_sets]]
id = \"site\"
trusted_keys = [{ issuer_key_id = \"site.key\", public_key = \"$SITE_KEY\" }]
TOML
systemctl restart openvibes-agent" >/dev/null 2>&1 || fail "add the site rule set to the agent"
wait_for "findings from the site's own published rule set" 180 \
    "[[ \$($SQL \"SELECT count(*) FROM findings WHERE rule_set_id = 'site' AND rule_id = 'site.processes'\") -ge 1 ]]"
wait_for "the agent's inventory is stored (protocol P8)" 120 \
    "[[ \$($SQL \"SELECT count(*) FROM host_packages\") -gt 100 ]]"
# P11: a package change reaches the platform as a change set, not a full
# report. `rpm -e --justdb` drops tar from the package database only (its
# files stay); the restarted agent scans at once and sends the difference.
in_c 'rpm -q tar' >/dev/null 2>&1 || fail "the e2e image has no tar package to remove"
in_c 'rpm -e --justdb --nodeps tar && systemctl restart openvibes-agent' || fail "change the agent's inventory"
wait_for "the agent sent inventory changes (protocol P11)" 120 \
    'journalctl -u openvibes-ingest -o cat | grep -q "\"endpoint\":\"/v1/inventory/changes\".*\"status\":204"'
[[ $(in_c "$SQL \"SELECT count(*) FROM host_packages h JOIN package_versions v ON v.id = h.package_version_id WHERE v.name = 'tar'\"") == 0 ]] ||
    fail "the platform still lists tar after the change set"
ok "a package change arrives as inventory changes"

# P13: the agent reports its rule matches as changes. A platform that lost
# its copy (match_sha256 cleared) asks through the next heartbeat and gets a
# replace; a rule that stops matching ends its match.
RULE="agent_id = (SELECT agent_id FROM agents WHERE status = 'active') AND rule_id = 'host.has.processes'"
wait_for "the match arrived as finding changes (protocol P13)" 120 \
    "[[ \$($SQL \"SELECT count(*) FROM current_findings WHERE $RULE AND source = 'changes' AND ended_at IS NULL\") == 1 ]]"
in_c "$SQL \"UPDATE agents SET match_sha256 = NULL WHERE status = 'active'\"" >/dev/null || fail "clear match_sha256"
wait_for "a heartbeat resync brought a replace" 180 \
    "[[ \$($SQL \"SELECT count(*) FROM agents WHERE status = 'active' AND match_sha256 IS NOT NULL\") == 1 ]]"
in_c "runuser -u openvibes-admin -- openvibes-admin rules publish /test/bundle-v2.json && systemctl restart openvibes-agent" \
    >/dev/null 2>&1 || fail "publish the never-matching rule"
wait_for "the match ended when the rule stopped matching" 180 \
    "[[ \$($SQL \"SELECT count(*) FROM current_findings WHERE $RULE AND ended_at IS NOT NULL\") == 1 ]]"
ok "finding changes: resync and a match that ends (protocol P13)"

# P12: the agent reports its health with each heartbeat; the platform stores
# it with the 5-minute heartbeat write, so each check can wait that long.
# An unreadable package database turns the agent Degraded (collector_failing).
AGENTS='runuser -u openvibes-admin -- openvibes-admin agent list'
wait_for "the agent reports healthy (protocol P12)" 420 "$AGENTS | grep -q 'health healthy'"
in_c 'chmod 000 /var/lib/rpm/rpmdb.sqlite && systemctl restart openvibes-agent' || fail "hide the RPM database"
wait_for "the agent reports collector_failing" 420 "$AGENTS | grep -q 'health degraded (collector_failing'"
in_c 'chmod 644 /var/lib/rpm/rpmdb.sqlite && systemctl restart openvibes-agent' || fail "restore the RPM database"
ok "agent health reaches the platform"
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
allowed alice '/usr/bin/openvibes-admin helper config-read vulns' ||
    fail "operators may not read configs through the helper"
allowed alice '/usr/bin/openvibes-admin helper config-write vulns' ||
    fail "operators may not save configs through the helper"
allowed bob '/usr/bin/openvibes-admin helper config-write vulns' &&
    fail "a non-operator may save configs"
allowed alice '/usr/bin/openvibes-admin helper enable openvibes-llm.service' &&
    fail "operators may run helper verbs beyond logs and configs"
in_c '/usr/bin/openvibes-admin helper logs openvibes-vulns.service 5' | grep -q . ||
    fail "the helper, as root, reads a unit's log"
in_c '/usr/bin/openvibes-admin helper logs systemd-journald.service 5' >/dev/null 2>&1 &&
    fail "the helper read a unit outside the allow-list"
in_c 'runuser -u openvibes-admin -- /usr/bin/openvibes-admin status' >/dev/null ||
    fail "openvibes-admin status as openvibes-admin"
# A config save through the helper, as root as sudo runs it: checked by the
# service's type, owner, group and mode kept, the old file kept as .bak; an
# invalid file is refused and changes nothing.
in_c 'openvibes-admin helper config-read vulns | sed "s/^check_interval_minutes = 60 /check_interval_minutes = 30 /" |
      openvibes-admin helper config-write vulns' || fail "config-write through the helper"
[[ $(in_c 'stat -c "%U:%G %a" /etc/openvibes/vulns.toml') == "root:openvibes-vulns 640" ]] ||
    fail "config-write kept owner, group and mode"
in_c 'grep -q "^check_interval_minutes = 30 " /etc/openvibes/vulns.toml && test -f /etc/openvibes/vulns.toml.bak' ||
    fail "config-write content and backup"
in_c 'sed "s/^check_interval_minutes = 30 /check_interval_minutes = 5 /" /etc/openvibes/vulns.toml |
      openvibes-admin helper config-write vulns' >/dev/null 2>&1 && fail "config-write accepted an invalid file"
in_c 'grep -q "^check_interval_minutes = 30 " /etc/openvibes/vulns.toml' || fail "a refused write changed the file"
in_c 'runuser -u alice -- systemctl --no-ask-password restart openvibes-vulns.service' ||
    fail "restart after a config save"
wait_for "vulns ready with the saved config" 30 'curl -fsS http://127.0.0.1:18483/ready'
ok "operators restart units through polkit; sudo lets them read logs, read and save configs, and use the admin CLI; others cannot"

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
