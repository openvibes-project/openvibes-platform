#!/usr/bin/env bash
# End to end under systemd: documented Fedora install scripted in podman
# fedora:44 with systemd as PID 1. The platform, agent, and optional console
# RPMs are installed and run as their dedicated service users. The agent
# enrolls, fetches signed rules, and delivers findings and inventory.
# Usage: scripts/systemd-e2e.sh RPM_DIR SIGN_BIN [CONSOLE_RPM]
#   RPM_DIR  the openvibes-{ingest,distribution,vulns,admin} RPMs and one
#            openvibes-agent RPM (built from the pinned agent revision)
#   SIGN_BIN the agent repository's sign_bundle example, built
#   CONSOLE_RPM optional production console RPM
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PODMAN=${PODMAN:-podman}
C=ov-platform-e2e
IMAGE=ov-e2e:44
W=$ROOT/target/systemd-e2e
[[ $# == 2 || $# == 3 ]] || { echo "usage: $0 RPM_DIR SIGN_BIN [CONSOLE_RPM]" >&2; exit 2; }
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
        for unit in openvibes-ingest openvibes-distribution openvibes-vulns openvibes-agent openvibes-console; do
            echo "--- $unit"
            "$PODMAN" exec "$C" journalctl -u "$unit" --no-pager -n 15 2>/dev/null || true
        done
    fi
    "$PODMAN" rm -f "$C" >/dev/null 2>&1 || true
    exit "$status"
}
trap cleanup EXIT

rm -rf "$W"; mkdir -p "$W"
cp "$1"/openvibes-{ingest,distribution,vulns,admin,agent}-*.rpm "$W/"
(($(ls "$W"/openvibes-agent-*.rpm | wc -l) == 1)) || fail "want exactly one agent RPM in $1"
cp "$2" "$W/sign_bundle"
KEY=$("$W/sign_bundle" keygen "$W/signing.key" | tail -1)
cat > "$W/rules.json" <<'RULES'
{"schema_version":1,"rules":[
 {"id":"host.has.processes","version":1,"title":"Processes are running","severity":"info",
  "confidence":100,"expression":"facts['process.count'] >= 1","finding_message":"The host runs processes"}]}
RULES
"$W/sign_bundle" sign "$W/signing.key" "$W/rules.json" baseline 1 org.rules 7 "$W/bundle.json" >/dev/null

printf 'FROM registry.fedoraproject.org/fedora:44\nRUN dnf -q -y install systemd postgresql-server procps-ng util-linux curl openssl && dnf clean all\n' |
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
in_c 'runuser -u postgres -- createuser --createrole openvibes_admin &&
      runuser -u postgres -- createdb -O openvibes_admin openvibes &&
      runuser -u openvibes_admin -- openvibes-admin migrate &&
      runuser -u openvibes_admin -- openvibes-admin maintenance' >/dev/null || fail "database"
ok "platform installed, schema migrated"

# Optional C5 package validation. Install only after the platform migrations
# create the least-privilege console database role and schema.
if [[ $# == 3 ]]; then
    cp "$3" "$W/openvibes-console.rpm"
    in_c 'dnf -q -y install /test/openvibes-console.rpm' >/dev/null 2>&1 || fail "install console RPM"
    in_c 'set -e
          openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
              -subj "/CN=console.example.invalid" \
              -addext "subjectAltName=DNS:console.example.invalid" \
              -keyout /etc/openvibes/tls/console-key.pem \
              -out /etc/openvibes/tls/console-chain.pem >/dev/null 2>&1
          chown root:openvibes_console /etc/openvibes/tls/console-{key,chain}.pem
          chmod 0640 /etc/openvibes/tls/console-{key,chain}.pem
          cat > /etc/openvibes/console.toml <<TOML
development_listen = "0.0.0.0:443"
health_listen = "127.0.0.1:18482"
transport_mode = "direct_tls"
database_url = "postgresql:///openvibes?host=/run/postgresql&user=openvibes_console"
public_origin = "https://console.example.invalid"
server_certificate_file = "/etc/openvibes/tls/console-chain.pem"
server_key_file = "/etc/openvibes/tls/console-key.pem"
TOML
          chown root:openvibes_console /etc/openvibes/console.toml
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

    in_c 'touch /var/lib/openvibes-console/c5-upgrade-sentinel &&
          dnf -q -y reinstall /test/openvibes-console.rpm' >/dev/null 2>&1 || fail "reinstall console RPM"
    in_c 'test -f /var/lib/openvibes-console/c5-upgrade-sentinel &&
          grep -q direct_tls /etc/openvibes/console.toml &&
          test -r /etc/openvibes/tls/console-key.pem' || fail "console upgrade changed local state"
    wait_for "console remains ready after RPM reinstall" 30 '[[ "$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:18482/ready)" == 204 ]]'
    wait_for "console remains available over TLS after RPM reinstall" 30 \
        '[[ "$(curl -ksS --resolve console.example.invalid:443:127.0.0.1 -o /dev/null -w "%{http_code}" https://console.example.invalid/)" == 200 ]]'
    ok "console RPM reinstall preserves local config, TLS files, and state"

    in_c 'cat > /etc/openvibes/console.toml <<TOML
development_listen = "0.0.0.0:443"
health_listen = "127.0.0.1:18482"
transport_mode = "reverse_proxy"
database_url = "postgresql:///openvibes?host=/run/postgresql&user=openvibes_console"
public_origin = "https://console.example.invalid"
unix_socket_file = "/run/openvibes-console/console.sock"
trusted_proxy_uids = [0]
TOML
          systemctl restart openvibes-console' >/dev/null 2>&1 || fail "configure Unix proxy mode"
    wait_for "console Unix proxy socket" 30 '[[ -S /run/openvibes-console/console.sock ]]'
    wait_for "allowed Unix proxy UID serves shell" 30 \
        '[[ "$(curl -sS --unix-socket /run/openvibes-console/console.sock -H "Host: console.example.invalid" -o /dev/null -w "%{http_code}" http://localhost/)" == 200 ]]'
    in_c 'set -e
          status=$(runuser -u openvibes_console -- curl -sS --unix-socket /run/openvibes-console/console.sock -H "Host: console.example.invalid" -o /dev/null -w "%{http_code}" http://localhost/)
          [[ "$status" == 403 ]]' || fail "reject untrusted Unix proxy UID"
    ok "console Unix proxy accepts only the configured peer UID"
fi

# 3-4, 7. CA: the root (here in the container, normally offline), the
# intermediate, and one server certificate each for ingest and distribution.
in_c 'set -e
      A="runuser -u openvibes_admin -- openvibes-admin"
      openvibes-admin ca init-root --out /root/ca-root >/dev/null
      S=/run/openvibes-ca
      install -d -o openvibes_admin -g openvibes_admin -m 0700 $S
      $A ca intermediate-request --out $S/int >/dev/null
      openvibes-admin ca sign-intermediate --root /root/ca-root --csr $S/int/intermediate.csr \
          --out $S/int/intermediate.crt >/dev/null
      install -o openvibes_admin -m 0644 /root/ca-root/root.crt $S/int/root.crt
      chown openvibes_admin $S/int/intermediate.crt
      $A ca import-intermediate --cert $S/int/intermediate.crt --key $S/int/intermediate.key \
          --root-cert $S/int/root.crt >/dev/null
      for name in localhost rules.localhost; do
          $A ca issue-server $name --san 127.0.0.1 --issuer-cert $S/int/intermediate.crt \
              --issuer-key $S/int/intermediate.key --out $S/tls >/dev/null
      done
      install -m 0644 $S/int/intermediate.crt /etc/openvibes/pki/intermediate.crt
      install -o openvibes_ingest -g openvibes_ingest -m 0600 $S/int/intermediate.key /var/lib/openvibes-ingest/intermediate.key
      install -m 0644 $S/tls/localhost.crt /etc/openvibes/tls/ingest.crt
      install -o openvibes_ingest -g openvibes_ingest -m 0600 $S/tls/localhost.key /etc/openvibes/tls/ingest.key
      install -m 0644 $S/tls/rules.localhost.crt /etc/openvibes/tls/distribution.crt
      install -o openvibes_distribution -g openvibes_distribution -m 0600 $S/tls/rules.localhost.key /etc/openvibes/tls/distribution.key
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
             -e 's#^\(kev\|epss\|nvd\|euvd\)_url = .*#\1_url = \"\"#' /etc/openvibes/vulns.toml &&
      systemctl enable --now openvibes-vulns" >/dev/null 2>&1 || fail "start vulns"
wait_for "vulns service ready" 30 'curl -fsS http://127.0.0.1:18483/ready'
in_c 'runuser -u openvibes_admin -- openvibes-admin feeds import /test/updateinfo-test.xml --source fedora-44-x86_64' >/dev/null ||
    fail "feeds import"
printf '{"vulnerabilities":[{"cveID":"CVE-2026-99999","dateAdded":"2026-09-25","knownRansomwareCampaignUse":"Known"}]}' \
    > "$W/kev-test.json"
in_c 'runuser -u openvibes_admin -- openvibes-admin feeds import /test/kev-test.json --source kev' >/dev/null ||
    fail "kev import"
ok "offline feed and KEV imported"

# Rules: trust the signing key and publish the signed bundle.
in_c "runuser -u openvibes_admin -- openvibes-admin rules trust add baseline org.rules $KEY &&
      runuser -u openvibes_admin -- openvibes-admin rules publish /test/bundle.json" >/dev/null 2>&1 ||
    fail "publish rules"
ok "rules trusted and published"

# The agent, as its first-run steps say.
TOKEN=$(in_c 'runuser -u openvibes_admin -- openvibes-admin token create --expires 1h' |
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
SQL='runuser -u openvibes_admin -- psql -d openvibes -AtX -c'
wait_for "agent enrolled" 60 "[[ \$($SQL \"SELECT count(*) FROM agents WHERE status = 'active'\") == 1 ]]"
wait_for "agent fetched its rules from distribution (200)" 120 \
    'journalctl -u openvibes-distribution -o cat | grep -q "\"endpoint\":\"/v1/rule-bundle\".*\"status\":200"'
wait_for "findings from the published rule set in PostgreSQL" 120 \
    "[[ \$($SQL \"SELECT count(*) FROM findings WHERE rule_set_id = 'baseline' AND rule_id = 'host.has.processes'\") -ge 1 ]]"
wait_for "the agent's inventory is stored (protocol P8)" 120 \
    "[[ \$($SQL \"SELECT count(*) FROM host_packages\") -gt 100 ]]"
wait_for "the vulns service re-matched the host: bash vulnerable" 60 \
    "[[ \$($SQL \"SELECT count(*) FROM vulnerabilities WHERE advisory_id = 'FEDORA-TEST-bash' AND fixed_at IS NULL\") == 1 ]]"
in_c 'runuser -u openvibes_admin -- openvibes-admin vulns list' | grep -q 'FEDORA-TEST-bash.*bash .* -> .*999.0-1.fc44' ||
    fail "vulns list does not show the bash vulnerability"
in_c 'runuser -u openvibes_admin -- openvibes-admin vulns list' | grep -q 'FEDORA-TEST-bash.*exploited (KEV, ransomware)' ||
    fail "vulns list does not show the KEV mark"
ok "openvibes-admin vulns list shows it, marked exploited (KEV)"
echo "systemd-e2e: all checks passed"
