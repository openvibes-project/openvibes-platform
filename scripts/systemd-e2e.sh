#!/usr/bin/env bash
# End to end under systemd: the documented install (docs/components/
# packaging.md, "First install on Fedora" and "Trying the whole system"),
# scripted in podman fedora:44 with systemd as PID 1. PostgreSQL, ingest,
# distribution, and the agent all run from their RPMs as their own units;
# the agent enrolls, fetches its signed rules from distribution, and its
# findings reach PostgreSQL.
# Usage: scripts/systemd-e2e.sh RPM_DIR SIGN_BIN
#   RPM_DIR  the openvibes-{ingest,distribution,admin} RPMs and one
#            openvibes-agent RPM (built from the pinned agent revision)
#   SIGN_BIN the agent repository's sign_bundle example, built
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PODMAN=${PODMAN:-podman}
C=ov-platform-e2e
IMAGE=ov-e2e:44
W=$ROOT/target/systemd-e2e
[[ $# == 2 ]] || { echo "usage: $0 RPM_DIR SIGN_BIN" >&2; exit 2; }
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
        for unit in openvibes-ingest openvibes-distribution openvibes-agent; do
            echo "--- $unit"
            "$PODMAN" exec "$C" journalctl -u "$unit" --no-pager -n 15 2>/dev/null || true
        done
    fi
    "$PODMAN" rm -f "$C" >/dev/null 2>&1 || true
    exit "$status"
}
trap cleanup EXIT

rm -rf "$W"; mkdir -p "$W"
cp "$1"/openvibes-{ingest,distribution,admin,agent}-*.rpm "$W/"
(($(ls "$W"/openvibes-agent-*.rpm | wc -l) == 1)) || fail "want exactly one agent RPM in $1"
cp "$2" "$W/sign_bundle"
KEY=$("$W/sign_bundle" keygen "$W/signing.key" | tail -1)
cat > "$W/rules.json" <<'RULES'
{"schema_version":1,"rules":[
 {"id":"host.has.processes","version":1,"title":"Processes are running","severity":"info",
  "confidence":100,"expression":"facts['process.count'] >= 1","finding_message":"The host runs processes"}]}
RULES
"$W/sign_bundle" sign "$W/signing.key" "$W/rules.json" baseline 1 org.rules 7 "$W/bundle.json" >/dev/null

printf 'FROM registry.fedoraproject.org/fedora:44\nRUN dnf -q -y install systemd postgresql-server procps-ng util-linux && dnf clean all\n' |
    "$PODMAN" build -q -t "$IMAGE" -f - "$W" >/dev/null
"$PODMAN" rm -f "$C" >/dev/null 2>&1 || true
# Rootless --privileged: privileged only inside the container's user
# namespace; it lets systemd apply the units' sandboxes (see the agent's
# scripts/systemd-test.sh).
"$PODMAN" run -d --systemd=always --privileged --name "$C" -v "$W:/test:Z" "$IMAGE" /sbin/init >/dev/null
wait_for "systemd is up" 30 'systemctl is-system-running | grep -qE "running|degraded"'

# 1-2. PostgreSQL, the platform RPMs, database and schema.
in_c 'postgresql-setup --initdb && systemctl enable --now postgresql' >/dev/null 2>&1 || fail "postgresql"
in_c 'dnf -q -y install /test/openvibes-ingest-*.rpm /test/openvibes-distribution-*.rpm /test/openvibes-admin-*.rpm' \
    >/dev/null 2>&1 || fail "install platform RPMs"
in_c 'runuser -u postgres -- createuser --createrole openvibes_admin &&
      runuser -u postgres -- createdb -O openvibes_admin openvibes &&
      runuser -u openvibes_admin -- openvibes-admin migrate &&
      runuser -u openvibes_admin -- openvibes-admin maintenance' >/dev/null || fail "database"
ok "platform installed, schema migrated"

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
platform_url = \"https://127.0.0.1\"
platform_ca_file = \"/etc/openvibes-agent/platform-ca.crt\"
enrollment_token_file = \"/etc/openvibes-agent/token\"
distribution_url = \"https://127.0.0.1\"
[[rule_sets]]
id = \"baseline\"
trusted_keys = [{ issuer_key_id = \"org.rules\", public_key = \"$KEY\" }]
TOML
systemctl enable --now openvibes-agent" >/dev/null 2>&1 || fail "start agent"

SQL='runuser -u openvibes_admin -- psql -d openvibes -AtX -c'
wait_for "agent enrolled" 60 "[[ \$($SQL \"SELECT count(*) FROM agents WHERE status = 'active'\") == 1 ]]"
wait_for "agent fetched its rules from distribution (200)" 120 \
    'journalctl -u openvibes-distribution -o cat | grep -q "\"endpoint\":\"/v1/rule-bundle\".*\"status\":200"'
wait_for "findings from the published rule set in PostgreSQL" 120 \
    "[[ \$($SQL \"SELECT count(*) FROM findings WHERE rule_set_id = 'baseline' AND rule_id = 'host.has.processes'\") -ge 1 ]]"
echo "systemd-e2e: all checks passed"
