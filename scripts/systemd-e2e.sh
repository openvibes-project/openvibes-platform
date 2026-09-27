#!/usr/bin/env bash
# End to end under systemd: the documented install (docs/components/
# packaging.md, "First install on Fedora" and "Trying the whole system"),
# scripted in podman fedora:44 with systemd as PID 1. PostgreSQL, ingest,
# distribution, and the agent all run from their RPMs as their own units;
# the agent enrolls, fetches its signed rules from distribution, and its
# findings reach PostgreSQL. openvibes-llm serves a tiny test model to
# `openvibes-admin assistant check` from inside its sandbox.
# Usage: scripts/systemd-e2e.sh RPM_DIR SIGN_BIN
#   RPM_DIR  the openvibes-{ingest,distribution,vulns,admin,llm} RPMs and one
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
        for unit in openvibes-ingest openvibes-distribution openvibes-vulns openvibes-agent openvibes-llm; do
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

printf 'FROM registry.fedoraproject.org/fedora:44\nRUN dnf -q -y install systemd postgresql-server procps-ng util-linux && dnf clean all\n' |
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
             -e 's#^\(kev\|epss\|nvd\|euvd\|osv\)_url = .*#\1_url = \"\"#' /etc/openvibes/vulns.toml &&
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
in_c "runuser -u openvibes_admin -- openvibes-admin assistant model install /test/tiny.gguf --sha256 $SHA --alias tiny" \
    >/dev/null || fail "model install"
[[ "$(in_c 'stat -c "%a" /var/lib/openvibes-llm/models/tiny.gguf')" == 444 ]] || fail "installed model is not read-only"
in_c 'systemctl reset-failed openvibes-llm; systemctl enable --now openvibes-llm' >/dev/null 2>&1 || fail "start openvibes-llm"
wait_for "openvibes-llm ready" 60 "curl -fsS $LLM/health"
in_c "pid=\$(systemctl show -p MainPID --value openvibes-llm);
      [[ \$(stat -c %U /proc/\$pid) == openvibes_llm ]] &&
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
# The console reads the key as its own credential; here openvibes_admin gets
# a private copy for the check.
in_c "install -o openvibes_admin -m 0600 /etc/openvibes/llm-api-key /run/llm-key &&
      printf '[assistant]\nenabled = true\n[assistant.backend]\nurl = \"$LLM/v1\"\nmodel = \"tiny\"\napi_key_file = \"/run/llm-key\"\n' > /run/console.toml &&
      chmod 0644 /run/console.toml &&
      runuser -u openvibes_admin -- openvibes-admin assistant check --file /run/console.toml > /run/check.out 2>&1" ||
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
