#!/usr/bin/env bash
# The assistant model switch on upgrade (#264), under systemd in podman
# fedora:44 with Hugging Face unreachable: a host on an earlier pinned model upgrades;
# the RPM step must keep its model and model.conf, and the switch after it
# (openvibes-llm-tune.service) must keep the model in use when the new one
# cannot be downloaded, and say so.
# Usage: scripts/model-switch-e2e.sh OLD_DIR NEW_DIR
#   OLD_DIR  a release whose model.pin names a model in packaging/llm/past-models
#            (openvibes-{admin,ingest,distribution,vulns,signer,llm,llm-model} RPMs;
#            Setup installs the platform with its database from them)
#   NEW_DIR  the same packages at the current version
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PODMAN=${PODMAN:-podman}
C=ov-model-switch
IMAGE=ov-model-switch:44
W=$ROOT/target/model-switch
[[ $# == 2 ]] || { echo "usage: $0 OLD_DIR NEW_DIR" >&2; exit 2; }
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }
in_c() { "$PODMAN" exec "$C" bash -c "$1"; }
cleanup() {
    local status=$?
    if ((status != 0)); then
        "$PODMAN" exec "$C" journalctl -u openvibes-llm-tune -u openvibes-llm-model-fetch --no-pager -n 30 2>/dev/null || true
    fi
    "$PODMAN" rm -f "$C" >/dev/null 2>&1 || true
    exit "$status"
}
trap cleanup EXIT

rm -rf "$W"; mkdir -p "$W/old" "$W/new"
for d in old new; do
    src=$1; [[ $d == new ]] && src=$2
    cp "$src"/openvibes-{admin,ingest,distribution,vulns,signer,llm,llm-model}-[0-9]*.rpm "$W/$d/"
done
OLD_MODEL=$(rpm -qlp "$W"/old/openvibes-llm-model-*.rpm | sed -n 's|^/var/lib/openvibes-llm/models/||p')
grep -qx "$OLD_MODEL" "$ROOT/packaging/llm/past-models" || fail "the old release's model $OLD_MODEL is not in past-models"

# Everything both releases require, installed while the image still has
# network (the test container has none).
deps=$(rpm -qp --requires "$W"/old/*.rpm "$W"/new/*.rpm 2>/dev/null |
    awk '{print $1}' | grep -E '^[a-z][a-z0-9_.+-]*$' | grep -v '^openvibes' | sort -u | tr '\n' ' ')
printf 'FROM registry.fedoraproject.org/fedora:44
RUN dnf -q -y install systemd procps-ng util-linux curl postgresql-server %s && dnf clean all
' "$deps" | "$PODMAN" build -q -t "$IMAGE" -f - "$W" >/dev/null
"$PODMAN" rm -f "$C" >/dev/null 2>&1 || true
"$PODMAN" run -d --systemd=always --privileged --name "$C" -v "$W:/test:Z" "$IMAGE" /sbin/init >/dev/null
for _ in $(seq 30); do in_c 'systemctl is-system-running | grep -qE "running|degraded"' 2>/dev/null && break; sleep 1; done

# 1. The old release installed by Setup (database included: `assistant model
#    fetch` is an audited admin command), its model in place, the assistant
#    on with the local model.
in_c 'dnf -q -y --disablerepo="*" install /test/old/openvibes-admin-*.rpm' >/dev/null 2>&1 || fail "install openvibes-admin"
in_c 'openvibes-admin setup --quick --components ingest,distribution,vulns --hostname localhost \
      --san 127.0.0.1 --repo-dir /test/old --allow-unsigned-local' > "$W/setup.out" 2>&1 ||
    { cat "$W/setup.out"; fail "setup --quick"; }
in_c 'dnf -q -y --disablerepo="*" install /test/old/openvibes-llm-*.rpm' >/dev/null 2>&1 || fail "install the old assistant packages"
in_c "echo stand-in > /var/lib/openvibes-llm/models/$OLD_MODEL && chmod 0444 /var/lib/openvibes-llm/models/$OLD_MODEL"
in_c "grep -qx 'OPENVIBES_LLM_MODEL=/var/lib/openvibes-llm/models/$OLD_MODEL' /var/lib/openvibes-llm/model.conf" ||
    fail "the old release does not select $OLD_MODEL"
OLD_ALIAS=$(in_c 'sed -n "s/^OPENVIBES_LLM_ALIAS=//p" /var/lib/openvibes-llm/model.conf')
printf '%s\n' 'development_listen = "127.0.0.1:8443"' 'health_listen = "127.0.0.1:8444"' '[assistant]' 'enabled = true' \
    '[assistant.backend]' 'url = "http://127.0.0.1:18430/v1"' "model = \"$OLD_ALIAS\"" > "$W/console.toml"
in_c 'cp /test/console.toml /etc/openvibes/console.toml'
in_c 'systemctl enable -q openvibes-llm.socket'
BEFORE=$(in_c 'sha256sum /var/lib/openvibes-llm/model.conf')
ok "old release on $OLD_MODEL"

# 2. Upgrade: the RPM step keeps the model in use and model.conf.
# Hugging Face unreachable: the new model's download must fail, deterministically.
in_c 'echo "127.0.0.1 huggingface.co" >> /etc/hosts'
in_c 'dnf -q -y --disablerepo="*" upgrade /test/new/*.rpm' >/dev/null 2>&1 || fail "upgrade"
in_c "test -f /var/lib/openvibes-llm/models/$OLD_MODEL" || fail "the upgrade deleted the model in use"
in_c "rpm -qf /var/lib/openvibes-llm/models/$OLD_MODEL | grep -q '^openvibes-llm-model-'" || fail "$OLD_MODEL is no longer owned"
[[ "$(in_c 'sha256sum /var/lib/openvibes-llm/model.conf')" == "$BEFORE" ]] || fail "the upgrade rewrote model.conf"
ok "the upgrade kept $OLD_MODEL and model.conf"

# 3. The switch after it: no download, so the old model stays and it says so.
for _ in $(seq 120); do
    in_c 'journalctl -u openvibes-llm-tune --no-pager -o cat | grep -q "assistant-model:"' && break
    sleep 1
done
LINE=$(in_c 'journalctl -u openvibes-llm-tune --no-pager -o cat | grep "assistant-model:" | tail -1')
[[ "$LINE" == *"keeps using $OLD_MODEL"* ]] || fail "the switch did not report keeping the old model: $LINE"
in_c 'journalctl -u openvibes-llm-model-fetch --no-pager -o cat | grep -q "cannot download"' ||
    fail "the download did not fail for want of network: $(in_c 'journalctl -u openvibes-llm-model-fetch --no-pager -o cat | tail -3')"
in_c "test -f /var/lib/openvibes-llm/models/$OLD_MODEL" || fail "the failed switch removed the old model"
in_c "grep -qx 'OPENVIBES_LLM_MODEL=/var/lib/openvibes-llm/models/$OLD_MODEL' /var/lib/openvibes-llm/model.conf" ||
    fail "the failed switch changed the selected model"
in_c "grep -q 'model = \"$OLD_ALIAS\"' /etc/openvibes/console.toml" || fail "the failed switch changed console.toml"
ok "a failed download keeps $OLD_MODEL in use ($LINE)"

# 4. Optional (local, MODEL_FILE=the new pin's real .gguf): with the new
#    model's file in place, the next run completes the switch.
if [[ -n ${MODEL_FILE:-} ]]; then
    NEW_MODEL=$(sed -n 's/^LLM_MODEL_FILE=//p' "$ROOT/packaging/llm/model.pin")
    "$PODMAN" cp "$MODEL_FILE" "$C:/var/lib/openvibes-llm/models/$NEW_MODEL"
    in_c "chown openvibes-admin:openvibes-admin /var/lib/openvibes-llm/models/$NEW_MODEL"
    in_c 'systemctl start openvibes-llm-tune.service' || true
    LINE=$(in_c 'journalctl -u openvibes-llm-tune --no-pager -o cat | grep "assistant-model:" | tail -1')
    [[ "$LINE" == *"switched from $OLD_MODEL to $NEW_MODEL"* ]] || fail "the switch did not complete: $LINE"
    in_c "grep -qx 'OPENVIBES_LLM_MODEL=/var/lib/openvibes-llm/models/$NEW_MODEL' /var/lib/openvibes-llm/model.conf" ||
        fail "model.conf does not select $NEW_MODEL"
    NEW_ALIAS=$(sed -n 's/^LLM_MODEL_ALIAS=//p' "$ROOT/packaging/llm/model.pin")
    in_c "grep -q 'model = \"$NEW_ALIAS\"' /etc/openvibes/console.toml" || fail "console.toml still asks for $OLD_ALIAS"
    in_c "test ! -e /var/lib/openvibes-llm/models/$OLD_MODEL" || fail "the old model was not removed"
    ok "with the new model in place the switch completed ($LINE)"
fi
