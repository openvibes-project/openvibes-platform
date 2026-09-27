#!/usr/bin/env bash
# Setup's whole life cycle under systemd (admin TUI spec §12), in podman
# fedora:44 with systemd as PID 1, from built RPMs:
# install (with the agent on the host) → repair after breaking things →
# uninstall keeping data → install again (same CA, same agent) → update to
# newer packages → remove everything (nothing left).
# Usage: scripts/setup-lifecycle-e2e.sh OLD_DIR NEW_DIR
#   OLD_DIR  lower-version openvibes-{ingest,distribution,vulns,admin}-*.rpm
#            and one openvibes-agent RPM
#   NEW_DIR  the same packages at the current version
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PODMAN=${PODMAN:-podman}
C=ov-setup-lifecycle
IMAGE=ov-e2e:44
W=$ROOT/target/setup-lifecycle
[[ $# == 2 ]] || { echo "usage: $0 OLD_DIR NEW_DIR" >&2; exit 2; }
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
        for unit in openvibes-ingest openvibes-distribution openvibes-vulns openvibes-agent; do
            echo "--- $unit"
            "$PODMAN" exec "$C" journalctl -u "$unit" --no-pager -n 15 2>/dev/null || true
        done
    fi
    "$PODMAN" rm -f "$C" >/dev/null 2>&1 || true
    exit "$status"
}
trap cleanup EXIT

rm -rf "$W"; mkdir -p "$W/old" "$W/new"
for d in old new; do
    src=$1; [[ $d == new ]] && src=$2
    cp "$src"/openvibes-{ingest,distribution,vulns,admin,agent}-[0-9]*.rpm "$W/$d/"
done
printf 'FROM registry.fedoraproject.org/fedora:44
RUN dnf -q -y install systemd postgresql-server procps-ng util-linux curl polkit sudo && dnf clean all
' | "$PODMAN" build -q -t "$IMAGE" -f - "$W" >/dev/null
"$PODMAN" rm -f "$C" >/dev/null 2>&1 || true
"$PODMAN" run -d --systemd=always --privileged --name "$C" -v "$W:/test:Z" "$IMAGE" /sbin/init >/dev/null
wait_for "systemd is up" 30 'systemctl is-system-running | grep -qE "running|degraded"'

QUICK='openvibes-admin setup --quick --components ingest,distribution,vulns,agent --hostname localhost \
       --san 127.0.0.1 --repo-dir /test/old --allow-unsigned-local'
agent_id() { in_c 'runuser -u openvibes-admin -- openvibes-admin agent list' | awk '$2 == "active" {print $1; exit}'; }
fingerprint() { in_c 'sha256sum /etc/openvibes/pki/root.crt' | cut -d' ' -f1; }

# 1. Install from the lower version, with the agent on this host.
in_c 'dnf -q -y install /test/old/openvibes-admin-*.rpm' >/dev/null 2>&1 || fail "install openvibes-admin"
in_c "$QUICK" > "$W/install.out" 2>&1 || { cat "$W/install.out"; fail "setup --quick"; }
AGENT=$(agent_id); [[ -n "$AGENT" ]] || fail "the local agent is not active"
ROOT_FP=$(fingerprint)
ok "installed with the local agent ($AGENT)"

# 2. Repair: a stopped service and a removed package come back; the CA is not touched.
in_c 'systemctl stop openvibes-distribution && rpm -e --nodeps openvibes-vulns' || fail "break things"
in_c 'openvibes-admin setup --repair' > "$W/repair.out" 2>&1 || { cat "$W/repair.out"; fail "setup --repair"; }
in_c 'systemctl is-active --quiet openvibes-distribution && rpm -q --quiet openvibes-vulns' || fail "repair did not restore"
[[ "$(fingerprint)" == "$ROOT_FP" ]] || fail "repair changed the CA"
ok "repair restored the stopped service and the removed package"

# 3. Uninstall keeping data, then install again: same CA, same agent.
in_c 'openvibes-admin setup --uninstall --keep-data' > "$W/keep.out" 2>&1 || { cat "$W/keep.out"; fail "uninstall --keep-data"; }
in_c '! rpm -q --quiet openvibes-ingest && test -e /etc/openvibes/pki/root.crt' || fail "keep-data removed data or kept packages"
in_c "$QUICK" > "$W/reinstall.out" 2>&1 || { cat "$W/reinstall.out"; fail "reinstall"; }
[[ "$(fingerprint)" == "$ROOT_FP" ]] || fail "reinstall made a new CA"
wait_for "the same agent reports again" 60 "runuser -u openvibes-admin -- openvibes-admin agent list | grep -q '^$AGENT  active'"
ok "uninstall keeping data and reinstall keep the CA and the agent's enrollment"

# 4. Update to the newer packages, with a backup first.
in_c 'openvibes-admin setup --update --update-repo-dir /test/new --backup /root/before-update.dump' > "$W/update.out" 2>&1 ||
    { cat "$W/update.out"; fail "setup --update"; }
NEW=$(in_c "rpm -qp --qf '%{VERSION}' /test/new/openvibes-ingest-*.rpm")
[[ "$(in_c "rpm -q --qf '%{VERSION}' openvibes-ingest")" == "$NEW" ]] || fail "ingest not upgraded to $NEW"
in_c 'test -s /root/before-update.dump && test -s /root/before-update.dump.roles.sql' || fail "no backup"
in_c 'runuser -u openvibes-admin -- openvibes-admin status' >/dev/null || fail "schema not current after update"
wait_for "the agent reports after the update" 60 "runuser -u openvibes-admin -- openvibes-admin agent list | grep -q '^$AGENT  active'"
ok "update upgraded the packages, migrated, and the agent keeps reporting"

# 5. Remove everything, then the admin tool itself: nothing is left.
in_c 'openvibes-admin setup --uninstall --everything --confirm localhost' > "$W/purge.out" 2>&1 ||
    { cat "$W/purge.out"; fail "uninstall --everything"; }
in_c 'dnf -q -y remove openvibes-admin' >/dev/null 2>&1 || fail "remove openvibes-admin"
[[ -z "$(in_c "rpm -qa 'openvibes-*'")" ]] || fail "packages left"
in_c '! ls -d /etc/openvibes /etc/openvibes-agent /var/lib/openvibes-* 2>/dev/null' || fail "files left"
in_c '! getent passwd openvibes-ingest openvibes-admin openvibes_agent && ! getent group openvibes-operators' || fail "accounts left"
[[ -z "$(in_c "runuser -u postgres -- psql -Atqc \"SELECT 1 FROM pg_database WHERE datname = 'openvibes'\"")" ]] || fail "database left"
[[ -z "$(in_c "runuser -u postgres -- psql -Atqc \"SELECT 1 FROM pg_roles WHERE rolname LIKE 'openvibes-%'\"")" ]] || fail "roles left"
ok "remove everything left no packages, files, accounts, database or roles"
echo "setup-lifecycle-e2e: all checks passed"
