#!/usr/bin/env bash
# Upgrade from openvibes_* service accounts (admin TUI spec §2) under a real
# systemd: install the base RPMs (built from main, before the rename), set up
# the database, start openvibes-vulns, then replace the packages with the
# new RPMs and check that users, groups, roles, configs and file owners were
# renamed and the service works again. A second reinstall must change nothing.
# `rpm -U --replacepkgs` upgrades whether the new RPMs carry the same or a
# newer version. A process still running as an old account makes that
# package's %pre refuse, leaving it consistent on the old name.
# Usage: scripts/upgrade-e2e.sh BASE_RPM_DIR NEW_RPM_DIR
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PODMAN=${PODMAN:-podman}
C=ov-platform-upgrade
IMAGE=ov-e2e:44
W=$ROOT/target/upgrade-e2e
[[ $# == 2 ]] || { echo "usage: $0 BASE_RPM_DIR NEW_RPM_DIR" >&2; exit 2; }
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
    ((status == 0)) || "$PODMAN" exec "$C" journalctl -u openvibes-vulns --no-pager -n 20 2>/dev/null || true
    "$PODMAN" rm -f "$C" >/dev/null 2>&1 || true
    exit "$status"
}
trap cleanup EXIT

PKGS=(ingest distribution vulns admin)
rm -rf "$W"; mkdir -p "$W/base" "$W/new"
for p in "${PKGS[@]}"; do
    cp "$1"/openvibes-$p-[0-9]*.rpm "$W/base/"
    cp "$2"/openvibes-$p-[0-9]*.rpm "$W/new/"
done
printf 'FROM registry.fedoraproject.org/fedora:44\nRUN dnf -q -y install systemd postgresql-server procps-ng util-linux sudo polkit curl && dnf clean all\n' |
    "$PODMAN" build -q -t "$IMAGE" -f - "$W" >/dev/null
"$PODMAN" rm -f "$C" >/dev/null 2>&1 || true
"$PODMAN" run -d --systemd=always --privileged --name "$C" -v "$W:/test:Z" "$IMAGE" /sbin/init >/dev/null
wait_for "systemd is up" 30 'systemctl is-system-running | grep -qE "running|degraded"'

# The base install, as documented before the rename.
in_c 'postgresql-setup --initdb && systemctl enable --now postgresql' >/dev/null 2>&1 || fail "postgresql"
in_c 'dnf -q -y install /test/base/*.rpm' >/dev/null 2>&1 || fail "install base RPMs"
in_c 'getent passwd openvibes_vulns' >/dev/null || fail "base RPMs do not use openvibes_* accounts"
in_c 'runuser -u postgres -- createuser --createrole openvibes_admin &&
      runuser -u postgres -- createdb -O openvibes_admin openvibes &&
      runuser -u openvibes_admin -- openvibes-admin migrate &&
      runuser -u openvibes_admin -- openvibes-admin maintenance' >/dev/null || fail "base database"
# No network: only the offline feed paths, as in systemd-e2e.sh.
in_c "sed -i -e 's|^metalink_url = .*|metalink_url = \"http://127.0.0.1:9/metalink?release={release}\\&arch={arch}\"|' -e 's#^\(kev\|epss\|nvd\|euvd\|osv\)_url = .*#\1_url = \"\"#' /etc/openvibes/vulns.toml &&
      systemctl enable --now openvibes-vulns" >/dev/null 2>&1 || fail "start base vulns"
wait_for "base vulns ready" 30 'curl -fsS http://127.0.0.1:18483/ready'
in_c 'systemctl enable openvibes-maintenance.timer' >/dev/null 2>&1 || true

# A process still runs as openvibes_admin: openvibes-admin's upgrade refuses
# and keeps the old, consistent account; the others go ahead.
in_c 'systemd-run -q --unit=ov-holder -p User=openvibes_admin sleep 600' || fail "start the holding process"
out=$(in_c 'rpm -U --replacepkgs /test/new/*.rpm 2>&1') && fail "upgrade went ahead while openvibes_admin had a process"
grep -q 'processes still run as openvibes_admin' <<<"$out" || fail "no message about the process: $out"
in_c 'getent passwd openvibes_admin && ! getent passwd openvibes-admin' >/dev/null || fail "admin account changed despite the refusal: $(in_c 'getent passwd | grep openvibes; getent group | grep openvibes')"
[[ "$(in_c 'stat -c %G /etc/openvibes/admin.toml')" == openvibes_admin ]] || fail "admin.toml group changed despite the refusal"
in_c 'runuser -u openvibes_admin -- openvibes-admin status' >/dev/null || fail "admin CLI broken after the refused upgrade"
ok "a process under the old account makes that package's upgrade refuse, consistently"
in_c 'systemctl stop ov-holder' >/dev/null 2>&1 || true

# The upgrade.
in_c 'rpm -U --replacepkgs /test/new/*.rpm' || fail "upgrade to the new RPMs"
for p in "${PKGS[@]}"; do
    in_c "getent passwd openvibes-$p && getent group openvibes-$p && ! getent passwd openvibes_$p && ! getent group openvibes_$p" >/dev/null ||
        fail "account openvibes_$p not renamed to openvibes-$p"
done
ok "OS users and groups renamed"
[[ "$(in_c 'stat -c %U /var/lib/openvibes-ingest')" == openvibes-ingest ]] || fail "ingest state directory owner"
[[ "$(in_c 'stat -c %G /etc/openvibes/vulns.toml')" == openvibes-vulns ]] || fail "vulns.toml group"
ok "file owners follow the renamed accounts"
roles=$(in_c "runuser -u postgres -- psql -AtX -c \"SELECT rolname FROM pg_roles WHERE rolname LIKE 'openvibes%' ORDER BY 1\"")
[[ "$roles" == $'openvibes-admin\nopenvibes-distribution\nopenvibes-ingest\nopenvibes-vulns' ]] || fail "roles: $roles"
ok "PostgreSQL roles renamed"
for p in "${PKGS[@]}"; do
    in_c "grep -q 'user=openvibes-$p\"' /etc/openvibes/$p.toml && ! grep -q openvibes_$p /etc/openvibes/$p.toml" ||
        fail "$p.toml user= not rewritten"
done
in_c "grep -q '^kev_url = \"\"' /etc/openvibes/vulns.toml" || fail "the operator's other vulns.toml edits were lost"
ok "configs point at the renamed roles, other edits kept"
wait_for "vulns running again after the upgrade, as openvibes-vulns" 30 \
    'systemctl is-active -q openvibes-vulns && [[ $(ps -o uid= -C openvibes-vulns | tr -d " ") == $(id -u openvibes-vulns) ]]'
# The new RPMs may carry newer migrations; services report not-ready until
# the operator migrates, as after any upgrade.
in_c 'runuser -u openvibes-admin -- openvibes-admin migrate' >/dev/null || fail "migrate after the upgrade"
wait_for "vulns ready after migrate" 30 'curl -fsS http://127.0.0.1:18483/ready'
in_c 'runuser -u openvibes-admin -- openvibes-admin status' >/dev/null || fail "openvibes-admin status after the upgrade"
ok "services and the admin CLI work after the upgrade"

# Reinstalling again changes nothing.
before=$(in_c 'getent passwd | grep openvibes; md5sum /etc/openvibes/*.toml')
in_c 'dnf -q -y reinstall /test/new/*.rpm' || fail "second reinstall"
[[ "$(in_c 'getent passwd | grep openvibes; md5sum /etc/openvibes/*.toml')" == "$before" ]] || fail "second reinstall changed accounts or configs"
wait_for "vulns still ready" 30 'curl -fsS http://127.0.0.1:18483/ready'
ok "a second reinstall changes nothing"
