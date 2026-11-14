#!/bin/bash
# End to end for the platform container image (#604): the image boots under
# systemd with no privileged mode, Setup works in it as on the appliance, and
# a new container on the same volumes (a new image) keeps the data.
#
# Usage: bash scripts/container-e2e.sh [IMAGE]
#   IMAGE defaults to openvibes-platform:dev; ENGINE picks docker or podman
#   (default: whichever is installed, podman first).
set -euo pipefail

image=${1:-openvibes-platform:dev}
engine=${ENGINE:-$(command -v podman || command -v docker || true)}
[[ -n $engine ]] || { echo "neither podman nor docker is installed" >&2; exit 1; }
C=ov-container-e2e
vols=(etc:/etc/openvibes pgsql:/var/lib/pgsql admin:/var/lib/openvibes-admin
      console:/var/lib/openvibes-console feed:/var/lib/openvibes-feed
      ingest:/var/lib/openvibes-ingest llm:/var/lib/openvibes-llm
      signer:/var/lib/openvibes-signer vulns:/var/lib/openvibes-vulns)

ok() { echo "ok: $*"; }
fail() { echo "FAIL: $*" >&2; "$engine" logs "$C" 2>&1 | tail -40 >&2 || true; exit 1; }
in_c() { "$engine" exec "$C" bash -c "$1"; }
wait_for() {
    local what=$1 secs=$2 check=$3
    for _ in $(seq "$secs"); do in_c "$check" > /dev/null 2>&1 && return 0; sleep 1; done
    fail "$what (waited ${secs}s)"
}
cleanup() {
    "$engine" rm -f "$C" > /dev/null 2>&1 || true
    for v in "${vols[@]}"; do "$engine" volume rm -f "$C-${v%%:*}" > /dev/null 2>&1 || true; done
}
# What compose.yaml will give the container: named volumes, and for Docker
# the tmpfs mounts systemd needs (Podman adds them itself). Never --privileged.
start() {
    local args=(-d --name "$C" -p 127.0.0.1::443)
    for v in "${vols[@]}"; do args+=(-v "$C-${v%%:*}:${v#*:}"); done
    [[ $(basename "$engine") == docker ]] && args+=(--tmpfs /run --tmpfs /run/lock --tmpfs /tmp)
    "$engine" run "${args[@]}" "$image" > /dev/null
    wait_for "systemd is up" 60 'systemctl is-system-running | grep -qE "^(running|degraded)$"'
}
[[ -n ${KEEP:-} ]] || trap cleanup EXIT
cleanup

# 1. Boots unprivileged, with no failed unit.
start
[[ $("$engine" inspect -f '{{.HostConfig.Privileged}}' "$C") == false ]] || fail "the container is privileged"
failed=$(in_c 'systemctl list-units --failed --no-legend --plain')
[[ -z $failed ]] || fail "failed units: $failed"
ok "boots under systemd with no privileged mode and no failed unit"

# 2. Setup as on the appliance; the console answers.
in_c 'openvibes-admin setup --quick --components ingest,distribution,vulns,console --hostname localhost --san 127.0.0.1' \
    > "${TMPDIR:-/tmp}/ov-container-setup.out" 2>&1 || { cat "${TMPDIR:-/tmp}/ov-container-setup.out"; fail "setup --quick"; }
wait_for "the console answers" 60 'curl -skf -o /dev/null https://127.0.0.1/'
port=$("$engine" port "$C" 443/tcp | head -n 1 | sed 's/.*://')
# The console checks the Host header: it is the name it was set up for
# (a host port other than 443 is #606's to handle).
curl -skf -o /dev/null -H "Host: 127.0.0.1" "https://127.0.0.1:$port/" || fail "the console does not answer on the published port $port"
in_c 'runuser -u openvibes-admin -- openvibes-admin status' > /dev/null || fail "openvibes-admin status"
root_fp=$(in_c 'sha256sum /etc/openvibes/pki/root.crt' | cut -d' ' -f1)
ok "Setup works in the container and the console answers on the published port"

# 3. A new container on the same volumes (what a new image does) keeps the
#    data, the accounts own it, and the services come back by themselves.
# systemd stops PostgreSQL and the services cleanly given the time
# (compose.yaml's stop_grace_period).
"$engine" stop -t 60 "$C" > /dev/null
"$engine" rm -f "$C" > /dev/null
start
wait_for "the console answers after the restart" 180 'curl -skf -o /dev/null https://127.0.0.1/'
[[ $(in_c 'sha256sum /etc/openvibes/pki/root.crt' | cut -d' ' -f1) == "$root_fp" ]] || fail "the CA changed"
in_c 'runuser -u openvibes-admin -- openvibes-admin status' > /dev/null || fail "the database is gone"
wrong=$(in_c 'find /etc/openvibes /var/lib/openvibes-* /var/lib/pgsql -nouser -o -nogroup' | head -n 5)
[[ -z $wrong ]] || fail "files with no owner on the volumes: $wrong"
failed=$(in_c 'systemctl list-units --failed --no-legend --plain')
[[ -z $failed ]] || fail "failed units after the restart: $failed"
ok "a new container on the same volumes keeps the CA and the database, and starts the services"
echo "container-e2e: all checks passed"
