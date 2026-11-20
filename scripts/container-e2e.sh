#!/bin/bash
# End to end for the platform container (#604, #606, #607), started from
# packaging/container/compose.yaml as a user would: the image boots under
# systemd with no privileged mode, sets itself up from the compose file's
# settings (a bad one stops it with a message), and a new container on the
# same volumes (a new image) keeps the data.
#
# Usage: bash scripts/container-e2e.sh [IMAGE]
#   IMAGE defaults to openvibes-platform:dev; ENGINE picks docker or podman
#   (default: whichever is installed, podman first). Needs `ENGINE compose`.
set -euo pipefail

image=${1:-openvibes-platform:dev}
engine=${ENGINE:-$(command -v podman || command -v docker || true)}
[[ -n $engine ]] || { echo "neither podman nor docker is installed" >&2; exit 1; }
here=$(cd "$(dirname "$0")/.." && pwd)
P=ov-container-e2e
C=
# The console on a free port of 127.0.0.1, not the host's 443; the rest of
# the compose file as is.
override=$(mktemp)
cat > "$override" <<'YAML'
services:
  openvibes:
    ports: !override
      - "127.0.0.1::443"
YAML
# The settings a user puts in .env (#607); the password changes per run.
export OPENVIBES_HOSTNAME=localhost OPENVIBES_EXTRA_NAMES=127.0.0.1
export OPENVIBES_ADMIN_PASSWORD=too-short
compose() {
    OPENVIBES_IMAGE=$image "$engine" compose --progress quiet -p "$P" -f "$here/packaging/container/compose.yaml" \
        -f "$override" "$@" 2> >(grep -v 'external compose provider' >&2)
}

ok() { echo "ok: $*"; }
fail() {
    echo "FAIL: $*" >&2
    {
        echo "--- state"; "$engine" inspect -f '{{.State.Status}} exit={{.State.ExitCode}} {{.State.Error}}' "$C"
        echo "--- systemd"; "$engine" exec "$C" sh -c 'systemctl is-system-running; systemctl list-jobs --no-pager | head -20; grep cgroup /proc/self/mountinfo' 
        echo "--- log"; "$engine" logs "$C" 2>&1 | tail -60
    } >&2 2>&1 || true
    exit 1
}
in_c() { "$engine" exec "$C" bash -c "$1"; }
wait_for() {
    local what=$1 secs=$2 check=$3
    for _ in $(seq "$secs"); do in_c "$check" > /dev/null 2>&1 && return 0; sleep 1; done
    fail "$what (waited ${secs}s)"
}
cleanup() {
    compose down -v -t 60 > /dev/null 2>&1 || true
}
start() {
    compose up -d > /dev/null
    C=$(compose ps -q openvibes)
    [[ -n $C ]] || fail "compose started no container"
    wait_for "systemd is up" 60 'systemctl is-system-running | grep -qE "^(starting|running|degraded)$"'
}
[[ -n ${KEEP:-} ]] || trap 'cleanup; rm -f "$override"' EXIT
cleanup

# 0. Compose refuses to start without the required settings.
if OPENVIBES_HOSTNAME='' compose config > /dev/null 2>&1; then fail "compose starts with no OPENVIBES_HOSTNAME"; fi
ok "compose refuses to start without OPENVIBES_HOSTNAME"

# 1. Boots unprivileged; a password that's too short stops the first start
#    with a message, before anything is set up.
start
[[ $("$engine" inspect -f '{{.HostConfig.Privileged}}' "$C") == false ]] || fail "the container is privileged"
wait_for "the start unit gave up" 60 "systemctl is-failed -q openvibes-container-start"
[[ $("$engine" logs "$C" 2>&1) == *'OPENVIBES_ADMIN_PASSWORD needs at least 15 characters'* ]] || fail "the log does not say the password is too short"
in_c '! test -e /etc/openvibes/setup.toml' || fail "Setup ran with a bad setting"
failed=$(in_c 'systemctl list-units --failed --no-legend --plain | grep -v openvibes-container-start || true')
[[ -z $failed ]] || fail "failed units: $failed"
ok "boots under systemd with no privileged mode, and a short password stops Setup with a message"

# 2. With the setting fixed, `compose up -d` again sets it up; the console
#    answers.
OPENVIBES_ADMIN_PASSWORD="e2e-$(head -c 12 /dev/urandom | base64 | tr -d '/+=')"
export OPENVIBES_ADMIN_PASSWORD
start
wait_for "the first start set the platform up" 900 "systemctl is-active -q openvibes-container-start"
wait_for "the console answers" 60 'curl -skf -o /dev/null https://127.0.0.1/'
[[ $("$engine" logs "$C" 2>&1) == *'OpenVIBES console: https://localhost'* ]] || fail "the log does not say where the console is"
# "admin" signs in with the password from the settings (expanded inside).
# shellcheck disable=SC2016
in_c 'cd /tmp && curl -ksSf -c j -o p.json https://localhost/auth/v1/preauth &&
    csrf=$(sed -n "s/.*\"csrf_token\":\"\([^\"]*\)\".*/\1/p" p.json) &&
    test "$(curl -ksS -b j -c j -o /dev/null -w "%{http_code}" -H "Origin: https://localhost" \
        -H "Sec-Fetch-Site: same-origin" -H "X-CSRF-Token: $csrf" -H "Content-Type: application/json" \
        -d "{\"username\":\"admin\",\"password\":\"'"$OPENVIBES_ADMIN_PASSWORD"'\"}" \
        https://localhost/auth/v1/login)" = 200; rm -f j p.json' || fail "admin cannot sign in with OPENVIBES_ADMIN_PASSWORD"
port=$("$engine" port "$C" 443/tcp | head -n 1 | sed 's/.*://')
# The console checks the Host header: it is the name it was set up for
# (here the test's own free port stands in for 443).
curl -skf -o /dev/null -H "Host: 127.0.0.1" "https://127.0.0.1:$port/" || fail "the console does not answer on the published port $port"
in_c 'runuser -u openvibes-admin -- openvibes-admin status' > /dev/null || fail "openvibes-admin status"
root_fp=$(in_c 'sha256sum /etc/openvibes/pki/root.crt' | cut -d' ' -f1)
ok "the first start sets the platform up from the settings, admin signs in, and the console answers on the published port"

# 3. A new container on the same volumes (what a new image does) keeps the
#    data, the accounts own it, and the services come back by themselves.
# compose.yaml's stop_grace_period gives systemd the time to stop
# PostgreSQL and the services cleanly.
compose down > /dev/null
start
wait_for "the console answers after the restart" 180 'curl -skf -o /dev/null https://127.0.0.1/'
wait_for "the start unit finished" 60 "systemctl is-active -q openvibes-container-start"
[[ $("$engine" logs "$C" 2>&1) == *'OpenVIBES console: https://localhost'* ]] || fail "the log does not say where the console is"
[[ $(in_c 'sha256sum /etc/openvibes/pki/root.crt' | cut -d' ' -f1) == "$root_fp" ]] || fail "the CA changed"
in_c 'runuser -u openvibes-admin -- openvibes-admin status' > /dev/null || fail "the database is gone"
wrong=$(in_c 'find /etc/openvibes /var/lib/openvibes-* /var/lib/pgsql -nouser -o -nogroup' | head -n 5)
[[ -z $wrong ]] || fail "files with no owner on the volumes: $wrong"
failed=$(in_c 'systemctl list-units --failed --no-legend --plain')
[[ -z $failed ]] || fail "failed units after the restart: $failed"
ok "a new container on the same volumes keeps the CA and the database, starts the services and says where the console is"
echo "container-e2e: all checks passed"
