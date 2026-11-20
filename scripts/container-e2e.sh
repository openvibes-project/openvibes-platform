#!/bin/bash
# End to end for the platform container (#604, #606, #607), started from
# packaging/container/compose.yaml as a user would: the image boots under
# systemd with no privileged mode, sets itself up from the compose file's
# settings (a bad one stops it with a message), a new container on the same
# volumes (a new image) keeps the data and applies changed settings, and a CA from your own PKI
# (OPENVIBES_CA_FILE) is imported instead of one OpenVIBES makes.
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
# Step 4 adds a second override that mounts the CA file.
extra=()
compose() {
    OPENVIBES_IMAGE=$image "$engine" compose --progress quiet -p "$P" -f "$here/packaging/container/compose.yaml" \
        -f "$override" "${extra[@]}" "$@" 2> >(grep -v 'external compose provider' >&2)
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
ca_dir=$(mktemp -d)
[[ -n ${KEEP:-} ]] || trap 'cleanup; rm -rf "$override" "$ca_dir"' EXIT
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
#    Two settings changed meanwhile (#636): a new name and another port for
#    agents.
# compose.yaml's stop_grace_period gives systemd the time to stop
# PostgreSQL and the services cleanly.
compose down > /dev/null
export OPENVIBES_EXTRA_NAMES=127.0.0.1,ov-e2e.test OPENVIBES_INGEST_PORT=18500
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
# TLS checks the new name against the platform's own root (the console may
# answer 421 to it; only the handshake matters here).
in_c 'curl -sS -o /dev/null --cacert /etc/openvibes/pki/root.crt --resolve ov-e2e.test:443:127.0.0.1 https://ov-e2e.test/' \
    || fail "the console's certificate does not have the new name"
wait_for "ingest listens on the new port" 60 'ss -ltnH "sport = :18500" | grep -q .'
[[ $("$engine" logs "$C" 2>&1) == *'ingest port moved from 18423 to 18500'* ]] || fail "the log does not say agents still call the old ingest port"
ok "a new container on the same volumes keeps the CA and the database, starts the services, applies a new name and a moved port, and says where the console is"

# 4. A CA from your own PKI: a root and an intermediate made apart from
#    the platform (with the image's offline CA commands, in a throwaway
#    container), the intermediate's chain and key in one mounted file. The
#    first start imports it, and the platform trusts that root, not one of
#    its own.
"$engine" run --rm --entrypoint bash "$image" -c 'set -e; cd /tmp
    openvibes-admin ca init-root --out root > /dev/null
    openvibes-admin ca intermediate-request --out int > /dev/null
    openvibes-admin ca sign-intermediate --root root --csr int/intermediate.csr --out int/intermediate.crt > /dev/null
    cat int/intermediate.crt root/root.crt int/intermediate.key' > "$ca_dir/ca.pem" || fail "making a CA to import"
chmod 644 "$ca_dir/ca.pem"
# The second certificate in the file is the root.
own_root=$(awk '/BEGIN CERTIFICATE/{n++} n==2{print} n==2&&/END CERTIFICATE/{exit}' "$ca_dir/ca.pem" | grep -v -- '-----' | tr -d '\n')
cat > "$ca_dir/mount.yaml" <<YAML
services:
  openvibes:
    volumes:
      - "$ca_dir/ca.pem:/mnt/ca.pem:ro,z"
YAML
extra=(-f "$ca_dir/mount.yaml")
compose down -v -t 60 > /dev/null
export OPENVIBES_CA_FILE=/mnt/ca.pem
start
wait_for "the first start imported the CA and set the platform up" 900 "systemctl is-active -q openvibes-container-start"
wait_for "the console answers with the imported CA" 60 'curl -skf -o /dev/null https://127.0.0.1/'
installed=$(in_c 'grep -v -- "-----" /etc/openvibes/pki/root.crt | tr -d "\n"')
[[ -n $own_root && $installed == "$own_root" ]] || fail "the platform does not trust the imported CA's root"
[[ $(in_c 'sha256sum /etc/openvibes/pki/root.crt' | cut -d' ' -f1) != "$root_fp" ]] || fail "the root is still the one from step 2"
ok "a CA from your own PKI (OPENVIBES_CA_FILE) is imported on the first start, and the platform trusts its root"
echo "container-e2e: all checks passed"
