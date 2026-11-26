#!/bin/bash
# End to end for the platform container (#604, #606, #607), started from
# packaging/container/compose.yaml as a user would: the image boots under
# systemd with no privileged mode, sets itself up from the compose file's
# settings (a bad one stops it with a message), a new container on the same
# volumes (a new image) keeps the data and applies changed settings, a new
# image backs up and migrates the database first (#609), an agent installed
# with the console's install line enrolls and reports, before and after a new
# image (#611), and a CA from your own PKI
# (OPENVIBES_CA_FILE) is imported instead of one OpenVIBES makes.
#
# Usage: bash scripts/container-e2e.sh [IMAGE [ASSISTANT_IMAGE]]
#   IMAGE defaults to openvibes-platform:dev; with ASSISTANT_IMAGE (from
#   build-assistant-image.sh) step 5 tests the assistant container (#643)
#   with a tiny test model. ENGINE picks docker or podman
#   (default: whichever is installed, podman first). Needs `ENGINE compose`,
#   and for the agent (x86_64 only, as its packages are) the internet: it
#   installs from the project's website, as the install line does.
set -euo pipefail

image=${1:-openvibes-platform:dev}
assistant_image=${2:-}
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
      # The agent (step 3a) reaches ingest and distribution here, on the
      # host's loopback, as an agent on another host would through the
      # published ports. Step 3 moves ingest to 18500.
      - "127.0.0.1:18423:18423"
      - "127.0.0.1:18500:18500"
      - "127.0.0.1:18424:18424"
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
A=$P-agent
cleanup() {
    "$engine" rm -f -t 30 "$A" > /dev/null 2>&1 || true
    # With the profile, so the assistant (step 5) and its volumes go too.
    COMPOSE_PROFILES=assistant compose down -v -t 60 > /dev/null 2>&1 || true
}
in_a() { "$engine" exec "$A" bash -c "$1"; }
admin() { in_c "runuser -u openvibes-admin -- openvibes-admin $1"; }
# The agent's last scan, from `agent show` ("last scan <when>, <n> rules ...").
last_scan() { admin "agent show $agent_id" 2>/dev/null | sed -n 's/^last scan //p'; }
# When the platform last heard from it (a heartbeat a minute), from
# `agent list` ("<id>  active  last seen YYYY-MM-DD HH:MM UTC  ...").
last_seen() { admin 'agent list' 2>/dev/null | awk -v id="$agent_id" '$1 == id {print $5 " " $6}'; }
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

# 3a. An agent on "another host" (#611): a systemd container on the host's
#     network, installed and enrolled with the line `agent command` prints
#     (the console's Copy CLI install), from the project's website. It
#     enrolls, fetches its rules and reports a scan. Agent packages are
#     x86_64 only.
agent_id=
if [[ $(uname -m) == x86_64 ]]; then
    agent_ctx=$(mktemp -d)
    printf '%s\n' 'FROM docker.io/library/almalinux:10' \
        'RUN dnf -q -y install systemd procps-ng && dnf -q clean all' \
        'STOPSIGNAL SIGRTMIN+3' 'CMD ["/sbin/init"]' > "$agent_ctx/Containerfile"
    "$engine" build -q -t "$A" -f "$agent_ctx/Containerfile" "$agent_ctx" > /dev/null || fail "building the agent's host image"
    rm -rf "$agent_ctx"
    "$engine" run -d --name "$A" -t --network host --cgroupns host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
        --tmpfs /run --tmpfs /run/lock --tmpfs /tmp "$A" > /dev/null || fail "starting the agent's host"
    for _ in $(seq 60); do
        in_a 'systemctl is-system-running | grep -qE "^(starting|running|degraded)$"' 2> /dev/null && break; sleep 1
    done
    line=$(admin 'agent command' | head -n 1)
    # Step 3 moved ingest, so the platform carries its port. The line holds
    # the enrollment token: never printed.
    [[ $line == 'curl -fsSL https://openvibes-project.github.io/install.sh | sudo sh -s -- --agent --platform localhost:18500 '* ]] \
        || fail "agent command printed no install line for localhost:18500 (it begins: ${line:0:70})"
    # Root in the container: the line as printed, without sudo.
    in_a "${line/| sudo sh/| sh}" > /dev/null || fail "the install line failed on the agent's host"
    for _ in $(seq 120); do
        agent_id=$(admin 'agent list' | awk '$2 == "active" {print $1; exit}')
        [[ -n $agent_id ]] && break; sleep 1
    done
    [[ -n $agent_id ]] || fail "the agent did not enroll"
    for _ in $(seq 180); do [[ -n $(last_scan) ]] && break; sleep 1; done
    scan=$(last_scan)
    [[ $scan =~ ,\ ([1-9][0-9]*)\ rules ]] || fail "the agent reported no scan with rules: '$scan'"
    ok "an agent installed with the console's install line enrolls ($agent_id), fetches its rules and reports a scan"
else
    echo "skip: the agent (step 3a): agent packages are x86_64 only"
fi

# 3b. A new image (#609): the data says an older image last ran it, so the
#     start backs the database up to the backups volume, migrates it, keeps
#     the newest three image-update backups, and records this image.
image_version=$(in_c "rpm -q --qf '%{VERSION}-%{RELEASE}' openvibes-admin")
[[ $(in_c 'cat /etc/openvibes/container-image') == "$image_version" ]] || fail "the start did not record the image's version"
# The minute before the new image: the agent's next heartbeat after it is
# later.
before_update=$(date -u '+%Y-%m-%d %H:%M')
in_c 'echo 0.0.1-1 > /etc/openvibes/container-image
    install -d -m 0700 /var/backups/openvibes
    for n in 1 2 3; do
        f=/var/backups/openvibes/openvibes-0.0.0-2000010$n-000000.dump
        touch -d "2000-01-0$n" "$f" "$f.roles.sql"
    done'
compose down > /dev/null
start
wait_for "the start unit finished after the new image" 300 "systemctl is-active -q openvibes-container-start"
log=$("$engine" logs "$C" 2>&1)
[[ $log == *"updating from 0.0.1-1 to $image_version: backing up the database first"* ]] || fail "the log does not say the image changed"
[[ $log == *'OpenVIBES: database updated:'* ]] || fail "the log does not say the database was updated"
in_c 'set -e; f=$(ls /var/backups/openvibes/openvibes-0.0.1-*.dump); test -s "$f"; test -s "$f.roles.sql"
    pg_restore --list "$f" > /dev/null' || fail "no readable backup on the backups volume"
left=$(in_c 'ls /var/backups/openvibes/*.dump | xargs -n1 basename | sort | tr "\n" " "')
[[ $left == "openvibes-0.0.0-20000102-000000.dump openvibes-0.0.0-20000103-000000.dump openvibes-0.0.1-"*".dump " ]] \
    || fail "the backups kept are not the newest three: $left"
in_c 'test ! -e /var/backups/openvibes/openvibes-0.0.0-20000101-000000.dump.roles.sql' || fail "an old backup's roles file was left"
[[ $(in_c 'cat /etc/openvibes/container-image') == "$image_version" ]] || fail "the new image's version was not recorded"
wait_for "the console answers after the new image" 120 'curl -skf -o /dev/null https://127.0.0.1/'
in_c 'runuser -u openvibes-admin -- openvibes-admin status' > /dev/null || fail "the database is not current after the new image"
"$engine" volume ls -q | grep -qx "${P}_backups" || fail "the backups are not on their own volume"
if [[ -n $agent_id ]]; then
    # The same agent, with its certificate, carries on after the new image:
    # still enrolled, and heard from after it (its heartbeat).
    [[ $(admin 'agent list' | awk -v id="$agent_id" '$1 == id {print $2}') == active ]] || fail "the agent is not active after the new image"
    # A date, not "never", which sorts after one.
    for _ in $(seq 240); do seen=$(last_seen); [[ $seen =~ ^[0-9] && $seen > $before_update ]] && break; sleep 1; done
    [[ $seen =~ ^[0-9] && $seen > $before_update ]] || fail "the platform has not heard from the agent since the new image (last seen $seen)"
    ok "the agent stays enrolled across the new image and the platform hears from it again"
fi
ok "a new image backs up the database to the backups volume, migrates it, keeps the newest three backups, and the platform comes back"

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

# 5. The assistant, its own container (#643): off until it answers (#653),
#    on with the compose profile. The real model is 2.7 GB, so a variant
#    of the image pins a tiny random-weight one (scripts/tiny-gguf.py) at a
#    file:// URL: the download and its SHA-256 check still run.
if [[ -n $assistant_image ]]; then
    # What a signed-in admin's session offers ("assistant.use" or not);
    # expanded inside the container.
    # shellcheck disable=SC2016
    session='cd /tmp && curl -ksSf -c j -o p.json https://localhost/auth/v1/preauth &&
        csrf=$(sed -n "s/.*\"csrf_token\":\"\([^\"]*\)\".*/\1/p" p.json) &&
        curl -ksSf -b j -c j -o /dev/null -H "Origin: https://localhost" -H "Sec-Fetch-Site: same-origin" \
            -H "X-CSRF-Token: $csrf" -H "Content-Type: application/json" \
            -d "{\"username\":\"admin\",\"password\":\"$OPENVIBES_ADMIN_PASSWORD\"}" https://localhost/auth/v1/login &&
        curl -ksSf -b j https://localhost/api/v1/session; rm -f j p.json'
    in_c "grep -q '^url = \"http://127.0.0.1:18430/v1\"' /etc/openvibes/console.toml" || fail "the console is not pointed at the assistant"
    [[ $(in_c 'stat -c "%u:%g %a" /var/lib/openvibes-assistant-key/llm-api-key') == "0:976 640" ]] || fail "the shared key is not root:976 0640"
    [[ $(in_c 'stat -c "%U %a" /etc/openvibes/llm-api-key') == "openvibes-console 400" ]] || fail "the console's key is not its own, 0400"
    offered=$(in_c "OPENVIBES_ADMIN_PASSWORD='$OPENVIBES_ADMIN_PASSWORD' bash -c '$session'") || fail "reading the admin's session"
    [[ $offered == *'"principal"'* ]] || fail "the session did not answer: $offered"
    [[ $offered != *'"assistant.use"'* ]] || fail "the console offers an assistant that never answered"
    ok "without the assistant container, the console is set up for it but offers no assistant"

    tiny=$(mktemp -d)
    python3 "$here/scripts/tiny-gguf.py" "$tiny/tiny.gguf"
    sum=$(sha256sum "$tiny/tiny.gguf" | cut -d' ' -f1)
    printf 'LLM_MODEL_FILE=tiny.gguf\nLLM_MODEL_URL=file:///opt/tiny.gguf\nLLM_MODEL_SHA256=%s\nLLM_MODEL_ALIAS=%s\n' \
        "$sum" "$(in_c "sed -n 's/^LLM_MODEL_ALIAS=//p' /usr/share/openvibes-llm/model.pin")" > "$tiny/model.pin"
    printf 'FROM %s\nCOPY tiny.gguf /opt/tiny.gguf\nCOPY model.pin /usr/share/openvibes-llm/model.pin\n' "$assistant_image" |
        "$engine" build -q -t openvibes-assistant:e2e -f - "$tiny" > /dev/null || fail "building the test assistant image"
    rm -rf "$tiny"
    COMPOSE_PROFILES=assistant OPENVIBES_ASSISTANT_IMAGE=openvibes-assistant:e2e compose up -d > /dev/null
    A=$(COMPOSE_PROFILES=assistant compose ps -q assistant)
    [[ -n $A ]] || fail "compose started no assistant container"
    # The log read whole first: grep -q would close the pipe on the engine
    # under pipefail.
    alog() { "$engine" logs "$A" 2>&1 | grep 'OpenVIBES assistant\|openvibes-llm-check' || true; }
    for _ in $(seq 60); do [[ $(alog) == *serving* ]] && break; sleep 2; done
    [[ $(alog) == *"model downloaded and checked"* ]] || fail "the assistant did not download and check its model: $(alog)"
    [[ $(alog) == *serving* ]] || fail "the assistant does not serve: $(alog)"
    [[ $("$engine" exec "$A" id -u) == 976 ]] || fail "the assistant runs as $("$engine" exec "$A" id -u), not 976"
    [[ $(in_c 'curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:18430/v1/models') == 401 ]] || fail "the assistant answers without the key"
    wait_for "the console offers the assistant once it answers" 150 \
        "OPENVIBES_ADMIN_PASSWORD='$OPENVIBES_ADMIN_PASSWORD' bash -c '$session' | grep -q '\"assistant.use\"'"
    ok "with the assistant profile, the assistant downloads and checks its model, needs the key, and the console offers it"
fi
echo "container-e2e: all checks passed"
