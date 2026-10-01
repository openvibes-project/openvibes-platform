#!/usr/bin/env bash
# The platform half of scripts/alarms-e2e.sh, inside fedora:44 (host
# network): this build's RPMs, then PostgreSQL, ingest (integration-lib.sh)
# and a direct-TLS console as an unprivileged user, until stopped.
# Env: RPMS (directory), SHARED (the work directory shared with the host,
# holding console.crt and console.key), CONSOLE_PORT, CONSOLE_HEALTH_PORT.
# The platform lives in $SHARED/platform/run.
set -euo pipefail
if [[ $(id -u) == 0 ]]; then
    dnf -q -y install postgresql-server procps-ng jq >/dev/null
    rpms=()
    for package in admin ingest console; do
        rpms+=("$(ls "$RPMS"/openvibes-"$package"-[0-9]*.x86_64.rpm | sort -V | tail -1)")
    done
    dnf -q -y install "${rpms[@]}" >/dev/null
    useradd -m ci
    mkdir -p "$SHARED/platform"; chown ci "$SHARED/platform"
    exec runuser -u ci -- env RPMS="$RPMS" SHARED="$SHARED" CONSOLE_PORT="$CONSOLE_PORT" \
        CONSOLE_HEALTH_PORT="$CONSOLE_HEALTH_PORT" bash "$0"
fi

ROOT=$(cd "$(dirname "$0")/.." && pwd)
source "$ROOT/scripts/integration-lib.sh"
W=$SHARED/platform/run INGEST_PORT=28423 HEALTH_PORT=28480 OPENVIBES_BIN_DIR=/usr/bin
start_platform

cat > "$W/console.toml" <<EOF
development_listen = "127.0.0.1:$CONSOLE_PORT"
health_listen = "127.0.0.1:$CONSOLE_HEALTH_PORT"
transport_mode = "direct_tls"
database_url = "postgresql:///openvibes?host=$W/pg/run&user=openvibes-console"
public_origin = "https://127.0.0.1:$CONSOLE_PORT"
server_certificate_file = "$SHARED/console.crt"
server_key_file = "$SHARED/console.key"
EOF
/usr/bin/openvibes-console --config "$W/console.toml" 2> "$W/console.log" &
PIDS+=("$!")
wait_for "console ready" 30 curl -fsS "http://127.0.0.1:$CONSOLE_HEALTH_PORT/ready"
# The agent on the host reads the root certificate (not the key).
chmod a+x "$W/ca" "$W/ca/root"; chmod a+r "$W/ca/root/root.crt"
touch "$W/ready"
wait
