# Sourced by the integration and packaging scripts. No side effects on source.

# The agent revision the platform pins for openvibes-core (single source).
agent_rev() {
    sed -n 's/^openvibes-core = .*rev = "\([0-9a-f]\{40\}\)".*/\1/p' "$ROOT/Cargo.toml"
}

# Installs openvibes-agent at the pinned revision into DIR/bin (cached).
build_agent() {
    local dir=$1 rev
    rev=$(agent_rev)
    [[ -n "$rev" ]] || { echo "FAIL: no pinned agent revision in Cargo.toml" >&2; return 1; }
    if [[ ! -x "$dir/bin/openvibes-agent" || "$(cat "$dir/rev" 2>/dev/null)" != "$rev" ]]; then
        cargo install --quiet --locked --force \
            --git https://github.com/openvibes-project/openvibes-agent.git --rev "$rev" \
            --root "$dir" openvibes-agent >&2
        echo "$rev" > "$dir/rev"
    fi
    echo "$dir/bin/openvibes-agent"
}

# Writes a signed integration bundle and prints its public key:
# bundle OUT_FILE [VERSION [PAD_RULES]], with BUNDLE_BIN if set.
bundle() {
    if [[ -n "${BUNDLE_BIN:-}" ]]; then "$BUNDLE_BIN" "$@"
    else (cd "$ROOT" && cargo run -q --locked -p openvibes-ingest --example integration_bundle -- "$@"); fi
}

# wait_for DESC SECONDS CMD...: poll CMD once a second until it succeeds.
wait_for() {
    local desc=$1 seconds=$2
    shift 2
    for ((i = 0; i < seconds; i++)); do
        if "$@" >/dev/null 2>&1; then
            echo "ok: $desc"
            return 0
        fi
        sleep 1
    done
    echo "FAIL: $desc (after ${seconds}s)" >&2
    return 1
}

# Stops everything start_platform (and callers, via PIDS) started; on failure
# prints the tail of every log under $W.
cleanup() {
    local status=$?
    for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
    wait 2>/dev/null || true
    [[ -d "$W/pg/data" ]] && pg_ctl -D "$W/pg/data" -m immediate stop >/dev/null 2>&1 || true
    if ((status != 0)); then
        for log in "$W"/*.log; do
            [[ -f "$log" ]] && { echo "--- $(basename "$log") (tail)"; tail -n 20 "$log"; }
        done
    fi
    exit "$status"
}

# Fresh local platform under $W: PostgreSQL (Unix socket only), schema,
# built-in CA, and openvibes-ingest on 127.0.0.1:$INGEST_PORT until /ready.
# Uses ROOT, W, INGEST_PORT, HEALTH_PORT, OPENVIBES_BIN_DIR (built if unset)
# and INGEST_EXTRA (extra ingest.toml lines). Defines admin, sql, PIDS,
# INGEST_PID, and the EXIT trap.
start_platform() {
    PIDS=()
    trap cleanup EXIT
    rm -rf "$W"; mkdir -p "$W/pg/run" "$W/ca"

    # Binaries.
    if [[ -z "${OPENVIBES_BIN_DIR:-}" ]]; then
        cargo build --quiet --release --locked -p openvibes-ingest -p openvibes-distribution \
            -p openvibes-admin
        OPENVIBES_BIN_DIR="$ROOT/target/release"
    fi
    admin() { "$OPENVIBES_BIN_DIR/openvibes-admin" --config "$W/admin.toml" "$@"; }

    # PostgreSQL (Unix socket only) and the schema.
    # As in the documented install: a superuser creates an admin role that
    # may only create roles, and the database it owns.
    initdb -D "$W/pg/data" -U postgres --auth=trust >/dev/null
    pg_ctl -D "$W/pg/data" -o "-k $W/pg/run -c listen_addresses=''" -l "$W/pg/log" -w start >/dev/null
    createuser -h "$W/pg/run" -U postgres --createrole openvibes_admin
    createdb -h "$W/pg/run" -U postgres -O openvibes_admin openvibes
    sql() { psql -h "$W/pg/run" -U openvibes_admin -d openvibes -AtX -c "$1"; }
    echo "database_url = \"postgresql:///openvibes?host=$W/pg/run&user=openvibes_admin\"" > "$W/admin.toml"
    admin migrate >/dev/null
    admin maintenance >/dev/null

    # Built-in CA: root, intermediate, server certificate for 127.0.0.1.
    admin ca init-root --out "$W/ca/root" >/dev/null
    admin ca intermediate-request --out "$W/ca/int" >/dev/null
    admin ca sign-intermediate --root "$W/ca/root" --csr "$W/ca/int/intermediate.csr" \
        --out "$W/ca/int/intermediate.crt" >/dev/null
    admin ca import-intermediate --cert "$W/ca/int/intermediate.crt" \
        --key "$W/ca/int/intermediate.key" --root-cert "$W/ca/root/root.crt" >/dev/null
    admin ca issue-server localhost --san 127.0.0.1 --issuer-cert "$W/ca/int/intermediate.crt" \
        --issuer-key "$W/ca/int/intermediate.key" --out "$W/ca/tls" >/dev/null

    # Ingest.
    cat > "$W/ingest.toml" <<EOF
listen = "127.0.0.1:$INGEST_PORT"
health_listen = "127.0.0.1:$HEALTH_PORT"
server_certificate_file = "$W/ca/tls/localhost.crt"
server_key_file = "$W/ca/tls/localhost.key"
client_ca_file = "$W/ca/int/intermediate.crt"
issuing_certificate_file = "$W/ca/int/intermediate.crt"
issuing_key_file = "$W/ca/int/intermediate.key"
database_url = "postgresql:///openvibes?host=$W/pg/run&user=openvibes_ingest"
EOF
    [[ -n "${INGEST_EXTRA:-}" ]] && printf '%s\n' "$INGEST_EXTRA" >> "$W/ingest.toml"
    "$OPENVIBES_BIN_DIR/openvibes-ingest" --config "$W/ingest.toml" 2> "$W/ingest.log" &
    INGEST_PID=$!
    PIDS+=("$INGEST_PID")
    wait_for "ingest ready" 30 curl -fsS "http://127.0.0.1:$HEALTH_PORT/ready"
}

# openvibes-distribution on 127.0.0.1:$DIST_PORT (default 28424) until
# /ready on $DIST_HEALTH_PORT (default 28481), with the platform's server
# certificate and the least-privilege database role. Call after
# start_platform; again after stop_distribution to restart. Defines DIST_PID.
start_distribution() {
    DIST_PORT=${DIST_PORT:-28424}
    DIST_HEALTH_PORT=${DIST_HEALTH_PORT:-28481}
    cat > "$W/distribution.toml" <<EOF
listen = "127.0.0.1:$DIST_PORT"
health_listen = "127.0.0.1:$DIST_HEALTH_PORT"
server_certificate_file = "$W/ca/tls/localhost.crt"
server_key_file = "$W/ca/tls/localhost.key"
client_ca_file = "$W/ca/int/intermediate.crt"
database_url = "postgresql:///openvibes?host=$W/pg/run&user=openvibes_distribution"
EOF
    "$OPENVIBES_BIN_DIR/openvibes-distribution" --config "$W/distribution.toml" 2>> "$W/distribution.log" &
    DIST_PID=$!
    PIDS+=("$DIST_PID")
    wait_for "distribution ready" 30 curl -fsS "http://127.0.0.1:$DIST_HEALTH_PORT/ready"
}

# Stops distribution and forgets its PID.
stop_distribution() {
    kill "$DIST_PID"; wait "$DIST_PID" 2>/dev/null || true
    local kept=() pid
    for pid in "${PIDS[@]}"; do [[ "$pid" == "$DIST_PID" ]] || kept+=("$pid"); done
    PIDS=("${kept[@]}")
}
