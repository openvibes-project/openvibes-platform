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
