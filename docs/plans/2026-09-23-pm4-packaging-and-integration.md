# PM4: RPM Packaging and Cross-Repo Integration — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `openvibes-ingest` and `openvibes-admin` install as RPMs on Fedora, and a script proves the exit-criteria sequence with the real agent binary. The sequence is: enroll, heartbeat, deliver exactly once, restart, renew, revoke, and re-enroll.

**Architecture:**
- **Integration test:** `scripts/integration-agent.sh` drives everything as an unprivileged user. It uses:
  - a throwaway PostgreSQL cluster from Fedora's packages;
  - the built-in CA, created with `openvibes-admin`;
  - `openvibes-ingest` on loopback;
  - the agent built at the revision the platform pins.
- **Checks:** the script asserts only on what the platform and agent really store: PostgreSQL rows, the agent's SQLite queue, and ingest's JSON request log.
- **Packaging:** `scripts/build-rpm.sh` builds the release binaries and wraps them with `rpmbuild -bb`. The result is an `openvibes-ingest` RPM and an `openvibes-admin` RPM, each with a hardened systemd unit and a sysusers entry. `scripts/check-rpm.sh` verifies an installed system.
- **CI:** a `fedora:44` container job builds the RPMs, installs them, checks them, and runs the integration script against the installed binaries.

**Tech Stack:** bash, PostgreSQL 18 (`postgresql-server`), `sqlite3`, `jq`, `curl`, `rpm-build`, `systemd-rpm-macros`, systemd units, sysusers.d. The test bundle is written by a Rust example that uses the agent's `openvibes-rules`, `ed25519-dalek` 3.0.0 and `sha2` 0.11, at the pinned agent revision.

**Spec:** `docs/specs/2026-09-23-ingest-subproject-design.md`:
- section 1: exit criteria 1–3;
- section 3: config;
- section 7: admin maintenance timer;
- section 8: cross-repo integration;
- section 9: packaging;
- section 10: PM4 row.

## Global Constraints

- **Carried over:** PM0–PM3 constraints still apply. That means the toolchain, lints, `--locked`, the commit trailer, component docs updated in the same change, `CARGO_NET_GIT_FETCH_WITH_CLI=true`, and every CI action pinned to a commit SHA.
- **Agent revision:** the agent is built at exactly the revision that `Cargo.toml` pins for `openvibes-core`. The script reads it from there and never takes a second copy of the hash.
- **Unit hardening:** each unit has `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, and `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`.
- **Service users:** `openvibes_ingest` and `openvibes_admin`. They match the PostgreSQL role names, so Fedora's default `local all all peer` authentication works without an ident map.
- **Paths:**
  - configs: `/etc/openvibes/ingest.toml` (0640 root:openvibes_ingest) and `/etc/openvibes/admin.toml` (0640 root:openvibes_admin), both `%config(noreplace)`;
  - state: `/var/lib/openvibes-ingest` (0700 openvibes_ingest).
- **Maintenance:** `openvibes-maintenance.timer` runs `openvibes-admin maintenance` daily.
- **Secrets:** no secrets in the repository. The rule-signing seed in the example is a published test-only constant, `[7; 32]`, the same as the agent's tests, and it signs only the integration bundle.
- **Script hygiene:** scripts use `set -euo pipefail`, keep everything under `target/integration` (or `target/rpm`), and kill every process they started on exit, including on failure.
- **Planning ruling:** no tmpfiles.d entry. The RPM owns `/var/lib/openvibes-ingest` (0700), so it exists at install time for the intermediate key. Ingest only reads it (no `StateDirectory`, no write access under `ProtectSystem=strict`). Spec section 9 names tmpfiles for the same purpose. Cost if wrong: one 1-line file.
- **Allowed tools:** scripts use only `bash`, coreutils, `curl`, `jq`, `sqlite3`, `psql`, and the PostgreSQL server binaries.

## Review Focus

- **No findings lost on revocation:** findings queued before a revocation are still delivered after re-enrollment, and the agent's acknowledged set equals the stored set. (Task 3 checks this after re-enrollment.)
- **No leftover processes:** a failed run leaves no ingest, agent, or PostgreSQL process behind, so a rerun is not blocked by a busy port. (Tasks 2–3 use an `EXIT` trap. Task 3 has a step that runs the script with a failing check and then checks for stray processes.)
- **Edited configs survive upgrades:** `rpm -qc` lists both configs, and the spec marks them `%config(noreplace)`. (Task 4's check.)
- **Private key protection:** the intermediate key directory is readable only by the ingest user, and the admin user cannot read ingest's config. (Task 4 checks modes and owners.)
- **Clean shutdown:** stopping the unit shuts ingest down cleanly (`KillSignal=SIGINT`, because the binary listens for ctrl-c) and does not kill it mid-request. (Task 4: the unit contains it and `systemd-analyze verify` passes.)

---

### Task 1: Signed integration bundle and the pinned agent binary

**Files:**
- Create `crates/openvibes-ingest/examples/integration_bundle.rs`.
- Create `scripts/integration-lib.sh`, with the shared helpers that later tasks use.
- Modify `crates/openvibes-ingest/Cargo.toml` (dev-dependencies) and the workspace `Cargo.toml` (`openvibes-rules`, `ed25519-dalek`, `sha2` in `[workspace.dependencies]`).
- Update `docs/components/openvibes-ingest.md` ("Integration bundle" paragraph).

**Interfaces:**
- **Produces the example:** `cargo run -q --locked -p openvibes-ingest --example integration_bundle -- OUT_FILE` writes a signed envelope for rule set `integration` with issuer key `integration.test`. It holds two always-true rules, `integration.processes` (`facts['process.count'] >= 1`) and `integration.processes.nonnegative` (`facts['process.count'] >= 0`). The envelope was created 1 hour ago and expires in 7 days. The example prints the base64url public key on stdout.
- **Produces `scripts/integration-lib.sh`**, sourced by the other scripts:
  - `agent_rev`: prints the pinned revision.
  - `build_agent DIR`: installs `openvibes-agent` at that revision into `DIR/bin` and prints the binary's path.
  - `wait_for DESC SECONDS CMD...`: polls every second and prints `ok: DESC`, or `FAIL: DESC` and returns 1.

- [ ] **Step 1: Add dependencies.** In the workspace `Cargo.toml`, `[workspace.dependencies]`:

```toml
openvibes-rules = { git = "https://github.com/openvibes-project/openvibes-agent.git", rev = "8dfa7744c23febfda48383cc206d6b2c0f6e1fc9" }
ed25519-dalek = { version = "3.0.0", default-features = false, features = ["fast", "zeroize"] }
sha2 = { version = "0.11", default-features = false }
```

In `crates/openvibes-ingest/Cargo.toml`, `[dev-dependencies]`, add `openvibes-rules.workspace = true`, `ed25519-dalek.workspace = true`, `sha2.workspace = true`.

- [ ] **Step 2: Write the example.** `crates/openvibes-ingest/examples/integration_bundle.rs`:

```rust
//! Writes a signed rule bundle for `scripts/integration-agent.sh` and prints
//! its base64url public key. Test-only: the seed is a published constant
//! (the agent's tests use the same one) and signs nothing else.

use std::{
    path::PathBuf,
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use openvibes_core::{
    Confidence, Identifier, PayloadEncoding, ResourceLimits, Rule, RuleSet, SchemaVersion,
    Severity, SignedRuleEnvelope,
};
use openvibes_rules::signing_preimage;
use sha2::{Digest, Sha256};

const HOUR_MS: i64 = 3_600_000;

fn rule(id: &str, expression: &str) -> Rule {
    Rule {
        id: Identifier::new(id).expect("valid id"),
        version: 1,
        title: "Integration rule".into(),
        severity: Severity::Info,
        confidence: Confidence::new(100).expect("valid confidence"),
        expression: expression.into(),
        finding_message: "Integration test finding".into(),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [out] = args.as_slice() else {
        eprintln!("usage: integration_bundle OUT_FILE");
        return ExitCode::from(2);
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX));
    let key = SigningKey::from_bytes(&[7; 32]);
    let payload = serde_json::to_string(&RuleSet {
        schema_version: SchemaVersion::V1,
        rules: vec![
            rule("integration.processes", "facts['process.count'] >= 1"),
            rule("integration.processes.nonnegative", "facts['process.count'] >= 0"),
        ],
    })
    .expect("rule set serializes");
    let mut envelope = SignedRuleEnvelope {
        schema_version: SchemaVersion::V1,
        rule_set_id: Identifier::new("integration").expect("valid id"),
        rule_set_version: 1,
        issuer_key_id: Identifier::new("integration.test").expect("valid id"),
        created_at_unix_ms: now - HOUR_MS,
        expires_at_unix_ms: now + 7 * 24 * HOUR_MS,
        payload_encoding: PayloadEncoding::Json,
        payload_sha256_hex: Sha256::digest(payload.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        payload,
        signature_base64url: String::new(),
    };
    let preimage = signing_preimage(&envelope, ResourceLimits::V1).expect("valid envelope");
    envelope.signature_base64url = URL_SAFE_NO_PAD.encode(key.sign(&preimage).to_bytes());
    let bytes = serde_json::to_vec(&envelope).expect("envelope serializes");
    if std::fs::write(PathBuf::from(out), bytes).is_err() {
        eprintln!("integration_bundle: cannot write the bundle");
        return ExitCode::FAILURE;
    }
    println!("{}", URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()));
    ExitCode::SUCCESS
}
```

If the workspace lints reject `expect` in examples, use `#![allow(clippy::expect_used)]` at the top with the comment "test tool, not shipped". Ledger that as a ruling.

- [ ] **Step 3: Write `scripts/integration-lib.sh`.**

```bash
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
```

- [ ] **Step 4: Verify the bundle with the real agent in local-only mode (the test for this task).** This must be run by hand. Only the agent's own `export` proves that the agent accepts the bundle.

```bash
export CARGO_NET_GIT_FETCH_WITH_CLI=true
ROOT=$PWD; source scripts/integration-lib.sh
W=target/integration/t1; rm -rf "$W"; mkdir -p "$W/state" "$W/out"; chmod 700 "$W/state"
AGENT=$(build_agent "$PWD/target/integration/agent")
KEY=$(cargo run -q --locked -p openvibes-ingest --example integration_bundle -- "$PWD/$W/rules.json")
cat > "$W/agent.toml" <<EOF
state_dir = "$PWD/$W/state"
scan_interval_seconds = 86400
[[rule_sets]]
id = "integration"
bundle_file = "$PWD/$W/rules.json"
trusted_keys = [{ issuer_key_id = "integration.test", public_key = "$KEY" }]
EOF
"$AGENT" export "$PWD/$W/agent.toml" "$PWD/$W/out"
```

Expected: `openvibes-agent: exported 0 findings`. A local-only agent that has never scanned has queued nothing, and `export` doesn't scan. Next, run the agent once so it scans, stop it, then export again:

```bash
timeout 5 "$AGENT" "$PWD/$W/agent.toml" || true
"$AGENT" export "$PWD/$W/agent.toml" "$PWD/$W/out"
```

Expected: `exported 2 findings`, with no `rule set integration:` error line in the first command's stderr.

**RED check:** change the key's last character in `agent.toml`, rerun the timed agent, and see a `rule set integration:` error and 0 new findings. Then restore the key.

- [ ] **Step 5:** Run `cargo clippy --locked --workspace --all-targets -- -D warnings -F unsafe-code` and `cargo fmt --all --check`. Expected: clean.

- [ ] **Step 6: Docs and commit.** Add to `docs/components/openvibes-ingest.md`, under "How to test":

> The `integration_bundle` example writes a signed test rule bundle for `scripts/integration-agent.sh`. It is test-only (published seed) and never shipped.

Commit:

```bash
git add Cargo.toml Cargo.lock crates/openvibes-ingest scripts/integration-lib.sh docs/components/openvibes-ingest.md
git commit -m "Add the signed integration bundle example and agent build helper"
```

---

### Task 2: Integration script, part 1 (platform up, enrollment, exactly-once delivery)

**Files:**
- Create `scripts/integration-agent.sh`.
- Create `docs/components/integration-agent.md`.
- Update `docs/components/README.md`.

**Interfaces:**
- **Consumes:** Task 1's `agent_rev`, `build_agent`, `wait_for`, and the `integration_bundle` example.
- **Produces:** `scripts/integration-agent.sh`, run from any directory; exit 0 means every check passed. Environment overrides:
  - `OPENVIBES_BIN_DIR` (default: builds with `cargo build --release --locked` and uses `target/release`);
  - `AGENT_BIN` (default: `build_agent target/integration/agent`);
  - `BUNDLE_BIN` (default: `cargo run` of the example);
  - `INGEST_PORT` (default 28423) and `HEALTH_PORT` (default 28480).
- **Check functions defined here, reused by Task 3:**
  - `restart_agent`: starts the agent, or stops and starts it.
  - `heartbeats_ok`: prints how many heartbeats got 204.
  - `acked_equals_stored`: succeeds when the agent's pending queue is empty, it has acknowledged at least one finding, and its acknowledged ids equal the ids in `findings`.
  - `sql`: runs a query as the admin role.

- [ ] **Step 1: Write the script up to the enrollment check.** Before the token exists, the agent config names a token file that is **missing**, so the check must fail (RED).

```bash
#!/usr/bin/env bash
# Cross-repo integration (spec section 8): the real agent, built at the
# pinned revision, against openvibes-ingest and Fedora's PostgreSQL, all as
# the current (unprivileged) user under target/integration/run.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
source "$ROOT/scripts/integration-lib.sh"
export CARGO_NET_GIT_FETCH_WITH_CLI=true

W="$ROOT/target/integration/run"
INGEST_PORT=${INGEST_PORT:-28423}
HEALTH_PORT=${HEALTH_PORT:-28480}
PIDS=()
cleanup() {
    local status=$?
    for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
    wait 2>/dev/null || true
    [[ -d "$W/pg/data" ]] && pg_ctl -D "$W/pg/data" -m immediate stop >/dev/null 2>&1 || true
    if ((status != 0)); then
        echo "--- ingest log (tail)"; tail -n 20 "$W/ingest.log" 2>/dev/null || true
        echo "--- agent log (tail)"; tail -n 20 "$W/agent.log" 2>/dev/null || true
    fi
    exit "$status"
}
trap cleanup EXIT
rm -rf "$W"; mkdir -p "$W/pg/run" "$W/ca" "$W/agent/state"; chmod 700 "$W/agent/state"

# Binaries.
if [[ -z "${OPENVIBES_BIN_DIR:-}" ]]; then
    cargo build --quiet --release --locked -p openvibes-ingest -p openvibes-admin
    OPENVIBES_BIN_DIR="$ROOT/target/release"
fi
AGENT_BIN=${AGENT_BIN:-$(build_agent "$ROOT/target/integration/agent")}
admin() { "$OPENVIBES_BIN_DIR/openvibes-admin" --config "$W/admin.toml" "$@"; }

# PostgreSQL (Unix socket only) and the schema.
initdb -D "$W/pg/data" -U openvibes_admin --auth=trust >/dev/null
pg_ctl -D "$W/pg/data" -o "-k $W/pg/run -c listen_addresses=''" -l "$W/pg/log" -w start >/dev/null
createdb -h "$W/pg/run" -U openvibes_admin openvibes
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
"$OPENVIBES_BIN_DIR/openvibes-ingest" --config "$W/ingest.toml" 2> "$W/ingest.log" &
PIDS+=($!)
wait_for "ingest ready" 30 curl -fsS "http://127.0.0.1:$HEALTH_PORT/ready"

# Agent config with the signed integration bundle.
if [[ -n "${BUNDLE_BIN:-}" ]]; then
    KEY=$("$BUNDLE_BIN" "$W/agent/rules.json")
else
    KEY=$(cd "$ROOT" && cargo run -q --locked -p openvibes-ingest --example integration_bundle -- "$W/agent/rules.json")
fi
cat > "$W/agent/agent.toml" <<EOF
platform_url = "https://127.0.0.1:$INGEST_PORT"
platform_ca_file = "$W/ca/root/root.crt"
state_dir = "$W/agent/state"
enrollment_token_file = "$W/agent/token"
scan_interval_seconds = 86400
[[rule_sets]]
id = "integration"
bundle_file = "$W/agent/rules.json"
trusted_keys = [{ issuer_key_id = "integration.test", public_key = "$KEY" }]
EOF

AGENT_PID=
restart_agent() {
    if [[ -n "$AGENT_PID" ]]; then kill "$AGENT_PID"; wait "$AGENT_PID" 2>/dev/null || true; fi
    "$AGENT_BIN" "$W/agent/agent.toml" 2>> "$W/agent.log" &
    AGENT_PID=$!
    PIDS+=("$AGENT_PID")
}
active_agents() { [[ "$(sql "SELECT count(*) FROM agents WHERE status = 'active'")" == "$1" ]]; }

restart_agent
wait_for "agent enrolled" 20 active_agents 1
```

Run it: `bash scripts/integration-agent.sh`.

Expected: `ok: ingest ready`, then `FAIL: agent enrolled (after 20s)`, the agent log tail showing `waiting for an enrollment token`, and a nonzero exit. This proves the check sees a missing enrollment. Afterwards, `pgrep -f "$PWD/target/integration/run"` prints nothing, which proves the trap cleaned up.

- [ ] **Step 2: Issue the token (GREEN).** Insert this before `restart_agent`:

```bash
new_token() {
    admin token create --expires 1h | sed -n 's/^token \([A-Za-z0-9_-]\{43\}\)$/\1/p' > "$W/agent/token"
    chmod 600 "$W/agent/token"
    [[ -s "$W/agent/token" ]]
}
new_token
```

Run the script. Expected: `ok: agent enrolled`, exit 0.

- [ ] **Step 3: Heartbeat and exactly-once checks.** First add them with a deliberately wrong expectation (RED). Append:

```bash
FIRST_AGENT=$(sql "SELECT agent_id FROM agents WHERE status = 'active'")
heartbeats_ok() {
    jq -r 'select(.fields.endpoint == "/v1/heartbeat" and .fields.status == 204) | 1' \
        "$W/ingest.log" 2>/dev/null | wc -l
}
more_heartbeats_than() { (($(heartbeats_ok) > $1)); }
wait_for "heartbeat accepted" 20 more_heartbeats_than 0

acked_equals_stored() {
    local pending acked stored
    pending=$(sqlite3 "$W/agent/state/queue.sqlite" "SELECT count(*) FROM pending")
    acked=$(sqlite3 "$W/agent/state/queue.sqlite" "SELECT finding_id FROM acknowledged ORDER BY 1")
    stored=$(sql "SELECT finding_id FROM findings ORDER BY 1")
    [[ "$pending" == 0 && -n "$acked" && "$acked" == "$stored" ]]
}
wait_for "findings delivered exactly once" 20 acked_equals_stored
[[ "$(sql "SELECT count(*) FROM findings")" == 3 ]] || { echo "FAIL: expected 2 findings"; exit 1; }
```

Run it. Expected: the three `ok:` lines, then `FAIL: expected 2 findings`, because the count is really 2. That proves the count check works. Change `== 3` to `== 2` and run again. Expected: exit 0.

If `jq` finds no heartbeat, run `head -3 target/integration/run/ingest.log` and fit the filter to the real JSON shape. That shape is tracing-subscriber's JSON with fields under `.fields`. Ledger the change.

- [ ] **Step 4: Docs.**
  - Create `docs/components/integration-agent.md`, with the sections purpose, what it proves, how to run, environment overrides, requirements, failure output, and how to test. Requirements are `postgresql-server`, `sqlite`, `jq`, `curl`, and git access to the private agent repository.
  - Add it to `docs/components/README.md`.

- [ ] **Step 5: Commit.**

```bash
git add scripts/integration-agent.sh docs/components
git commit -m "Add the cross-repo integration script: enrollment and exactly-once delivery"
```

---

### Task 3: Integration script, part 2 (restart, renewal, revocation, re-enrollment)

**Files:**
- Modify `scripts/integration-agent.sh`.
- Modify `docs/components/integration-agent.md`.

**Interfaces:**
- **Consumes:** Task 2's `restart_agent`, `heartbeats_ok`, `more_heartbeats_than`, `acked_equals_stored`, `sql`, `new_token`, `admin`, and `FIRST_AGENT`.
- **Agent facts:**
  - Renewal is due at `obtained_at + 2/3 × (expires_at − obtained_at)`, and both values are stored in `identity.sqlite`, table `identity`, columns `obtained_at_ms` and `expires_at_ms`.
  - The agent ticks every 60 s and reads the token file only while it has no identity.
  - A 403 carrying `identity_revoked` deletes the stored identity. Queued findings stay.

- [ ] **Step 1: Restart and reconnect.** Append:

```bash
BEFORE=$(heartbeats_ok)
restart_agent
wait_for "agent reconnected after restart" 20 more_heartbeats_than "$BEFORE"
wait_for "no finding delivered twice after restart" 10 acked_equals_stored
```

Run the script. Expected: both `ok:` lines. (The agent scans on start only once per 86,400 s, and its last-scan time persists, so a restart adds no findings. If a restart does rescan, the check still holds: new ids are delivered once.)

- [ ] **Step 2: Renewal (RED, then GREEN).** First append the check alone, without forcing renewal:

```bash
certificates() { [[ "$(sql "SELECT count(*) FROM certificates WHERE agent_id = '$FIRST_AGENT'")" == "$1" ]]; }
wait_for "certificate renewed" 15 certificates 2
```

Run it. Expected: `FAIL: certificate renewed`, since renewal is not due for 20 days. Now put this before the check, to make renewal due while the agent is stopped:

```bash
kill "$AGENT_PID"; wait "$AGENT_PID" 2>/dev/null || true; AGENT_PID=
sqlite3 "$W/agent/state/identity.sqlite" "UPDATE identity SET obtained_at_ms = 0"
restart_agent
```

Run it. Expected: `ok: certificate renewed`. Then append:

```bash
BEFORE=$(heartbeats_ok)
wait_for "renewed certificate authenticates" 75 more_heartbeats_than "$BEFORE"
```

Expected: ok. This runs within one 60 s tick.

- [ ] **Step 3: Revocation and re-enrollment.** Append:

```bash
admin agent revoke "$FIRST_AGENT" >/dev/null
new_token   # the agent reads it only once its identity is gone
revoked_answer() {
    # A command substitution, not a pipe into grep -q: under pipefail an early
    # grep exit can SIGPIPE jq and fail the check even on a match.
    [[ -n "$(jq -r 'select(.fields.status == 403) | 1' "$W/ingest.log")" ]]
}
wait_for "revoked agent told identity_revoked" 75 revoked_answer
reenrolled() {
    [[ "$(sql "SELECT count(*) FROM agents WHERE status = 'active' AND agent_id <> '$FIRST_AGENT'")" == 1 ]]
}
wait_for "agent re-enrolled with a new token" 75 reenrolled
[[ "$(sql "SELECT status FROM agents WHERE agent_id = '$FIRST_AGENT'")" == revoked ]]
wait_for "no finding lost or duplicated across re-enrollment" 75 acked_equals_stored
echo "integration: all checks passed"
```

Run it. Expected: every `ok:` line and `integration: all checks passed`, in under 5 minutes.

**RED check for the 403 filter:** temporarily change `== 403` to `== 418`, and see `FAIL: revoked agent told identity_revoked`. Then restore it.

- [ ] **Step 4: Cleanup on failure.** Run `INGEST_PORT=1 bash scripts/integration-agent.sh`: the ingest can't bind, so `ingest ready` fails. Then run `pgrep -af "target/integration/run"`. Expected: nothing, which shows no ingest, agent, or PostgreSQL process was left behind.

- [ ] **Step 5: Docs and commit.** Extend `integration-agent.md` with the full sequence and the renewal trick. The trick is that `obtained_at_ms = 0` in the agent's identity store makes renewal due at once, without faking the clock, which would future-date findings.

```bash
git add scripts/integration-agent.sh docs/components/integration-agent.md
git commit -m "Integration: restart, renewal, revocation, re-enrollment with the real agent"
```

---

### Task 4: RPM packaging

**Files:**
- Create `packaging/rpm/openvibes-platform.spec`.
- Create `packaging/rpm/openvibes-ingest.service`.
- Create `packaging/rpm/openvibes-maintenance.service` and `packaging/rpm/openvibes-maintenance.timer`.
- Create `packaging/rpm/openvibes-ingest.sysusers` and `packaging/rpm/openvibes-admin.sysusers`.
- Create `packaging/rpm/ingest.toml` and `packaging/rpm/admin.toml`.
- Create `scripts/build-rpm.sh` and `scripts/check-rpm.sh`.
- Create `docs/components/packaging.md`, and update `docs/components/README.md`.

**Interfaces:**
- **Produces `scripts/build-rpm.sh`:** builds the release binaries and writes `target/rpm/RPMS/x86_64/openvibes-{ingest,admin}-0.1.0-1.<dist>.x86_64.rpm`.
- **Produces `scripts/check-rpm.sh`:** run as root on a system with both RPMs installed. Exit 0 means users, modes, config flags and units are right.

- [ ] **Step 1: Write the check first (RED).** `scripts/check-rpm.sh`:

```bash
#!/usr/bin/env bash
# Verifies an installed openvibes-ingest + openvibes-admin (run as root).
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
expect_stat() { # PATH MODE OWNER:GROUP
    [[ "$(stat -c '%a %U:%G' "$1")" == "$2 $3" ]] || fail "$1 is $(stat -c '%a %U:%G' "$1"), want $2 $3"
}
for user in openvibes_ingest openvibes_admin; do
    getent passwd "$user" >/dev/null || fail "no user $user"
done
expect_stat /etc/openvibes/ingest.toml 640 root:openvibes_ingest
expect_stat /etc/openvibes/admin.toml 640 root:openvibes_admin
expect_stat /var/lib/openvibes-ingest 700 openvibes_ingest:openvibes_ingest
rpm -qc openvibes-ingest | grep -qx /etc/openvibes/ingest.toml || fail "ingest.toml not %config"
rpm -qc openvibes-admin | grep -qx /etc/openvibes/admin.toml || fail "admin.toml not %config"
[[ "$(rpm -q --qf '[%{FILENAMES} %{FILEFLAGS:fflags}\n]' openvibes-ingest openvibes-admin | grep -c '\.toml cn')" == 2 ]] || fail "configs not noreplace"
systemd-analyze verify /usr/lib/systemd/system/openvibes-ingest.service \
    /usr/lib/systemd/system/openvibes-maintenance.service \
    /usr/lib/systemd/system/openvibes-maintenance.timer || fail "unit verification"
grep -q '^KillSignal=SIGINT' /usr/lib/systemd/system/openvibes-ingest.service || fail "no graceful stop"
/usr/bin/openvibes-admin --help >/dev/null || fail "openvibes-admin does not run"
out=$(/usr/bin/openvibes-ingest --config /nonexistent 2>&1) && fail "ingest started without config"
[[ "$out" == *"invalid ingest configuration"* ]] || fail "ingest error: $out"
echo "check-rpm: ok"
```

Run it on a fresh container:

```bash
podman run --rm -v "$PWD:/src:Z" -w /src registry.fedoraproject.org/fedora:44 bash scripts/check-rpm.sh
```

Expected: `FAIL: no user openvibes_ingest`.

- [ ] **Step 2: Units, sysusers, configs.**

`packaging/rpm/openvibes-ingest.service`:

```ini
[Unit]
Description=OpenVIBES ingest service
Documentation=https://github.com/openvibes-project/openvibes-platform
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=exec
User=openvibes_ingest
Group=openvibes_ingest
ExecStart=/usr/bin/openvibes-ingest --config /etc/openvibes/ingest.toml
# The binary shuts down gracefully on SIGINT (ctrl-c).
KillSignal=SIGINT
Restart=on-failure
RestartSec=5s
LimitNOFILE=65536
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
```

`packaging/rpm/openvibes-maintenance.service`: the same hardening block minus `KillSignal`, `Restart*`, `LimitNOFILE` and `[Install]`, with:

```ini
[Unit]
Description=OpenVIBES finding partition maintenance
After=postgresql.service

[Service]
Type=oneshot
User=openvibes_admin
Group=openvibes_admin
ExecStart=/usr/bin/openvibes-admin maintenance
```

`packaging/rpm/openvibes-maintenance.timer`:

```ini
[Unit]
Description=Daily OpenVIBES finding partition maintenance

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
```

`packaging/rpm/openvibes-ingest.sysusers`:

```
u openvibes_ingest - "OpenVIBES ingest service" /var/lib/openvibes-ingest -
```

`packaging/rpm/openvibes-admin.sysusers`:

```
u openvibes_admin - "OpenVIBES administration" - -
```

`packaging/rpm/ingest.toml` is spec section 3's example verbatim, starting with the comment `# Edit before starting openvibes-ingest; see docs/components/packaging.md.` `packaging/rpm/admin.toml`:

```toml
database_url = "postgresql:///openvibes?host=/run/postgresql&user=openvibes_admin"
```

- [ ] **Step 3: Spec file.** `packaging/rpm/openvibes-platform.spec`:

```spec
# Binary packaging: scripts/build-rpm.sh builds the release binaries with
# the pinned toolchain first; this spec only installs them.
%global debug_package %{nil}

Name:           openvibes-platform
Version:        %{ov_version}
Release:        1%{?dist}
Summary:        OpenVIBES platform services
License:        MIT
URL:            https://github.com/openvibes-project/openvibes-platform
BuildRequires:  systemd-rpm-macros

%description
OpenVIBES platform services.

%package -n openvibes-ingest
Summary:        OpenVIBES agent-facing ingest service
%{?systemd_requires}

%description -n openvibes-ingest
Receives enrollments, renewals, heartbeats, and findings from OpenVIBES agents over mTLS.

%package -n openvibes-admin
Summary:        OpenVIBES operator CLI and maintenance timer
%{?systemd_requires}

%description -n openvibes-admin
Schema migration, built-in CA, tokens, agents, and daily partition maintenance.

%install
S=%{_sourcedir}
install -D -m 0755 $S/target/release/openvibes-ingest %{buildroot}%{_bindir}/openvibes-ingest
install -D -m 0755 $S/target/release/openvibes-admin %{buildroot}%{_bindir}/openvibes-admin
install -D -m 0644 $S/packaging/rpm/openvibes-ingest.service %{buildroot}%{_unitdir}/openvibes-ingest.service
install -D -m 0644 $S/packaging/rpm/openvibes-maintenance.service %{buildroot}%{_unitdir}/openvibes-maintenance.service
install -D -m 0644 $S/packaging/rpm/openvibes-maintenance.timer %{buildroot}%{_unitdir}/openvibes-maintenance.timer
install -D -m 0644 $S/packaging/rpm/openvibes-ingest.sysusers %{buildroot}%{_sysusersdir}/openvibes-ingest.conf
install -D -m 0644 $S/packaging/rpm/openvibes-admin.sysusers %{buildroot}%{_sysusersdir}/openvibes-admin.conf
install -D -m 0640 $S/packaging/rpm/ingest.toml %{buildroot}%{_sysconfdir}/openvibes/ingest.toml
install -D -m 0640 $S/packaging/rpm/admin.toml %{buildroot}%{_sysconfdir}/openvibes/admin.toml
install -d -m 0700 %{buildroot}%{_sharedstatedir}/openvibes-ingest
install -d -m 0755 %{buildroot}%{_sysconfdir}/openvibes/tls %{buildroot}%{_sysconfdir}/openvibes/pki
install -D -m 0644 $S/LICENSE %{buildroot}%{_licensedir}/openvibes-ingest/LICENSE
install -D -m 0644 $S/LICENSE %{buildroot}%{_licensedir}/openvibes-admin/LICENSE

%post -n openvibes-ingest
%systemd_post openvibes-ingest.service
%preun -n openvibes-ingest
%systemd_preun openvibes-ingest.service
%postun -n openvibes-ingest
%systemd_postun_with_restart openvibes-ingest.service

%post -n openvibes-admin
%systemd_post openvibes-maintenance.timer
%preun -n openvibes-admin
%systemd_preun openvibes-maintenance.timer
%postun -n openvibes-admin
%systemd_postun openvibes-maintenance.timer

%files -n openvibes-ingest
%license %{_licensedir}/openvibes-ingest/LICENSE
%{_bindir}/openvibes-ingest
%{_unitdir}/openvibes-ingest.service
%{_sysusersdir}/openvibes-ingest.conf
%dir %{_sysconfdir}/openvibes
%dir %{_sysconfdir}/openvibes/tls
%dir %{_sysconfdir}/openvibes/pki
%config(noreplace) %attr(0640, root, openvibes_ingest) %{_sysconfdir}/openvibes/ingest.toml
%dir %attr(0700, openvibes_ingest, openvibes_ingest) %{_sharedstatedir}/openvibes-ingest

%files -n openvibes-admin
%license %{_licensedir}/openvibes-admin/LICENSE
%{_bindir}/openvibes-admin
%{_unitdir}/openvibes-maintenance.service
%{_unitdir}/openvibes-maintenance.timer
%{_sysusersdir}/openvibes-admin.conf
%dir %{_sysconfdir}/openvibes
%config(noreplace) %attr(0640, root, openvibes_admin) %{_sysconfdir}/openvibes/admin.toml
```

If Fedora 44's rpm does not create the sysusers users before placing files (check-rpm fails with `no user` or with root-owned files), add `%pre -n <pkg>` sections with `%sysusers_create_compat <file>`. Ledger that as a ruling.

- [ ] **Step 4: `scripts/build-rpm.sh`.**

```bash
#!/usr/bin/env bash
# Builds target/rpm/RPMS/x86_64/openvibes-{ingest,admin}-*.rpm.
set -euo pipefail
cd "$(dirname "$0")/.."
export CARGO_NET_GIT_FETCH_WITH_CLI=true
cargo build --release --locked -p openvibes-ingest -p openvibes-admin
version=$(grep -m1 '^version = ' Cargo.toml | cut -d'"' -f2)
rpmbuild -bb packaging/rpm/openvibes-platform.spec \
    --define "_topdir $PWD/target/rpm" --define "_sourcedir $PWD" \
    --define "ov_version $version"
ls target/rpm/RPMS/*/openvibes-*.rpm
```

- [ ] **Step 5: GREEN in a Fedora 44 container.** Build on the host, then install and check in a clean container:

```bash
bash scripts/build-rpm.sh
podman run --rm -v "$PWD:/src:Z" -w /src registry.fedoraproject.org/fedora:44 bash -c \
  'dnf -q -y install systemd && dnf -q -y install target/rpm/RPMS/x86_64/openvibes-*.rpm && bash scripts/check-rpm.sh'
```

Expected: `check-rpm: ok`. The host is Fedora 44 as well, so host-built binaries link against the same glibc.

- [ ] **Step 6: Docs and commit.** Create `docs/components/packaging.md`:
  - **Purpose:** the two RPMs.
  - **Files and modes:** a table.
  - **Service users**, and why they match the PostgreSQL role names (peer auth).
  - **First install on Fedora:**
    1. `dnf install postgresql-server`, then `postgresql-setup --initdb`, then `systemctl enable --now postgresql`.
    2. `sudo -u postgres createuser --createrole openvibes_admin`, then `sudo -u postgres createdb -O openvibes_admin openvibes`.
    3. `sudo -u openvibes_admin openvibes-admin migrate`.
    4. CA bootstrap: root offline; `intermediate-request` on the host; sign offline; `import-intermediate`; install `intermediate.key` 0600 as `openvibes_ingest` in `/var/lib/openvibes-ingest`; `issue-server` into `/etc/openvibes/tls`.
    5. Edit `ingest.toml`, then `systemctl enable --now openvibes-ingest openvibes-maintenance.timer`.
    6. Open firewall port 18423/tcp.
  - **Hardening list.**
  - **Known gaps:** the audit actor under `sudo -u` is `openvibes_admin`, and sudo's log names the human; the retention days are set in two places.
  - **How to test:** `build-rpm.sh` plus `check-rpm.sh` in a container.

Add it to `docs/components/README.md`.

```bash
git add packaging scripts/build-rpm.sh scripts/check-rpm.sh docs/components
git commit -m "Package openvibes-ingest and openvibes-admin as RPMs with hardened units"
```

---

### Task 5: Fedora CI job (RPMs installed, integration against them)

**Files:**
- Modify `.github/workflows/ci.yml`.
- Update `docs/components/integration-agent.md` and `docs/components/packaging.md` ("CI" lines).

**Interfaces:**
- **Consumes:** `scripts/build-rpm.sh`, `scripts/check-rpm.sh`, `scripts/integration-agent.sh` (`OPENVIBES_BIN_DIR`, `AGENT_BIN`, `BUNDLE_BIN`), and `build_agent`.

- [ ] **Step 1: Add the job.** Use the same pinned `actions/checkout` SHA as the existing job:

```yaml
  fedora:
    name: RPMs and agent integration (fedora:44)
    runs-on: ubuntu-latest
    timeout-minutes: 45
    container: registry.fedoraproject.org/fedora:44
    steps:
      - name: Install build and test packages
        run: >-
          dnf -q -y install git gcc cargo rust rpm-build systemd-rpm-macros systemd
          postgresql-server sqlite jq curl procps-ng util-linux

      - name: Checkout repository
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - name: Authenticate git for private dependencies
        shell: bash
        env:
          AGENT_TOKEN: ${{ secrets.OPENVIBESAGENT }}
          PROTOCOL_TOKEN: ${{ secrets.OPENVIBEPROTOCOL }}
        run: |
          if [ -z "$AGENT_TOKEN" ] || [ -z "$PROTOCOL_TOKEN" ]; then
            echo "::error::secrets OPENVIBESAGENT and OPENVIBEPROTOCOL must both be set"
            exit 1
          fi
          git config --global --add safe.directory "$GITHUB_WORKSPACE"
          git config --global url."https://x-access-token:${AGENT_TOKEN}@github.com/openvibes-project/openvibes-agent".insteadOf "https://github.com/openvibes-project/openvibes-agent"
          git config --global url."https://x-access-token:${PROTOCOL_TOKEN}@github.com/openvibes-project/openvibes-protocol".insteadOf "https://github.com/openvibes-project/openvibes-protocol"
          git submodule update --init

      - name: Build RPMs
        run: bash scripts/build-rpm.sh

      - name: Install and check RPMs
        run: |
          dnf -q -y install target/rpm/RPMS/x86_64/openvibes-*.rpm
          bash scripts/check-rpm.sh

      # initdb refuses root: build the agent and bundle tool as root (which
      # has the git credentials), then run the integration as a plain user.
      - name: Build the pinned agent and the bundle tool
        shell: bash
        run: |
          ROOT=$PWD; source scripts/integration-lib.sh
          build_agent "$PWD/target/integration/agent" > agent-path
          cargo build --release --locked -p openvibes-ingest --example integration_bundle

      - name: Integration against the installed binaries
        shell: bash
        run: |
          useradd -m ci
          chown -R ci "$GITHUB_WORKSPACE"
          runuser -u ci -- env OPENVIBES_BIN_DIR=/usr/bin \
            AGENT_BIN="$(cat agent-path)" \
            BUNDLE_BIN="$PWD/target/release/examples/integration_bundle" \
            PATH="/usr/libexec/postgresql:/usr/bin:/bin" \
            bash scripts/integration-agent.sh
```

Fedora ships `initdb` and `pg_ctl` under `/usr/bin`. If they are not there (the step fails with `initdb: command not found`), find them with `rpm -ql postgresql-server | grep bin/initdb` and fix `PATH`. Ledger the fix.

- [ ] **Step 2: Local dry run of the risky parts.** Run the integration script locally in full, `bash scripts/integration-agent.sh`. Expected: `integration: all checks passed`.

- [ ] **Step 3: Docs.** Add a "CI" line to `integration-agent.md` and `packaging.md`: the `fedora` job runs `build-rpm.sh`, installs the RPMs, runs `check-rpm.sh`, then runs the integration as user `ci` against `/usr/bin` binaries.

- [ ] **Step 4: Commit, push the branch, and watch CI.**

```bash
git add .github/workflows/ci.yml docs/components
git commit -m "CI: build, install, and check the RPMs on Fedora and run the agent integration against them"
git push -u origin pm4
gh pr create --title "PM4: RPM packaging and cross-repo integration" --body "..."
gh run watch --exit-status
```

Expected: both jobs green. The PM4 exit (spec section 1, items 1 to 3) now holds:
- item 1: Tasks 2 and 3 in CI on Fedora, with Fedora's PostgreSQL;
- items 2 and 3: the PM3 suite in the ubuntu job.
