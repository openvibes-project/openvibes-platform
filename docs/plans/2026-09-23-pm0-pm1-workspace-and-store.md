# PM0 + PM1: Workspace, CI, and Storage — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Rust workspace that builds against the agent's `openvibes-core`, passes the shared protocol fixtures, and owns a migrated PostgreSQL schema that `openvibes-admin migrate | status | maintenance` manage.

**Architecture:** Cargo workspace in `openvibes-platform`. `platform-config` loads bounded TOML; `platform-store` is the only crate touching PostgreSQL (`tokio-postgres` + `deadpool-postgres`, SQL migrations embedded with `include_str!`); `openvibes-admin` is a `clap` CLI over the store. `openvibes-ingest` exists only as a skeleton holding the fixture test.

**Tech Stack:** Rust 1.95.0, tokio 1, tokio-postgres 0.7.18, deadpool-postgres 0.14.2, clap 4.6, serde, toml 1.1.6, PostgreSQL (Fedora package).

**Spec:** `docs/specs/2026-09-23-ingest-subproject-design.md` (sections 2, 3, 4, 7, 8, 10); architecture in `docs/specs/2026-09-23-platform-architecture-design.md`.

## Global Constraints

- Toolchain `1.95.0`, edition 2024, `#![forbid(unsafe_code)]` in every crate, workspace lints `unsafe_code = "forbid"`, clippy `all = "deny"`.
- `clippy.toml` bans `std::process::Command` and TLS verification bypasses (copy the agent's file).
- `openvibes-core` from `https://github.com/openvibes-project/openvibes-agent.git`, `rev = "e73e188ad0c8c4a5b75f21e494934177f0362a23"`.
- Protocol fixtures from submodule `protocol/` = `openvibes-protocol` at `7e99e2e846628a5bc46524a5fb54c9e9389c7ea6`.
- Config files: TOML, `deny_unknown_fields`, absolute paths only, at most 64 KiB.
- `Cargo.lock` committed; always `--locked`. Every CI action pinned to a full SHA with the version in a comment.
- Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`; git identity `itismelime <26064407+itismelime@users.noreply.github.com>`.
- `openvibes-core` is in a private repository: build with `CARGO_NET_GIT_FETCH_WITH_CLI=true` so cargo uses your git credentials (locally and in CI).
- Store tests run against a real PostgreSQL named by `OPENVIBES_TEST_DATABASE_URL`; they fail (never skip) when it is unset.

## Review Focus

- A migration applied twice must be a no-op, and a database at a **newer** schema version must be refused, not "migrated down". (Task 5 tests both.)
- `maintenance` run on consecutive days, or twice on one day, must not fail on partitions that already exist and must never drop today's partition. (Task 6.)
- A config file that is a symlink to something huge, or not UTF-8, is refused without reading it all. (Task 2 caps the read.)
- `status` against an empty database (no agents, no partitions) prints zeros instead of erroring. (Task 6.)
- The admin CLI writes an audit row even when the command fails. (Task 7.)

---

### Task 0 (operator): install PostgreSQL binaries

- [ ] Run `sudo dnf install postgresql-server postgresql` (binaries only; do not enable the system service).
- [ ] Check: `initdb --version` prints a version.

### Task 1: Workspace, toolchain, `openvibes-core`, fixture test

**Files:** Create `Cargo.toml`, `rust-toolchain.toml`, `rustfmt.toml`, `clippy.toml`, `.gitignore`, `.gitmodules` (via `git submodule add`), `crates/openvibes-ingest/{Cargo.toml,src/main.rs,tests/protocol_fixtures.rs}`.

**Interfaces:** Produces the workspace every later task adds crates to.

- [ ] **Step 1:** Copy `rust-toolchain.toml`, `rustfmt.toml`, `clippy.toml` verbatim from `../openvibes-agent/`. Add the protocol submodule: `git submodule add https://github.com/openvibes-project/openvibes-protocol.git protocol && git -C protocol checkout 7e99e2e846628a5bc46524a5fb54c9e9389c7ea6`. `.gitignore`: `/target`.
- [ ] **Step 2:** Write `Cargo.toml`:

```toml
[workspace]
resolver = "3"
members = ["crates/openvibes-ingest"]

[workspace.package]
version = "0.1.0"
edition = "2024"
rust-version = "1.95"
license = "MIT"

[workspace.dependencies]
openvibes-core = { git = "https://github.com/openvibes-project/openvibes-agent.git", rev = "e73e188ad0c8c4a5b75f21e494934177f0362a23" }
serde = { version = "1.0.228", features = ["derive"] }
serde_json = "1.0.145"
toml = { version = "1.1.6", default-features = false, features = ["std", "serde", "parse"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
tokio-postgres = "0.7.18"
deadpool-postgres = "0.14.2"
clap = { version = "4.6.7", features = ["derive"] }

[workspace.lints.rust]
unsafe_code = "forbid"

[workspace.lints.clippy]
all = "deny"
```

- [ ] **Step 3:** `crates/openvibes-ingest/Cargo.toml` (package `openvibes-ingest`, `[lints] workspace = true`, deps `openvibes-core.workspace = true`, dev-deps `serde.workspace`, `serde_json.workspace`); `src/main.rs`:

```rust
#![forbid(unsafe_code)]

//! Agent-facing ingest service (built in PM3).

fn main() {
    eprintln!("openvibes-ingest: not implemented yet (PM3)");
    std::process::exit(2);
}
```

- [ ] **Step 4:** Write the failing fixture test `tests/protocol_fixtures.rs`, a copy of `../openvibes-agent/crates/openvibes-core/tests/protocol_fixtures.rs` with the root changed to `Path::new(env!("CARGO_MANIFEST_DIR")).join("../../protocol/fixtures/v1")` (identical mapping of message names to types, including `finding-export`, `inventory-export`, `rule-bundle-request`).
- [ ] **Step 5:** Run `cargo test --locked -p openvibes-ingest` without the submodule checked out: expect FAIL "protocol fixtures missing". Then `git submodule update --init` and rerun: expect PASS (1 test).
- [ ] **Step 6:** `cargo fmt --all --check && cargo clippy --locked --workspace --all-targets -- -D warnings -F unsafe-code` clean. Commit: `Create the platform workspace with the shared protocol fixtures`.

### Task 2: `platform-config`

**Files:** Create `crates/platform-config/{Cargo.toml,src/lib.rs}`; add to workspace members.

**Interfaces:** Produces `pub fn load<T: DeserializeOwned>(path: &Path) -> Result<T, ConfigError>` and `pub fn require_absolute(paths: &[&Path]) -> Result<(), ConfigError>`; `ConfigError` is a `Copy` enum `{ Missing, TooLarge, Invalid, RelativePath }` whose `Display` never echoes content or paths.

- [ ] **Step 1:** Write tests in `src/lib.rs` (`#[cfg(test)]`), using `CARGO_TARGET_TMPDIR`-style temp paths from `std::env::temp_dir()` plus the process id:

```rust
#[derive(serde::Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
struct Sample { name: String }

#[test]
fn loads_bounded_strict_toml() {
    let dir = std::env::temp_dir().join(format!("ov-config-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let good = dir.join("good.toml");
    std::fs::write(&good, "name = \"ingest\"\n").unwrap();
    assert_eq!(load::<Sample>(&good).unwrap(), Sample { name: "ingest".into() });
    let unknown = dir.join("unknown.toml");
    std::fs::write(&unknown, "name = \"x\"\nnmae = \"typo\"\n").unwrap();
    assert_eq!(load::<Sample>(&unknown).unwrap_err(), ConfigError::Invalid);
    let big = dir.join("big.toml");
    std::fs::write(&big, format!("name = \"{}\"\n", "x".repeat(64 * 1024))).unwrap();
    assert_eq!(load::<Sample>(&big).unwrap_err(), ConfigError::TooLarge);
    let binary = dir.join("binary.toml");
    std::fs::write(&binary, [0xff, 0xfe]).unwrap();
    assert_eq!(load::<Sample>(&binary).unwrap_err(), ConfigError::Invalid);
    assert_eq!(load::<Sample>(&dir.join("absent.toml")).unwrap_err(), ConfigError::Missing);
    assert_eq!(require_absolute(&[Path::new("rel/x")]).unwrap_err(), ConfigError::RelativePath);
    assert!(require_absolute(&[Path::new("/etc/x")]).is_ok());
}
```

- [ ] **Step 2:** Run `cargo test --locked -p platform-config`: FAIL (functions missing).
- [ ] **Step 3:** Implement: `const MAX_BYTES: u64 = 64 * 1024;` open the file (`NotFound` → `Missing`, other errors → `Invalid`), `take(MAX_BYTES + 1).read_to_end`, more than `MAX_BYTES` → `TooLarge`, `std::str::from_utf8` failure → `Invalid`, `toml::from_str` failure → `Invalid`. `require_absolute` returns `RelativePath` for the first non-absolute path.
- [ ] **Step 4:** Run the test: PASS. Commit: `Add bounded, strict TOML config loading`.

### Task 3: CI

**Files:** Create `.github/workflows/ci.yml`.

- [ ] **Step 1:** Write the workflow: triggers `push`/`pull_request` on `main` and `workflow_dispatch`; `permissions: contents: read`; one `ubuntu-latest` job with a `postgres:17` service (`POSTGRES_PASSWORD: ci`, port 5432, health check `pg_isready`); steps: `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1` with `persist-credentials: false`; a bash step with `env: TOKEN: ${{ secrets.OPENVIBES }}` that runs `git config --global url."https://x-access-token:${TOKEN}@github.com/".insteadOf "https://github.com/"` then `git submodule update --init` (the secret is used verbatim; never transform it); `rustup toolchain install`; `Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6 # v2.9.2`; env `CARGO_NET_GIT_FETCH_WITH_CLI: "true"` and `OPENVIBES_TEST_DATABASE_URL: postgresql://postgres:ci@localhost:5432/postgres`; run fmt, clippy (`-D warnings -F unsafe-code`), `cargo doc` with `RUSTDOCFLAGS=-D warnings`, `cargo test --locked --workspace`, and `cargo audit --deny warnings` via `taiki-e/install-action@7623a79cdfecb99d681017af368ca353d9f49bb5 # v2.87.19` (`tool: cargo-audit@0.22.2`).
- [ ] **Step 2 (operator):** Create a fine-grained PAT, read-only **Contents** on `openvibes-agent` and `openvibes-protocol`, and store it as secret `OPENVIBES` in the platform repository (created on GitHub by then: private, `openvibes-project/openvibes-platform`). Paste only the token at the prompt of `gh secret set OPENVIBES -R openvibes-project/openvibes-platform`.
- [ ] **Step 3:** Push; expect every step green. Commit: `Add CI with a PostgreSQL service`.

### Task 4: Local test database script

**Files:** Create `scripts/test-db.sh` (executable).

- [ ] **Step 1:** Write it: `set -euo pipefail`; data dir `target/pg/data`, socket dir `target/pg/run`; if no data dir, `initdb -D "$DATA" -U openvibes_test --auth=trust >/dev/null`; `pg_ctl -D "$DATA" -o "-k $RUN -c listen_addresses=''" -l target/pg/log -w start` unless `pg_ctl status` succeeds; subcommand `stop` runs `pg_ctl -D "$DATA" -m fast stop`; finally print `export OPENVIBES_TEST_DATABASE_URL="postgresql:///postgres?host=$PWD/target/pg/run&user=openvibes_test"`.
- [ ] **Step 2:** Run `eval "$(scripts/test-db.sh)" && psql "$OPENVIBES_TEST_DATABASE_URL" -c 'select 1'`: prints 1. Commit: `Add a throwaway PostgreSQL for local tests`.

### Task 5: `platform-store` with migration 0001

**Files:** Create `crates/platform-store/{Cargo.toml,src/lib.rs,src/migrate.rs,tests/migrate.rs}`, `migrations/0001_initial.sql`.

**Interfaces:**
- Produces `pub async fn connect(url: &str) -> Result<deadpool_postgres::Pool, StoreError>` (pool size 16),
  `pub const SCHEMA_VERSION: i32 = 1;`,
  `pub async fn migrate(client: &mut deadpool_postgres::Client) -> Result<i32, StoreError>` (returns the version now in place),
  `pub async fn schema_version(client: &deadpool_postgres::Client) -> Result<Option<i32>, StoreError>`,
  `StoreError` enum `{ Unavailable, NewerSchema(i32), Query }` with `From<tokio_postgres::Error>` → `Query` (connection errors → `Unavailable`).

- [ ] **Step 1:** Write `migrations/0001_initial.sql` exactly as the spec's section 4, as SQL:

```sql
CREATE TABLE agents (
    agent_id text PRIMARY KEY CHECK (agent_id ~ '^agent\.[0-9a-f-]{36}$'),
    status text NOT NULL CHECK (status IN ('active', 'revoked')),
    enrolled_at timestamptz NOT NULL, revoked_at timestamptz,
    last_seen_at timestamptz, scanner_version text, capabilities text[] NOT NULL DEFAULT '{}');
CREATE TABLE certificates (
    serial bytea PRIMARY KEY CHECK (length(serial) = 16),
    agent_id text NOT NULL REFERENCES agents, spki_sha256 bytea NOT NULL CHECK (length(spki_sha256) = 32),
    not_before timestamptz NOT NULL, not_after timestamptz NOT NULL,
    issued_at timestamptz NOT NULL, chain_pem text NOT NULL);
CREATE TABLE enrollment_tokens (
    token_id uuid PRIMARY KEY, token_sha256 bytea NOT NULL UNIQUE CHECK (length(token_sha256) = 32),
    label text, created_at timestamptz NOT NULL, created_by text NOT NULL,
    expires_at timestamptz NOT NULL, max_uses integer NOT NULL DEFAULT 1 CHECK (max_uses > 0),
    revoked_at timestamptz);
CREATE TABLE token_uses (
    token_id uuid NOT NULL REFERENCES enrollment_tokens, spki_sha256 bytea NOT NULL,
    agent_id text NOT NULL REFERENCES agents, serial bytea NOT NULL REFERENCES certificates,
    used_at timestamptz NOT NULL, PRIMARY KEY (token_id, spki_sha256));
CREATE TABLE findings (
    finding_id text NOT NULL, observed_day date NOT NULL, observed_at timestamptz NOT NULL,
    agent_id text NOT NULL, scan_id text NOT NULL, rule_id text NOT NULL,
    rule_version bigint NOT NULL, severity text NOT NULL, confidence smallint NOT NULL,
    message text NOT NULL, evidence text[] NOT NULL, received_at timestamptz NOT NULL,
    origin text NOT NULL CHECK (origin IN ('online', 'import')), authenticated boolean NOT NULL,
    PRIMARY KEY (finding_id, observed_day)) PARTITION BY RANGE (observed_day);
CREATE TABLE current_findings (
    agent_id text NOT NULL REFERENCES agents, rule_id text NOT NULL,
    last_finding_id text NOT NULL, rule_version bigint NOT NULL, severity text NOT NULL,
    first_observed_at timestamptz NOT NULL, last_observed_at timestamptz NOT NULL,
    PRIMARY KEY (agent_id, rule_id));
CREATE TABLE audit_log (
    id bigserial PRIMARY KEY, at timestamptz NOT NULL DEFAULT now(), actor text NOT NULL,
    action text NOT NULL, target text, result text NOT NULL, detail jsonb NOT NULL DEFAULT '{}');
DO $$ BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'openvibes_ingest') THEN
        CREATE ROLE openvibes_ingest LOGIN;
    END IF;
-- Roles are cluster-wide: parallel migrations (tests) can race on creation.
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
GRANT SELECT, INSERT, UPDATE ON agents, certificates, token_uses, findings, current_findings TO openvibes_ingest;
GRANT SELECT ON enrollment_tokens TO openvibes_ingest;
GRANT INSERT ON audit_log TO openvibes_ingest;
GRANT USAGE ON SEQUENCE audit_log_id_seq TO openvibes_ingest;
```

- [ ] **Step 2:** Write the failing tests `tests/migrate.rs`. Each test creates a fresh database named `ov_test_<random u64>` via the URL in `OPENVIBES_TEST_DATABASE_URL` (panic with "set OPENVIBES_TEST_DATABASE_URL, see scripts/test-db.sh" when unset), replacing the path's database name, and drops it at the end:

```rust
#[tokio::test]
async fn migration_applies_once_and_is_idempotent() {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    assert_eq!(platform_store::schema_version(&client).await.unwrap(), None);
    assert_eq!(platform_store::migrate(&mut client).await.unwrap(), 1);
    assert_eq!(platform_store::migrate(&mut client).await.unwrap(), 1);
    assert_eq!(platform_store::schema_version(&client).await.unwrap(), Some(1));
}

#[tokio::test]
async fn a_newer_schema_is_refused() {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    client.execute("UPDATE schema_version SET version = 99", &[]).await.unwrap();
    assert!(matches!(platform_store::migrate(&mut client).await, Err(platform_store::StoreError::NewerSchema(99))));
}
```

- [ ] **Step 3:** Run (with `eval "$(scripts/test-db.sh)"`): FAIL, functions missing.
- [ ] **Step 4:** Implement `migrate.rs`: `const MIGRATIONS: &[(i32, &str)] = &[(1, include_str!("../../../migrations/0001_initial.sql"))];`. In one transaction: `CREATE TABLE IF NOT EXISTS schema_version (version integer NOT NULL)`, `LOCK TABLE schema_version IN EXCLUSIVE MODE` (two admins cannot migrate at once), read the version (0 if no row); if above `SCHEMA_VERSION` return `NewerSchema(v)`; apply each later migration with `batch_execute`; write the new version (insert or update); commit.
- [ ] **Step 5:** Run: PASS (2 tests). Clippy clean. Commit: `Add platform-store with the initial schema`.

### Task 6: Partitions, status, and maintenance queries

**Files:** Create `crates/platform-store/src/{maintenance.rs,status.rs}`, `crates/platform-store/tests/maintenance.rs`.

**Interfaces:** Produces
`pub async fn ensure_partitions(client: &deadpool_postgres::Client, today: chrono::NaiveDate, days_ahead: u32) -> Result<u32, StoreError>` (returns partitions created),
`pub async fn drop_partitions_before(client: &deadpool_postgres::Client, cutoff: chrono::NaiveDate) -> Result<u32, StoreError>`,
`pub struct Status { pub schema_version: Option<i32>, pub agents_active: i64, pub agents_offline: i64, pub agents_revoked: i64, pub tokens_usable: i64, pub oldest_partition: Option<NaiveDate>, pub newest_partition: Option<NaiveDate> }`,
`pub async fn status(client: &deadpool_postgres::Client, now: chrono::DateTime<chrono::Utc>) -> Result<Status, StoreError>`.
Add `chrono = { version = "0.4", default-features = false, features = ["clock", "std"] }` to the workspace and `tokio-postgres` feature `with-chrono-0_4`.

- [ ] **Step 1:** Write failing tests: on a migrated fresh database, `ensure_partitions(today, 7)` returns 8 (today plus 7), a second call returns 0; `drop_partitions_before(today)` returns 0 (today's partition is kept); after `ensure_partitions` with `today - 100 days` and then `drop_partitions_before(today - 90 days)` the dropped count is 10 and `status().oldest_partition` is `today - 90 days`. `status()` on a migrated empty database returns all counts 0 and both partition dates `None`. Offline counting: insert an active agent with `last_seen_at = now - 16 min` and one with `now - 1 min`; `agents_offline == 1`.
- [ ] **Step 2:** Run: FAIL.
- [ ] **Step 3:** Implement. Partitions are named `findings_YYYYMMDD` and created with `CREATE TABLE IF NOT EXISTS findings_YYYYMMDD PARTITION OF findings FOR VALUES FROM ('YYYY-MM-DD') TO ('next day')` (names built only from `NaiveDate` formatting, never from input). Detect existing partitions via `pg_inherits` joined to `pg_class` where the parent is `findings`. `drop_partitions_before` drops partitions whose day is strictly before `cutoff` and never today. Offline = active and (`last_seen_at` is null or older than 15 minutes). Usable tokens = not revoked, not expired, and uses below `max_uses`.
- [ ] **Step 4:** Run: PASS. Commit: `Add finding partitions, retention, and status queries`.

### Task 7: `openvibes-admin migrate | status | maintenance`

**Files:** Create `crates/openvibes-admin/{Cargo.toml,src/main.rs,src/audit.rs}`, `crates/openvibes-admin/tests/cli.rs`; add `platform-store::audit::record(client, actor, action, target, result)` in `crates/platform-store/src/audit.rs`.

**Interfaces:** Consumes Tasks 2, 5, 6. Produces the `openvibes-admin` binary; config `/etc/openvibes/admin.toml` (overridable with `--config PATH`) with the single key `database_url`.

- [ ] **Step 1:** Write failing CLI tests (`tests/cli.rs`) that run the built binary through `std::process::Command` inside the test file only, with `#![allow(clippy::disallowed_types)] // test drives the CLI binary; not shipped code`: against a fresh database and a temp config file, `migrate` prints `schema version 1` and exits 0; `status` prints lines `agents active 0`, `agents offline 0`, `agents revoked 0`, `tokens usable 0`; `maintenance` prints `created 8 partitions, dropped 0`; after each command `audit_log` has one more row with `actor` equal to the `USER` environment value and `result` `ok`; `status` against a database at schema 99 exits non-zero and still adds an audit row with `result` `error`.
- [ ] **Step 2:** Run: FAIL.
- [ ] **Step 3:** Implement with `clap` derive (`#[command(subcommand)]` enum `Migrate | Status | Maintenance { #[arg(long, default_value_t = 90)] retention_days: u32 }`). Actor = `USER` environment variable, else `unknown`. Every command: run, then call `audit::record` with `ok` or `error` (recording is attempted even on failure; if recording itself fails, print a warning and exit non-zero). `status` and `maintenance` refuse to run unless `schema_version == SCHEMA_VERSION`, printing `run openvibes-admin migrate`. Errors print a fixed message per `StoreError` variant, never SQL or connection strings.
- [ ] **Step 4:** Run: PASS; whole workspace fmt, clippy, doc, test clean. Commit: `Add openvibes-admin migrate, status, and maintenance`.
- [ ] **Step 5:** Update `openvibes-protocol/PLAN.md` housekeeping (spec section 11): tick the agent side of P3, note the ingest side of P1/P2 as in progress in `openvibes-platform`. Commit and push in the protocol repository.

## Exit (PM0 + PM1)

CI green on GitHub; locally `eval "$(scripts/test-db.sh)" && cargo test --locked --workspace` passes; `openvibes-admin migrate`, `status`, and `maintenance` work against the throwaway cluster, each leaving an audit row.
