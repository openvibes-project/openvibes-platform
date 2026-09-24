# SP2: Distribution Service — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Serve operator-published, offline-signed rule bundles to authenticated agents over `POST /v1/rule-bundle`, with the same TLS, authentication, load controls and packaging as ingest.

**Architecture:**
- **DM0:** the agent-facing server plumbing moves out of `openvibes-ingest` into a library crate, `platform-agent-server`: TLS config, the expiry-tolerant verifier, the `AuthenticatedAgent` extractor, the load-control and logging middleware, the health router, `ApiError`, and the accept loop with drain. Ingest keeps only its routes and state. Its tests are the gate.
- **DM1:** migration 0006 adds `rule_sets`, `rule_trust_keys` and `rule_bundles` plus the `openvibes_distribution` role. `platform_store::rules` holds every rules query. `openvibes-admin rules …` manages trust keys and publishes envelopes after verifying them with the agent's own `openvibes-rules` loader.
- **DM2:** `openvibes-distribution`, a thin service on `platform-agent-server` with one route. Each request makes one indexed query that answers 200, 204 or 404, and it keeps no cache.
- **DM3:** an RPM subpackage, the real-agent integration steps, and the PLAN.md tick.
- **DM4:** a distribution mode in `openvibes-load`, with a recorded run.

**Tech Stack:** Rust 1.95, axum 0.8.9, hyper 1 and hyper-util, rustls 0.23 (TLS 1.3, ring), tokio-postgres and deadpool, PostgreSQL 18. From the agent repository at the pinned revision `94974bf`: `openvibes-core`, `openvibes-rules` and `openvibes-transport`. Also bash and rpmbuild.

**Spec:** `docs/specs/2026-09-24-distribution-subproject-design.md` (approved 2026-09-24). Protocol: `openvibes-protocol/spec/contracts-v1.md`, section "Rule distribution".

## Global Constraints

- **Toolchain and lints:** carried over from PM0–PM5. Rust 1.95, edition 2024. `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings -F unsafe-code`. `#![forbid(unsafe_code)]` and `#![deny(missing_docs)]` in every library. Build with `--locked` and `CARGO_NET_GIT_FETCH_WITH_CLI=true`. Tests need `eval "$(scripts/test-db.sh)"`.
- **Commits:** every commit ends with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Git identity: `itismelime` / `26064407+itismelime@users.noreply.github.com`.
- **Documentation:** a component page in `docs/components/` is created or updated in the same commit as its component. `docs/components/README.md` indexes them.
- **Ports:** agent listener `0.0.0.0:18424`; health `127.0.0.1:18481`, loopback only and refused otherwise. Ingest stays at 18423 and 18480; the console has 18482.
- **Envelope size:** at most `ResourceLimits::V1.document_bytes` = 1,048,576 bytes, both when publishing and as the request body limit.
- **Roles:** `openvibes_distribution` gets `SELECT` on `agents`, `certificates`, `rule_sets`, `rule_bundles` and `schema_version`, and nothing else. `openvibes_ingest` gets no rights on the rule tables.
- **Responses:**
  - 200: the exact stored bytes, `content-type: application/json`, when `current_version` is absent or below the current version;
  - 204 with no body when it is at or above the current version;
  - 404 when the rule set is unknown or retired, or has no bundle;
  - 400 for a malformed or oversized body;
  - 401 for an unknown or expired certificate, 403 `identity_revoked` for a revoked agent;
  - 503 for a database failure or the in-flight limit;
  - 408 at the request deadline.
- **Migrations:** migration numbering is fixed: 0006 is SP2's. The console starts at 0007.
- **Pins:** no new external dependency beyond the workspace's existing ones.

## Review Focus

- **A rule set with trust keys but no published bundle:** an agent asking for it gets 404, never a 500 or an empty 200. Test `a_set_without_bundles_is_not_found` in Task 4.
- **`current_version` above anything published** (an agent that saw a later version before a database restore): 204, never 404 or a rollback. Test `a_newer_agent_version_gets_no_content` in Task 4.
- **Publishing after the signing key is removed:** refused, even when a previous version was signed by that key. Test `publish_refuses_a_removed_key` in Task 3.
- **The same bytes published twice concurrently:** exactly one row, and both commands succeed. The primary key, together with the check-then-insert running in one transaction under a per-set advisory lock, guarantees this. Test `concurrent_identical_publishes_store_one_row` in Task 2.
- **Retiring a set that agents still poll:** 404 from the next request on, and the stored bundles remain for audit. Test `a_retired_set_is_not_found` in Task 4.

---

### Task 1 (DM0): Extract `platform-agent-server`

**Files:**
- Create `crates/platform-agent-server/Cargo.toml` and `crates/platform-agent-server/src/{lib.rs,tls.rs,auth.rs,limits.rs,error.rs,health.rs,request.rs,serve.rs}`.
- Create `docs/components/platform-agent-server.md`.
- Modify: `Cargo.toml` (members), `crates/openvibes-ingest/Cargo.toml`, `crates/openvibes-ingest/src/{lib.rs,server.rs,config.rs,error.rs,delivery.rs,enroll.rs}`.
- Delete `crates/openvibes-ingest/src/{tls.rs,auth.rs,limits.rs,health.rs,request.rs}`.
- Update: `docs/components/openvibes-ingest.md` and `docs/components/README.md`.

**Interfaces (Produces, used by Task 5):**

```rust
// platform_agent_server
pub struct Settings {             // the fields both services share
    pub listen: SocketAddr, pub health_listen: SocketAddr,
    pub server_certificate_file: PathBuf, pub server_key_file: PathBuf,
    pub client_ca_file: PathBuf, pub database_url: String,
    pub max_in_flight: usize, pub request_timeout_seconds: u64,
    pub max_connections: usize, pub database_pool_size: usize,
}
impl Settings { pub fn validate(&self) -> Result<(), ServerError>; } // absolute paths, loopback health, ranges as ingest today
pub enum ServerError { Config, Tls, Database, Listen }              // Copy, Display, Error
pub enum ApiError { BadRequest, Unauthorized, Revoked, NotFound, Unavailable, Busy, Timeout }
pub struct AuthenticatedAgent(pub String);   // FromRequestParts<S> where Pool: FromRef<S>
pub const MAX_BODY_BYTES: usize = 1_048_576;
pub fn parse<T: DeserializeOwned + Validate>(body: &[u8]) -> Result<T, ApiError>;
pub fn read_pem(path: &Path) -> Result<String, ServerError>;
pub async fn run(settings: &Settings, listener: TcpListener, health: TcpListener,
                 app: impl FnOnce(Pool) -> Router, shutdown: impl Future<Output = ()>)
                 -> Result<(), ServerError>;
```

`run` validates `settings`, connects the pool (`InvalidUrl` → `Config`, anything else → `Database`), builds the TLS acceptor, and calls `app(pool.clone())`. It then wraps the returned router in `DefaultBodyLimit::max(MAX_BODY_BYTES)`, `bound` and `log`, serves health on `health`, and runs the accept loop exactly as ingest's `run` does today: connection semaphore, `no_delay`, handshake and header-read deadline, the `Peer` extension, and `GracefulShutdown` drain.

- [ ] **Step 1: The ingest suite is this task's test. Record the baseline.**

Run `eval "$(scripts/test-db.sh)"; cargo test --locked -p openvibes-ingest 2>&1 | grep -E '^test result' > "$CLAUDE_JOB_DIR/tmp/dm0-before.txt"; cat "$CLAUDE_JOB_DIR/tmp/dm0-before.txt"`
Expected: every line `ok`. Keep the pass counts. After the move they must equal these, minus the one `no_delay` unit test, which moves.

- [ ] **Step 2: Write the one new behavioural test (it must fail first).**

`log` labels requests by axum's `MatchedPath` rather than ingest's hard-coded list, so a second service needs no list. Add this unit test to `crates/platform-agent-server/src/limits.rs`:

```rust
#[cfg(test)]
mod tests {
    use axum::{Router, body::Body, http::Request, middleware, routing::post};
    use tower::ServiceExt;

    #[test]
    fn endpoint_label_is_the_matched_route_or_other() {
        assert_eq!(super::endpoint_label(Some("/v1/rule-bundle")), "/v1/rule-bundle");
        assert_eq!(super::endpoint_label(None), "other");
    }

    #[tokio::test]
    async fn unknown_paths_are_not_copied_into_logs() {
        let app = Router::new()
            .route("/v1/x", post(|| async { "ok" }))
            .layer(middleware::from_fn(super::log));
        let response = app
            .oneshot(Request::post("/secret-token-in-path").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), 404);
    }
}
```

Write the `Cargo.toml` first, as below. Then create `limits.rs` containing only these tests and an `endpoint_label` stub of `todo!()`. Run `cargo test --locked -p platform-agent-server`. Expected: FAIL (panic `not yet implemented`).

```toml
[package]
name = "platform-agent-server"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[dependencies]
axum.workspace = true
chrono.workspace = true
hyper.workspace = true
hyper-util.workspace = true
openvibes-core.workspace = true
platform-config = { path = "../platform-config" }
platform-pki = { path = "../platform-pki" }
platform-store = { path = "../platform-store" }
rustls.workspace = true
serde.workspace = true
serde_json.workspace = true
tokio.workspace = true
tokio-rustls.workspace = true
tower.workspace = true
tracing.workspace = true

[lints]
workspace = true
```

Add `"crates/platform-agent-server"` to the workspace `members`.

- [ ] **Step 3: Move the code.**

Use `git mv` so history follows the files: `tls.rs`, `auth.rs`, `limits.rs`, `health.rs` and `request.rs` go from `crates/openvibes-ingest/src/` to `crates/platform-agent-server/src/`. Merge the test module from Step 2 back into the moved `limits.rs`. Then make these edits:

1. `tls.rs`:
   - `server_config(cert: &Path, key: &Path, client_ca: &Path) -> Result<Arc<ServerConfig>, ServerError>`;
   - every `IngestError::Tls` becomes `ServerError::Tls`;
   - `read_pem` becomes `pub`.
2. `error.rs`:
   - create it with `ServerError`. Its `Display` strings are: `"invalid configuration"`, `"invalid TLS or CA certificate or key file"`, `"database unavailable"`, `"cannot bind a listener"`;
   - move `ApiError` here from ingest's `error.rs` and make it `pub`, together with `From<StoreError>`;
   - add the variant `NotFound => (StatusCode::NOT_FOUND, "not found")`.
3. `auth.rs`:
   - `Peer` and `AuthenticatedAgent` become `pub`;
   - the impl becomes generic: `impl<S: Send + Sync> FromRequestParts<S> for AuthenticatedAgent where Pool: FromRef<S>`, with `let pool = Pool::from_ref(state);` in place of `state.pool`. The body is otherwise unchanged.
4. `limits.rs`:
   - `pub(crate) struct Limits { pub in_flight: Arc<Semaphore>, pub request_timeout: Duration }` with `#[derive(Clone)]`;
   - `bound` takes `State<Limits>`.
   - Replace `endpoint_name` with:

```rust
/// The route that matched, or `other`; logs never copy the raw path.
fn endpoint_label(matched: Option<&str>) -> &str {
    matched.unwrap_or("other")
}

pub(crate) async fn log(request: Request, next: Next) -> Response {
    let matched = request.extensions().get::<MatchedPath>().map(|m| m.as_str().to_owned());
    let endpoint = endpoint_label(matched.as_deref()).to_owned();
    // … rest unchanged, with `endpoint` a String …
}
```

5. `request.rs`: `MAX_BODY_BYTES` and `parse` become `pub`; its `ApiError` import is now `crate::ApiError`.
6. `health.rs`: `pub(crate) fn router(pool: Pool) -> Router`, unchanged.
7. `serve.rs`:
   - `Settings` with its `validate`. This is ingest's `validate` minus the certificate-days, retention and issuing-file checks: absolute paths, loopback health, `max_in_flight >= 1`, timeout 1–300, connections 1–65,536, pool 1–1024;
   - `no_delay` and its unit test, moved from ingest's `server.rs`;
   - `run`: the loop body of ingest's `run`, moved verbatim, with `routes(state)` replaced by:

```rust
let limits = Limits {
    in_flight: Arc::new(Semaphore::new(settings.max_in_flight)),
    request_timeout: Duration::from_secs(settings.request_timeout_seconds),
};
let router = app(pool.clone())
    .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
    .layer(middleware::from_fn_with_state(limits, crate::limits::bound))
    .layer(middleware::from_fn(crate::limits::log));
```

8. `lib.rs`: the crate doc; `mod` lines; `pub use` for `Settings`, `ServerError`, `ApiError`, `AuthenticatedAgent`, `MAX_BODY_BYTES`, `parse`, `read_pem` and `run`.

- [ ] **Step 4: Rewire ingest.**

1. `config.rs`: keep `IngestConfig` field for field; the TOML file is unchanged. Add:

```rust
impl IngestConfig {
    /// The fields the shared agent server needs.
    pub fn settings(&self) -> platform_agent_server::Settings {
        platform_agent_server::Settings {
            listen: self.listen, health_listen: self.health_listen,
            server_certificate_file: self.server_certificate_file.clone(),
            server_key_file: self.server_key_file.clone(),
            client_ca_file: self.client_ca_file.clone(),
            database_url: self.database_url.clone(),
            max_in_flight: self.max_in_flight,
            request_timeout_seconds: self.request_timeout_seconds,
            max_connections: self.max_connections,
            database_pool_size: self.database_pool_size,
        }
    }
}
```

   `validate` becomes `self.settings().validate().map_err(|_| IngestError::Config)?`, followed by the ingest-only checks: absolute issuing paths, certificate days 1–365, retention 1–36,500.

2. `error.rs`: keep `IngestError` and its `Display` text (`check-rpm.sh` greps for "invalid ingest configuration"). Add:

```rust
impl From<platform_agent_server::ServerError> for IngestError {
    fn from(error: platform_agent_server::ServerError) -> Self {
        use platform_agent_server::ServerError as E;
        match error { E::Config => Self::Config, E::Tls => Self::Tls,
                      E::Database => Self::Database, E::Listen => Self::Listen }
    }
}
```

   Delete `ApiError` from this file.

3. `server.rs`:
   - `AppState { pool, issuer, client_certificate_days, finding_retention_days }`, dropping `in_flight` and `request_timeout`;
   - `impl FromRef<AppState> for Pool { fn from_ref(s: &AppState) -> Pool { s.pool.clone() } }`;
   - `routes` keeps only the four `.route` lines and `.with_state(state)`;
   - `serve` is unchanged;
   - `run`:

```rust
pub async fn run(config: IngestConfig, listener: TcpListener, health: TcpListener,
                 shutdown: impl Future<Output = ()>) -> Result<(), IngestError> {
    config.validate()?;
    let read = |path| platform_agent_server::read_pem(path).map_err(IngestError::from);
    let issuer = Arc::new(
        Issuer::load(&read(&config.issuing_certificate_file)?, &read(&config.issuing_key_file)?)
            .map_err(|_| IngestError::Tls)?,
    );
    let (days, retention) = (config.client_certificate_days, config.finding_retention_days);
    platform_agent_server::run(&config.settings(), listener, health,
        move |pool| routes(AppState { pool, issuer, client_certificate_days: days,
                                      finding_retention_days: retention }),
        shutdown).await.map_err(IngestError::from)
}
```

4. `delivery.rs` and `enroll.rs`: import `ApiError`, `AuthenticatedAgent` and `parse` from `platform_agent_server`. `crate::request::parse` becomes `platform_agent_server::parse`.
5. `lib.rs`: drop the moved `mod` lines. `accepts` calls `platform_agent_server::parse`.
6. `Cargo.toml`: add `platform-agent-server = { path = "../platform-agent-server" }`. Remove `hyper`, `hyper-util`, `rustls`, `tokio-rustls` and `tower` if nothing in ingest's `src/` uses them any more (check with `grep -rn 'hyper\|rustls\|tower' crates/openvibes-ingest/src`).

- [ ] **Step 5: Run the tests.**

Run `cargo test --locked -p platform-agent-server -p openvibes-ingest 2>&1 | grep -E '^test result|FAILED|panicked'`.
Expected: the shared crate's 3 tests pass (the 2 new ones and `accepted_sockets_disable_nagle`). Every ingest test binary shows the same counts as `dm0-before.txt`, minus the moved unit test. Nothing fails. `tests/logging.rs` still sees `"endpoint":"other"` for an unknown path, and `/v1/findings` is logged by its matched route.

- [ ] **Step 6: Run the whole gate.**

Run `cargo fmt --all --check && cargo clippy --locked --workspace --all-targets --all-features -- -D warnings -F unsafe-code && cargo doc --locked --workspace --no-deps && cargo test --locked --workspace 2>&1 | tail -3`, then `bash scripts/integration-agent.sh`, then `bash scripts/load/run.sh 50 1000 10`.
Expected: all clean; `integration: all checks passed`; a load summary with `"pass": true`.

- [ ] **Step 7: Documentation.**

Write `docs/components/platform-agent-server.md` in the house format:
- purpose: the shared agent-facing server;
- interfaces: the `Produces` block above;
- config: `Settings`, and which service TOML keys map to it;
- failure behaviour: the status table from Global Constraints, the handshake failure for a foreign CA, and the drain on shutdown;
- how to test: the two crates' suites, the integration run and the load smoke.

In `openvibes-ingest.md`, replace the module descriptions of TLS, auth and limits with a link to the new page. Add the new page to `README.md`.

- [ ] **Step 8: Commit.**

```bash
git add -A crates/platform-agent-server crates/openvibes-ingest Cargo.toml Cargo.lock docs/components
git commit -m "Extract the agent-facing server into platform-agent-server (DM0)"
```

---

### Task 2 (DM1): Migration 0006 and the store `rules` module

**Files:**
- Create `migrations/0006_rule_distribution.sql`, `crates/platform-store/src/rules.rs` and `crates/platform-store/tests/rules.rs`.
- Modify `crates/platform-store/src/{lib.rs,migrate.rs}`.
- Update `docs/components/platform-store.md`.

**Interfaces (Produces, used by Tasks 3 and 4):**

```rust
// platform_store::rules
pub struct TrustKey { pub rule_set_id: String, pub issuer_key_id: String,
                      pub public_key: [u8; 32], pub added_at: DateTime<Utc>,
                      pub removed_at: Option<DateTime<Utc>> }
pub enum TrustAdded { Added, AlreadyTrusted, Conflict, Retired }
pub async fn add_trust_key(c: &Client, set: &str, issuer: &str, key: [u8; 32]) -> Result<TrustAdded, StoreError>;
pub async fn trust_keys(c: &Client, set: Option<&str>) -> Result<Vec<TrustKey>, StoreError>;
pub async fn active_trust_keys(c: &Client, set: &str) -> Result<Vec<([u8; 32], String)>, StoreError>; // (key, issuer)
pub async fn remove_trust_key(c: &Client, set: &str, issuer: &str) -> Result<bool, StoreError>;
pub struct NewBundle<'a> { pub rule_set_id: &'a str, pub version: i64, pub envelope: &'a [u8],
                           pub envelope_sha256: [u8; 32], pub issuer_key_id: &'a str,
                           pub created_at_ms: i64, pub expires_at_ms: i64, pub published_by: &'a str }
pub enum Published { Stored, Unchanged, VersionConflict, NotAboveCurrent(i64), Retired, UnknownSet }
pub async fn publish(c: &mut Client, bundle: &NewBundle<'_>) -> Result<Published, StoreError>;
pub struct RuleSetRow { pub rule_set_id: String, pub created_at: DateTime<Utc>,
                        pub retired_at: Option<DateTime<Utc>>, pub current_version: Option<i64>,
                        pub current_expires_at_ms: Option<i64>, pub trusted_keys: i64 }
pub async fn list(c: &Client) -> Result<Vec<RuleSetRow>, StoreError>;
pub struct BundleRow { pub version: i64, pub envelope_sha256: [u8; 32], pub issuer_key_id: String,
                       pub created_at_ms: i64, pub expires_at_ms: i64,
                       pub published_at: DateTime<Utc>, pub published_by: String, pub bytes: i32 }
pub async fn bundles(c: &Client, set: &str) -> Result<Vec<BundleRow>, StoreError>; // newest first
pub async fn retire(c: &Client, set: &str) -> Result<bool, StoreError>;
pub enum Served { Unknown, UpToDate, Envelope(Vec<u8>) }
pub async fn serve(c: &Client, set: &str, current_version: Option<i64>) -> Result<Served, StoreError>;
```

- [ ] **Step 1: Write the failing store tests** in `crates/platform-store/tests/rules.rs`.

Admin-side calls run on the database owner connection. `serve` runs as `openvibes_distribution` (`SET ROLE`, the same pattern as `as_ingest` in `tests/ingest.rs`).

```rust
//! Rule distribution queries: admin writes as the owner, `serve` as the
//! least-privilege `openvibes_distribution` role.
mod common;

use common::TestDb;
use platform_store::{Client, rules::{self, NewBundle, Published, Served, TrustAdded}};

async fn setup() -> (TestDb, Client) {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    (db, client)
}

async fn as_role(db: &TestDb, role: &str) -> Client {
    let client = db.pool.get().await.unwrap();
    client.batch_execute(&format!("SET ROLE {role}")).await.unwrap();
    client
}

fn bundle(version: i64, envelope: &[u8]) -> NewBundle<'_> {
    NewBundle { rule_set_id: "baseline", version, envelope, envelope_sha256: [version as u8; 32],
                issuer_key_id: "org.rules", created_at_ms: 1, expires_at_ms: i64::MAX,
                published_by: "test" }
}

#[tokio::test]
async fn trust_keys_are_added_once_and_conflicts_refused() {
    let (db, client) = setup().await;
    assert_eq!(rules::add_trust_key(&client, "baseline", "org.rules", [1; 32]).await.unwrap(), TrustAdded::Added);
    assert_eq!(rules::add_trust_key(&client, "baseline", "org.rules", [1; 32]).await.unwrap(), TrustAdded::AlreadyTrusted);
    assert_eq!(rules::add_trust_key(&client, "baseline", "org.rules", [2; 32]).await.unwrap(), TrustAdded::Conflict);
    assert!(rules::remove_trust_key(&client, "baseline", "org.rules").await.unwrap());
    assert!(rules::active_trust_keys(&client, "baseline").await.unwrap().is_empty());
    // A removed id is never re-used for a different key.
    assert_eq!(rules::add_trust_key(&client, "baseline", "org.rules", [1; 32]).await.unwrap(), TrustAdded::Conflict);
    db.drop().await;
}

#[tokio::test]
async fn publish_stores_exact_bytes_and_serves_by_version() {
    let (db, mut client) = setup().await;
    rules::add_trust_key(&client, "baseline", "org.rules", [1; 32]).await.unwrap();
    let v1 = br#"{"exact":"bytes","v":1}"#;
    assert_eq!(rules::publish(&mut client, &bundle(1, v1)).await.unwrap(), Published::Stored);
    let dist = as_role(&db, "openvibes_distribution").await;
    assert_eq!(rules::serve(&dist, "baseline", None).await.unwrap(), Served::Envelope(v1.to_vec()));
    assert_eq!(rules::serve(&dist, "baseline", Some(1)).await.unwrap(), Served::UpToDate);
    assert_eq!(rules::serve(&dist, "baseline", Some(9)).await.unwrap(), Served::UpToDate);
    assert_eq!(rules::serve(&dist, "unknown", None).await.unwrap(), Served::Unknown);
    db.drop().await;
}

#[tokio::test]
async fn publish_is_idempotent_and_refuses_conflicts_and_old_versions() {
    let (db, mut client) = setup().await;
    rules::add_trust_key(&client, "baseline", "org.rules", [1; 32]).await.unwrap();
    rules::publish(&mut client, &bundle(2, b"two")).await.unwrap();
    assert_eq!(rules::publish(&mut client, &bundle(2, b"two")).await.unwrap(), Published::Unchanged);
    assert_eq!(rules::publish(&mut client, &bundle(2, b"TWO")).await.unwrap(), Published::VersionConflict);
    assert_eq!(rules::publish(&mut client, &bundle(1, b"one")).await.unwrap(), Published::NotAboveCurrent(2));
    let mut unknown = bundle(1, b"x");
    unknown.rule_set_id = "nobody";
    assert_eq!(rules::publish(&mut client, &unknown).await.unwrap(), Published::UnknownSet);
    db.drop().await;
}

#[tokio::test]
async fn concurrent_identical_publishes_store_one_row() {
    let (db, client) = setup().await;
    rules::add_trust_key(&client, "baseline", "org.rules", [1; 32]).await.unwrap();
    let (mut a, mut b) = (db.pool.get().await.unwrap(), db.pool.get().await.unwrap());
    let (ra, rb) = tokio::join!(rules::publish(&mut a, &bundle(1, b"same")),
                                rules::publish(&mut b, &bundle(1, b"same")));
    let mut outcomes = [ra.unwrap(), rb.unwrap()];
    outcomes.sort_by_key(|o| format!("{o:?}"));
    assert_eq!(outcomes, [Published::Stored, Published::Unchanged]);
    assert_eq!(rules::bundles(&client, "baseline").await.unwrap().len(), 1);
    db.drop().await;
}

#[tokio::test]
async fn a_retired_set_is_unknown_and_refuses_publishing() {
    let (db, mut client) = setup().await;
    rules::add_trust_key(&client, "baseline", "org.rules", [1; 32]).await.unwrap();
    rules::publish(&mut client, &bundle(1, b"one")).await.unwrap();
    assert!(rules::retire(&client, "baseline").await.unwrap());
    let dist = as_role(&db, "openvibes_distribution").await;
    assert_eq!(rules::serve(&dist, "baseline", None).await.unwrap(), Served::Unknown);
    assert_eq!(rules::publish(&mut client, &bundle(2, b"two")).await.unwrap(), Published::Retired);
    assert_eq!(rules::add_trust_key(&client, "baseline", "k2", [3; 32]).await.unwrap(), TrustAdded::Retired);
    assert_eq!(rules::bundles(&client, "baseline").await.unwrap().len(), 1, "kept for audit");
    db.drop().await;
}

#[tokio::test]
async fn the_distribution_role_has_only_the_rights_it_uses() {
    let (db, _client) = setup().await;
    let dist = as_role(&db, "openvibes_distribution").await;
    for ok in ["SELECT count(*) FROM agents", "SELECT count(*) FROM certificates",
               "SELECT count(*) FROM rule_sets", "SELECT count(*) FROM rule_bundles",
               "SELECT version FROM schema_version"] {
        dist.batch_execute(ok).await.expect(ok);
    }
    for denied in ["SELECT count(*) FROM rule_trust_keys", "SELECT count(*) FROM findings",
                   "SELECT count(*) FROM enrollment_tokens", "INSERT INTO rule_sets (rule_set_id) VALUES ('x')",
                   "UPDATE agents SET status = 'revoked'", "DELETE FROM rule_bundles"] {
        let error = dist.batch_execute(denied).await.expect_err(denied);
        assert_eq!(error.code(), Some(&tokio_postgres::error::SqlState::INSUFFICIENT_PRIVILEGE), "{denied}");
    }
    let ingest = as_role(&db, "openvibes_ingest").await;
    for denied in ["SELECT count(*) FROM rule_sets", "SELECT count(*) FROM rule_bundles",
                   "SELECT count(*) FROM rule_trust_keys"] {
        let error = ingest.batch_execute(denied).await.expect_err(denied);
        assert_eq!(error.code(), Some(&tokio_postgres::error::SqlState::INSUFFICIENT_PRIVILEGE), "{denied}");
    }
    db.drop().await;
}
```

Derive `Debug`, `PartialEq` and `Eq` on `TrustAdded`, `Published` and `Served`. Check whether `tests/Cargo`-level dev-deps already include `tokio-postgres` for the SqlState import (`tests/ingest.rs` uses it, so they do).

Run `cargo test --locked -p platform-store --test rules`. Expected: compile failure, `unresolved import platform_store::rules`.

- [ ] **Step 2: Migration 0006.**

```sql
-- OpenVIBES platform schema version 6: rule distribution (SP2). Operators
-- publish offline-signed envelopes; the distribution service serves the
-- highest version of each live rule set, byte for byte.
CREATE TABLE rule_sets (
    rule_set_id text PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT now(),
    retired_at timestamptz
);
CREATE TABLE rule_trust_keys (
    rule_set_id text NOT NULL REFERENCES rule_sets,
    issuer_key_id text NOT NULL,
    public_key bytea NOT NULL CHECK (length(public_key) = 32),
    added_at timestamptz NOT NULL DEFAULT now(),
    removed_at timestamptz,
    PRIMARY KEY (rule_set_id, issuer_key_id)
);
CREATE TABLE rule_bundles (
    rule_set_id text NOT NULL REFERENCES rule_sets,
    version bigint NOT NULL CHECK (version > 0),
    envelope bytea NOT NULL CHECK (length(envelope) BETWEEN 1 AND 1048576),
    envelope_sha256 bytea NOT NULL CHECK (length(envelope_sha256) = 32),
    issuer_key_id text NOT NULL,
    created_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL,
    published_at timestamptz NOT NULL DEFAULT now(),
    published_by text NOT NULL,
    PRIMARY KEY (rule_set_id, version)
);
DO $$ BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'openvibes_distribution') THEN
        CREATE ROLE openvibes_distribution LOGIN;
    END IF;
-- Roles are cluster-wide: parallel migrations (tests) can race on creation.
EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
END $$;
GRANT SELECT ON agents, certificates, rule_sets, rule_bundles, schema_version
    TO openvibes_distribution;
```

In `migrate.rs`: `SCHEMA_VERSION = 6` and append `(6, include_str!("../../../migrations/0006_rule_distribution.sql"))`. The existing const-assert enforces the pairing.

Before writing `serve`, check `ingest::authenticate`'s SQL. It must only `SELECT` from `agents` and `certificates`, and it does: `SELECT a.agent_id, a.status, c.spki_sha256 …`. So the distribution role needs no more.

- [ ] **Step 3: `rules.rs`.** Key queries:

```rust
/// Advisory lock namespace for per-set publishing ("ovru").
const PUBLISH_LOCK: i32 = 0x6f76_7275;

pub async fn publish(c: &mut Client, b: &NewBundle<'_>) -> Result<Published, StoreError> {
    let tx = c.transaction().await?;
    // Serializes publishers of one set, so check-then-insert is atomic.
    tx.execute("SELECT pg_advisory_xact_lock($1, hashtext($2))", &[&PUBLISH_LOCK, &b.rule_set_id]).await?;
    let Some(set) = tx.query_opt("SELECT retired_at IS NOT NULL FROM rule_sets WHERE rule_set_id = $1",
                                 &[&b.rule_set_id]).await? else { return Ok(Published::UnknownSet) };
    if set.get::<_, bool>(0) { return Ok(Published::Retired); }
    if let Some(row) = tx.query_opt("SELECT envelope FROM rule_bundles WHERE rule_set_id = $1 AND version = $2",
                                    &[&b.rule_set_id, &b.version]).await? {
        let stored: Vec<u8> = row.get(0);
        return Ok(if stored == b.envelope { Published::Unchanged } else { Published::VersionConflict });
    }
    let current: Option<i64> = tx.query_one("SELECT max(version) FROM rule_bundles WHERE rule_set_id = $1",
                                            &[&b.rule_set_id]).await?.get(0);
    if let Some(current) = current.filter(|c| *c >= b.version) { return Ok(Published::NotAboveCurrent(current)); }
    tx.execute("INSERT INTO rule_bundles (rule_set_id, version, envelope, envelope_sha256, issuer_key_id, \
                created_at_ms, expires_at_ms, published_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
               &[&b.rule_set_id, &b.version, &b.envelope, &b.envelope_sha256.as_slice(), &b.issuer_key_id,
                 &b.created_at_ms, &b.expires_at_ms, &b.published_by]).await?;
    tx.commit().await?;
    Ok(Published::Stored)
}

/// One indexed query (primary key, backwards): the highest version of a
/// live set, with its bytes only when the agent's version is older.
pub async fn serve(c: &Client, set: &str, current: Option<i64>) -> Result<Served, StoreError> {
    let row = c.query_opt(
        "SELECT CASE WHEN b.version > $2 THEN b.envelope END FROM rule_bundles b \
         JOIN rule_sets s USING (rule_set_id) \
         WHERE b.rule_set_id = $1 AND s.retired_at IS NULL ORDER BY b.version DESC LIMIT 1",
        &[&set, &current.unwrap_or(0)]).await?;
    Ok(match row {
        None => Served::Unknown,
        Some(row) => row.get::<_, Option<Vec<u8>>>(0).map_or(Served::UpToDate, Served::Envelope),
    })
}
```

`add_trust_key`:
1. `INSERT INTO rule_sets (rule_set_id) VALUES ($1) ON CONFLICT DO NOTHING`.
2. If the set's `retired_at` is set, return `Retired`.
3. `INSERT … ON CONFLICT (rule_set_id, issuer_key_id) DO NOTHING RETURNING 1`: a row returned means `Added`.
4. Otherwise read the existing row: the same key with `removed_at IS NULL` is `AlreadyTrusted`, anything else is `Conflict`.

All of it runs in one transaction.

The remaining functions:
- `remove_trust_key`: `UPDATE … SET removed_at = now() WHERE … AND removed_at IS NULL`, returning whether a row changed;
- `retire`: `UPDATE rule_sets SET retired_at = now() WHERE rule_set_id = $1 AND retired_at IS NULL`;
- `list`: a `LEFT JOIN LATERAL` on the newest bundle and a count of active keys;
- `bundles`: newest first, with `length(envelope)` as `bytes`.

The module doc says it runs within the grants of the admin role (writes) and `openvibes_distribution` (`serve`). Declare it in `lib.rs` as `/// Rule sets, trust keys, and published bundles.\npub mod rules;`.

- [ ] **Step 4: Run the tests.**

Run `cargo test --locked -p platform-store 2>&1 | grep -E '^test result|FAILED'`. Expected: every binary `ok`, including the 6 new ones. `tests/migrate.rs` asserts `SCHEMA_VERSION`; if it hard-codes 5, update it to 6 and note it in the commit.

- [ ] **Step 5: Documentation and commit.**

In `platform-store.md`, add the three tables, the role grants and the `rules` functions, plus a note that `serve` is one primary-key-ordered query.

```bash
git add migrations/0006_rule_distribution.sql crates/platform-store docs/components/platform-store.md
git commit -m "Store rule sets, trust keys, and signed bundles (migration 6)"
```

---

### Task 3 (DM1): `openvibes-admin rules …`

**Files:**
- Create `crates/openvibes-admin/src/rules.rs` and `crates/openvibes-admin/tests/rules.rs`.
- Modify: `crates/openvibes-admin/src/main.rs`, `crates/openvibes-admin/Cargo.toml` (add `openvibes-core`, `openvibes-rules`, `ed25519-dalek` and `sha2` as dependencies; `base64` is already present), `crates/openvibes-ingest/examples/integration_bundle.rs`.
- Update `docs/components/openvibes-admin.md`.

**Interfaces:**
- Consumes Task 2's `platform_store::rules::*`.
- Produces the CLI. Each line is `command` → audit action; audit targets are listed after.
  - `rules trust add RULE_SET ISSUER_KEY_ID PUBLIC_KEY_B64URL` → `rules trust add`;
  - `rules trust list [RULE_SET]`;
  - `rules trust remove RULE_SET ISSUER_KEY_ID`;
  - `rules publish FILE` → `rules publish`, target `RULE_SET vVERSION sha256:HEX`;
  - `rules list`;
  - `rules show RULE_SET`;
  - `rules retire RULE_SET`.
  - The other targets: `RULE_SET` for list, show and retire; `RULE_SET/ISSUER_KEY_ID` for the trust commands.
- Produces `integration_bundle OUT_FILE [VERSION [PAD_RULES]]`:
  - VERSION defaults to 1;
  - version ≥ 2 adds the rule `integration.v2` (`facts['process.count'] >= 1`), so a finding proves the agent runs v2;
  - PAD_RULES adds that many never-matching rules (`facts['process.count'] < 0`) with 2,000-character messages, about 2 KB each, to reach a target envelope size;
  - it still prints the base64url public key.

- [ ] **Step 1: Extend `integration_bundle`** (test tooling, used by the tests below).

Parse `[out, rest @ ..]`: `rest[0]` is VERSION (`u64`, ≥ 1) and `rest[1]` is PAD_RULES (`usize`, ≤ 500). Anything else prints the usage and exits 2. Set `rule_set_version: version`, push the extra rules, and keep everything else. Run `cargo run -q --locked -p openvibes-ingest --example integration_bundle -- "$CLAUDE_JOB_DIR/tmp/b2.json" 2 100 && wc -c "$CLAUDE_JOB_DIR/tmp/b2.json"`. Expected: a key line, and a file of about 200–220 KB.

- [ ] **Step 2: Write the failing CLI tests** in `crates/openvibes-admin/tests/rules.rs`.

The tests use `common::TestDb::create()`, `run` and `audit_targets`. They build envelopes with the `integration_bundle` logic inlined as a helper, `sign(version, key_seed, expires_in_ms)`, which returns the JSON bytes and the public key. Tests:

```rust
#[tokio::test] async fn publish_stores_the_exact_bytes()               // trust add, publish; bytes in rule_bundles == file bytes; audit target "baseline v1 sha256:<hex>"
#[tokio::test] async fn publish_refuses_an_untrusted_issuer()           // no trust add → exit 1, stderr "untrusted issuer", no row
#[tokio::test] async fn publish_refuses_a_bad_signature()               // flip one payload byte → "invalid signature" (or digest mismatch), no row
#[tokio::test] async fn publish_refuses_an_expired_envelope()           // expires_in_ms = -1 → "expired", no row
#[tokio::test] async fn publish_warns_when_expiry_is_near()             // expires in 2 days → exit 0, stderr contains "expires in less than 7 days"
#[tokio::test] async fn publish_refuses_old_or_conflicting_versions()   // v2 then v1 → "not above current version 2"; v2 different bytes → "version 2 already published with different content"; v2 same bytes → exit 0 "unchanged"
#[tokio::test] async fn publish_refuses_a_removed_key()                 // add, publish v1, trust remove, publish v2 → "untrusted issuer"
#[tokio::test] async fn publish_refuses_an_oversized_file()             // 1_048_577 bytes of spaces → "larger than 1048576 bytes", nothing parsed
#[tokio::test] async fn trust_add_rejects_bad_keys()                    // not base64url / 31 bytes / weak (all-zero) key → exit 1, "invalid public key"
#[tokio::test] async fn list_show_retire_round_trip()                   // list shows "baseline v1 keys 1"; show lists versions newest first; retire → list shows "retired"
#[tokio::test] async fn every_rules_command_is_audited()                // failed publish recorded as ("rules publish", error)
```

Write the bodies in the style of `tests/token.rs` (read it first). Every assertion checks the exit code, the stderr text and the database state.

Run `cargo test --locked -p openvibes-admin --test rules`. Expected: FAIL, with `unrecognized subcommand 'rules'` from every CLI call.

- [ ] **Step 3: `rules.rs`.**

1. Add the variant `Rules { #[command(subcommand)] command: rules::RulesCommand }` with the usual clap doc strings. `name()` returns the action strings above.
2. Add the `Command::Rules` arm in `main`, like `Token`: `rules::run(command, &mut client, &actor).await` returns `(Result<String, String>, Option<String>)`.
3. `publish`, in order:

```rust
const MAX_ENVELOPE: u64 = 1_048_576; // ResourceLimits::V1.document_bytes
const WARN_DAYS_MS: i64 = 7 * 24 * 3_600_000;

// 1. Read at most MAX_ENVELOPE + 1 bytes; more is "larger than 1048576 bytes".
// 2. serde_json::from_slice::<SignedRuleEnvelope>(&bytes) → else "not a signed rule envelope".
// 3. keys = rules::active_trust_keys(client, envelope.rule_set_id.as_str())
//    → TrustedRuleKey::new(set_id.clone(), Identifier::new(issuer)?, key) for each.
// 4. RuleLoader::new(keys, ResourceLimits::V1)?.load_json(&bytes, LoadContext {
//        expected_rule_set_id: &envelope.rule_set_id, now_unix_ms: now, last_accepted: None })
//    map LoadError → message: UntrustedIssuer "untrusted issuer", InvalidSignature | DigestMismatch
//    "invalid signature", Expired "expired", NotYetValid "created in the future", other → its Display.
// 5. version = i64::try_from(rule_set_version) → else "version out of range".
// 6. rules::publish(client, &NewBundle { envelope: &bytes, envelope_sha256: Sha256::digest(&bytes).into(),
//        published_by: actor, … }) and map Published:
//    Stored → "published RULE_SET vN\n", Unchanged → "unchanged: RULE_SET vN already published\n",
//    VersionConflict → Err("version N already published with different content"),
//    NotAboveCurrent(c) → Err("version N is not above current version c"),
//    Retired → Err("rule set is retired"), UnknownSet → Err("untrusted issuer") (no keys ⇒ step 4 already failed).
// 7. If expires_at_unix_ms - now < WARN_DAYS_MS: eprintln!("openvibes-admin: warning: bundle expires in less than 7 days").
```

   The rollback floor is the stored current version, which the store checks in step 6. So `last_accepted: None` is correct here: the loader checks signature, trust and time only.

4. `trust add`:
   - decode `URL_SAFE_NO_PAD`; the result must be 32 bytes;
   - `ed25519_dalek::VerifyingKey::from_bytes` must succeed and `!is_weak()`, otherwise "invalid public key";
   - both ids go through `openvibes_core::Identifier::new`, otherwise "invalid identifier";
   - `TrustAdded`: `Added` → "trusted", `AlreadyTrusted` → "already trusted", `Conflict` → Err("issuer key id already used for a different or removed key"), `Retired` → Err("rule set is retired").
5. `trust list`: one line per key, `RULE_SET ISSUER_KEY_ID <b64url> added <rfc3339> [removed <rfc3339>]`.
6. `list`: `RULE_SET vN|none keys K expires <rfc3339>|- [retired]`.
7. `show`: `vN sha256:<hex> issuer <id> bytes B published <rfc3339> by <actor> expires <rfc3339>` per bundle, newest first. An unknown set is an error.
8. `retire`: a changed row prints "retired", otherwise Err("unknown or already retired rule set").

- [ ] **Step 4: Run the tests.**

Run `cargo test --locked -p openvibes-admin 2>&1 | grep -E '^test result|FAILED'`. Expected: all `ok`, including the 11 new ones.

- [ ] **Step 5: Documentation and commit.**

Add a "Rules" section to `openvibes-admin.md`: the commands, each refusal and its message, the 7-day warning, idempotency, and the audit target format.

```bash
git add crates/openvibes-admin crates/openvibes-ingest/examples/integration_bundle.rs Cargo.lock docs/components/openvibes-admin.md
git commit -m "Add openvibes-admin rules: trust keys, verified publishing (DM1)"
```

---

### Task 4 (DM2): `openvibes-distribution`

**Files:**
- Create:
  - `crates/openvibes-distribution/Cargo.toml` and `src/{lib.rs,config.rs,main.rs}`;
  - `tests/{support/mod.rs,bundle.rs,auth.rs,limits.rs,protocol_fixtures.rs}`;
  - `docs/components/openvibes-distribution.md`.
- Modify: workspace `Cargo.toml` (members) and `docs/components/README.md`.

**Interfaces:**
- Consumes Task 1's `platform_agent_server::{Settings, run, AuthenticatedAgent, ApiError, parse, ServerError}` and Task 2's `platform_store::rules::{serve, Served}`.
- Produces:

```rust
pub struct DistributionConfig { listen, health_listen, server_certificate_file, server_key_file,
    client_ca_file, database_url, max_in_flight (4096), request_timeout_seconds (10),
    max_connections (1024), database_pool_size (16) }   // deny_unknown_fields
impl DistributionConfig { pub fn settings(&self) -> Settings; pub fn validate(&self) -> Result<(), DistributionError>; }
pub fn load_config(path: &Path) -> Result<DistributionConfig, DistributionError>;
pub enum DistributionError { Config, Tls, Database, Listen }  // Display: "invalid distribution configuration", …
pub async fn serve(config, shutdown) -> Result<(), DistributionError>;
pub async fn run(config, listener, health, shutdown) -> Result<(), DistributionError>;
#[doc(hidden)] pub fn accepts(body: &[u8]) -> bool;  // RuleBundleRequest parses and validates
```

- The binary: `openvibes-distribution [--config PATH]`, default `/etc/openvibes/distribution.toml`, JSON logs on stderr, `SIGINT` drain.

- [ ] **Step 1: Test support.**

Copy `crates/openvibes-ingest/tests/support/mod.rs` to `crates/openvibes-distribution/tests/support/mod.rs` and adapt it:
- `World::start_with(|c: &mut DistributionConfig| …)` starts both services. First it starts ingest in-process, with the same config as now, so agents can enroll through `openvibes-transport`. Then it starts distribution on its own listeners with the same PKI (its own `issue_server` certificate) and the same database. It connects as the database owner; the least-privilege role is proven in Task 2.
- `World::enrolled_agent()` enrolls through ingest with `PlatformClient` and returns `(agent_id, ClientIdentity)`.
- `World::fetch(identity, request) -> Result<Option<Vec<u8>>, TransportError>` uses `PlatformClient::fetch_rule_bundle` against `distribution_url`, with `default_port` 18424.
- `raw(...)`, `raw_tls(...)` and `health_get` stay, pointed at distribution.
- `World::publish(version, bytes)` writes directly through `platform_store::rules` (`add_trust_key` once, then `publish`).
- `World::stop()` shuts both down.

Dev-dependencies: `openvibes-ingest`, `openvibes-transport`, `openvibes-core`, `rcgen`, `platform-pki`, `tokio-rustls`, `rustls`, `serde_json`.

- [ ] **Step 2: Write the failing service tests.**

`tests/bundle.rs`:

```rust
#[tokio::test] async fn first_fetch_returns_the_exact_bytes()          // publish v1 (arbitrary bytes incl. whitespace/key order); fetch(None) == Some(bytes) exactly; content-type application/json via raw()
#[tokio::test] async fn an_older_version_gets_the_current_bundle()     // publish v1, v2; fetch(Some(1)) == v2 bytes
#[tokio::test] async fn the_current_version_gets_no_content()          // fetch(Some(2)) == None (204), raw(): empty body
#[tokio::test] async fn a_newer_agent_version_gets_no_content()        // fetch(Some(99)) == None
#[tokio::test] async fn an_unknown_set_is_not_found()                  // raw() status 404
#[tokio::test] async fn a_set_without_bundles_is_not_found()           // add_trust_key only → 404
#[tokio::test] async fn a_retired_set_is_not_found()                   // publish, retire → 404
#[tokio::test] async fn malformed_requests_are_bad_requests()          // "{", current_version 0, schema_version 2, rule_set_id "a/b" → 400 each
```

`tests/auth.rs`:

```rust
#[tokio::test] async fn a_revoked_agent_is_told_identity_revoked()    // platform_store::agents revoke → 403, body {"schema_version":1,"code":"identity_revoked"}
#[tokio::test] async fn an_unknown_certificate_is_unauthorized()       // unrecorded_client() cert → 401
#[tokio::test] async fn an_expired_certificate_is_unauthorized()       // issue with not_after in the past (as ingest tests/tls.rs does) → 401
#[tokio::test] async fn no_client_certificate_is_unauthorized()        // raw_tls without cert → 401
#[tokio::test] async fn a_foreign_ca_fails_the_handshake()             // cert from a second root → handshake error, no HTTP status
```

`tests/limits.rs`:

```rust
#[tokio::test] async fn an_oversized_body_is_a_bad_request()           // Content-Length 1_048_577 → 400 before the body is read
#[tokio::test] async fn a_database_outage_is_unavailable()             // World with the database dropped (drop_database) → 503; /ready 503; /health 200
#[tokio::test] async fn the_in_flight_limit_answers_busy()             // start_with(max_in_flight = 1); hold one request open (send headers, stall body) → second request 503
#[tokio::test] async fn health_is_loopback_only()                      // DistributionConfig with health_listen 0.0.0.0 → validate() == Err(Config)
#[tokio::test] async fn requests_are_logged_without_secrets()          // tracing capture as ingest tests/logging.rs: endpoint "/v1/rule-bundle", status, latency_ms, agent_id; never the body
```

`tests/protocol_fixtures.rs`: for every file in `openvibes-protocol/fixtures/v1/rule-bundle-request/`, `accepts(bytes)` equals `name.starts_with("valid")`. For every file in `signed-rule-envelope/` named `valid*`, publishing its bytes and fetching them returns identical bytes. Find the fixture directory the way ingest's `protocol_fixtures.rs` does (the protocol submodule path).

Create the crate with `lib.rs` exporting `todo!()` stubs for `run` and `serve`, so the tests compile. Run `cargo test --locked -p openvibes-distribution`. Expected: every test FAILS (panics `not yet implemented`).

- [ ] **Step 3: Implement.**

`config.rs` mirrors ingest's without the issuing and retention fields. `validate` is `self.settings().validate().map_err(|_| DistributionError::Config)`.

`lib.rs`:

```rust
#[derive(Clone)]
struct AppState { pool: Pool }
impl FromRef<AppState> for Pool { fn from_ref(s: &AppState) -> Pool { s.pool.clone() } }

async fn rule_bundle(AuthenticatedAgent(_): AuthenticatedAgent, State(state): State<AppState>,
                     body: Bytes) -> Result<Response, ApiError> {
    let request: RuleBundleRequest = platform_agent_server::parse(&body)?;
    let current = request.current_version.map(|v| i64::try_from(v).unwrap_or(i64::MAX));
    let client = state.pool.get().await.map_err(|_| ApiError::Unavailable)?;
    Ok(match platform_store::rules::serve(&client, request.rule_set_id.as_str(), current).await? {
        Served::Unknown => ApiError::NotFound.into_response(),
        Served::UpToDate => StatusCode::NO_CONTENT.into_response(),
        Served::Envelope(bytes) =>
            ([(header::CONTENT_TYPE, "application/json")], bytes).into_response(),
    })
}

pub async fn run(config: DistributionConfig, listener: TcpListener, health: TcpListener,
                 shutdown: impl Future<Output = ()>) -> Result<(), DistributionError> {
    config.validate()?;
    platform_agent_server::run(&config.settings(), listener, health,
        |pool| Router::new().route("/v1/rule-bundle", post(rule_bundle)).with_state(AppState { pool }),
        shutdown).await.map_err(DistributionError::from)
}
```

The extractor order is `AuthenticatedAgent` first. Authentication therefore runs before the body is parsed, as in ingest, so an unauthenticated client never gets a 400 that reveals the parser. `main.rs` is ingest's `main.rs` with the names changed.

- [ ] **Step 4: Run the tests.**

Run `cargo test --locked -p openvibes-distribution 2>&1 | grep -E '^test result|FAILED|panicked'`. Expected: all pass (19 service tests plus the fixture tests). Then run the workspace gate from Task 1, Step 6 (fmt, clippy, doc, test). Expected: clean.

- [ ] **Step 5: Documentation and commit.**

Write `openvibes-distribution.md`:
- purpose;
- interfaces: the route and the status table;
- config: every key with its default;
- failure behaviour: database down, retired set, foreign CA, drain;
- how to test.

Add it to `README.md`.

```bash
git add Cargo.toml Cargo.lock crates/openvibes-distribution docs/components
git commit -m "Add the openvibes-distribution service (DM2)"
```

---

### Task 5 (DM3): RPM subpackage

**Files:**
- Create `packaging/rpm/{openvibes-distribution.service,openvibes-distribution.sysusers,distribution.toml}`.
- Modify `packaging/rpm/openvibes-platform.spec`, `scripts/build-rpm.sh` and `scripts/check-rpm.sh`.
- Update `docs/components/packaging.md`.

- [ ] **Step 1: Write the failing check.**

Extend `scripts/check-rpm.sh`: `openvibes_distribution` joins the user loop, and these lines are added:

```bash
expect_stat /etc/openvibes/distribution.toml 640 root:openvibes_distribution
rpm -qc openvibes-distribution | grep -qx /etc/openvibes/distribution.toml || fail "distribution.toml not %config"
systemd-analyze verify /usr/lib/systemd/system/openvibes-distribution.service || fail "distribution unit verification"
grep -q '^KillSignal=SIGINT' /usr/lib/systemd/system/openvibes-distribution.service || fail "distribution unit lacks KillSignal=SIGINT"
out=$(/usr/bin/openvibes-distribution --config /nonexistent 2>&1) && fail "distribution started without config"
[[ "$out" == *"invalid distribution configuration"* ]] || fail "distribution error: $out"
```

The `noreplace` count becomes 3, with `openvibes-distribution` added to that `rpm -q` list. Run `bash scripts/build-rpm.sh && sudo dnf -y reinstall target/rpm/RPMS/x86_64/openvibes-*.rpm; sudo bash scripts/check-rpm.sh`. Expected: `FAIL: no user openvibes_distribution`. If local sudo is unavailable, the fedora:44 CI job runs this step, and the red run is the first CI run of this commit before Step 2 is pushed.

- [ ] **Step 2: Package it.**

- `openvibes-distribution.service`: a copy of `openvibes-ingest.service` with its `Description`, `User`/`Group` and `ExecStart` changed. It is still `KillSignal=SIGINT` and hardened the same way. It has no `StateDirectory`, because distribution writes nothing.
- `openvibes-distribution.sysusers`: `u openvibes_distribution - "OpenVIBES distribution service" - -`.
- `distribution.toml`:

```toml
# Edit before starting openvibes-distribution; see docs/components/packaging.md.
listen = "0.0.0.0:18424"
health_listen = "127.0.0.1:18481"          # /health, /ready; loopback only
server_certificate_file = "/etc/openvibes/tls/distribution.crt"   # chain, leaf first
server_key_file = "/etc/openvibes/tls/distribution.key"
client_ca_file = "/etc/openvibes/pki/intermediate.crt"            # accepted client issuers
database_url = "postgresql:///openvibes?host=/run/postgresql&user=openvibes_distribution"
max_in_flight = 4096                        # above this: 503
```

- Spec:
  - add `%package -n openvibes-distribution`, its `%description`, the install lines (binary, unit, sysusers, `distribution.toml` at 0640, LICENSE), `%post`/`%preun`/`%postun` systemd macros, and a `%files` section with `%config(noreplace) %attr(0640, root, openvibes_distribution)`;
  - add a changelog line.
- `build-rpm.sh`: add `-p openvibes-distribution` to the release build.

Then run the Step 1 commands again. Expected: `check-rpm: ok`.

- [ ] **Step 3: Documentation and commit.**

In `packaging.md`, add:
- the subpackage;
- first-time setup: `openvibes-admin ca issue-server --name distribution …` writing `/etc/openvibes/tls/distribution.{crt,key}` owned `root:openvibes_distribution`, with the key at 0640;
- `firewall-cmd --add-port=18424/tcp --permanent`;
- `systemctl enable --now openvibes-distribution`;
- PostgreSQL `pg_hba` peer mapping for the new role, the same as ingest's.

```bash
git add packaging scripts/build-rpm.sh scripts/check-rpm.sh docs/components/packaging.md
git commit -m "Package openvibes-distribution as an RPM subpackage (DM3)"
```

---

### Task 6 (DM3): Integration with the real agent

**Files:**
- Modify `scripts/integration-lib.sh` (a `start_distribution` helper), `scripts/integration-agent.sh` and `.github/workflows/ci.yml` (the bundle tool is already built; nothing new unless a step fails).
- Update `docs/components/integration-agent.md`.
- In `openvibes-protocol`: update `PLAN.md`.

**Interfaces:**
- Consumes the `integration_bundle` arguments from Task 3 and the binary from Task 4.
- Produces `start_distribution`. It reads `W`, `DIST_PORT` (default 28424) and `DIST_HEALTH_PORT` (default 28481). It issues `$W/ca/distribution.{crt,key}` with the same `admin ca issue-server` call `start_platform` uses for ingest, and writes `$W/distribution.toml` with the owner database URL. It starts `openvibes-distribution` (log `$W/distribution.log`), appends to `PIDS`, sets `DIST_PID`, and waits for `/ready`.

- [ ] **Step 1: Write the failing integration checks.**

In `integration-agent.sh`, after the existing ingest checks and before the revocation block:

1. Call `start_distribution`.
2. Write v1 and v2 bundles with `integration_bundle` (versions 1 and 2).
3. Trust and publish v1: `admin rules trust add integration integration.test "$KEY"` and `admin rules publish "$W/v1.json"`. Then `ok "rules v1 published"`.
4. Rewrite `agent.toml` with `distribution_url = "https://127.0.0.1:$DIST_PORT"` and without `bundle_file`. Keep `scan_interval_seconds = 86400`: each `restart_agent` triggers a scan, which triggers a fetch.
5. `restart_agent`, then `wait_for "agent fetched v1" grep -q '"endpoint":"/v1/rule-bundle".*"status":200' "$W/distribution.log"` and `ok`.
6. `admin rules publish "$W/v2.json"`, `restart_agent`, then `wait_for "agent runs v2" sql_has "SELECT 1 FROM findings WHERE rule_set_id = 'integration' AND rule_id = 'integration.v2'"` and `ok`.
7. Outage: `kill "$DIST_PID"`, `restart_agent`, then `wait_for "scans continue without distribution"`. Check that the finding count for `integration.v2` increased after the restart. Also check that `agent.log` records the fetch failure without exiting: the agent PID is still alive. Then `ok`.
8. Restart distribution (`start_distribution`).
9. Keep the existing revocation step and add a check after it: `restart_agent`, then `wait_for "distribution refuses the revoked agent" grep -q '"endpoint":"/v1/rule-bundle".*"status":403' "$W/distribution.log"` and `ok`.

Define `sql_has() { [[ -n "$(sql "$1")" ]]; }` next to `active_agents`.

Run `bash scripts/integration-agent.sh`. Expected: FAIL at `start_distribution: command not found`.

- [ ] **Step 2: Add `start_distribution`** to `integration-lib.sh`, following `start_platform`'s ingest block. `OPENVIBES_BIN_DIR` selects installed binaries; otherwise it uses `target/release`, adding `-p openvibes-distribution` to the release build.

Run `bash scripts/integration-agent.sh`. Expected: `integration: all checks passed` with the 6 new `ok:` lines. Run it again with `DIST_PORT=1`. Expected: `FAIL: distribution ready`, the tail of `distribution.log`, and no leftover processes.

- [ ] **Step 3: CI.**

The fedora job's integration step runs against `/usr/bin`, which now includes `openvibes-distribution` from Task 5's RPM, so it needs no new step. Push the branch, open a draft PR and watch both jobs: `gh pr checks --watch`. Expected: both pass.

- [ ] **Step 4: Documentation and commit.**

In `integration-agent.md`, add the new checks and the ports 28424 and 28481.

```bash
git add scripts/integration-lib.sh scripts/integration-agent.sh docs/components/integration-agent.md
git commit -m "Integration: the real agent fetches, updates, survives outage, is refused when revoked (DM3)"
```

- [ ] **Step 5: Protocol housekeeping** (separate repository, separate PR; merge only with the user's approval).

In `openvibes-protocol/PLAN.md`:
- tick P4 "Distribution service";
- in the table row 6, change `n/a (distribution service: todo)` to `done (openvibes-distribution)`.

Branch, commit (`Tick P4: distribution service implemented`), push, and open a PR.

---

### Task 7 (DM4): Distribution load run

**Files:**
- Modify `scripts/load/src/main.rs` and `scripts/load/run.sh`.
- Update `docs/components/load.md`.

**Interfaces:**
- New `openvibes-load` flags:
  - `--distribution-url URL`: when set, each tick is one `fetch_rule_bundle` for `--rule-set` (default `integration`) with `current_version: None`, the worst case (full body every time), instead of heartbeats and findings;
  - `--distribution-pid P`, for CPU accounting.
- Summary changes:
  - `latency_ms.bundle`;
  - `cpu_cores.distribution`;
  - `bundle_bytes`, the size of the first fetched envelope;
  - in this mode, `target_rps` = agents × 1000 / interval_ms.
- `run.sh`: `MODE=distribution` starts distribution with `start_distribution`, publishes a signed envelope of about 200 KB (`integration_bundle "$W/big.json" 1 100` plus `admin rules trust add` and `publish`), and passes the new flags.

- [ ] **Step 1: Write the failing smoke run.**

Run `MODE=distribution bash scripts/load/run.sh 50 1000 10`. Expected: FAIL, `unexpected argument '--distribution-url'`.

- [ ] **Step 2: Implement.**

1. Add `Kind::Bundle`.
2. In `tick`, when `args.distribution_url` is set, build a second `TransportConfig`: a clone with `base_url` set to the distribution URL and `default_port` 18424. Then time `client.fetch_rule_bundle(&RuleBundleRequest { schema_version: V1, rule_set_id: id(args.rule_set.clone()), current_version: None })`. `Ok(Some(bytes))` is a success: record `bytes.len()` in a new `Sample.bytes` field. `Ok(None)` is an error, `"bundle: unexpected 204"`, because the worst case must be measured.
3. `snapshot` gains a 4th slot, filled from `--distribution-pid`.
4. The summary gains `bundle` latency, `cpu_cores.distribution` and `bundle_bytes` (the maximum of `Sample.bytes`).

Run the smoke again. Expected: `"pass": true` and `bundle_bytes` between 190,000 and 230,000.

- [ ] **Step 3: The recorded run.**

Run `MODE=distribution bash scripts/load/run.sh 2000 2000 120`: 1,000 req/s for 120 s, the spec's Q9 target. Record it in `load.md` under a new "Distribution" heading, with the same hardware statement as the ingest run: CPU, cores, RAM, kernel, PostgreSQL version, the shared host, and each process's CPU, plus the achieved rate, p50 and p99 latency, and errors. If it fails, record the failing numbers truthfully and the limiting resource. Do not tune the run until it passes without saying so.

- [ ] **Step 4: CI smoke.**

In `ci.yml`, after the ingest load smoke, add:

```yaml
      - name: Distribution load smoke against the installed binaries
        shell: bash
        run: |
          runuser -u ci -- env OPENVIBES_BIN_DIR=/usr/bin LOAD_DIR=/home/ci/load-dist MODE=distribution \
            LOAD_BIN="$PWD/target/release/openvibes-load" \
            BUNDLE_BIN="$PWD/target/release/examples/integration_bundle" \
            bash scripts/load/run.sh 50 1000 10
```

`run.sh` uses `BUNDLE_BIN` when set, as `integration-agent.sh` does.

- [ ] **Step 5: Commit.**

```bash
git add scripts/load .github/workflows/ci.yml docs/components/load.md
git commit -m "Load: distribution mode and the recorded 1,000 req/s run (DM4)"
```
