# Console Dashboards, part 1 of 3: Store and API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Users save dashboards (a name plus a layout of widgets) on the
platform, list the ones they own or that are shared with a role they
hold, share one with a role (`dashboards.share`), and choose a home
dashboard. Everything is audited.

**Architecture:**
- Migration 0026 adds `console_dashboards`, `console_user_home` and the
  `dashboards.share` permission.
- `platform_store::dashboards` holds the SQL (ownership, visibility,
  version check and audit rows in one transaction).
- A new `openvibes-console` module, `dashboards.rs`, holds layout
  validation and the HTTP handlers. They reuse a session-only
  authentication helper extracted from `authenticated_permission`.

**Tech Stack:** Rust (axum, tokio-postgres, utoipa, serde_json), PostgreSQL.

**Spec:** `docs/superpowers/specs/2026-09-28-console-dashboards-design.md`.
Parts 2 (demo API) and 3 (UI) are separate plans, and part 3 depends on
this one's API types.

## Global Constraints

- **Migration:** `migrations/0026_console_dashboards.sql`, schema version
  26. `SCHEMA_VERSION` and `MIGRATIONS` in
  `crates/platform-store/src/migrate.rs` change together; the build
  asserts it.
- **Limits:**
  - name: 1–80 characters, no control characters, trimmed;
  - layout ≤ 65536 bytes as JSON text, with `schema` = 1 and ≤ 40
    widgets;
  - widget `id`: `[a-z0-9-]{1,32}`, unique;
  - `x` 0–11, `w` 1–12, `x+w ≤ 12`, `y` 0–199, `h` 1–12;
  - `type` in `number`, `breakdown`, `attention`, `list`, `trend`,
    `top-hosts`, `note`;
  - `config`: an object, ≤ 16 keys; each value a string ≤ 256
    characters, an integer, a boolean, or an array of ≤ 16 strings each
    ≤ 256 characters;
  - ≤ 100 dashboards per owner.
- **Routes (browser session only; a bearer token gets 403):**
  - `GET` and `POST /api/v1/dashboards`;
  - `GET`, `PUT` (`If-Match` required) and `DELETE
    /api/v1/dashboards/{dashboard_id}`;
  - `PUT /api/v1/dashboards/{dashboard_id}/sharing`;
  - `GET` and `PUT /api/v1/me/home`.
- **Status codes:**
  - not found and not visible are both 404;
  - visible but not owned is 403;
  - stale is 412; missing `If-Match` is 428;
  - invalid body JSON is 400; validation is 422 with `field_errors`
    (at most 32);
  - over 100 dashboards and unknown role are both 422;
  - the database unavailable is 503.
- **Audit actions:** `dashboard.create`, `dashboard.update`,
  `dashboard.delete`, `dashboard.share`, `dashboard.home`. They are
  written in the same transaction as the change, with `target_kind`
  `dashboard` and `target_id` the id. The layout is never put in
  `detail`.
- **Visibility:** the owner, or the holder of any unrevoked binding
  (global or asset-group) to `shared_role_id`.
- **Repository gate:**
  - `eval "$(scripts/test-db.sh)"`, `cargo fmt --all --check`,
    `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings -F unsafe-code`,
    `cargo doc --locked --workspace --all-features --no-deps`,
    `cargo test --locked --workspace --all-features`,
    `cargo audit --deny warnings`;
  - `bash scripts/build-console.sh`, `bash scripts/check-names.sh`;
  - `cargo run --locked -p openvibes-console --bin export_openapi -- --check docs/api/console-v1.openapi.json`.
- **Commits** end with
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Every component change updates its `docs/components/*.md` page in the
  same task.

## Review Focus

1. **An asset-group-only binding to the shared role must count.** A user
   with an analyst binding on the Production group sees a dashboard
   shared with `analyst`. Tested in Task 2 (`scoped_binding_sees_shared_dashboard`).
2. **Revoking the binding must hide the dashboard, and home falls back.**
   After `revoke_user_role_binding`, the shared dashboard disappears from
   the list, `get` returns `None`, and `home` returns `None` even though
   the home row still points at it. Tested in Task 2
   (`revoked_binding_hides_dashboard_and_home`).
3. **A malformed id must answer 404, never 500.** An id that isn't a UUID
   (`/api/v1/dashboards/not-a-uuid`) is compared as text, so the
   PostgreSQL cast can't fail. Tested in Task 4 (`malformed_id_is_not_found`).
4. **A layout sent as an array or a number** is 422 with field `layout`,
   not a panic or 500. Tested in Task 3 (`layout_must_be_an_object`).
5. **Two browser tabs saving:** the second save with the old version is
   412 and the stored layout is the first tab's. Tested in Task 2
   (`stale_update_is_refused_and_keeps_the_first_save`) and Task 4.

---

### Task 1: Migration 0026 and the `dashboards.share` permission

**Files:**
- Create: `migrations/0026_console_dashboards.sql`
- Modify: `crates/platform-store/src/migrate.rs` (`SCHEMA_VERSION`, `MIGRATIONS`)
- Modify: `crates/openvibes-console/src/api.rs` (`Permission` enum)
- Modify: `crates/openvibes-console/src/rbac.rs` (`ALL_PERMISSIONS`)
- Modify: `docs/components/platform-store.md`, `docs/components/openvibes-console.md` (schema 26), `docs/components/console-rbac.md` (new permission)

**Interfaces:**
- Produces: the tables `console_dashboards(dashboard_id uuid, owner_user_id uuid, name text, layout jsonb, shared_role_id text NULL, version integer, created_at, updated_at)` and `console_user_home(user_id uuid, dashboard_id uuid)`; `crate::Permission::DashboardsShare` (serialised as `"dashboards.share"`), granted to Admin only.

- [ ] **Step 1: Add the permission in Rust first (the parity test goes RED)**

In `crates/openvibes-console/src/api.rs`, after the `AssistantUse` variant:

```rust
    /// Share one's own dashboards with a role (global only).
    #[serde(rename = "dashboards.share")]
    DashboardsShare,
```

In `crates/openvibes-console/src/rbac.rs`, add the variant as the last
entry of `ALL_PERMISSIONS`:

```rust
    Permission::AssistantUse,
    Permission::DashboardsShare,
];
```

`is_agent_bound` is unchanged: the permission is global.

- [ ] **Step 2: Run the parity test and watch it fail**

Run: `eval "$(scripts/test-db.sh)" && cargo test -q --locked -p openvibes-console --all-features --test auth_http database_builtin_permissions`
Expected: FAIL, "PostgreSQL and Rust built-in roles diverged". The right-hand side contains `("admin", "dashboards.share")`.

- [ ] **Step 3: Write the migration**

`migrations/0026_console_dashboards.sql`:

```sql
-- OpenVIBES platform schema version 26: user dashboards. A dashboard stores
-- only a layout of widgets; every widget reads through the permission-
-- checked console API with the viewer's own scope.
CREATE TABLE console_dashboards (
    dashboard_id uuid PRIMARY KEY,
    owner_user_id uuid NOT NULL REFERENCES console_users ON DELETE CASCADE,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
    layout jsonb NOT NULL CHECK (jsonb_typeof(layout) = 'object' AND octet_length(layout::text) <= 65536),
    shared_role_id text NULL REFERENCES console_roles ON DELETE SET NULL,
    version integer NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);
CREATE INDEX console_dashboards_owner_idx ON console_dashboards (owner_user_id);
CREATE INDEX console_dashboards_shared_idx ON console_dashboards (shared_role_id)
    WHERE shared_role_id IS NOT NULL;

CREATE TABLE console_user_home (
    user_id uuid PRIMARY KEY REFERENCES console_users ON DELETE CASCADE,
    dashboard_id uuid NOT NULL REFERENCES console_dashboards ON DELETE CASCADE
);

INSERT INTO console_permissions (permission_id, scope_class)
VALUES ('dashboards.share', 'global')
ON CONFLICT (permission_id) DO NOTHING;
INSERT INTO console_role_permissions (role_id, permission_id)
VALUES ('admin', 'dashboards.share')
ON CONFLICT DO NOTHING;

GRANT SELECT, INSERT, UPDATE, DELETE ON console_dashboards, console_user_home
    TO "openvibes-console";
```

In `crates/platform-store/src/migrate.rs`, set `pub const SCHEMA_VERSION: i32 = 26;` and append:

```rust
    (
        26,
        include_str!("../../../migrations/0026_console_dashboards.sql"),
    ),
```

- [ ] **Step 4: Run the parity and migration tests and watch them pass**

Run: `cargo test -q --locked -p openvibes-console --all-features --test auth_http database_builtin_permissions && cargo test -q --locked -p platform-store --lib every_migration_file`
Expected: PASS (1 test each).

- [ ] **Step 5: Update the docs**

- `docs/components/openvibes-console.md`: "requires schema version 25" becomes "requires schema version 26".
- `docs/components/platform-store.md`: add after the schema-25 paragraph:
  "Schema 26 adds `console_dashboards` (a layout per dashboard, owner,
  optional shared role, version) and `console_user_home`, and grants the
  new global permission `dashboards.share` to Admin."
- `docs/components/console-rbac.md`: add `dashboards.share` (global,
  Admin) to the permission list: "share one's own dashboards with a
  role".

- [ ] **Step 6: Run the full workspace tests and commit**

Run: `cargo test -q --locked --workspace --all-features 2>&1 | grep -E "test result|FAILED"`
Expected: every line is `test result: ok`.

```bash
git add migrations/0026_console_dashboards.sql crates/platform-store/src/migrate.rs crates/openvibes-console/src/api.rs crates/openvibes-console/src/rbac.rs docs/components
git commit -m "Store: dashboards schema (26) and the dashboards.share permission

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 2: `platform_store::dashboards`

**Files:**
- Create: `crates/platform-store/src/dashboards.rs`
- Modify: `crates/platform-store/src/lib.rs` (`pub mod dashboards;`)
- Test: `crates/platform-store/tests/console_dashboards.rs`
- Modify: `docs/components/platform-store.md` (module section)

**Interfaces:**
- Consumes: the Task 1 tables; `console_auth::{create_local_user, NewLocalUser, create_user_role_binding, revoke_user_role_binding}` in tests.
- Produces (all `pub`, in `platform_store::dashboards`):
  - `const MAX_DASHBOARDS_PER_OWNER: i64 = 100;`
  - `struct Dashboard { dashboard_id: String, owner_user_id: String, owner_display_name: String, name: String, layout: serde_json::Value, shared_role_id: Option<String>, version: i64, created_at: DateTime<Utc>, updated_at: DateTime<Utc> }` (derive `Clone, Debug, PartialEq`)
  - `enum Refusal { NotFound, NotOwner, Stale, TooMany, UnknownRole }` (derive `Clone, Copy, Debug, Eq, PartialEq`)
  - `async fn list_visible(client: &Client, user_id: &str) -> Result<Vec<Dashboard>, StoreError>`: own dashboards first, then shared ones, each by name
  - `async fn get_visible(client: &Client, user_id: &str, dashboard_id: &str) -> Result<Option<Dashboard>, StoreError>`
  - `async fn create(client: &mut Client, user_id: &str, name: &str, layout: &serde_json::Value, now: DateTime<Utc>) -> Result<Result<Dashboard, Refusal>, StoreError>`
  - `async fn update(client: &mut Client, user_id: &str, dashboard_id: &str, name: &str, layout: &serde_json::Value, expected_version: i64, now: DateTime<Utc>) -> Result<Result<Dashboard, Refusal>, StoreError>`
  - `async fn delete(client: &mut Client, user_id: &str, dashboard_id: &str) -> Result<Result<(), Refusal>, StoreError>`
  - `async fn set_sharing(client: &mut Client, user_id: &str, dashboard_id: &str, role_id: Option<&str>, now: DateTime<Utc>) -> Result<Result<Dashboard, Refusal>, StoreError>`
  - `async fn home(client: &Client, user_id: &str) -> Result<Option<String>, StoreError>`: `None` when unset or no longer visible
  - `async fn set_home(client: &mut Client, user_id: &str, dashboard_id: Option<&str>) -> Result<Result<(), Refusal>, StoreError>`

- [ ] **Step 1: Write the failing tests**

`crates/platform-store/tests/console_dashboards.rs`:

```rust
//! Dashboards: ownership, visibility through role bindings, versions,
//! limits, home fallback, and transactional audit rows.

mod common;

use chrono::Utc;
use common::TestDb;
use platform_store::{
    Client,
    console_auth::{NewLocalUser, create_local_user, create_user_role_binding, revoke_user_role_binding},
    dashboards::{self, Refusal},
};
use serde_json::json;

const ALICE: &str = "11111111-1111-4111-8111-111111111111";
const BOB: &str = "33333333-3333-4333-8333-333333333333";

async fn user(client: &mut Client, id: &str, binding: &str, name: &str, role: &str) {
    create_local_user(client, &NewLocalUser {
        user_id: id, binding_id: binding, username: name, display_name: name,
        password_phc: "$argon2id$v=19$m=19456,t=2,p=1$opaque-salt$opaque-hash",
        role_id: role, actor_id: "test", now: Utc::now(),
    }).await.unwrap();
}

async fn setup() -> (TestDb, Client) {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    user(&mut client, ALICE, "22222222-2222-4222-8222-222222222222", "alice", "admin").await;
    user(&mut client, BOB, "44444444-4444-4444-8444-444444444444", "bob", "viewer").await;
    (db, client)
}

fn layout() -> serde_json::Value {
    json!({"schema": 1, "widgets": [{"id": "w1", "type": "number", "x": 0, "y": 0, "w": 3, "h": 2, "config": {"metric": "agents.active"}}]})
}

#[tokio::test]
async fn owner_creates_updates_and_deletes_with_versions_and_audit() {
    let (db, mut client) = setup().await;
    let created = dashboards::create(&mut client, ALICE, "Morning", &layout(), Utc::now()).await.unwrap().unwrap();
    assert_eq!((created.version, created.owner_display_name.as_str()), (1, "alice"));
    let updated = dashboards::update(&mut client, ALICE, &created.dashboard_id, "Morning check", &layout(), 1, Utc::now())
        .await.unwrap().unwrap();
    assert_eq!((updated.version, updated.name.as_str()), (2, "Morning check"));
    assert_eq!(dashboards::delete(&mut client, ALICE, &created.dashboard_id).await.unwrap(), Ok(()));
    assert!(dashboards::get_visible(&client, ALICE, &created.dashboard_id).await.unwrap().is_none());
    let actions: Vec<String> = client
        .query("SELECT action FROM audit_log WHERE target_kind = 'dashboard' ORDER BY id", &[])
        .await.unwrap().iter().map(|row| row.get(0)).collect();
    assert_eq!(actions, ["dashboard.create", "dashboard.update", "dashboard.delete"]);
    let leaked: i64 = client
        .query_one("SELECT count(*) FROM audit_log WHERE detail::text LIKE '%widgets%'", &[])
        .await.unwrap().get(0);
    assert_eq!(leaked, 0, "the layout must not be copied into the audit log");
    db.drop().await;
}

#[tokio::test]
async fn stale_update_is_refused_and_keeps_the_first_save() {
    let (db, mut client) = setup().await;
    let created = dashboards::create(&mut client, ALICE, "A", &layout(), Utc::now()).await.unwrap().unwrap();
    dashboards::update(&mut client, ALICE, &created.dashboard_id, "First tab", &layout(), 1, Utc::now()).await.unwrap().unwrap();
    let second = dashboards::update(&mut client, ALICE, &created.dashboard_id, "Second tab", &layout(), 1, Utc::now()).await.unwrap();
    assert_eq!(second, Err(Refusal::Stale));
    assert_eq!(dashboards::get_visible(&client, ALICE, &created.dashboard_id).await.unwrap().unwrap().name, "First tab");
    db.drop().await;
}

#[tokio::test]
async fn others_see_only_what_is_shared_with_their_role_and_cannot_change_it() {
    let (db, mut client) = setup().await;
    let created = dashboards::create(&mut client, ALICE, "Team", &layout(), Utc::now()).await.unwrap().unwrap();
    assert!(dashboards::list_visible(&client, BOB).await.unwrap().is_empty());
    assert!(dashboards::get_visible(&client, BOB, &created.dashboard_id).await.unwrap().is_none());
    let shared = dashboards::set_sharing(&mut client, ALICE, &created.dashboard_id, Some("viewer"), Utc::now()).await.unwrap().unwrap();
    assert_eq!(shared.shared_role_id.as_deref(), Some("viewer"));
    assert_eq!(dashboards::list_visible(&client, BOB).await.unwrap().len(), 1);
    assert_eq!(
        dashboards::update(&mut client, BOB, &created.dashboard_id, "Mine now", &layout(), shared.version, Utc::now()).await.unwrap(),
        Err(Refusal::NotOwner)
    );
    assert_eq!(dashboards::delete(&mut client, BOB, &created.dashboard_id).await.unwrap(), Err(Refusal::NotOwner));
    assert_eq!(
        dashboards::set_sharing(&mut client, ALICE, &created.dashboard_id, Some("no_such_role"), Utc::now()).await.unwrap(),
        Err(Refusal::UnknownRole)
    );
    assert_eq!(
        dashboards::update(&mut client, BOB, "not-a-uuid", "x", &layout(), 1, Utc::now()).await.unwrap(),
        Err(Refusal::NotFound)
    );
    db.drop().await;
}

#[tokio::test]
async fn scoped_binding_sees_shared_dashboard() {
    let (db, mut client) = setup().await;
    let group: String = client
        .query_one(
            "INSERT INTO console_asset_groups (asset_group_id, name, created_at, created_by)
             VALUES (gen_random_uuid(), 'Production', now(), 'test') RETURNING asset_group_id::text",
            &[],
        )
        .await.unwrap().get(0);
    create_user_role_binding(&mut client, BOB, "analyst", Some(&group), "test", Utc::now()).await.unwrap().unwrap();
    let created = dashboards::create(&mut client, ALICE, "Analysts", &layout(), Utc::now()).await.unwrap().unwrap();
    dashboards::set_sharing(&mut client, ALICE, &created.dashboard_id, Some("analyst"), Utc::now()).await.unwrap().unwrap();
    assert_eq!(dashboards::list_visible(&client, BOB).await.unwrap()[0].name, "Analysts");
    db.drop().await;
}

#[tokio::test]
async fn revoked_binding_hides_dashboard_and_home() {
    let (db, mut client) = setup().await;
    let binding = create_user_role_binding(&mut client, BOB, "analyst", None, "test", Utc::now()).await.unwrap().unwrap();
    let created = dashboards::create(&mut client, ALICE, "Analysts", &layout(), Utc::now()).await.unwrap().unwrap();
    dashboards::set_sharing(&mut client, ALICE, &created.dashboard_id, Some("analyst"), Utc::now()).await.unwrap().unwrap();
    assert_eq!(dashboards::set_home(&mut client, BOB, Some(&created.dashboard_id)).await.unwrap(), Ok(()));
    assert_eq!(dashboards::home(&client, BOB).await.unwrap(), Some(created.dashboard_id.clone()));
    revoke_user_role_binding(&mut client, &binding.binding_id, "test", Utc::now()).await.unwrap();
    assert!(dashboards::list_visible(&client, BOB).await.unwrap().is_empty());
    assert!(dashboards::get_visible(&client, BOB, &created.dashboard_id).await.unwrap().is_none());
    assert_eq!(dashboards::home(&client, BOB).await.unwrap(), None);
    db.drop().await;
}

#[tokio::test]
async fn home_is_cleared_with_its_dashboard_and_must_be_visible() {
    let (db, mut client) = setup().await;
    let created = dashboards::create(&mut client, ALICE, "Mine", &layout(), Utc::now()).await.unwrap().unwrap();
    assert_eq!(dashboards::set_home(&mut client, BOB, Some(&created.dashboard_id)).await.unwrap(), Err(Refusal::NotFound));
    dashboards::set_home(&mut client, ALICE, Some(&created.dashboard_id)).await.unwrap().unwrap();
    dashboards::delete(&mut client, ALICE, &created.dashboard_id).await.unwrap().unwrap();
    assert_eq!(dashboards::home(&client, ALICE).await.unwrap(), None);
    assert_eq!(dashboards::set_home(&mut client, ALICE, None).await.unwrap(), Ok(()));
    db.drop().await;
}

#[tokio::test]
async fn an_owner_may_keep_at_most_one_hundred_dashboards() {
    let (db, mut client) = setup().await;
    for index in 0..dashboards::MAX_DASHBOARDS_PER_OWNER {
        dashboards::create(&mut client, ALICE, &format!("D{index}"), &layout(), Utc::now()).await.unwrap().unwrap();
    }
    assert_eq!(
        dashboards::create(&mut client, ALICE, "One too many", &layout(), Utc::now()).await.unwrap(),
        Err(Refusal::TooMany)
    );
    db.drop().await;
}
```

(`revoke_user_role_binding` returns a `BindingRevocation`. If the test
fails to compile because `create_user_role_binding` returns a struct
without `binding_id`, read `BindingSummary` in `console_auth.rs`: the field
is `binding_id: String`.)

- [ ] **Step 2: Run the tests and watch them fail**

Run: `cargo test -q --locked -p platform-store --test console_dashboards 2>&1 | tail -3`
Expected: compile error, "unresolved import `platform_store::dashboards`".

- [ ] **Step 3: Implement the module**

`crates/platform-store/src/dashboards.rs`:

```rust
//! User dashboards: a named layout owned by one console user, optionally
//! shared with a role. Only layouts are stored; widgets read their data
//! through the permission-checked console API. Every change and its audit
//! row commit together; the layout is never copied into the audit log.

use chrono::{DateTime, Utc};
use tokio_postgres::Row;

use crate::{Client, StoreError};

/// Most dashboards one user may own.
pub const MAX_DASHBOARDS_PER_OWNER: i64 = 100;

/// One stored dashboard as seen by a viewer.
#[derive(Clone, Debug, PartialEq)]
pub struct Dashboard {
    /// Stable UUID.
    pub dashboard_id: String,
    /// Owning console user.
    pub owner_user_id: String,
    /// Owner's display name, for "shared by".
    pub owner_display_name: String,
    /// 1–80 characters.
    pub name: String,
    /// Validated layout document (see the console's layout validation).
    pub layout: serde_json::Value,
    /// Role whose holders may view the dashboard.
    pub shared_role_id: Option<String>,
    /// Version for conditional updates.
    pub version: i64,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Last change.
    pub updated_at: DateTime<Utc>,
}

/// Why a change was refused (not a database failure).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// No such dashboard, or not visible to the caller.
    NotFound,
    /// Visible but owned by someone else.
    NotOwner,
    /// `expected_version` is not the current version.
    Stale,
    /// The owner already has [`MAX_DASHBOARDS_PER_OWNER`].
    TooMany,
    /// The role to share with does not exist.
    UnknownRole,
}

const COLUMNS: &str = "d.dashboard_id::text, d.owner_user_id::text, u.display_name, d.name, d.layout,
    d.shared_role_id, d.version::bigint, d.created_at, d.updated_at";

/// Visible to `$1`: owned, or shared with a role of one of `$1`'s live bindings.
const VISIBLE: &str = "(d.owner_user_id::text = $1 OR d.shared_role_id IN (
    SELECT b.role_id FROM console_role_bindings b
    WHERE b.user_id::text = $1 AND b.revoked_at IS NULL))";

fn dashboard(row: &Row) -> Dashboard {
    Dashboard {
        dashboard_id: row.get(0),
        owner_user_id: row.get(1),
        owner_display_name: row.get(2),
        name: row.get(3),
        layout: row.get(4),
        shared_role_id: row.get(5),
        version: row.get(6),
        created_at: row.get(7),
        updated_at: row.get(8),
    }
}

/// Own dashboards first, then shared ones; each group by name.
pub async fn list_visible(client: &Client, user_id: &str) -> Result<Vec<Dashboard>, StoreError> {
    let rows = client
        .query(
            &format!(
                "SELECT {COLUMNS} FROM console_dashboards d
                 JOIN console_users u ON u.user_id = d.owner_user_id
                 WHERE {VISIBLE}
                 ORDER BY d.owner_user_id::text <> $1, lower(d.name), d.dashboard_id"
            ),
            &[&user_id],
        )
        .await?;
    Ok(rows.iter().map(dashboard).collect())
}

/// One dashboard if the user may see it. Ids are compared as text, so a
/// malformed id is simply not found.
pub async fn get_visible(
    client: &Client,
    user_id: &str,
    dashboard_id: &str,
) -> Result<Option<Dashboard>, StoreError> {
    let row = client
        .query_opt(
            &format!(
                "SELECT {COLUMNS} FROM console_dashboards d
                 JOIN console_users u ON u.user_id = d.owner_user_id
                 WHERE d.dashboard_id::text = $2 AND {VISIBLE}"
            ),
            &[&user_id, &dashboard_id],
        )
        .await?;
    Ok(row.as_ref().map(dashboard))
}

async fn audit(
    tx: &tokio_postgres::Transaction<'_>,
    user_id: &str,
    action: &str,
    dashboard_id: &str,
    detail: serde_json::Value,
) -> Result<(), StoreError> {
    tx.execute(
        "INSERT INTO audit_log (actor, action, target, result, detail,
             actor_kind, actor_id, actor_display, target_kind, target_id)
         SELECT $1, $2, $3, 'success', $4, 'user', $1, u.display_name, 'dashboard', $3
         FROM console_users u WHERE u.user_id::text = $1",
        &[&user_id, &action, &dashboard_id, &detail],
    )
    .await?;
    Ok(())
}

/// Locks the dashboard row and says whether `user_id` owns it; `None`
/// when it is not visible to them.
async fn lock_owned(
    tx: &tokio_postgres::Transaction<'_>,
    user_id: &str,
    dashboard_id: &str,
) -> Result<Option<(bool, i64)>, StoreError> {
    let row = tx
        .query_opt(
            &format!(
                "SELECT d.owner_user_id::text = $1, d.version::bigint FROM console_dashboards d
                 WHERE d.dashboard_id::text = $2 AND {VISIBLE} FOR UPDATE OF d"
            ),
            &[&user_id, &dashboard_id],
        )
        .await?;
    Ok(row.map(|row| (row.get(0), row.get(1))))
}

async fn reread(tx: &tokio_postgres::Transaction<'_>, dashboard_id: &str) -> Result<Dashboard, StoreError> {
    let row = tx
        .query_one(
            &format!(
                "SELECT {COLUMNS} FROM console_dashboards d
                 JOIN console_users u ON u.user_id = d.owner_user_id
                 WHERE d.dashboard_id::text = $1"
            ),
            &[&dashboard_id],
        )
        .await?;
    Ok(dashboard(&row))
}

/// Creates a dashboard owned by `user_id` (at most 100 per owner).
pub async fn create(
    client: &mut Client,
    user_id: &str,
    name: &str,
    layout: &serde_json::Value,
    now: DateTime<Utc>,
) -> Result<Result<Dashboard, Refusal>, StoreError> {
    let tx = client.transaction().await?;
    // Serialises concurrent creates by one owner so the limit holds.
    tx.execute("SELECT 1 FROM console_users WHERE user_id::text = $1 FOR UPDATE", &[&user_id])
        .await?;
    let owned: i64 = tx
        .query_one("SELECT count(*) FROM console_dashboards WHERE owner_user_id::text = $1", &[&user_id])
        .await?
        .get(0);
    if owned >= MAX_DASHBOARDS_PER_OWNER {
        tx.rollback().await?;
        return Ok(Err(Refusal::TooMany));
    }
    let id: String = tx
        .query_one(
            "INSERT INTO console_dashboards
                 (dashboard_id, owner_user_id, name, layout, created_at, updated_at)
             VALUES (gen_random_uuid(), $1::text::uuid, $2, $3, $4, $4)
             RETURNING dashboard_id::text",
            &[&user_id, &name, layout, &now],
        )
        .await?
        .get(0);
    audit(&tx, user_id, "dashboard.create", &id, serde_json::json!({ "name": name })).await?;
    let created = reread(&tx, &id).await?;
    tx.commit().await?;
    Ok(Ok(created))
}

/// Replaces name and layout if `user_id` owns it and the version matches.
pub async fn update(
    client: &mut Client,
    user_id: &str,
    dashboard_id: &str,
    name: &str,
    layout: &serde_json::Value,
    expected_version: i64,
    now: DateTime<Utc>,
) -> Result<Result<Dashboard, Refusal>, StoreError> {
    let tx = client.transaction().await?;
    let refusal = match lock_owned(&tx, user_id, dashboard_id).await? {
        None => Some(Refusal::NotFound),
        Some((false, _)) => Some(Refusal::NotOwner),
        Some((true, version)) if version != expected_version => Some(Refusal::Stale),
        Some(_) => None,
    };
    if let Some(refusal) = refusal {
        tx.rollback().await?;
        return Ok(Err(refusal));
    }
    tx.execute(
        "UPDATE console_dashboards SET name = $2, layout = $3, version = version + 1, updated_at = $4
         WHERE dashboard_id::text = $1",
        &[&dashboard_id, &name, layout, &now],
    )
    .await?;
    audit(&tx, user_id, "dashboard.update", dashboard_id, serde_json::json!({ "name": name })).await?;
    let updated = reread(&tx, dashboard_id).await?;
    tx.commit().await?;
    Ok(Ok(updated))
}

/// Deletes an owned dashboard (homes pointing at it are removed by cascade).
pub async fn delete(
    client: &mut Client,
    user_id: &str,
    dashboard_id: &str,
) -> Result<Result<(), Refusal>, StoreError> {
    let tx = client.transaction().await?;
    match lock_owned(&tx, user_id, dashboard_id).await? {
        None => {
            tx.rollback().await?;
            return Ok(Err(Refusal::NotFound));
        }
        Some((false, _)) => {
            tx.rollback().await?;
            return Ok(Err(Refusal::NotOwner));
        }
        Some(_) => {}
    }
    tx.execute("DELETE FROM console_dashboards WHERE dashboard_id::text = $1", &[&dashboard_id])
        .await?;
    audit(&tx, user_id, "dashboard.delete", dashboard_id, serde_json::json!({})).await?;
    tx.commit().await?;
    Ok(Ok(()))
}

/// Shares an owned dashboard with `role_id`, or stops sharing (`None`).
/// The caller checks `dashboards.share` first.
pub async fn set_sharing(
    client: &mut Client,
    user_id: &str,
    dashboard_id: &str,
    role_id: Option<&str>,
    now: DateTime<Utc>,
) -> Result<Result<Dashboard, Refusal>, StoreError> {
    let tx = client.transaction().await?;
    let previous = match lock_owned(&tx, user_id, dashboard_id).await? {
        None => Some(Refusal::NotFound),
        Some((false, _)) => Some(Refusal::NotOwner),
        Some(_) => None,
    };
    if let Some(refusal) = previous {
        tx.rollback().await?;
        return Ok(Err(refusal));
    }
    if let Some(role_id) = role_id {
        let known = tx
            .query_opt("SELECT 1 FROM console_roles WHERE role_id = $1", &[&role_id])
            .await?
            .is_some();
        if !known {
            tx.rollback().await?;
            return Ok(Err(Refusal::UnknownRole));
        }
    }
    let old: Option<String> = tx
        .query_one("SELECT shared_role_id FROM console_dashboards WHERE dashboard_id::text = $1", &[&dashboard_id])
        .await?
        .get(0);
    tx.execute(
        "UPDATE console_dashboards SET shared_role_id = $2, version = version + 1, updated_at = $3
         WHERE dashboard_id::text = $1",
        &[&dashboard_id, &role_id, &now],
    )
    .await?;
    audit(&tx, user_id, "dashboard.share", dashboard_id, serde_json::json!({ "from": old, "to": role_id })).await?;
    let shared = reread(&tx, dashboard_id).await?;
    tx.commit().await?;
    Ok(Ok(shared))
}

/// The user's home dashboard if it is set and still visible to them.
pub async fn home(client: &Client, user_id: &str) -> Result<Option<String>, StoreError> {
    let row = client
        .query_opt(
            &format!(
                "SELECT d.dashboard_id::text FROM console_user_home h
                 JOIN console_dashboards d ON d.dashboard_id = h.dashboard_id
                 WHERE h.user_id::text = $1 AND {VISIBLE}"
            ),
            &[&user_id],
        )
        .await?;
    Ok(row.map(|row| row.get(0)))
}

/// Sets (or clears, with `None`) the home dashboard; it must be visible.
pub async fn set_home(
    client: &mut Client,
    user_id: &str,
    dashboard_id: Option<&str>,
) -> Result<Result<(), Refusal>, StoreError> {
    let tx = client.transaction().await?;
    match dashboard_id {
        None => {
            tx.execute("DELETE FROM console_user_home WHERE user_id::text = $1", &[&user_id]).await?;
        }
        Some(dashboard_id) => {
            if lock_owned(&tx, user_id, dashboard_id).await?.is_none() {
                tx.rollback().await?;
                return Ok(Err(Refusal::NotFound));
            }
            tx.execute(
                "INSERT INTO console_user_home (user_id, dashboard_id)
                 VALUES ($1::text::uuid, $2::text::uuid)
                 ON CONFLICT (user_id) DO UPDATE SET dashboard_id = EXCLUDED.dashboard_id",
                &[&user_id, &dashboard_id],
            )
            .await?;
        }
    }
    audit(&tx, user_id, "dashboard.home", dashboard_id.unwrap_or("builtin:overview"), serde_json::json!({})).await?;
    tx.commit().await?;
    Ok(Ok(()))
}
```

Add `pub mod dashboards;` to `crates/platform-store/src/lib.rs`, next to
`pub mod audit;`. If `tokio_postgres::Row` or `Transaction` aren't
reachable under those paths, use the aliases the crate already
re-exports: look at `console_auth.rs`'s `use` lines.

- [ ] **Step 4: Run the tests and watch them pass**

Run: `cargo test -q --locked -p platform-store --test console_dashboards 2>&1 | grep -E "test result|FAILED|panicked"`
Expected: `test result: ok. 7 passed`.

- [ ] **Step 5: Add a Store docs section and commit**

In `docs/components/platform-store.md`, add a `### Dashboards
(\`dashboards\`)` section. It describes the functions from the
Interfaces block, the visibility rule, the 100-per-owner limit, the
`Refusal` values, and that audit rows carry the name but never the
layout.

```bash
git add crates/platform-store/src/dashboards.rs crates/platform-store/src/lib.rs crates/platform-store/tests/console_dashboards.rs docs/components/platform-store.md
git commit -m "Store: dashboards (ownership, sharing by role, versions, home, audit)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 3: Layout validation and API types

**Files:**
- Create: `crates/openvibes-console/src/dashboards.rs` (validation now; handlers in Task 4)
- Modify: `crates/openvibes-console/src/lib.rs` (`mod dashboards;`, re-export the new API types)
- Modify: `crates/openvibes-console/src/api.rs` (new types)

**Interfaces:**
- Produces (crate-internal, in `crate::dashboards`):
  - `pub(crate) const WIDGET_TYPES: [&str; 7] = ["number", "breakdown", "attention", "list", "trend", "top-hosts", "note"];`
  - `pub(crate) fn validate_name(raw: &str) -> Result<String, FieldError>`: returns the trimmed name
  - `pub(crate) fn validate_layout(layout: &serde_json::Value) -> Result<(), Vec<FieldError>>`: at most 32 errors; field paths such as `layout`, `layout.widgets`, `layout.widgets[3].type`
- Produces (public API types in `api.rs`, all `Serialize`/`ToSchema`; requests `Deserialize` with `deny_unknown_fields`):
  - `DashboardView { dashboard_id: String, name: String, owner_display_name: String, mine: bool, shared_role_id: Option<String>, version: u64, layout: serde_json::Value (#[schema(value_type = Object)]), created_at: String, updated_at: String }`
  - `DashboardPage { items: Vec<DashboardView> }`
  - `SaveDashboardRequest { name: String, layout: serde_json::Value (#[schema(value_type = Object)]) }`
  - `ShareDashboardRequest { role_id: Option<String> }`
  - `HomeDashboard { dashboard_id: Option<String> }` (both request and response)

- [ ] **Step 1: Write the failing unit tests**

At the bottom of the new `crates/openvibes-console/src/dashboards.rs`:

```rust
#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{validate_layout, validate_name};

    fn widget(id: &str, kind: &str, x: i64, w: i64) -> serde_json::Value {
        json!({"id": id, "type": kind, "x": x, "y": 0, "w": w, "h": 2, "config": {"metric": "agents.active"}})
    }

    fn fields(layout: serde_json::Value) -> Vec<String> {
        validate_layout(&layout).unwrap_err().into_iter().map(|error| error.field).collect()
    }

    #[test]
    fn a_small_valid_layout_passes() {
        assert!(validate_layout(&json!({"schema": 1, "widgets": [widget("w1", "number", 0, 3), widget("w2", "note", 3, 9)]})).is_ok());
        assert!(validate_layout(&json!({"schema": 1, "widgets": []})).is_ok());
    }

    #[test]
    fn layout_must_be_an_object() {
        assert_eq!(fields(json!([1, 2])), ["layout"]);
        assert_eq!(fields(json!(7)), ["layout"]);
    }

    #[test]
    fn schema_widget_count_and_size_are_bounded() {
        assert_eq!(fields(json!({"schema": 2, "widgets": []})), ["layout.schema"]);
        let many: Vec<_> = (0..41).map(|i| widget(&format!("w{i}"), "number", 0, 1)).collect();
        assert_eq!(fields(json!({"schema": 1, "widgets": many})), ["layout.widgets"]);
        let long = "x".repeat(256);
        let heavy: Vec<_> = (0..40).map(|i| json!({"id": format!("w{i}"), "type": "note", "x": 0, "y": 0, "w": 1, "h": 1,
            "config": {"text": vec![long.clone(); 7]}})).collect();
        assert_eq!(fields(json!({"schema": 1, "widgets": heavy})), ["layout"]);
    }

    #[test]
    fn each_widget_is_checked_with_a_precise_path() {
        let layout = json!({"schema": 1, "widgets": [
            widget("w1", "pie-chart", 0, 3),
            widget("w1", "number", 10, 3),
            widget("Bad Id", "number", 0, 13),
            {"id": "w4", "type": "number", "x": 0, "y": 200, "w": 1, "h": 13, "config": {}},
            {"id": "w5", "type": "number", "x": 0, "y": 0, "w": 1, "h": 1, "config": {"nested": {"a": 1}}},
        ]});
        assert_eq!(fields(layout), [
            "layout.widgets[0].type",
            "layout.widgets[1].id", "layout.widgets[1].x",
            "layout.widgets[2].id", "layout.widgets[2].w",
            "layout.widgets[3].y", "layout.widgets[3].h",
            "layout.widgets[4].config.nested",
        ]);
    }

    #[test]
    fn names_are_trimmed_and_bounded() {
        assert_eq!(validate_name("  Morning  ").unwrap(), "Morning");
        assert!(validate_name("   ").is_err());
        assert!(validate_name(&"n".repeat(81)).is_err());
        assert!(validate_name("tab\there").is_err());
        assert_eq!(validate_name(&"é".repeat(80)).unwrap().chars().count(), 80);
    }
}
```

- [ ] **Step 2: Run the tests and watch them fail**

Add `mod dashboards;` to `lib.rs` so the module compiles into the crate.
Run: `cargo test -q --locked -p openvibes-console --lib dashboards 2>&1 | tail -3`
Expected: compile error, "cannot find function `validate_layout`".

- [ ] **Step 3: Implement validation**

At the top of `crates/openvibes-console/src/dashboards.rs`:

```rust
//! Dashboards over `/api/v1`: layout validation (here) and the HTTP
//! handlers. A layout is data the UI renders; the server keeps it bounded
//! and well-formed, and forward-compatible through an allow-list of types.

use serde_json::Value;

use crate::FieldError;

pub(crate) const WIDGET_TYPES: [&str; 7] = ["number", "breakdown", "attention", "list", "trend", "top-hosts", "note"];
const MAX_LAYOUT_BYTES: usize = 65_536;
const MAX_WIDGETS: usize = 40;
const MAX_ERRORS: usize = 32;

fn error(field: String, code: &str, message: &str) -> FieldError {
    FieldError { field, code: code.to_owned(), message: message.to_owned() }
}

pub(crate) fn validate_name(raw: &str) -> Result<String, FieldError> {
    let name = raw.trim();
    let count = name.chars().count();
    if count == 0 || count > 80 || name.chars().any(char::is_control) {
        return Err(error("name".into(), "invalid_name", "Use 1 to 80 characters, without control characters"));
    }
    Ok(name.to_owned())
}

fn int(value: Option<&Value>) -> Option<i64> {
    value.and_then(Value::as_i64)
}

fn valid_config_value(value: &Value) -> bool {
    match value {
        Value::String(text) => text.chars().count() <= 256,
        Value::Bool(_) => true,
        Value::Number(number) => number.is_i64(),
        Value::Array(items) => items.len() <= 16 && items.iter().all(|item| item.as_str().is_some_and(|text| text.chars().count() <= 256)),
        _ => false,
    }
}

pub(crate) fn validate_layout(layout: &Value) -> Result<(), Vec<FieldError>> {
    let Some(object) = layout.as_object() else {
        return Err(vec![error("layout".into(), "invalid_layout", "The layout must be an object")]);
    };
    if serde_json::to_vec(layout).map_or(true, |bytes| bytes.len() > MAX_LAYOUT_BYTES) {
        return Err(vec![error("layout".into(), "layout_too_large", "The layout exceeds 64 KiB")]);
    }
    let mut errors = Vec::new();
    if object.get("schema").and_then(Value::as_i64) != Some(1) {
        errors.push(error("layout.schema".into(), "unsupported_schema", "Layout schema must be 1"));
    }
    let Some(widgets) = object.get("widgets").and_then(Value::as_array) else {
        errors.push(error("layout.widgets".into(), "invalid_widgets", "widgets must be an array"));
        return Err(errors);
    };
    if widgets.len() > MAX_WIDGETS {
        errors.push(error("layout.widgets".into(), "too_many_widgets", "A dashboard holds at most 40 widgets"));
        return Err(errors);
    }
    let mut seen = std::collections::HashSet::new();
    for (index, widget) in widgets.iter().enumerate() {
        let at = |field: &str| format!("layout.widgets[{index}].{field}");
        let Some(widget) = widget.as_object() else {
            errors.push(error(format!("layout.widgets[{index}]"), "invalid_widget", "A widget must be an object"));
            continue;
        };
        let kind = widget.get("type").and_then(Value::as_str);
        if !kind.is_some_and(|kind| WIDGET_TYPES.contains(&kind)) {
            errors.push(error(at("type"), "unknown_widget_type", "Unknown widget type"));
        }
        let id = widget.get("id").and_then(Value::as_str).unwrap_or_default();
        let id_ok = (1..=32).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !id_ok || !seen.insert(id.to_owned()) {
            errors.push(error(at("id"), "invalid_widget_id", "Widget ids are 1-32 of a-z, 0-9 and -, unique"));
        }
        let (x, y, w, h) = (int(widget.get("x")), int(widget.get("y")), int(widget.get("w")), int(widget.get("h")));
        let w_ok = w.is_some_and(|w| (1..=12).contains(&w));
        if !x.is_some_and(|x| (0..=11).contains(&x)) || (w_ok && x.zip(w).is_some_and(|(x, w)| x + w > 12)) {
            errors.push(error(at("x"), "invalid_position", "x must be 0-11 and x + w at most 12"));
        }
        if !w_ok {
            errors.push(error(at("w"), "invalid_size", "w must be 1-12"));
        }
        if !y.is_some_and(|y| (0..=199).contains(&y)) {
            errors.push(error(at("y"), "invalid_position", "y must be 0-199"));
        }
        if !h.is_some_and(|h| (1..=12).contains(&h)) {
            errors.push(error(at("h"), "invalid_size", "h must be 1-12"));
        }
        match widget.get("config").and_then(Value::as_object) {
            None => errors.push(error(at("config"), "invalid_config", "config must be an object")),
            Some(config) if config.len() > 16 => errors.push(error(at("config"), "invalid_config", "config holds at most 16 keys")),
            Some(config) => {
                for (key, value) in config {
                    if key.len() > 32 || !valid_config_value(value) {
                        errors.push(error(at(&format!("config.{key}")), "invalid_config", "Config values are short strings, integers, booleans or string lists"));
                    }
                }
            }
        }
    }
    errors.truncate(MAX_ERRORS);
    if errors.is_empty() { Ok(()) } else { Err(errors) }
}
```

(`FieldError` fields are `pub`, and the struct is built directly because
`problem.rs` has no constructor for it. In the "x + w > 12" test widget
`w1` at x = 10 with w = 3, only `x` is flagged, because `w` alone is
valid.)

- [ ] **Step 4: Run the tests and watch them pass**

Run: `cargo test -q --locked -p openvibes-console --lib dashboards 2>&1 | grep -E "test result|panicked"`
Expected: `test result: ok. 5 passed`.

- [ ] **Step 5: Add the API types**

In `crates/openvibes-console/src/api.rs`, after `UpdateAuditRetentionRequest`:

```rust
/// One dashboard as the viewer sees it.
#[derive(Clone, Debug, PartialEq, Serialize, ToSchema)]
pub struct DashboardView {
    /// Stable UUID.
    pub dashboard_id: String,
    /// 1–80 characters.
    pub name: String,
    /// Display name of the owner.
    pub owner_display_name: String,
    /// Whether the viewer owns it (only owners may change it).
    pub mine: bool,
    /// Role it is shared with, if any.
    pub shared_role_id: Option<String>,
    /// Version for `If-Match`.
    pub version: u64,
    /// Layout: `{ "schema": 1, "widgets": [...] }`.
    #[schema(value_type = Object)]
    pub layout: serde_json::Value,
    /// RFC 3339 creation time.
    pub created_at: String,
    /// RFC 3339 last change.
    pub updated_at: String,
}

/// Dashboards visible to the viewer: own first, then shared.
#[derive(Clone, Debug, PartialEq, Serialize, ToSchema)]
pub struct DashboardPage {
    /// At most 100 own dashboards plus those shared with the viewer's roles.
    pub items: Vec<DashboardView>,
}

/// Create or replace a dashboard's name and layout.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SaveDashboardRequest {
    /// 1–80 characters.
    pub name: String,
    /// Layout document (validated; at most 64 KiB and 40 widgets).
    #[schema(value_type = Object)]
    pub layout: serde_json::Value,
}

/// Share with a role, or stop sharing with `null`.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ShareDashboardRequest {
    /// Built-in role id, or `null`.
    pub role_id: Option<String>,
}

/// The dashboard that opens first; `null` is the built-in Overview.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct HomeDashboard {
    /// Visible dashboard id, or `null`.
    pub dashboard_id: Option<String>,
}
```

Add `DashboardPage, DashboardView, HomeDashboard, SaveDashboardRequest,
ShareDashboardRequest` to the `pub use api::{...}` list in `lib.rs`, in
alphabetical order.

- [ ] **Step 6: Build, lint and commit**

Run: `cargo clippy --locked -p openvibes-console --all-targets --all-features -- -D warnings -F unsafe-code 2>&1 | tail -3`
Expected: no warnings. Dead-code warnings for types not used until
Task 4 are the one exception: if clippy flags them, put
`#[allow(dead_code, reason = "used by the handlers in the next commit")]`
on the module in `lib.rs` for this commit and remove it in Task 4.

```bash
git add crates/openvibes-console/src/dashboards.rs crates/openvibes-console/src/lib.rs crates/openvibes-console/src/api.rs
git commit -m "Console: dashboard layout validation and API types

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 4: Handlers, routes, OpenAPI and the generated client

**Files:**
- Modify: `crates/openvibes-console/src/router.rs`:
  - extract `session_user` from `authenticated_permission`;
  - make `problem_response`, `authentication_required`, `unavailable_auth` and `parse_if_match_version` `pub(crate)`;
  - register the routes in `authenticated_api_router`.
- Modify: `crates/openvibes-console/src/dashboards.rs` (handlers)
- Modify: `crates/openvibes-console/src/openapi.rs` (paths, schemas)
- Regenerate: `docs/api/console-v1.openapi.json`, `crates/openvibes-console/web/src/api/generated.ts`
- Test: `crates/openvibes-console/tests/dashboards_http.rs`
- Create: `docs/components/console-dashboards.md`
- Modify: `docs/components/README.md`, `docs/components/openvibes-console.md` (route list)

**Interfaces:**
- Consumes: `platform_store::dashboards::*` (Task 2); `validate_name`, `validate_layout`, the API types (Task 3).
- Produces:
  - `pub(crate) struct SessionUser { pub(crate) user_id: String, pub(crate) capabilities: Vec<crate::EffectiveCapability> }`
  - `pub(crate) async fn session_user(state: &AuthHttpState, headers: &HeaderMap, csrf_required: bool) -> Result<SessionUser, Response>`: a bearer token is 403, no credentials 401
  - the handlers `list_dashboards`, `create_dashboard`, `get_dashboard`, `update_dashboard`, `delete_dashboard`, `share_dashboard`, `get_home`, `set_home` (all `pub(crate)`, in `crate::dashboards`)

- [ ] **Step 1: Write the failing HTTP tests**

`crates/openvibes-console/tests/dashboards_http.rs`. It copies
`auth_http.rs`'s `TestDb`, `database_url`, `cookie_pair` and `new_preauth`
unchanged (lines 72–162 of `auth_http.rs`; copy them verbatim). Then:

```rust
//! Dashboards over HTTP: auth, ownership, sharing, versions, validation, audit.

use std::{hash::{BuildHasher, Hasher}, net::SocketAddr};

use axum::{body::{Body, to_bytes}, extract::ConnectInfo, http::{Request, StatusCode, header}};
use chrono::Utc;
use openvibes_console::{NormalizedPassword, TrustedPeer, authenticated_router, hash_password};
use platform_store::console_auth::{NewLocalUser, create_local_user};
use serde_json::{Value, json};
use tower::ServiceExt;

// (TestDb, database_url, cookie_pair, new_preauth copied from auth_http.rs)

const PASSWORD: &str = "violet-satellite-mountain-otter-2026";

async fn user(client: &mut platform_store::Client, id: &str, binding: &str, name: &str, role: &str) {
    let phc = hash_password(&NormalizedPassword::new(PASSWORD).unwrap()).unwrap();
    create_local_user(client, &NewLocalUser {
        user_id: id, binding_id: binding, username: name, display_name: name,
        password_phc: phc.as_str(), role_id: role, actor_id: "test", now: Utc::now(),
    }).await.unwrap();
}

/// Signs in and returns (session cookie, CSRF token).
async fn login(router: &axum::Router, username: &str) -> (String, String) {
    let (preauth, browser, csrf) = new_preauth(router).await;
    let response = router.clone().oneshot(
        Request::builder().method("POST").uri("/auth/v1/login")
            .header(header::ORIGIN, "https://console.example").header("sec-fetch-site", "same-origin")
            .header("x-csrf-token", csrf).header(header::COOKIE, format!("{preauth}; {browser}"))
            .header(header::CONTENT_TYPE, "application/json")
            .extension(ConnectInfo(TrustedPeer::new("127.0.0.1:4242".parse::<SocketAddr>().unwrap())))
            .body(Body::from(format!("{{\"username\":\"{username}\",\"password\":\"{PASSWORD}\"}}"))).unwrap(),
    ).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = cookie_pair(&response, "__Host-openvibes-session=");
    let session = call(router, "GET", "/api/v1/session", &cookie, "", None, None).await;
    (cookie, session.1["csrf_token"].as_str().unwrap().to_owned())
}

/// One request; returns (status, JSON body or Null, ETag).
async fn call(router: &axum::Router, method: &str, uri: &str, cookie: &str, csrf: &str, body: Option<Value>, if_match: Option<&str>)
    -> (StatusCode, Value, Option<String>) {
    let mut request = Request::builder().method(method).uri(uri).header(header::COOKIE, cookie)
        .header(header::ORIGIN, "https://console.example").header("sec-fetch-site", "same-origin")
        .header("x-csrf-token", csrf).header(header::CONTENT_TYPE, "application/json");
    if let Some(version) = if_match { request = request.header(header::IF_MATCH, version); }
    let response = router.clone().oneshot(request.body(Body::from(body.map(|b| b.to_string()).unwrap_or_default())).unwrap()).await.unwrap();
    let status = response.status();
    let etag = response.headers().get(header::ETAG).map(|v| v.to_str().unwrap().to_owned());
    let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null), etag)
}

fn layout() -> Value {
    json!({"schema": 1, "widgets": [{"id": "w1", "type": "number", "x": 0, "y": 0, "w": 3, "h": 2, "config": {"metric": "agents.active"}}]})
}

async fn setup() -> (TestDb, axum::Router) {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    user(&mut client, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", "alice", "admin").await;
    user(&mut client, "33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444", "bob", "analyst").await;
    drop(client);
    let router = authenticated_router(db.pool.clone(), "https://console.example");
    (db, router)
}

#[tokio::test]
async fn owner_lifecycle_with_etags_and_preconditions() {
    let (db, router) = setup().await;
    assert_eq!(call(&router, "GET", "/api/v1/dashboards", "", "", None, None).await.0, StatusCode::UNAUTHORIZED);
    let (cookie, csrf) = login(&router, "alice").await;
    let (status, created, etag) = call(&router, "POST", "/api/v1/dashboards", &cookie, &csrf, Some(json!({"name": " Morning ", "layout": layout()})), None).await;
    assert_eq!((status, created["name"].as_str(), etag.as_deref()), (StatusCode::CREATED, Some("Morning"), Some("\"1\"")));
    let uri = format!("/api/v1/dashboards/{}", created["dashboard_id"].as_str().unwrap());
    let (_, page, _) = call(&router, "GET", "/api/v1/dashboards", &cookie, "", None, None).await;
    assert_eq!(page["items"][0]["mine"], true);
    let body = json!({"name": "Morning check", "layout": layout()});
    assert_eq!(call(&router, "PUT", &uri, &cookie, &csrf, Some(body.clone()), None).await.0, StatusCode::PRECONDITION_REQUIRED);
    let (status, updated, etag) = call(&router, "PUT", &uri, &cookie, &csrf, Some(body.clone()), Some("\"1\"")).await;
    assert_eq!((status, updated["version"].as_u64(), etag.as_deref()), (StatusCode::OK, Some(2), Some("\"2\"")));
    assert_eq!(call(&router, "PUT", &uri, &cookie, &csrf, Some(body), Some("\"1\"")).await.0, StatusCode::PRECONDITION_FAILED);
    assert_eq!(call(&router, "DELETE", &uri, &cookie, &csrf, None, None).await.0, StatusCode::NO_CONTENT);
    assert_eq!(call(&router, "GET", &uri, &cookie, "", None, None).await.0, StatusCode::NOT_FOUND);
    db.drop().await;
}

#[tokio::test]
async fn malformed_id_is_not_found() {
    let (db, router) = setup().await;
    let (cookie, _) = login(&router, "alice").await;
    assert_eq!(call(&router, "GET", "/api/v1/dashboards/not-a-uuid", &cookie, "", None, None).await.0, StatusCode::NOT_FOUND);
    db.drop().await;
}

#[tokio::test]
async fn invalid_layouts_are_refused_with_field_errors() {
    let (db, router) = setup().await;
    let (cookie, csrf) = login(&router, "alice").await;
    let bad = json!({"name": "X", "layout": {"schema": 1, "widgets": [{"id": "w1", "type": "pie-chart", "x": 0, "y": 0, "w": 3, "h": 2, "config": {}}]}});
    let (status, problem, _) = call(&router, "POST", "/api/v1/dashboards", &cookie, &csrf, Some(bad), None).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(problem["field_errors"][0]["field"], "layout.widgets[0].type");
    assert_eq!(call(&router, "POST", "/api/v1/dashboards", &cookie, &csrf, Some(json!({"name": "", "layout": layout()})), None).await.0, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(call(&router, "POST", "/api/v1/dashboards", &cookie, &csrf, Some(json!({"name": "X", "layout": [1]})), None).await.0, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(call(&router, "POST", "/api/v1/dashboards", &cookie, &csrf, Some(json!({"name": "X"})), None).await.0, StatusCode::BAD_REQUEST);
    db.drop().await;
}

#[tokio::test]
async fn sharing_needs_the_permission_and_shows_read_only_to_the_role() {
    let (db, router) = setup().await;
    let (alice, alice_csrf) = login(&router, "alice").await;
    let (bob, bob_csrf) = login(&router, "bob").await;
    let (_, own, _) = call(&router, "POST", "/api/v1/dashboards", &bob, &bob_csrf, Some(json!({"name": "Bob's", "layout": layout()})), None).await;
    let bob_uri = format!("/api/v1/dashboards/{}/sharing", own["dashboard_id"].as_str().unwrap());
    assert_eq!(call(&router, "PUT", &bob_uri, &bob, &bob_csrf, Some(json!({"role_id": "viewer"})), None).await.0, StatusCode::FORBIDDEN);
    let (_, team, _) = call(&router, "POST", "/api/v1/dashboards", &alice, &alice_csrf, Some(json!({"name": "Team", "layout": layout()})), None).await;
    let id = team["dashboard_id"].as_str().unwrap().to_owned();
    let uri = format!("/api/v1/dashboards/{id}");
    assert_eq!(call(&router, "GET", &uri, &bob, "", None, None).await.0, StatusCode::NOT_FOUND);
    assert_eq!(call(&router, "PUT", &format!("{uri}/sharing"), &alice, &alice_csrf, Some(json!({"role_id": "no_such"})), None).await.0, StatusCode::UNPROCESSABLE_ENTITY);
    let (status, shared, _) = call(&router, "PUT", &format!("{uri}/sharing"), &alice, &alice_csrf, Some(json!({"role_id": "analyst"})), None).await;
    assert_eq!((status, shared["shared_role_id"].as_str()), (StatusCode::OK, Some("analyst")));
    let (_, seen, _) = call(&router, "GET", &uri, &bob, "", None, None).await;
    assert_eq!((seen["mine"].as_bool(), seen["owner_display_name"].as_str()), (Some(false), Some("alice")));
    assert_eq!(call(&router, "PUT", &uri, &bob, &bob_csrf, Some(json!({"name": "x", "layout": layout()})), Some("\"2\"")).await.0, StatusCode::FORBIDDEN);
    assert_eq!(call(&router, "PUT", "/api/v1/me/home", &bob, &bob_csrf, Some(json!({"dashboard_id": id})), None).await.0, StatusCode::OK);
    assert_eq!(call(&router, "GET", "/api/v1/me/home", &bob, "", None, None).await.1["dashboard_id"], id.as_str());
    call(&router, "PUT", &format!("{uri}/sharing"), &alice, &alice_csrf, Some(json!({"role_id": null})), None).await;
    assert_eq!(call(&router, "GET", &uri, &bob, "", None, None).await.0, StatusCode::NOT_FOUND);
    assert_eq!(call(&router, "GET", "/api/v1/me/home", &bob, "", None, None).await.1["dashboard_id"], Value::Null);
    db.drop().await;
}

#[tokio::test]
async fn bearer_tokens_are_refused_and_changes_are_audited() {
    let (db, router) = setup().await;
    let response = router.clone().oneshot(Request::builder().uri("/api/v1/dashboards")
        .header(header::AUTHORIZATION, "Bearer ovst_anything").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let (cookie, csrf) = login(&router, "alice").await;
    call(&router, "POST", "/api/v1/dashboards", &cookie, &csrf, Some(json!({"name": "A", "layout": layout()})), None).await;
    let client = db.pool.get().await.unwrap();
    let count: i64 = client.query_one("SELECT count(*) FROM audit_log WHERE action = 'dashboard.create'", &[]).await.unwrap().get(0);
    assert_eq!(count, 1);
    drop(client);
    db.drop().await;
}
```

(If `TrustedPeer` or `hash_password` are imported from a different
path in `auth_http.rs`, copy its `use` lines exactly.)

- [ ] **Step 2: Run the tests and watch them fail**

Run: `cargo test -q --locked -p openvibes-console --all-features --test dashboards_http 2>&1 | grep -E "test result|FAILED|panicked" | head`
Expected: FAIL. `/api/v1/dashboards` answers 404 through `api_not_found`,
so the 401, 201 and similar assertions fail.

- [ ] **Step 3: Extract `session_user` in `router.rs`**

Replace the session branch of `authenticated_permission`. That is
everything after the `let secret = match presented_credentials(headers)
{ ... };` block, from `let digest = session_digest(...)` through
`let capabilities = crate::resolve_capabilities(&resolved);`. Move it
into:

```rust
/// A signed-in browser user and their effective capabilities. Bearer
/// tokens are refused: dashboards and preferences belong to people.
pub(crate) struct SessionUser {
    pub(crate) user_id: String,
    pub(crate) capabilities: Vec<crate::EffectiveCapability>,
}

pub(crate) async fn session_user(
    state: &AuthHttpState,
    headers: &HeaderMap,
    csrf_required: bool,
) -> Result<SessionUser, Response> {
    use crate::auth::{PresentedCredentials, presented_credentials};
    match presented_credentials(headers) {
        Ok(PresentedCredentials::Session(secret)) => session_capabilities(state, headers, secret.expose_secret(), csrf_required).await,
        Ok(PresentedCredentials::Bearer(_)) => Err(problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN, "permission_denied", "Access is not available"))),
        _ => Err(authentication_required()),
    }
}

/// The session path shared by `authenticated_permission` and `session_user`:
/// verifies the session and CSRF, touches it, and resolves capabilities.
async fn session_capabilities(
    state: &AuthHttpState,
    headers: &HeaderMap,
    secret: &str,
    csrf_required: bool,
) -> Result<SessionUser, Response> {
    use crate::auth::{session_csrf, session_digest};
    let now = Utc::now();
    let digest = session_digest(secret);
    let csrf = session_csrf(secret).0;
    // ... the moved lines, unchanged, from `let client = state.pool.get()...`
    // through `let capabilities = crate::resolve_capabilities(&resolved);` ...
    Ok(SessionUser { user_id: active.user_id, capabilities })
}
```

Then `authenticated_permission`'s session path becomes:

```rust
    let user = session_capabilities(state, headers, secret.expose_secret(), csrf_required).await?;
    match user.capabilities.iter().find(|capability| capability.permission == permission) {
        Some(capability) => match &capability.scope {
            crate::PermissionScope::Global => Ok((AgentScope::Global, user.user_id)),
            crate::PermissionScope::AssetGroups { asset_group_ids } => {
                Ok((AgentScope::AssetGroups(asset_group_ids.clone()), user.user_id))
            }
        },
        None => Err(problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN, "permission_denied", "Access is not available"))),
    }
```

Make `authentication_required`, `unavailable_auth` and
`parse_if_match_version` `pub(crate)`. Run the existing suite before
going on:

Run: `cargo test -q --locked -p openvibes-console --all-features 2>&1 | grep -E "test result|FAILED"`
Expected: every existing test still passes. The refactor must not change behaviour.

- [ ] **Step 4: Write the handlers in `dashboards.rs`**

```rust
use axum::{
    Json,
    extract::{Path, State, rejection::JsonRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::{SecondsFormat, Utc};
use platform_store::dashboards::{self as store, Dashboard, Refusal};

use crate::{
    DashboardPage, DashboardView, HomeDashboard, Permission, PermissionScope, ProblemDetails,
    SaveDashboardRequest, ShareDashboardRequest,
    problem::problem_response,
    router::{AuthHttpState, parse_if_match_version, session_user, unavailable_auth},
};

fn view(dashboard: Dashboard, user_id: &str) -> DashboardView {
    DashboardView {
        mine: dashboard.owner_user_id == user_id,
        dashboard_id: dashboard.dashboard_id,
        name: dashboard.name,
        owner_display_name: dashboard.owner_display_name,
        shared_role_id: dashboard.shared_role_id,
        version: dashboard.version.try_into().unwrap_or_default(),
        layout: dashboard.layout,
        created_at: dashboard.created_at.to_rfc3339_opts(SecondsFormat::Secs, true),
        updated_at: dashboard.updated_at.to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

fn with_etag(status: StatusCode, dashboard: DashboardView) -> Response {
    let etag = format!("\"{}\"", dashboard.version);
    let mut response = (status, Json(dashboard)).into_response();
    response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(value) = HeaderValue::from_str(&etag) {
        response.headers_mut().insert(header::ETAG, value);
    }
    response
}

fn refused(refusal: Refusal) -> Response {
    problem_response(match refusal {
        Refusal::NotFound => ProblemDetails::not_found("dashboard_not_found", "Dashboard not found"),
        Refusal::NotOwner => ProblemDetails::new(StatusCode::FORBIDDEN, "not_dashboard_owner", "Only the owner can change this dashboard; duplicate it instead"),
        Refusal::Stale => ProblemDetails::new(StatusCode::PRECONDITION_FAILED, "stale_dashboard", "The dashboard changed since you loaded it"),
        Refusal::TooMany => ProblemDetails::new(StatusCode::UNPROCESSABLE_ENTITY, "too_many_dashboards", "You already have 100 dashboards"),
        Refusal::UnknownRole => ProblemDetails::new(StatusCode::UNPROCESSABLE_ENTITY, "unknown_role", "No such role"),
    })
}

fn invalid(errors: Vec<crate::FieldError>) -> Response {
    let mut problem = ProblemDetails::new(StatusCode::UNPROCESSABLE_ENTITY, "invalid_dashboard", "The dashboard is invalid");
    problem.field_errors = Some(errors);
    problem_response(problem)
}

fn bad_request() -> Response {
    problem_response(ProblemDetails::new(StatusCode::BAD_REQUEST, "invalid_request", "The request body is invalid"))
}

/// Validates name and layout; the trimmed name on success.
fn checked(request: &SaveDashboardRequest) -> Result<String, Response> {
    let name = crate::dashboards::validate_name(&request.name);
    let layout = crate::dashboards::validate_layout(&request.layout);
    match (name, layout) {
        (Ok(name), Ok(())) => Ok(name),
        (name, layout) => {
            let mut errors: Vec<_> = name.err().into_iter().collect();
            errors.extend(layout.err().unwrap_or_default());
            Err(invalid(errors))
        }
    }
}
```

and the handlers. Each carries a `#[utoipa::path(...)]` attribute in the
style of `update_authenticated_audit_retention`, listing its status codes
(`tag = "dashboards"`):

```rust
pub(crate) async fn list_dashboards(State(state): State<AuthHttpState>, headers: HeaderMap) -> Response {
    let user = match session_user(&state, &headers, false).await { Ok(user) => user, Err(response) => return response };
    let Ok(client) = state.pool.get().await else { return unavailable_auth() };
    match store::list_visible(&client, &user.user_id).await {
        Ok(items) => Json(DashboardPage { items: items.into_iter().map(|d| view(d, &user.user_id)).collect() }).into_response(),
        Err(_) => unavailable_auth(),
    }
}

pub(crate) async fn create_dashboard(State(state): State<AuthHttpState>, headers: HeaderMap,
    payload: Result<Json<SaveDashboardRequest>, JsonRejection>) -> Response {
    let user = match session_user(&state, &headers, true).await { Ok(user) => user, Err(response) => return response };
    let Ok(Json(request)) = payload else { return bad_request() };
    let name = match checked(&request) { Ok(name) => name, Err(response) => return response };
    let Ok(mut client) = state.pool.get().await else { return unavailable_auth() };
    match store::create(&mut client, &user.user_id, &name, &request.layout, Utc::now()).await {
        Ok(Ok(dashboard)) => with_etag(StatusCode::CREATED, view(dashboard, &user.user_id)),
        Ok(Err(refusal)) => refused(refusal),
        Err(_) => unavailable_auth(),
    }
}

pub(crate) async fn get_dashboard(State(state): State<AuthHttpState>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let user = match session_user(&state, &headers, false).await { Ok(user) => user, Err(response) => return response };
    let Ok(client) = state.pool.get().await else { return unavailable_auth() };
    match store::get_visible(&client, &user.user_id, &id).await {
        Ok(Some(dashboard)) => with_etag(StatusCode::OK, view(dashboard, &user.user_id)),
        Ok(None) => refused(Refusal::NotFound),
        Err(_) => unavailable_auth(),
    }
}

pub(crate) async fn update_dashboard(State(state): State<AuthHttpState>, headers: HeaderMap, Path(id): Path<String>,
    payload: Result<Json<SaveDashboardRequest>, JsonRejection>) -> Response {
    let user = match session_user(&state, &headers, true).await { Ok(user) => user, Err(response) => return response };
    let expected = match parse_if_match_version(&headers) {
        Ok(Some(version)) => version,
        Ok(None) => return problem_response(ProblemDetails::new(StatusCode::PRECONDITION_REQUIRED, "precondition_required", "If-Match is required")),
        Err(()) => return problem_response(ProblemDetails::new(StatusCode::BAD_REQUEST, "invalid_precondition", "If-Match must contain one quoted version")),
    };
    let Ok(Json(request)) = payload else { return bad_request() };
    let name = match checked(&request) { Ok(name) => name, Err(response) => return response };
    let Ok(mut client) = state.pool.get().await else { return unavailable_auth() };
    match store::update(&mut client, &user.user_id, &id, &name, &request.layout, expected, Utc::now()).await {
        Ok(Ok(dashboard)) => with_etag(StatusCode::OK, view(dashboard, &user.user_id)),
        Ok(Err(refusal)) => refused(refusal),
        Err(_) => unavailable_auth(),
    }
}

pub(crate) async fn delete_dashboard(State(state): State<AuthHttpState>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let user = match session_user(&state, &headers, true).await { Ok(user) => user, Err(response) => return response };
    let Ok(mut client) = state.pool.get().await else { return unavailable_auth() };
    match store::delete(&mut client, &user.user_id, &id).await {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(refusal)) => refused(refusal),
        Err(_) => unavailable_auth(),
    }
}

pub(crate) async fn share_dashboard(State(state): State<AuthHttpState>, headers: HeaderMap, Path(id): Path<String>,
    payload: Result<Json<ShareDashboardRequest>, JsonRejection>) -> Response {
    let user = match session_user(&state, &headers, true).await { Ok(user) => user, Err(response) => return response };
    let may_share = user.capabilities.iter().any(|c| c.permission == Permission::DashboardsShare && c.scope == PermissionScope::Global);
    if !may_share {
        return problem_response(ProblemDetails::new(StatusCode::FORBIDDEN, "permission_denied", "Access is not available"));
    }
    let Ok(Json(request)) = payload else { return bad_request() };
    let Ok(mut client) = state.pool.get().await else { return unavailable_auth() };
    match store::set_sharing(&mut client, &user.user_id, &id, request.role_id.as_deref(), Utc::now()).await {
        Ok(Ok(dashboard)) => with_etag(StatusCode::OK, view(dashboard, &user.user_id)),
        Ok(Err(refusal)) => refused(refusal),
        Err(_) => unavailable_auth(),
    }
}

pub(crate) async fn get_home(State(state): State<AuthHttpState>, headers: HeaderMap) -> Response {
    let user = match session_user(&state, &headers, false).await { Ok(user) => user, Err(response) => return response };
    let Ok(client) = state.pool.get().await else { return unavailable_auth() };
    match store::home(&client, &user.user_id).await {
        Ok(dashboard_id) => Json(HomeDashboard { dashboard_id }).into_response(),
        Err(_) => unavailable_auth(),
    }
}

pub(crate) async fn set_home(State(state): State<AuthHttpState>, headers: HeaderMap,
    payload: Result<Json<HomeDashboard>, JsonRejection>) -> Response {
    let user = match session_user(&state, &headers, true).await { Ok(user) => user, Err(response) => return response };
    let Ok(Json(request)) = payload else { return bad_request() };
    let Ok(mut client) = state.pool.get().await else { return unavailable_auth() };
    match store::set_home(&mut client, &user.user_id, request.dashboard_id.as_deref()).await {
        Ok(Ok(())) => Json(request).into_response(),
        Ok(Err(refusal)) => refused(refusal),
        Err(_) => unavailable_auth(),
    }
}
```

(`problem_response` lives in `crate::problem`, which is already
`pub(crate)`. If `AuthHttpState` is private in `router.rs`, make it
`pub(crate)`. The `ProblemDetails::new` constructor is `pub(crate)`.)

- [ ] **Step 5: Register the routes and the OpenAPI entries**

In `authenticated_api_router` (router.rs), before `.method_not_allowed_fallback`:

```rust
        .route("/v1/dashboards", get(crate::dashboards::list_dashboards).post(crate::dashboards::create_dashboard))
        .route(
            "/v1/dashboards/{dashboard_id}",
            get(crate::dashboards::get_dashboard)
                .put(crate::dashboards::update_dashboard)
                .delete(crate::dashboards::delete_dashboard),
        )
        .route("/v1/dashboards/{dashboard_id}/sharing", axum::routing::put(crate::dashboards::share_dashboard))
        .route("/v1/me/home", get(crate::dashboards::get_home).put(crate::dashboards::set_home))
```

In `openapi.rs`, add the eight handlers to `paths(...)` and the five
types to `components(schemas(...))`. Then regenerate:

```bash
cargo run -q --locked -p openvibes-console --bin export_openapi > docs/api/console-v1.openapi.json
npm --prefix crates/openvibes-console/web run generate:api
```

- [ ] **Step 6: Run the HTTP tests and the whole console suite**

Run: `cargo test -q --locked -p openvibes-console --all-features 2>&1 | grep -E "test result|FAILED|panicked"`
Expected: all ok, including `dashboards_http` with 5 passed and the `api_contract` snapshot test.

- [ ] **Step 7: Write the component page and index**

`docs/components/console-dashboards.md` covers:
- **Purpose:** from the spec's Goal and Principles.
- **Interfaces:** the route table from the Global Constraints, with each
  status code, and the layout limits.
- **Configuration:** none.
- **Failure behaviour:** the spec's table.
- **How to test:** `cargo test -p platform-store --test console_dashboards`
  and `cargo test -p openvibes-console --test dashboards_http`, both
  with `OPENVIBES_TEST_DATABASE_URL`.

Also:
- add a row to `docs/components/README.md`: `console-dashboards` |
  console module | "user dashboards: layouts, sharing by role, home" |
  link;
- add the dashboard routes to `openvibes-console.md`'s route list.

- [ ] **Step 8: Run the full repository gate and commit**

Run the Global Constraints gate. Expected: `GATE-GREEN` equivalent; every
command exits 0. `export_openapi --check` reports no drift.

```bash
git add crates/openvibes-console docs/api/console-v1.openapi.json docs/components
git commit -m "Console: /api/v1/dashboards and /me/home (session only, audited)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

Then push the branch and open the part-1 PR against `main`.
