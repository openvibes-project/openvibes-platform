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

const COLUMNS: &str =
    "d.dashboard_id::text, d.owner_user_id::text, u.display_name, d.name, d.layout,
    d.shared_role_id, d.version::bigint, d.created_at, d.updated_at";

/// Visible to `$1`: owned, or shared with a role of one of `$1`'s live bindings.
const VISIBLE: &str = "(d.owner_user_id = $1::text::uuid OR d.shared_role_id IN (
    SELECT b.role_id FROM console_role_bindings b
    WHERE b.user_id = $1::text::uuid AND b.revoked_at IS NULL))";

/// True for a canonical UUID (8-4-4-4-12 hex, any case). Other ids are simply
/// not found, before any query, so a cast can never fail.
fn is_uuid(id: &str) -> bool {
    id.len() == 36
        && id.char_indices().all(|(index, c)| match index {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        })
}

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
                 ORDER BY d.owner_user_id <> $1::text::uuid, lower(d.name), d.dashboard_id"
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
    if !is_uuid(dashboard_id) {
        return Ok(None);
    }
    let row = client
        .query_opt(
            &format!(
                "SELECT {COLUMNS} FROM console_dashboards d
                 JOIN console_users u ON u.user_id = d.owner_user_id
                 WHERE d.dashboard_id = $2::text::uuid AND {VISIBLE}"
            ),
            &[&user_id, &dashboard_id],
        )
        .await?;
    Ok(row.as_ref().map(dashboard))
}

async fn audit(
    tx: &deadpool_postgres::Transaction<'_>,
    user_id: &str,
    action: &str,
    dashboard_id: &str,
    detail: serde_json::Value,
) -> Result<(), StoreError> {
    tx.execute(
        "INSERT INTO audit_log (actor, action, target, result, detail,
             actor_kind, actor_id, actor_display, target_kind, target_id)
         SELECT $1, $2, $3, 'success', $4, 'user', $1, u.display_name, 'dashboard', $3
         FROM console_users u WHERE u.user_id = $1::text::uuid",
        &[&user_id, &action, &dashboard_id, &detail],
    )
    .await?;
    Ok(())
}

/// Locks the dashboard row and says whether `user_id` owns it; `None`
/// when it is not visible to them.
async fn lock_owned(
    tx: &deadpool_postgres::Transaction<'_>,
    user_id: &str,
    dashboard_id: &str,
) -> Result<Option<(bool, i64)>, StoreError> {
    if !is_uuid(dashboard_id) {
        return Ok(None);
    }
    let row = tx
        .query_opt(
            &format!(
                "SELECT d.owner_user_id = $1::text::uuid, d.version::bigint FROM console_dashboards d
                 WHERE d.dashboard_id = $2::text::uuid AND {VISIBLE} FOR UPDATE OF d"
            ),
            &[&user_id, &dashboard_id],
        )
        .await?;
    Ok(row.map(|row| (row.get(0), row.get(1))))
}

async fn reread(
    tx: &deadpool_postgres::Transaction<'_>,
    dashboard_id: &str,
) -> Result<Dashboard, StoreError> {
    let row = tx
        .query_one(
            &format!(
                "SELECT {COLUMNS} FROM console_dashboards d
                 JOIN console_users u ON u.user_id = d.owner_user_id
                 WHERE d.dashboard_id = $1::text::uuid"
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
    tx.execute(
        "SELECT 1 FROM console_users WHERE user_id = $1::text::uuid FOR UPDATE",
        &[&user_id],
    )
    .await?;
    let owned: i64 = tx
        .query_one(
            "SELECT count(*) FROM console_dashboards WHERE owner_user_id = $1::text::uuid",
            &[&user_id],
        )
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
    audit(
        &tx,
        user_id,
        "dashboard.create",
        &id,
        serde_json::json!({ "name": name }),
    )
    .await?;
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
         WHERE dashboard_id = $1::text::uuid",
        &[&dashboard_id, &name, layout, &now],
    )
    .await?;
    audit(
        &tx,
        user_id,
        "dashboard.update",
        dashboard_id,
        serde_json::json!({ "name": name }),
    )
    .await?;
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
    tx.execute(
        "DELETE FROM console_dashboards WHERE dashboard_id = $1::text::uuid",
        &[&dashboard_id],
    )
    .await?;
    audit(
        &tx,
        user_id,
        "dashboard.delete",
        dashboard_id,
        serde_json::json!({}),
    )
    .await?;
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
            .query_opt(
                "SELECT 1 FROM console_roles WHERE role_id = $1",
                &[&role_id],
            )
            .await?
            .is_some();
        if !known {
            tx.rollback().await?;
            return Ok(Err(Refusal::UnknownRole));
        }
    }
    let old: Option<String> = tx
        .query_one(
            "SELECT shared_role_id FROM console_dashboards WHERE dashboard_id = $1::text::uuid",
            &[&dashboard_id],
        )
        .await?
        .get(0);
    tx.execute(
        "UPDATE console_dashboards SET shared_role_id = $2, version = version + 1, updated_at = $3
         WHERE dashboard_id = $1::text::uuid",
        &[&dashboard_id, &role_id, &now],
    )
    .await?;
    audit(
        &tx,
        user_id,
        "dashboard.share",
        dashboard_id,
        serde_json::json!({ "from": old, "to": role_id }),
    )
    .await?;
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
                 WHERE h.user_id = $1::text::uuid AND {VISIBLE}"
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
            tx.execute(
                "DELETE FROM console_user_home WHERE user_id = $1::text::uuid",
                &[&user_id],
            )
            .await?;
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
    audit(
        &tx,
        user_id,
        "dashboard.home",
        dashboard_id.unwrap_or("builtin:overview"),
        serde_json::json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(Ok(()))
}
