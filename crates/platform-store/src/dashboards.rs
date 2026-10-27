//! User dashboards: a named layout owned by one console user, optionally
//! shared with some of the viewer's roles or with everyone. Only layouts are stored; widgets read their data
//! through the permission-checked console API. Every change and its audit
//! row commit together; the layout is never copied into the audit log.

use chrono::{DateTime, Utc};
use tokio_postgres::Row;

use crate::{Client, StoreError};

/// Most dashboards one user may own.
pub const MAX_DASHBOARDS_PER_OWNER: i64 = 100;

/// Who may view a dashboard besides its owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Visibility {
    /// Only the owner.
    Private,
    /// Holders of one of its roles.
    Roles,
    /// Every signed-in person.
    Everyone,
}

impl Visibility {
    /// The stored and API spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::Roles => "roles",
            Self::Everyone => "everyone",
        }
    }

    /// Parses the stored and API spelling.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "private" => Some(Self::Private),
            "roles" => Some(Self::Roles),
            "everyone" => Some(Self::Everyone),
            _ => None,
        }
    }
}

/// A role a dashboard is shared with.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedRole {
    /// Role id.
    pub role_id: String,
    /// Role name.
    pub name: String,
}

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
    /// Who may view it besides the owner.
    pub visibility: Visibility,
    /// The roles it is shared with, by name. The owner sees all of them;
    /// anyone else only the ones they hold themselves.
    pub roles: Vec<SharedRole>,
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
    /// A role to share with does not exist.
    UnknownRole,
    /// A role to share with is not one the caller holds.
    RoleNotHeld,
    /// Sharing with roles needs at least one role.
    NoRoles,
}

/// Roles `$1` holds through live bindings.
const HELD: &str = "SELECT b.role_id FROM console_role_bindings b
    WHERE b.user_id = $1::text::uuid AND b.revoked_at IS NULL";

/// Columns of one dashboard as seen by `$1`: the owner sees every role it is
/// shared with, anyone else only their own.
const COLUMNS: &str =
    "d.dashboard_id::text, d.owner_user_id::text, u.display_name, d.name, d.layout,
    d.visibility, d.version::bigint, d.created_at, d.updated_at,
    (SELECT COALESCE(jsonb_agg(jsonb_build_object('role_id', r.role_id, 'name', r.display_name)
         ORDER BY lower(r.display_name), r.role_id), '[]'::jsonb)
     FROM console_dashboard_roles dr JOIN console_roles r USING (role_id)
     WHERE dr.dashboard_id = d.dashboard_id
       AND (d.owner_user_id = $1::text::uuid
            OR dr.role_id IN (SELECT b.role_id FROM console_role_bindings b
                WHERE b.user_id = $1::text::uuid AND b.revoked_at IS NULL)))";

/// Visible to `$1`: owned, shared with everyone, or shared with a role of one
/// of `$1`'s live bindings.
const VISIBLE: &str = "(d.owner_user_id = $1::text::uuid OR d.visibility = 'everyone' OR (
    d.visibility = 'roles' AND EXISTS (
    SELECT 1 FROM console_dashboard_roles dr JOIN console_role_bindings b USING (role_id)
    WHERE dr.dashboard_id = d.dashboard_id AND b.user_id = $1::text::uuid
      AND b.revoked_at IS NULL)))";

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
    let roles: serde_json::Value = row.get(9);
    Dashboard {
        dashboard_id: row.get(0),
        owner_user_id: row.get(1),
        owner_display_name: row.get(2),
        name: row.get(3),
        layout: row.get(4),
        visibility: Visibility::parse(row.get::<_, &str>(5)).unwrap_or(Visibility::Private),
        version: row.get(6),
        created_at: row.get(7),
        updated_at: row.get(8),
        roles: roles
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|role| {
                Some(SharedRole {
                    role_id: role.get("role_id")?.as_str()?.to_string(),
                    name: role.get("name")?.as_str()?.to_string(),
                })
            })
            .collect(),
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
    user_id: &str,
    dashboard_id: &str,
) -> Result<Dashboard, StoreError> {
    let row = tx
        .query_one(
            &format!(
                "SELECT {COLUMNS} FROM console_dashboards d
                 JOIN console_users u ON u.user_id = d.owner_user_id
                 WHERE d.dashboard_id = $2::text::uuid"
            ),
            &[&user_id, &dashboard_id],
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
    let created = reread(&tx, user_id, &id).await?;
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
    let updated = reread(&tx, user_id, dashboard_id).await?;
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

/// Sets who an owned dashboard is shared with: nobody, some of the owner's
/// own roles (at least one), or everyone. The caller checks `dashboards.share`
/// (roles) and `dashboards.publish` (everyone) first.
pub async fn set_sharing(
    client: &mut Client,
    user_id: &str,
    dashboard_id: &str,
    visibility: Visibility,
    role_ids: &[String],
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
    let mut roles: Vec<&str> = if visibility == Visibility::Roles {
        role_ids.iter().map(String::as_str).collect()
    } else {
        Vec::new()
    };
    roles.sort_unstable();
    roles.dedup();
    let old = tx
        .query_one(
            "SELECT d.visibility, COALESCE(array_agg(dr.role_id ORDER BY dr.role_id)
                 FILTER (WHERE dr.role_id IS NOT NULL), '{}')
             FROM console_dashboards d
             LEFT JOIN console_dashboard_roles dr USING (dashboard_id)
             WHERE d.dashboard_id = $1::text::uuid GROUP BY d.dashboard_id",
            &[&dashboard_id],
        )
        .await?;
    let (old_visibility, old_roles): (String, Vec<String>) = (old.get(0), old.get(1));
    if visibility == Visibility::Roles {
        // A role the owner has since left may stay on the dashboard (and be
        // unticked); only roles being added must be held.
        let added: Vec<&str> = roles
            .iter()
            .copied()
            .filter(|role| !old_roles.iter().any(|old| old == role))
            .collect();
        let refusal = if roles.is_empty() {
            Some(Refusal::NoRoles)
        } else {
            let known: i64 = tx
                .query_one(
                    "SELECT count(*) FROM console_roles WHERE role_id = ANY($1)",
                    &[&roles],
                )
                .await?
                .get(0);
            let held: i64 = tx
                .query_one(
                    &format!("SELECT count(*) FROM console_roles WHERE role_id = ANY($2) AND role_id IN ({HELD})"),
                    &[&user_id, &added],
                )
                .await?
                .get(0);
            if usize::try_from(known).ok() != Some(roles.len()) {
                Some(Refusal::UnknownRole)
            } else if usize::try_from(held).ok() != Some(added.len()) {
                Some(Refusal::RoleNotHeld)
            } else {
                None
            }
        };
        if let Some(refusal) = refusal {
            tx.rollback().await?;
            return Ok(Err(refusal));
        }
    }
    tx.execute(
        "DELETE FROM console_dashboard_roles WHERE dashboard_id = $1::text::uuid",
        &[&dashboard_id],
    )
    .await?;
    for role_id in &roles {
        tx.execute(
            "INSERT INTO console_dashboard_roles (dashboard_id, role_id) VALUES ($1::text::uuid, $2)",
            &[&dashboard_id, role_id],
        )
        .await?;
    }
    tx.execute(
        "UPDATE console_dashboards SET visibility = $2, version = version + 1, updated_at = $3
         WHERE dashboard_id = $1::text::uuid",
        &[&dashboard_id, &visibility.as_str(), &now],
    )
    .await?;
    audit(
        &tx,
        user_id,
        "dashboard.share",
        dashboard_id,
        serde_json::json!({
            "from": { "visibility": old_visibility, "roles": old_roles },
            "to": { "visibility": visibility.as_str(), "roles": roles },
        }),
    )
    .await?;
    let shared = reread(&tx, user_id, dashboard_id).await?;
    tx.commit().await?;
    Ok(Ok(shared))
}

/// Dashboards left shared with roles but with none (their last role was
/// deleted) become private. Runs in the transaction that deleted the role;
/// each gets a `dashboard.share` audit row naming the person who deleted it.
pub async fn privatise_orphans(
    tx: &deadpool_postgres::Transaction<'_>,
    actor_id: &str,
    deleted_role_id: &str,
    now: DateTime<Utc>,
) -> Result<usize, StoreError> {
    let ids: Vec<String> = tx
        .query(
            "UPDATE console_dashboards d
             SET visibility = 'private', version = version + 1, updated_at = $1
             WHERE d.visibility = 'roles' AND NOT EXISTS (
                 SELECT 1 FROM console_dashboard_roles dr WHERE dr.dashboard_id = d.dashboard_id)
             RETURNING d.dashboard_id::text",
            &[&now],
        )
        .await?
        .iter()
        .map(|row| row.get(0))
        .collect();
    let detail = serde_json::json!({
        "from": { "visibility": "roles", "roles": [deleted_role_id] },
        "to": { "visibility": "private", "roles": [] },
        "reason": "role deleted",
    });
    for id in &ids {
        tx.execute(
            "INSERT INTO audit_log (at, actor, action, target, result, detail, actor_kind, actor_id,
                 actor_display, target_kind, target_id)
             VALUES ($4, $1, 'dashboard.share', $2, 'success', $3, 'user', $1, $1, 'dashboard', $2)",
            &[&actor_id, id, &detail, &now],
        )
        .await?;
    }
    Ok(ids.len())
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
