//! Console roles: named sets of permissions with a host reach (schema 52;
//! spec 2026-10-16-roles-permissions-design.md §4), and what a person or
//! service account holds through them.

use chrono::{DateTime, Utc};
use deadpool_postgres::GenericClient;
use tokio_postgres::Row;
use tokio_postgres::error::SqlState;

use crate::{Client, StoreError, console_auth::ACCESS_BINDING_LOCK};

/// The hosts a role's host permissions apply on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reach {
    /// No host: only the role's platform permissions apply.
    None,
    /// Every host.
    All,
    /// The hosts of these asset groups (ids, sorted).
    Groups(Vec<String>),
}

/// One stored role, as the console lists it.
#[derive(Clone, Debug)]
pub struct StoredRole {
    /// Stable id: `admin`, a former built-in id, or `r_` and 16 hex digits.
    pub role_id: String,
    /// Unique name regardless of case, 1–64 characters.
    pub name: String,
    /// Optional description, at most 500 characters.
    pub description: String,
    /// Only Administrator (`admin`) is built in: it cannot be changed.
    pub builtin: bool,
    /// Permission ids, sorted.
    pub permissions: Vec<String>,
    /// Hosts the role's host permissions apply on.
    pub reach: Reach,
    /// The reached groups as (id, name), by name.
    pub group_names: Vec<(String, String)>,
    /// Active bindings (people and service accounts) holding the role.
    pub members: i64,
    /// Optimistic-concurrency version, bumped on every save.
    pub version: i32,
}

/// What a create or update writes.
pub struct RoleInput<'a> {
    /// Role name.
    pub name: &'a str,
    /// Role description.
    pub description: &'a str,
    /// Permission ids (the console checks closure under needs).
    pub permissions: &'a [String],
    /// Host reach.
    pub reach: &'a Reach,
}

/// Outcome of a role write.
#[derive(Debug)]
pub enum RoleWrite {
    /// Written (for a delete: the role as it was).
    Saved(StoredRole),
    /// Another role has this name, regardless of case.
    NameTaken,
    /// The role changed since the version the caller read.
    Stale,
    /// No such role.
    NotFound,
    /// Administrator cannot be changed or deleted.
    Protected,
    /// The role still has this many active bindings.
    InUse(i64),
    /// A permission or group id does not exist (or the group was deleted
    /// during the write).
    UnknownReference,
}

/// Who holds roles.
#[derive(Clone, Copy, Debug)]
pub enum Principal<'a> {
    /// A local console user id.
    User(&'a str),
    /// A service account id.
    ServiceAccount(&'a str),
}

/// One role a principal holds: its permissions and reach.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    /// Role id.
    pub role_id: String,
    /// Permission ids.
    pub permissions: Vec<String>,
    /// Hosts the host permissions apply on.
    pub reach: Reach,
}

const PROTECTED: &str = "admin";

fn reach(all_hosts: bool, groups: Vec<String>) -> Reach {
    if all_hosts {
        Reach::All
    } else if groups.is_empty() {
        Reach::None
    } else {
        Reach::Groups(groups)
    }
}

const SELECT_ROLES: &str =
    "SELECT r.role_id, r.display_name, r.description, r.builtin, r.all_hosts,
    r.version,
    COALESCE((SELECT array_agg(rp.permission_id ORDER BY rp.permission_id)
              FROM console_role_permissions rp WHERE rp.role_id = r.role_id), '{}'),
    COALESCE((SELECT array_agg(rg.asset_group_id::text ORDER BY rg.asset_group_id::text)
              FROM console_role_groups rg WHERE rg.role_id = r.role_id), '{}'),
    COALESCE((SELECT array_agg(g.asset_group_id::text ORDER BY g.name)
              FROM console_role_groups rg JOIN console_asset_groups g USING (asset_group_id)
              WHERE rg.role_id = r.role_id), '{}'),
    COALESCE((SELECT array_agg(g.name ORDER BY g.name)
              FROM console_role_groups rg JOIN console_asset_groups g USING (asset_group_id)
              WHERE rg.role_id = r.role_id), '{}'),
    (SELECT count(*) FROM console_role_bindings b
     WHERE b.role_id = r.role_id AND b.revoked_at IS NULL)
  FROM console_roles r";

fn stored(row: &Row) -> StoredRole {
    let ids: Vec<String> = row.get(8);
    let names: Vec<String> = row.get(9);
    StoredRole {
        role_id: row.get(0),
        name: row.get(1),
        description: row.get(2),
        builtin: row.get(3),
        reach: reach(row.get(4), row.get(7)),
        version: row.get(5),
        permissions: row.get(6),
        group_names: ids.into_iter().zip(names).collect(),
        members: row.get(10),
    }
}

/// Every role, Administrator first, then by name.
pub async fn list_roles(client: &Client) -> Result<Vec<StoredRole>, StoreError> {
    let sql = format!("{SELECT_ROLES} ORDER BY r.builtin DESC, lower(r.display_name)");
    Ok(client.query(&sql, &[]).await?.iter().map(stored).collect())
}

/// One role by id.
pub async fn role(client: &Client, role_id: &str) -> Result<Option<StoredRole>, StoreError> {
    read_role(client, role_id).await
}

async fn read_role<C: GenericClient + Sync>(
    client: &C,
    role_id: &str,
) -> Result<Option<StoredRole>, StoreError> {
    let sql = format!("{SELECT_ROLES} WHERE r.role_id = $1");
    Ok(client
        .query_opt(&sql, &[&role_id])
        .await?
        .as_ref()
        .map(stored))
}

/// The refusal a failed role write means, if it is one: a name clash, or a
/// permission or group id that does not exist (or a group deleted meanwhile).
fn refusal(error: &tokio_postgres::Error) -> Option<RoleWrite> {
    let db = error.as_db_error()?;
    if db.code() == &SqlState::UNIQUE_VIOLATION
        && db.constraint() == Some("console_roles_name_unique")
    {
        Some(RoleWrite::NameTaken)
    } else if db.code() == &SqlState::FOREIGN_KEY_VIOLATION
        || db.code() == &SqlState::INVALID_TEXT_REPRESENTATION
    {
        Some(RoleWrite::UnknownReference)
    } else {
        None
    }
}

/// Writes name, permissions and groups, then audits.
async fn write_contents(
    tx: &deadpool_postgres::Transaction<'_>,
    role_id: &str,
    input: &RoleInput<'_>,
    action: &str,
    actor_id: &str,
    now: DateTime<Utc>,
) -> Result<RoleWrite, StoreError> {
    let all_hosts = *input.reach == Reach::All;
    let groups: &[String] = match input.reach {
        Reach::Groups(groups) => groups,
        Reach::None | Reach::All => &[],
    };
    let written: Result<u64, tokio_postgres::Error> = async {
        tx.execute(
            "UPDATE console_roles SET display_name = $2, description = $3, all_hosts = $4
             WHERE role_id = $1",
            &[&role_id, &input.name, &input.description, &all_hosts],
        )
        .await?;
        tx.execute(
            "DELETE FROM console_role_permissions WHERE role_id = $1",
            &[&role_id],
        )
        .await?;
        tx.execute(
            "INSERT INTO console_role_permissions (role_id, permission_id)
             SELECT DISTINCT $1::text, unnest($2::text[])",
            &[&role_id, &input.permissions],
        )
        .await?;
        tx.execute(
            "DELETE FROM console_role_groups WHERE role_id = $1",
            &[&role_id],
        )
        .await?;
        tx.execute(
            "INSERT INTO console_role_groups (role_id, asset_group_id)
             SELECT DISTINCT $1::text, unnest($2::text[])::uuid",
            &[&role_id, &groups],
        )
        .await
    }
    .await;
    if let Err(error) = written {
        return refusal(&error).ok_or_else(|| error.into());
    }
    let role = read_role(tx, role_id).await?.ok_or(StoreError::Query)?;
    audit(tx, action, actor_id, now, &role).await?;
    Ok(RoleWrite::Saved(role))
}

async fn audit(
    tx: &deadpool_postgres::Transaction<'_>,
    action: &str,
    actor_id: &str,
    now: DateTime<Utc>,
    role: &StoredRole,
) -> Result<(), StoreError> {
    let reach = match &role.reach {
        Reach::None => serde_json::json!("none"),
        Reach::All => serde_json::json!("all"),
        Reach::Groups(groups) => serde_json::json!(groups),
    };
    let detail = serde_json::json!({
        "name": role.name, "permissions": role.permissions, "reach": reach,
    });
    tx.execute(
        "INSERT INTO audit_log (at, actor, action, target, result, detail, actor_kind, actor_id,
             actor_display, target_kind, target_id)
         VALUES ($5, $1, $2, 'role', 'success', $3, 'user', $1, $1, 'role', $4)",
        &[&actor_id, &action, &detail, &role.role_id, &now],
    )
    .await?;
    Ok(())
}

async fn lock(tx: &deadpool_postgres::Transaction<'_>) -> Result<(), StoreError> {
    tx.query_one("SELECT pg_advisory_xact_lock($1)", &[&ACCESS_BINDING_LOCK])
        .await?;
    Ok(())
}

/// Creates a role with a fresh `r_` id, audited in the same transaction.
pub async fn create_role(
    client: &mut Client,
    input: &RoleInput<'_>,
    actor_id: &str,
    now: DateTime<Utc>,
) -> Result<RoleWrite, StoreError> {
    let tx = client.transaction().await?;
    lock(&tx).await?;
    let inserted = tx
        .query_one(
            "INSERT INTO console_roles (role_id, display_name, builtin, created_at, created_by)
             VALUES ('r_' || substr(md5(gen_random_uuid()::text), 1, 16), $1, false, $2, $3)
             RETURNING role_id",
            &[&input.name, &now, &actor_id],
        )
        .await;
    let role_id: String = match inserted {
        Ok(row) => row.get(0),
        Err(error) => return refusal(&error).ok_or_else(|| error.into()),
    };
    let written = write_contents(&tx, &role_id, input, "rbac.role.created", actor_id, now).await?;
    if matches!(written, RoleWrite::Saved(_)) {
        tx.commit().await?;
    }
    Ok(written)
}

/// Locks the role row; `Err(outcome)` when it is protected or missing.
async fn locked(
    tx: &deadpool_postgres::Transaction<'_>,
    role_id: &str,
) -> Result<Result<i32, RoleWrite>, StoreError> {
    if role_id == PROTECTED {
        return Ok(Err(RoleWrite::Protected));
    }
    lock(tx).await?;
    let row = tx
        .query_opt(
            "SELECT version FROM console_roles WHERE role_id = $1 FOR UPDATE",
            &[&role_id],
        )
        .await?;
    Ok(row.map(|row| row.get(0)).ok_or(RoleWrite::NotFound))
}

/// Replaces a role's name, description, permissions and reach when
/// `version` is still current.
pub async fn update_role(
    client: &mut Client,
    role_id: &str,
    version: i32,
    input: &RoleInput<'_>,
    actor_id: &str,
    now: DateTime<Utc>,
) -> Result<RoleWrite, StoreError> {
    let tx = client.transaction().await?;
    let current = match locked(&tx, role_id).await? {
        Ok(current) => current,
        Err(outcome) => return Ok(outcome),
    };
    if current != version {
        return Ok(RoleWrite::Stale);
    }
    tx.execute(
        "UPDATE console_roles SET version = version + 1 WHERE role_id = $1",
        &[&role_id],
    )
    .await?;
    let written = write_contents(&tx, role_id, input, "rbac.role.updated", actor_id, now).await?;
    if matches!(written, RoleWrite::Saved(_)) {
        tx.commit().await?;
    }
    Ok(written)
}

/// Deletes a role nobody holds; dashboards shared with it lose that share.
pub async fn delete_role(
    client: &mut Client,
    role_id: &str,
    actor_id: &str,
    now: DateTime<Utc>,
) -> Result<RoleWrite, StoreError> {
    let tx = client.transaction().await?;
    if let Err(outcome) = locked(&tx, role_id).await? {
        return Ok(outcome);
    }
    let role = read_role(&tx, role_id).await?.ok_or(StoreError::Query)?;
    if role.members > 0 {
        return Ok(RoleWrite::InUse(role.members));
    }
    tx.execute("DELETE FROM console_roles WHERE role_id = $1", &[&role_id])
        .await?;
    audit(&tx, "rbac.role.deleted", actor_id, now, &role).await?;
    tx.commit().await?;
    Ok(RoleWrite::Saved(role))
}

/// The roles a principal holds through active bindings, in one query.
pub async fn grants(client: &Client, principal: Principal<'_>) -> Result<Vec<Grant>, StoreError> {
    let (user, account) = match principal {
        Principal::User(id) => (Some(id), None),
        Principal::ServiceAccount(id) => (None, Some(id)),
    };
    let rows = client
        .query(
            "SELECT r.role_id, r.all_hosts,
                COALESCE(array_agg(DISTINCT rp.permission_id)
                    FILTER (WHERE rp.permission_id IS NOT NULL), '{}'),
                COALESCE(array_agg(DISTINCT rg.asset_group_id::text)
                    FILTER (WHERE rg.asset_group_id IS NOT NULL), '{}')
             FROM console_role_bindings b JOIN console_roles r USING (role_id)
             LEFT JOIN console_role_permissions rp USING (role_id)
             LEFT JOIN console_role_groups rg USING (role_id)
             WHERE b.revoked_at IS NULL
               AND (b.user_id = $1::text::uuid OR b.service_account_id = $2::text::uuid)
             GROUP BY r.role_id, r.all_hosts",
            &[&user, &account],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|row| Grant {
            role_id: row.get(0),
            reach: reach(row.get(1), row.get(3)),
            permissions: row.get(2),
        })
        .collect())
}

/// Who may be assigned a triaged item (alarm, finding, vulnerability): an
/// enabled user by username holding `permission` (the area's `*.triage`)
/// through an active role that reaches some host, or an Administrator.
/// Returns (user id, username).
pub(crate) async fn assignee(
    tx: &tokio_postgres::Transaction<'_>,
    username: &str,
    permission: &str,
) -> Result<Option<(String, String)>, StoreError> {
    Ok(tx
        .query_opt(
            "SELECT u.user_id::text, u.username FROM console_users u
             WHERE u.username = $1 AND u.enabled AND EXISTS (
                SELECT 1 FROM console_role_bindings b JOIN console_roles r USING (role_id)
                WHERE b.user_id = u.user_id AND b.revoked_at IS NULL
                  AND (r.role_id = 'admin' OR (
                    EXISTS (SELECT 1 FROM console_role_permissions rp
                            WHERE rp.role_id = r.role_id AND rp.permission_id = $2)
                    AND (r.all_hosts OR EXISTS (SELECT 1 FROM console_role_groups g
                                                WHERE g.role_id = r.role_id)))))",
            &[&username, &permission],
        )
        .await?
        .map(|row| (row.get(0), row.get(1))))
}
