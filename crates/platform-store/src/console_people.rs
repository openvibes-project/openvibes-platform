//! People (spec §4.4–4.6, §9.1): console users with their sign-in source
//! and roles, a person's recent activity, their details, enable and reset
//! password, a person's picture, and giving or removing a role from a user
//! or service account.
//! Each change is audited in its own transaction.

use chrono::{DateTime, Utc};
use deadpool_postgres::Transaction;
use tokio_postgres::Row;

use crate::{
    Client, StoreError,
    console_auth::{ACCESS_BINDING_LOCK, NewLocalUser, enabled_administrators, insert_local_user},
    console_roles::Principal,
};

/// One console user as People lists them.
#[derive(Clone, Debug)]
pub struct Person {
    /// User UUID.
    pub user_id: String,
    /// Canonical username.
    pub username: String,
    /// Display name.
    pub display_name: String,
    /// Optional email address.
    pub email: Option<String>,
    /// Whether the account can sign in.
    pub enabled: bool,
    /// `password` or `sso`.
    pub auth_source: String,
    /// The last successful sign-in.
    pub last_sign_in_at: Option<DateTime<Utc>>,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Roles held through active bindings, sorted.
    pub role_ids: Vec<String>,
}

/// One audited action a person took.
#[derive(Clone, Debug)]
pub struct Activity {
    /// Audit action, e.g. `user.updated`.
    pub action: String,
    /// Audit target, when there is one.
    pub target: Option<String>,
    /// When it happened.
    pub at: DateTime<Utc>,
}

/// Outcome of giving a role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoleGift {
    /// A new binding, audited.
    Given,
    /// The principal already held the role; nothing changed.
    AlreadyHeld,
    /// No such principal or role.
    NotFound,
}

/// Outcome of removing a role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingRevocation {
    /// Revoked and audited.
    Revoked,
    /// The principal did not hold the role.
    NotFound,
    /// This is the last enabled Administrator's binding.
    LastAdministrator,
}

const SELECT_PEOPLE: &str = "SELECT u.user_id::text, u.username, u.display_name, u.email,
    u.enabled, u.auth_source, u.last_sign_in_at, u.created_at,
    COALESCE((SELECT array_agg(b.role_id ORDER BY b.role_id) FROM console_role_bindings b
              WHERE b.user_id = u.user_id AND b.revoked_at IS NULL), '{}')
  FROM console_users u";

fn person_from(row: &Row) -> Person {
    Person {
        user_id: row.get(0),
        username: row.get(1),
        display_name: row.get(2),
        email: row.get(3),
        enabled: row.get(4),
        auth_source: row.get(5),
        last_sign_in_at: row.get(6),
        created_at: row.get(7),
        role_ids: row.get(8),
    }
}

/// Every console user, by username.
pub async fn people(client: &Client) -> Result<Vec<Person>, StoreError> {
    let sql = format!("{SELECT_PEOPLE} ORDER BY u.username");
    Ok(client
        .query(&sql, &[])
        .await?
        .iter()
        .map(person_from)
        .collect())
}

/// One console user; `user_id` must be a UUID.
pub async fn person(client: &Client, user_id: &str) -> Result<Option<Person>, StoreError> {
    let sql = format!("{SELECT_PEOPLE} WHERE u.user_id = $1::text::uuid");
    Ok(client
        .query_opt(&sql, &[&user_id])
        .await?
        .as_ref()
        .map(person_from))
}

/// The newest `limit` audit rows where the user is the actor
/// (`audit_log_actor_recent_idx`).
pub async fn recent_activity(
    client: &Client,
    user_id: &str,
    limit: i64,
) -> Result<Vec<Activity>, StoreError> {
    let rows = client
        .query(
            "SELECT action, target, at FROM audit_log WHERE actor_id = $1
             ORDER BY at DESC, id DESC LIMIT $2",
            &[&user_id, &limit],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|row| Activity {
            action: row.get(0),
            target: row.get(1),
            at: row.get(2),
        })
        .collect())
}

/// Creates a user holding `new_user.role_id` and `more_roles`, with an
/// optional email, in one transaction.
pub async fn create_user(
    client: &mut Client,
    new_user: &NewLocalUser<'_>,
    email: Option<&str>,
    more_roles: &[String],
) -> Result<(), StoreError> {
    let tx = client.transaction().await?;
    insert_local_user(&tx, new_user).await?;
    if email.is_some() {
        tx.execute(
            "UPDATE console_users SET email = $2 WHERE user_id = $1::text::uuid",
            &[&new_user.user_id, &email],
        )
        .await?;
    }
    for role_id in more_roles {
        let principal = Principal::User(new_user.user_id);
        bind(&tx, principal, role_id, new_user.actor_id, new_user.now).await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Sets the display name and/or email (`Some(None)` clears it). False when
/// there is no such user.
pub async fn set_details(
    client: &mut Client,
    user_id: &str,
    display_name: Option<&str>,
    email: Option<Option<&str>>,
    actor_id: &str,
    now: DateTime<Utc>,
) -> Result<bool, StoreError> {
    let tx = client.transaction().await?;
    let updated = tx
        .execute(
            "UPDATE console_users SET display_name = COALESCE($2, display_name),
                    email = CASE WHEN $3 THEN $4 ELSE email END
             WHERE user_id = $1::text::uuid",
            &[&user_id, &display_name, &email.is_some(), &email.flatten()],
        )
        .await?;
    if updated == 0 {
        tx.rollback().await?;
        return Ok(false);
    }
    let detail = serde_json::json!({
        "display_name": display_name.is_some(), "email": email.is_some(),
    });
    audit(&tx, "user.updated", actor_id, now, user_id, detail).await?;
    tx.commit().await?;
    Ok(true)
}

/// Enables a disabled user. False when there is no disabled user by that id.
pub async fn enable_user(
    client: &mut Client,
    user_id: &str,
    actor_id: &str,
    now: DateTime<Utc>,
) -> Result<bool, StoreError> {
    let tx = client.transaction().await?;
    let updated = tx
        .execute(
            "UPDATE console_users SET enabled = true, disabled_at = NULL
             WHERE user_id = $1::text::uuid AND NOT enabled",
            &[&user_id],
        )
        .await?;
    if updated == 0 {
        tx.rollback().await?;
        return Ok(false);
    }
    audit(
        &tx,
        "user.enabled",
        actor_id,
        now,
        user_id,
        serde_json::json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(true)
}

/// Replaces a user's password with a one-time one (`password_phc`): they
/// must set their own at the next sign-in, and every session ends.
pub async fn reset_password(
    client: &mut Client,
    user_id: &str,
    password_phc: &str,
    actor_id: &str,
    now: DateTime<Utc>,
) -> Result<bool, StoreError> {
    let tx = client.transaction().await?;
    let updated = tx
        .execute(
            "UPDATE console_credentials SET password_phc = $2, changed_at = $3
             WHERE user_id = $1::text::uuid",
            &[&user_id, &password_phc, &now],
        )
        .await?;
    if updated == 0 {
        tx.rollback().await?;
        return Ok(false);
    }
    tx.execute(
        "UPDATE console_users SET password_must_change = true,
                auth_generation = auth_generation + 1
         WHERE user_id = $1::text::uuid",
        &[&user_id],
    )
    .await?;
    tx.execute(
        "UPDATE console_sessions SET revoked_at = COALESCE(revoked_at, $2)
         WHERE user_id = $1::text::uuid",
        &[&user_id, &now],
    )
    .await?;
    let detail = serde_json::json!({});
    audit(&tx, "user.password_reset", actor_id, now, user_id, detail).await?;
    tx.commit().await?;
    Ok(true)
}

/// Gives `principal` the role. Giving a role already held changes nothing.
pub async fn give_role(
    client: &mut Client,
    principal: Principal<'_>,
    role_id: &str,
    actor_id: &str,
    now: DateTime<Utc>,
) -> Result<RoleGift, StoreError> {
    let tx = client.transaction().await?;
    lock(&tx).await?;
    if bind(&tx, principal, role_id, actor_id, now).await? {
        tx.commit().await?;
        return Ok(RoleGift::Given);
    }
    let held = active_binding(&tx, principal, role_id).await?.is_some();
    tx.rollback().await?;
    Ok(if held {
        RoleGift::AlreadyHeld
    } else {
        RoleGift::NotFound
    })
}

/// Takes the role from `principal`, never the last enabled Administrator's.
pub async fn remove_role(
    client: &mut Client,
    principal: Principal<'_>,
    role_id: &str,
    actor_id: &str,
    now: DateTime<Utc>,
) -> Result<BindingRevocation, StoreError> {
    let tx = client.transaction().await?;
    lock(&tx).await?;
    let Some((binding_id, enabled_user)) = active_binding(&tx, principal, role_id).await? else {
        tx.rollback().await?;
        return Ok(BindingRevocation::NotFound);
    };
    if role_id == "admin" && enabled_user && enabled_administrators(&tx).await? <= 1 {
        tx.rollback().await?;
        return Ok(BindingRevocation::LastAdministrator);
    }
    tx.execute(
        "UPDATE console_role_bindings SET revoked_at = $2, revoked_by = $3
         WHERE binding_id = $1::text::uuid",
        &[&binding_id, &now, &actor_id],
    )
    .await?;
    binding_audit(
        &tx,
        "rbac.binding.revoked",
        principal,
        role_id,
        &binding_id,
        actor_id,
        now,
    )
    .await?;
    tx.commit().await?;
    Ok(BindingRevocation::Revoked)
}

fn ids<'a>(principal: Principal<'a>) -> (Option<&'a str>, Option<&'a str>) {
    match principal {
        Principal::User(id) => (Some(id), None),
        Principal::ServiceAccount(id) => (None, Some(id)),
    }
}

async fn lock(tx: &Transaction<'_>) -> Result<(), StoreError> {
    tx.query_one("SELECT pg_advisory_xact_lock($1)", &[&ACCESS_BINDING_LOCK])
        .await?;
    Ok(())
}

/// The active binding's id, and whether it belongs to an enabled user.
async fn active_binding(
    tx: &Transaction<'_>,
    principal: Principal<'_>,
    role_id: &str,
) -> Result<Option<(String, bool)>, StoreError> {
    let (user, account) = ids(principal);
    Ok(tx
        .query_opt(
            "SELECT b.binding_id::text, COALESCE(u.enabled, false)
             FROM console_role_bindings b LEFT JOIN console_users u USING (user_id)
             WHERE b.revoked_at IS NULL AND b.role_id = $3
               AND (b.user_id = $1::text::uuid OR b.service_account_id = $2::text::uuid)",
            &[&user, &account, &role_id],
        )
        .await?
        .map(|row| (row.get(0), row.get(1))))
}

/// Inserts and audits a binding; false when the principal or role does not
/// exist or the role is already held.
async fn bind(
    tx: &Transaction<'_>,
    principal: Principal<'_>,
    role_id: &str,
    actor_id: &str,
    now: DateTime<Utc>,
) -> Result<bool, StoreError> {
    let (user, account) = ids(principal);
    let row = tx
        .query_opt(
            "INSERT INTO console_role_bindings
                 (binding_id, user_id, service_account_id, role_id, created_at, created_by)
             SELECT gen_random_uuid(), $1::text::uuid, $2::text::uuid, r.role_id, $4, $5
             FROM console_roles r
             WHERE r.role_id = $3
               AND (EXISTS (SELECT 1 FROM console_users WHERE user_id = $1::text::uuid)
                 OR EXISTS (SELECT 1 FROM console_service_accounts
                            WHERE service_account_id = $2::text::uuid))
             ON CONFLICT DO NOTHING
             RETURNING binding_id::text",
            &[&user, &account, &role_id, &now, &actor_id],
        )
        .await?;
    let Some(row) = row else { return Ok(false) };
    let binding_id: String = row.get(0);
    binding_audit(
        tx,
        "rbac.binding.created",
        principal,
        role_id,
        &binding_id,
        actor_id,
        now,
    )
    .await?;
    Ok(true)
}

async fn binding_audit(
    tx: &Transaction<'_>,
    action: &str,
    principal: Principal<'_>,
    role_id: &str,
    binding_id: &str,
    actor_id: &str,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let (user, account) = ids(principal);
    let detail = serde_json::json!({
        "role_id": role_id, "user_id": user, "service_account_id": account,
    });
    tx.execute(
        "INSERT INTO audit_log (at, actor, action, target, result, detail, actor_kind,
             actor_id, actor_display, target_kind, target_id)
         VALUES ($1, $2, $3, 'role_binding', 'success', $4, 'user', $2, $2,
             'role_binding', $5)",
        &[&now, &actor_id, &action, &detail, &binding_id],
    )
    .await?;
    Ok(())
}

/// Which of a person's two stored images.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PictureSize {
    /// 64 px.
    Small,
    /// 256 px.
    Large,
}

/// A stored picture: the image and its strong ETag value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Picture {
    /// The WebP image.
    pub image: Vec<u8>,
    /// SHA-256 of both images, hex.
    pub etag: String,
}

/// Stores a person's picture (replacing any), audited. Returns the ETag, or
/// `None` when there is no such person.
pub async fn set_picture(
    client: &mut Client,
    user_id: &str,
    large: &[u8],
    small: &[u8],
    animated: bool,
    actor_id: &str,
    now: DateTime<Utc>,
) -> Result<Option<String>, StoreError> {
    let tx = client.transaction().await?;
    let row = tx
        .query_opt(
            "INSERT INTO console_user_pictures (user_id, large, small, etag, animated, updated_at, updated_by)
             SELECT u.user_id, $2::bytea, $3::bytea, encode(sha256($2::bytea || $3::bytea), 'hex'), $4::boolean, $5::timestamptz, $6::text
             FROM console_users u WHERE u.user_id = $1::text::uuid
             ON CONFLICT (user_id) DO UPDATE SET large = EXCLUDED.large, small = EXCLUDED.small,
                 etag = EXCLUDED.etag, animated = EXCLUDED.animated,
                 updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by
             RETURNING etag",
            &[&user_id, &large, &small, &animated, &now, &actor_id],
        )
        .await?;
    let Some(row) = row else {
        tx.rollback().await?;
        return Ok(None);
    };
    let detail = serde_json::json!({ "animated": animated, "bytes": large.len() + small.len() });
    audit(&tx, "user.picture.set", actor_id, now, user_id, detail).await?;
    tx.commit().await?;
    Ok(Some(row.get(0)))
}

/// Removes a person's picture, audited. False when they had none.
pub async fn remove_picture(
    client: &mut Client,
    user_id: &str,
    actor_id: &str,
    now: DateTime<Utc>,
) -> Result<bool, StoreError> {
    let tx = client.transaction().await?;
    let removed = tx
        .execute(
            "DELETE FROM console_user_pictures WHERE user_id = $1::text::uuid",
            &[&user_id],
        )
        .await?;
    if removed == 0 {
        tx.rollback().await?;
        return Ok(false);
    }
    audit(
        &tx,
        "user.picture.removed",
        actor_id,
        now,
        user_id,
        serde_json::json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(true)
}

/// One image of a person's picture.
pub async fn picture(
    client: &Client,
    user_id: &str,
    size: PictureSize,
) -> Result<Option<Picture>, StoreError> {
    let column = match size {
        PictureSize::Small => "small",
        PictureSize::Large => "large",
    };
    let row = client
        .query_opt(
            &format!(
                "SELECT {column}, etag FROM console_user_pictures WHERE user_id = $1::text::uuid"
            ),
            &[&user_id],
        )
        .await?;
    Ok(row.map(|row| Picture {
        image: row.get(0),
        etag: row.get(1),
    }))
}

/// The ETag of everyone's picture, by user id (no images read).
pub async fn picture_etags(
    client: &Client,
) -> Result<std::collections::HashMap<String, String>, StoreError> {
    Ok(client
        .query("SELECT user_id::text, etag FROM console_user_pictures", &[])
        .await?
        .iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect())
}

/// The ETag of one person's picture, if they have one.
pub async fn picture_etag(client: &Client, user_id: &str) -> Result<Option<String>, StoreError> {
    Ok(client
        .query_opt(
            "SELECT etag FROM console_user_pictures WHERE user_id = $1::text::uuid",
            &[&user_id],
        )
        .await?
        .map(|row| row.get(0)))
}

async fn audit(
    tx: &Transaction<'_>,
    action: &str,
    actor_id: &str,
    now: DateTime<Utc>,
    user_id: &str,
    detail: serde_json::Value,
) -> Result<(), StoreError> {
    tx.execute(
        "INSERT INTO audit_log (at, actor, action, target, result, detail, actor_kind,
             actor_id, actor_display, target_kind, target_id)
         VALUES ($1, $2, $3, $4, 'success', $5, 'user', $2, $2, 'user', $4)",
        &[&now, &actor_id, &action, &user_id, &detail],
    )
    .await?;
    Ok(())
}
