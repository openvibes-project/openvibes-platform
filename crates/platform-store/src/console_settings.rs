//! General console settings (roles spec §7): one row per changed key, the
//! meaning and defaults live in the console. Changes are audited.

use chrono::{DateTime, Utc};
use deadpool_postgres::GenericClient;
use serde_json::Value;

use crate::{Client, StoreError, host_groups::AuditLine};

/// One stored setting.
#[derive(Clone, Debug)]
pub struct StoredSetting {
    /// The key, such as `suppressions.require_approval`.
    pub key: String,
    /// The value.
    pub value: Value,
    /// When it changed.
    pub changed_at: DateTime<Utc>,
    /// Who changed it.
    pub changed_by: String,
}

/// Every setting that has been changed from its default.
pub async fn all(client: &impl GenericClient) -> Result<Vec<StoredSetting>, StoreError> {
    let rows = client
        .query(
            "SELECT key, value, changed_at, changed_by FROM console_settings ORDER BY key",
            &[],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|row| StoredSetting {
            key: row.get(0),
            value: row.get(1),
            changed_at: row.get(2),
            changed_by: row.get(3),
        })
        .collect())
}

/// Stores `value` for `key` and audits `settings.changed` with the old and
/// new values, in one transaction. Returns the old value (`None` when the
/// key had no row). The caller has already checked `value` against the
/// key's definition.
pub async fn set(
    client: &mut Client,
    key: &str,
    value: &Value,
    actor: &str,
    now: DateTime<Utc>,
) -> Result<Option<Value>, StoreError> {
    let tx = client.transaction().await?;
    // serializes first writes of a key (no row to lock yet), so `old` is right
    tx.execute("SELECT pg_advisory_xact_lock(hashtext($1))", &[&key])
        .await?;
    let old: Option<Value> = tx
        .query_opt(
            "SELECT value FROM console_settings WHERE key = $1 FOR UPDATE",
            &[&key],
        )
        .await?
        .map(|row| row.get(0));
    tx.execute(
        "INSERT INTO console_settings (key, value, changed_at, changed_by) VALUES ($1, $2, $3, $4)
         ON CONFLICT (key) DO UPDATE
         SET value = EXCLUDED.value, changed_at = EXCLUDED.changed_at, changed_by = EXCLUDED.changed_by",
        &[&key, value, &now, &actor],
    )
    .await?;
    let detail = serde_json::json!({"key": key, "old": old, "new": value});
    tx.execute(
        "INSERT INTO audit_log (at, actor, action, target, result, detail, actor_kind, actor_id,
             actor_display, target_kind, target_id)
         VALUES ($1, $2, 'settings.changed', $3, 'success', $4, 'user', $2, $2, 'setting', $3)",
        &[&now, &actor, &key, &detail],
    )
    .await?;
    tx.commit().await?;
    Ok(old)
}

/// Puts `key` back to its default (deletes the row) and audits it. Returns
/// the old value (`None` when it already had the default).
pub async fn reset(
    client: &mut Client,
    key: &str,
    actor: &str,
    now: DateTime<Utc>,
) -> Result<Option<Value>, StoreError> {
    let tx = client.transaction().await?;
    let old: Option<Value> = tx
        .query_opt(
            "DELETE FROM console_settings WHERE key = $1 RETURNING value",
            &[&key],
        )
        .await?
        .map(|row| row.get(0));
    if old.is_some() {
        audit(&tx, key, &old, &Value::Null, actor, now).await?;
    }
    tx.commit().await?;
    Ok(old)
}

/// Every stored value by key: what a service applies over its file.
pub async fn values(
    client: &impl GenericClient,
) -> Result<std::collections::HashMap<String, Value>, StoreError> {
    Ok(all(client)
        .await?
        .into_iter()
        .map(|setting| (setting.key, setting.value))
        .collect())
}

/// The stored values whose key starts with `prefix`, read once over a
/// connection of its own: a service uses this at start, before its pool
/// exists, to apply the console's settings over its file.
///
/// # Errors
/// The database could not be reached or read.
pub async fn read_with_prefix(
    database_url: &str,
    prefix: &str,
) -> Result<std::collections::HashMap<String, Value>, StoreError> {
    let pool = crate::connect_sized(database_url, 1).await?;
    let client = pool.get().await.map_err(|_| StoreError::Unavailable)?;
    let mut values = values(&client).await?;
    values.retain(|key, _| key.starts_with(prefix));
    Ok(values)
}

/// When a secret was last set and by whom; the value is never read here.
#[derive(Clone, Debug)]
pub struct SecretInfo {
    /// The key, such as `vulns.nvd_api_key`.
    pub key: String,
    /// When it was set.
    pub changed_at: DateTime<Utc>,
    /// Who set it.
    pub changed_by: String,
}

/// The table a secret lives in: the console's own (`assistant.*`, which the
/// console process must read to use) or the services' (`service_secrets`,
/// which the console role can write but not read).
fn secret_table(key: &str) -> &'static str {
    if key.starts_with("assistant.") {
        "console_secrets"
    } else {
        "service_secrets"
    }
}

/// Which secrets are set (never their values).
pub async fn secrets_set(client: &impl GenericClient) -> Result<Vec<SecretInfo>, StoreError> {
    let rows = client
        .query(
            "SELECT key, changed_at, changed_by FROM service_secrets
             UNION ALL SELECT key, changed_at, changed_by FROM console_secrets ORDER BY key",
            &[],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|row| SecretInfo {
            key: row.get(0),
            changed_at: row.get(1),
            changed_by: row.get(2),
        })
        .collect())
}

/// Stores a secret, or removes it with `None`, and audits that it changed
/// (the audit line says set or not set, never the value).
pub async fn set_secret(
    client: &mut Client,
    key: &str,
    value: Option<&str>,
    actor: &str,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let table = secret_table(key);
    let tx = client.transaction().await?;
    tx.execute("SELECT pg_advisory_xact_lock(hashtext($1))", &[&key])
        .await?;
    let was_set = tx
        .query_opt(&format!("SELECT 1 FROM {table} WHERE key = $1"), &[&key])
        .await?
        .is_some();
    match value {
        // Not an upsert: `EXCLUDED.value` needs SELECT on `value`, which the
        // console's role does not have (the advisory lock makes the two
        // statements safe).
        Some(value) if was_set => {
            tx.execute(
                &format!(
                    "UPDATE {table} SET value = $2, changed_at = $3, changed_by = $4 WHERE key = $1"
                ),
                &[&key, &value, &now, &actor],
            )
            .await?;
        }
        Some(value) => {
            tx.execute(
                &format!("INSERT INTO {table} (key, value, changed_at, changed_by) VALUES ($1, $2, $3, $4)"),
                &[&key, &value, &now, &actor],
            )
            .await?;
        }
        None => {
            tx.execute(&format!("DELETE FROM {table} WHERE key = $1"), &[&key])
                .await?;
        }
    }
    let words = |set: bool| Value::from(if set { "set" } else { "not set" });
    audit(
        &tx,
        key,
        &Some(words(was_set)),
        &words(value.is_some()),
        actor,
        now,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// A secret's value; only the role that uses it may read it.
pub async fn secret(client: &impl GenericClient, key: &str) -> Result<Option<String>, StoreError> {
    let table = secret_table(key);
    Ok(client
        .query_opt(
            &format!("SELECT value FROM {table} WHERE key = $1"),
            &[&key],
        )
        .await?
        .map(|row| row.get(0)))
}

async fn audit(
    tx: &impl GenericClient,
    key: &str,
    old: &Option<Value>,
    new: &Value,
    actor: &str,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let detail = serde_json::json!({"key": key, "old": old, "new": new});
    tx.execute(
        "INSERT INTO audit_log (at, actor, action, target, result, detail, actor_kind, actor_id,
             actor_display, target_kind, target_id)
         VALUES ($1, $2, 'settings.changed', $3, 'success', $4, 'user', $2, $2, 'setting', $3)",
        &[&now, &actor, &key, &detail],
    )
    .await?;
    Ok(())
}

/// The newest `limit` setting changes, newest first.
pub async fn recent(client: &impl GenericClient, limit: i64) -> Result<Vec<AuditLine>, StoreError> {
    let rows = client
        .query(
            "SELECT at, COALESCE(actor_display, actor), action, detail FROM audit_log
             WHERE action = 'settings.changed' ORDER BY at DESC, id DESC LIMIT $1",
            &[&limit.clamp(1, 100)],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|row| AuditLine {
            at: row.get(0),
            actor: row.get(1),
            action: row.get(2),
            detail: row.get(3),
        })
        .collect())
}

/// Whether new suppressions wait for approval. False when the row is absent
/// or not a bool.
pub async fn require_approval(tx: &impl GenericClient) -> Result<bool, StoreError> {
    let row = tx
        .query_opt(
            "SELECT value FROM console_settings WHERE key = 'suppressions.require_approval'",
            &[],
        )
        .await?;
    Ok(row.is_some_and(|row| row.get::<_, Value>(0).as_bool().unwrap_or(false)))
}
