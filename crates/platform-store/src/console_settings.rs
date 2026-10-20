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
