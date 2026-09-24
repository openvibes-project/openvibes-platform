use chrono::{DateTime, Utc};
use deadpool_postgres::Client;

use crate::StoreError;

/// Administrator-controlled audit-log retention policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetentionPolicy {
    /// Number of days retained, including events at the cutoff.
    pub retention_days: i32,
    /// Monotonically increasing version for stale-write protection.
    pub version: i64,
    /// Last update time.
    pub updated_at: DateTime<Utc>,
    /// Actor that last changed the policy.
    pub updated_by: String,
}

/// Reads the singleton console audit retention policy.
pub async fn retention_policy(client: &Client) -> Result<RetentionPolicy, StoreError> {
    let row = client
        .query_one(
            "SELECT retention_days, version, updated_at, updated_by
             FROM console_audit_retention WHERE singleton",
            &[],
        )
        .await?;
    Ok(RetentionPolicy {
        retention_days: row.get(0),
        version: row.get(1),
        updated_at: row.get(2),
        updated_by: row.get(3),
    })
}

/// Updates audit retention and its audit event atomically. Returns `None` if
/// `expected_version` is stale. Values outside 1–36500 days are refused.
pub async fn update_retention_policy(
    client: &mut Client,
    retention_days: i32,
    expected_version: i64,
    updated_by: &str,
    now: DateTime<Utc>,
) -> Result<Option<RetentionPolicy>, StoreError> {
    if !(1..=36_500).contains(&retention_days) {
        return Err(StoreError::Query);
    }
    let tx = client.transaction().await?;
    let row = tx
        .query_one(
            "SELECT retention_days, version, updated_at, updated_by
             FROM console_audit_retention
             WHERE singleton FOR UPDATE",
            &[],
        )
        .await?;
    let current_version: i64 = row.get(1);
    if current_version != expected_version {
        tx.rollback().await?;
        return Ok(None);
    }
    if row.get::<_, i32>(0) == retention_days {
        let policy = RetentionPolicy {
            retention_days: row.get(0),
            version: row.get(1),
            updated_at: row.get(2),
            updated_by: row.get(3),
        };
        tx.rollback().await?;
        return Ok(Some(policy));
    }
    let row = tx
        .query_one(
            "UPDATE console_audit_retention
             SET retention_days = $1, version = version + 1,
                 updated_at = $2, updated_by = $3
             WHERE singleton RETURNING retention_days, version, updated_at, updated_by",
            &[&retention_days, &now, &updated_by],
        )
        .await?;
    let version: i64 = row.get(1);
    tx.execute(
        "INSERT INTO audit_log (actor, action, target, result, detail,
             actor_kind, actor_id, actor_display, target_kind, target_id)
         VALUES ($1, 'audit.retention.updated', 'audit_retention', 'success',
             jsonb_build_object('retention_days', $2::integer, 'version', $3::bigint),
             'user', $1, $1, 'audit_retention', 'singleton')",
        &[&updated_by, &retention_days, &version],
    )
    .await?;
    let policy = RetentionPolicy {
        retention_days: row.get(0),
        version: row.get(1),
        updated_at: row.get(2),
        updated_by: row.get(3),
    };
    tx.commit().await?;
    Ok(Some(policy))
}

/// Appends one audit entry. `detail` must never contain secrets.
pub async fn record(
    client: &Client,
    actor: &str,
    action: &str,
    target: Option<&str>,
    result: &str,
) -> Result<(), StoreError> {
    client
        .execute(
            "INSERT INTO audit_log (actor, action, target, result) VALUES ($1, $2, $3, $4)",
            &[&actor, &action, &target, &result],
        )
        .await?;
    Ok(())
}
