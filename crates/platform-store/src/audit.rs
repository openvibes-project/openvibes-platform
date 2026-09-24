use crate::{Client, StoreError, console_read::PageLimit};
use chrono::{DateTime, Duration, Utc};

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

/// Exclusive audit-event continuation key: timestamp then sequence id.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditCursor {
    /// Timestamp of the last event in the previous page.
    pub at: DateTime<Utc>,
    /// Database sequence id of the last event in the previous page.
    pub id: i64,
}

/// Bounded audit-event query. A lower timestamp is required for index use.
#[derive(Clone, Debug)]
pub struct AuditQuery {
    /// Inclusive lower timestamp.
    pub since: DateTime<Utc>,
    /// Exclusive upper timestamp.
    pub until: Option<DateTime<Utc>>,
    /// Optional exact actor filter.
    pub actor: Option<String>,
    /// Optional exact action filter.
    pub action: Option<String>,
    /// Optional exact result filter.
    pub result: Option<String>,
    /// Exclusive keyset cursor.
    pub after: Option<AuditCursor>,
    /// Bounded page size.
    pub limit: PageLimit,
}

/// Safe audit-event fields for the console. Event detail, source address, and
/// user-agent are intentionally omitted from this general list model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditEvent {
    /// Database sequence id.
    pub id: i64,
    /// Event timestamp.
    pub at: DateTime<Utc>,
    /// Human-readable actor.
    pub actor: String,
    /// Stable action code.
    pub action: String,
    /// Safe display target, if present.
    pub target: Option<String>,
    /// Result code.
    pub result: String,
    /// Correlation id, if present.
    pub request_id: Option<String>,
    /// Actor category.
    pub actor_kind: Option<String>,
    /// Stable actor id.
    pub actor_id: Option<String>,
    /// Authentication method, if applicable.
    pub authentication_method: Option<String>,
    /// Target category.
    pub target_kind: Option<String>,
    /// Stable target id.
    pub target_id: Option<String>,
    /// Safe reason code.
    pub reason_code: Option<String>,
}

/// One page of audit events in descending time and id order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditPage {
    /// At most the requested number of events.
    pub items: Vec<AuditEvent>,
    /// Cursor for the next page, if one exists.
    pub next: Option<AuditCursor>,
}

/// Lists a bounded set of audit events using exact filters and keyset paging.
pub async fn events(client: &Client, query: &AuditQuery) -> Result<AuditPage, StoreError> {
    let after = query.after.as_ref();
    let rows = client
        .query(
            "SELECT id, at, actor, action, target, result, request_id, actor_kind,
                    actor_id, authentication_method, target_kind, target_id, reason_code
             FROM audit_log
             WHERE at >= $1 AND ($2::timestamptz IS NULL OR at < $2)
               AND ($3::text IS NULL OR actor = $3)
               AND ($4::text IS NULL OR action = $4)
               AND ($5::text IS NULL OR result = $5)
               AND ($6::boolean = false OR (at, id) < ($7, $8))
             ORDER BY at DESC, id DESC LIMIT $9",
            &[
                &query.since,
                &query.until,
                &query.actor,
                &query.action,
                &query.result,
                &after.is_some(),
                &after.map(|cursor| cursor.at),
                &after.map(|cursor| cursor.id),
                &(i64::from(query.limit.get()) + 1),
            ],
        )
        .await?;
    let mut items: Vec<_> = rows.iter().map(audit_event_from_row).collect();
    let next = if items.len() > usize::from(query.limit.get()) {
        items.pop();
        items.last().map(|event| AuditCursor {
            at: event.at,
            id: event.id,
        })
    } else {
        None
    };
    Ok(AuditPage { items, next })
}

fn audit_event_from_row(row: &tokio_postgres::Row) -> AuditEvent {
    AuditEvent {
        id: row.get(0),
        at: row.get(1),
        actor: row.get(2),
        action: row.get(3),
        target: row.get(4),
        result: row.get(5),
        request_id: row.get(6),
        actor_kind: row.get(7),
        actor_id: row.get(8),
        authentication_method: row.get(9),
        target_kind: row.get(10),
        target_id: row.get(11),
        reason_code: row.get(12),
    }
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

/// Deletes at most 10,000 audit events older than the configured retention
/// cutoff. Repeated maintenance runs drain larger backlogs safely.
pub async fn cleanup_expired_events(
    client: &Client,
    now: DateTime<Utc>,
) -> Result<u64, StoreError> {
    let policy = retention_policy(client).await?;
    let cutoff = now - Duration::days(i64::from(policy.retention_days));
    let deleted = client
        .execute(
            "WITH expired AS (
                 SELECT id FROM audit_log WHERE at < $1
                 ORDER BY at, id LIMIT 10000
             )
             DELETE FROM audit_log a USING expired e WHERE a.id = e.id",
            &[&cutoff],
        )
        .await?;
    Ok(deleted)
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
