//! Host labels (spec §5.2): free strings on a host for filtering and
//! search. They never affect access, groups or rule assignment.

use chrono::{DateTime, Utc};

use crate::{Client, StoreError};

/// Most labels on one host.
pub const MAX_LABELS: i64 = 32;

/// The outcome of adding a label.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LabelWrite {
    /// Added.
    Added,
    /// Already there.
    AlreadyThere,
    /// The host already has [`MAX_LABELS`].
    TooMany,
    /// No such active host.
    NotFound,
    /// Empty after trimming, over 64 characters, or with a control character.
    Invalid,
}

/// The trimmed label, if valid.
fn valid(label: &str) -> Option<&str> {
    let label = label.trim();
    ((1..=64).contains(&label.chars().count()) && !label.chars().any(char::is_control))
        .then_some(label)
}

/// A host's labels, in byte order.
pub async fn labels(client: &Client, agent_id: &str) -> Result<Vec<String>, StoreError> {
    Ok(client
        .query(
            "SELECT label FROM console_host_labels WHERE agent_id = $1 ORDER BY label COLLATE \"C\"",
            &[&agent_id],
        )
        .await?
        .iter()
        .map(|row| row.get(0))
        .collect())
}

async fn audit(
    tx: &deadpool_postgres::Transaction<'_>,
    action: &str,
    agent_id: &str,
    label: &str,
    actor: &str,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    tx.execute(
        "INSERT INTO audit_log (at, actor, action, target, result, detail, actor_kind, actor_id,
             actor_display, target_kind, target_id)
         VALUES ($1, $2, $3, $4, 'success', jsonb_build_object('label', $5::text), 'user', $2, $2,
                 'agent', $4)",
        &[&now, &actor, &action, &agent_id, &label],
    )
    .await?;
    Ok(())
}

/// Adds a trimmed label to an active host, audited.
pub async fn add_label(
    client: &mut Client,
    agent_id: &str,
    label: &str,
    actor: &str,
    now: DateTime<Utc>,
) -> Result<LabelWrite, StoreError> {
    let Some(label) = valid(label) else {
        return Ok(LabelWrite::Invalid);
    };
    let tx = client.transaction().await?;
    // the row lock serialises adds to one host, so the cap holds
    let active = tx
        .query_opt(
            "SELECT 1 FROM agents WHERE agent_id = $1 AND status = 'active' FOR NO KEY UPDATE",
            &[&agent_id],
        )
        .await?;
    if active.is_none() {
        return Ok(LabelWrite::NotFound);
    }
    let row = tx
        .query_one(
            "SELECT count(*), bool_or(label = $2) IS TRUE FROM console_host_labels WHERE agent_id = $1",
            &[&agent_id, &label],
        )
        .await?;
    if row.get(1) {
        return Ok(LabelWrite::AlreadyThere);
    }
    if row.get::<_, i64>(0) >= MAX_LABELS {
        return Ok(LabelWrite::TooMany);
    }
    tx.execute(
        "INSERT INTO console_host_labels (agent_id, label, added_at, added_by) VALUES ($1, $2, $3, $4)",
        &[&agent_id, &label, &now, &actor],
    )
    .await?;
    audit(&tx, "host.label_added", agent_id, label, actor, now).await?;
    tx.commit().await?;
    Ok(LabelWrite::Added)
}

/// Removes a label (trimmed) from a host, audited; false when it was not there.
pub async fn remove_label(
    client: &mut Client,
    agent_id: &str,
    label: &str,
    actor: &str,
    now: DateTime<Utc>,
) -> Result<bool, StoreError> {
    let label = label.trim();
    let tx = client.transaction().await?;
    let removed = tx
        .execute(
            "DELETE FROM console_host_labels WHERE agent_id = $1 AND label = $2",
            &[&agent_id, &label],
        )
        .await?;
    if removed == 0 {
        return Ok(false);
    }
    audit(&tx, "host.label_removed", agent_id, label, actor, now).await?;
    tx.commit().await?;
    Ok(true)
}
