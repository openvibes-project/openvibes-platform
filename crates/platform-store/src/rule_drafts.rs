//! Draft rules for the site's own rule sets (`site`, `site-alarms`): saved by
//! the console's rule editor, never served to an agent until a set is signed
//! and published.

use chrono::{DateTime, Utc};

use crate::{Client, StoreError};

/// The site's findings rule set.
pub const SITE: &str = "site";
/// The site's threat-alarm rule set.
pub const SITE_ALARMS: &str = "site-alarms";

/// One saved draft rule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Draft {
    /// `site` or `site-alarms`.
    pub rule_set_id: String,
    /// The rule's id within the set.
    pub rule_id: String,
    /// The rule as the agent's loader reads it.
    pub rule: serde_json::Value,
    /// Who last saved it.
    pub updated_by: String,
    /// When.
    pub updated_at: DateTime<Utc>,
}

fn draft(row: &tokio_postgres::Row) -> Draft {
    Draft {
        rule_set_id: row.get(0),
        rule_id: row.get(1),
        rule: row.get(2),
        updated_by: row.get(3),
        updated_at: row.get(4),
    }
}

const COLUMNS: &str = "rule_set_id, rule_id, rule, updated_by, updated_at";

/// The drafts of `rule_set_id`, by rule id.
///
/// # Errors
/// A database failure.
pub async fn list(client: &Client, rule_set_id: &str) -> Result<Vec<Draft>, StoreError> {
    let rows = client
        .query(
            &format!("SELECT {COLUMNS} FROM rule_drafts WHERE rule_set_id = $1 ORDER BY rule_id"),
            &[&rule_set_id],
        )
        .await?;
    Ok(rows.iter().map(draft).collect())
}

/// One draft.
///
/// # Errors
/// A database failure.
pub async fn get(
    client: &Client,
    rule_set_id: &str,
    rule_id: &str,
) -> Result<Option<Draft>, StoreError> {
    let row = client
        .query_opt(
            &format!("SELECT {COLUMNS} FROM rule_drafts WHERE rule_set_id = $1 AND rule_id = $2"),
            &[&rule_set_id, &rule_id],
        )
        .await?;
    Ok(row.as_ref().map(draft))
}

/// Saves `rule` as the draft `rule_id` of `rule_set_id`, replacing an
/// earlier draft of it.
///
/// # Errors
/// A database failure.
pub async fn put(
    client: &Client,
    rule_set_id: &str,
    rule_id: &str,
    rule: &serde_json::Value,
    actor: &str,
    now: DateTime<Utc>,
) -> Result<Draft, StoreError> {
    let row = client
        .query_one(
            &format!(
                "INSERT INTO rule_drafts (rule_set_id, rule_id, rule, updated_by, updated_at)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (rule_set_id, rule_id) DO UPDATE
                 SET rule = EXCLUDED.rule, updated_by = EXCLUDED.updated_by,
                     updated_at = EXCLUDED.updated_at
                 RETURNING {COLUMNS}"
            ),
            &[&rule_set_id, &rule_id, rule, &actor, &now],
        )
        .await?;
    Ok(draft(&row))
}

/// Deletes a draft; `false` when there was none.
///
/// # Errors
/// A database failure.
pub async fn delete(client: &Client, rule_set_id: &str, rule_id: &str) -> Result<bool, StoreError> {
    Ok(client
        .execute(
            "DELETE FROM rule_drafts WHERE rule_set_id = $1 AND rule_id = $2",
            &[&rule_set_id, &rule_id],
        )
        .await?
        > 0)
}
