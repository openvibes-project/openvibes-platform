use crate::{Client, StoreError};
use chrono::{DateTime, Utc};

/// The administrator's internet-lookup setting for the assistant (one row).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Setting {
    /// 0 off, 1 security references (OSV, Bodhi), 2 those and web search through SearXNG.
    pub level: i16,
    /// SearXNG base URL, required at level 2.
    pub searxng_url: Option<String>,
    /// Extra internal domain names the outbound filter must refuse.
    pub internal_domains: Vec<String>,
    /// Monotonically increasing version for stale-write protection.
    pub version: i64,
    /// Last update time.
    pub updated_at: DateTime<Utc>,
    /// Actor that last changed the setting.
    pub updated_by: String,
}

/// The editable fields of the setting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Update {
    /// 0 off, 1 security references (OSV, Bodhi), 2 those and web search.
    pub level: i16,
    /// SearXNG base URL, required at level 2.
    pub searxng_url: Option<String>,
    /// Internal domain names to refuse, lowercase, at most 50.
    pub internal_domains: Vec<String>,
}

const COLUMNS: &str = "level, searxng_url, internal_domains, version, updated_at, updated_by";

fn from_row(row: &tokio_postgres::Row) -> Setting {
    Setting {
        level: row.get(0),
        searxng_url: row.get(1),
        internal_domains: row.get(2),
        version: row.get(3),
        updated_at: row.get(4),
        updated_by: row.get(5),
    }
}

/// Reads the singleton setting.
pub async fn get(client: &Client) -> Result<Setting, StoreError> {
    let row = client
        .query_one(
            &format!("SELECT {COLUMNS} FROM assistant_internet WHERE singleton"),
            &[],
        )
        .await?;
    Ok(from_row(&row))
}

/// Lowercase LDH labels (1-63 chars, no edge hyphen) joined by dots, 253
/// chars at most. A single label such as `intranet` is allowed.
fn valid_domain(d: &str) -> bool {
    d.len() <= 253
        && d.split('.').all(|l| {
            (1..=63).contains(&l.len())
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

fn json(level: i16, url: &Option<String>, domains: &[String]) -> serde_json::Value {
    serde_json::json!({"level": level, "searxng_url": url, "internal_domains": domains})
}

/// Updates the setting and its audit event atomically. Returns `None` if
/// `expected_version` is stale. A level outside 0-2, level 2 without a
/// SearXNG URL, or a malformed or surplus (over 50) domain is refused.
pub async fn update(
    client: &mut Client,
    update: &Update,
    expected_version: i64,
    by: &str,
    now: DateTime<Utc>,
) -> Result<Option<Setting>, StoreError> {
    if !(0..=2).contains(&update.level)
        || (update.level == 2 && update.searxng_url.is_none())
        || update.internal_domains.len() > 50
        || !update.internal_domains.iter().all(|d| valid_domain(d))
    {
        return Err(StoreError::Query);
    }
    let tx = client.transaction().await?;
    let row = tx
        .query_one(
            &format!("SELECT {COLUMNS} FROM assistant_internet WHERE singleton FOR UPDATE"),
            &[],
        )
        .await?;
    let old = from_row(&row);
    if old.version != expected_version {
        tx.rollback().await?;
        return Ok(None);
    }
    let row = tx
        .query_one(
            &format!(
                "UPDATE assistant_internet
                 SET level = $1, searxng_url = $2, internal_domains = $3,
                     version = version + 1, updated_at = $4, updated_by = $5
                 WHERE singleton RETURNING {COLUMNS}"
            ),
            &[
                &update.level,
                &update.searxng_url,
                &update.internal_domains,
                &now,
                &by,
            ],
        )
        .await?;
    let old_json = json(old.level, &old.searxng_url, &old.internal_domains);
    let new_json = json(update.level, &update.searxng_url, &update.internal_domains);
    tx.execute(
        "INSERT INTO audit_log (actor, action, target, result, detail,
             actor_kind, actor_id, actor_display, target_kind, target_id)
         VALUES ($1, 'assistant.internet.changed', 'assistant_internet', 'success',
             jsonb_build_object('old', $2::jsonb, 'new', $3::jsonb),
             'user', $1, $1, 'assistant_internet', 'singleton')",
        &[&by, &old_json, &new_json],
    )
    .await?;
    let setting = from_row(&row);
    tx.commit().await?;
    Ok(Some(setting))
}

/// Names the outbound filter must never let through: agent ids and hostnames
/// (and the first label of every dotted one, as `web-01` for `web-01.corp`),
/// console usernames and the configured internal domains, all lowercase.
pub async fn denylist(client: &Client) -> Result<Vec<String>, StoreError> {
    let rows = client
        .query(
            "SELECT lower(agent_id) FROM agents
             UNION SELECT lower(hostname) FROM agents
                   WHERE hostname IS NOT NULL AND hostname <> ''
             UNION SELECT split_part(lower(hostname), '.', 1) FROM agents
                   WHERE hostname LIKE '%.%'
             UNION SELECT lower(username) FROM console_users
             UNION SELECT lower(d) FROM assistant_internet, unnest(internal_domains) d",
            &[],
        )
        .await?;
    Ok(rows.iter().map(|r| r.get(0)).collect())
}
