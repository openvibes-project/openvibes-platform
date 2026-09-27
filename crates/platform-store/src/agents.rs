//! Agent listing, inspection, and revocation.

use chrono::{DateTime, Duration, Utc};

use crate::{Client, OFFLINE_AFTER_MINUTES, StoreError};

/// An agent as operators see it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentInfo {
    /// Platform-assigned id.
    pub agent_id: String,
    /// `active`, `revoked`, or `imported` (from export files, P3b).
    pub status: String,
    /// First enrollment.
    pub enrolled_at: DateTime<Utc>,
    /// Revocation time, if revoked.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Last recorded heartbeat.
    pub last_seen_at: Option<DateTime<Utc>>,
    /// Reported agent version.
    pub scanner_version: Option<String>,
    /// Certificates ever issued to it.
    pub certificates: i64,
    /// Imported hosts: the `agent_id` their files named, a label only.
    pub claimed_agent_id: Option<String>,
    /// The latest health report (P12); `None` when absent or unreadable.
    pub health: Option<openvibes_core::Health>,
    /// The report before it.
    pub health_previous: Option<openvibes_core::Health>,
    /// When the latest report was written.
    pub health_at: Option<DateTime<Utc>>,
}

impl AgentInfo {
    /// Health status and reasons; `None` unless the agent is active.
    #[must_use]
    pub fn health_status(
        &self,
        now: DateTime<Utc>,
    ) -> Option<(crate::health::HealthStatus, Vec<&'static str>)> {
        (self.status == "active").then(|| {
            crate::health::health_status(
                self.last_seen_at,
                self.health_at,
                self.health.as_ref(),
                self.health_previous.as_ref(),
                now,
            )
        })
    }
}

/// Which agents to list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Filter {
    /// Every agent.
    All,
    /// Active agents with no heartbeat for [`OFFLINE_AFTER_MINUTES`].
    Offline,
    /// Revoked agents.
    Revoked,
    /// Hosts imported from export files.
    Imported,
}

/// Outcome of [`revoke`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Revoke {
    /// The agent was active and is now revoked.
    Revoked,
    /// The agent was revoked before.
    AlreadyRevoked,
    /// No such agent.
    Unknown,
    /// An imported host: it has no identity to revoke.
    Imported,
}

const SELECT: &str = "SELECT a.agent_id, a.status, a.enrolled_at, a.revoked_at, a.last_seen_at,
        a.scanner_version,
        (SELECT count(*) FROM certificates c WHERE c.agent_id = a.agent_id),
        a.claimed_agent_id, a.health, a.health_previous, a.health_at
    FROM agents a";

fn info(row: &tokio_postgres::Row) -> AgentInfo {
    AgentInfo {
        agent_id: row.get(0),
        status: row.get(1),
        enrolled_at: row.get(2),
        revoked_at: row.get(3),
        last_seen_at: row.get(4),
        scanner_version: row.get(5),
        certificates: row.get(6),
        claimed_agent_id: row.get(7),
        // A report that does not parse counts as absent.
        health: row
            .get::<_, Option<serde_json::Value>>(8)
            .and_then(|value| serde_json::from_value(value).ok()),
        health_previous: row
            .get::<_, Option<serde_json::Value>>(9)
            .and_then(|value| serde_json::from_value(value).ok()),
        health_at: row.get(10),
    }
}

/// Agents matching `filter`, ordered by id.
pub async fn list(
    client: &Client,
    filter: Filter,
    now: DateTime<Utc>,
) -> Result<Vec<AgentInfo>, StoreError> {
    let offline_before = now - Duration::minutes(OFFLINE_AFTER_MINUTES);
    let rows = match filter {
        Filter::All => {
            client
                .query(&format!("{SELECT} ORDER BY a.agent_id"), &[])
                .await?
        }
        Filter::Revoked | Filter::Imported => {
            let status = if filter == Filter::Revoked {
                "revoked"
            } else {
                "imported"
            };
            client
                .query(
                    &format!("{SELECT} WHERE a.status = $1 ORDER BY a.agent_id"),
                    &[&status],
                )
                .await?
        }
        Filter::Offline => {
            client
                .query(
                    &format!(
                        "{SELECT} WHERE a.status = 'active'
                         AND (a.last_seen_at IS NULL OR a.last_seen_at < $1) ORDER BY a.agent_id"
                    ),
                    &[&offline_before],
                )
                .await?
        }
    };
    Ok(rows.iter().map(info).collect())
}

/// One agent, or `None` if unknown.
pub async fn show(client: &Client, agent_id: &str) -> Result<Option<AgentInfo>, StoreError> {
    let row = client
        .query_opt(&format!("{SELECT} WHERE a.agent_id = $1"), &[&agent_id])
        .await?;
    Ok(row.as_ref().map(info))
}

/// Revokes an active agent; its next request is refused with
/// `identity_revoked`.
pub async fn revoke(
    client: &Client,
    agent_id: &str,
    now: DateTime<Utc>,
) -> Result<Revoke, StoreError> {
    let changed = client
        .execute(
            "UPDATE agents SET status = 'revoked', revoked_at = $2
             WHERE agent_id = $1 AND status = 'active'",
            &[&agent_id, &now],
        )
        .await?;
    if changed == 1 {
        return Ok(Revoke::Revoked);
    }
    let status: Option<String> = client
        .query_opt(
            "SELECT status FROM agents WHERE agent_id = $1",
            &[&agent_id],
        )
        .await?
        .map(|row| row.get(0));
    Ok(match status.as_deref() {
        None => Revoke::Unknown,
        Some("imported") => Revoke::Imported,
        Some(_) => Revoke::AlreadyRevoked,
    })
}
