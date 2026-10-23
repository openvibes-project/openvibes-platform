//! The Hosts table of a vulnerability's page (step 5b ruling 9): its pairs
//! in reach, one row per host and covering advisory, by segment and page.

use chrono::{DateTime, NaiveDate, Utc};
use serde::Deserialize;

use crate::{
    Client, StoreError, console_read::AgentScope, host_list::values, vuln_summary::Lookup,
    vuln_summary_sql as sql, vuln_summary_sql::resolve,
};

values!(
    /// A Hosts card segment (ruling 9).
    HostSegment {
        /// Every pair.
        All = "all",
        /// Triage open, not fixed.
        Open = "open",
        /// Mitigated.
        Mitigated = "mitigated",
        /// Fixed by an update, accepted risk or false positive.
        Resolved = "resolved",
    }
);

/// One row of the Hosts table: a host and covering advisory.
#[derive(Clone, Debug)]
pub struct VulnHostRow {
    /// The host.
    pub agent_id: String,
    /// Its name.
    pub hostname: Option<String>,
    /// Its distribution, as the Hosts list names it.
    pub os: Option<String>,
    /// Its last address.
    pub address: Option<String>,
    /// The installed versions, comma-separated.
    pub installed: String,
    /// open, mitigated, accepted_risk, false_positive or resolved.
    pub state: String,
    /// (user id, display name).
    pub assignee: Option<(String, String)>,
    /// The covering advisory.
    pub advisory_id: String,
    /// The triage version for If-Match; none where triage does not apply
    /// (no fixable row, a CPE match, or fixed by an update).
    pub triage_version: Option<i64>,
    /// The fix is installed and waits for a reboot.
    pub reboot_needed: bool,
    /// When the pair was first seen.
    pub first_seen: DateTime<Utc>,
}

/// Pairs per segment.
#[derive(Clone, Copy, Debug, Default, Deserialize)]
pub struct Segments {
    /// Every pair.
    pub all: i64,
    /// Open.
    pub open: i64,
    /// Mitigated.
    pub mitigated: i64,
    /// Resolved.
    pub resolved: i64,
}

/// One page of the Hosts table.
#[derive(Clone, Debug)]
pub struct VulnHostsPage {
    /// The page, by host name then agent id.
    pub rows: Vec<VulnHostRow>,
    /// Pairs in the chosen segment.
    pub total: i64,
    /// Every segment's count.
    pub segments: Segments,
}

/// One page of `key`'s Hosts table within `scope`: `segment`, `offset`
/// (0–100000) and `limit` (1–100).
pub async fn vuln_hosts(
    client: &Client,
    key: &str,
    scope: &AgentScope,
    segment: HostSegment,
    offset: i64,
    limit: i64,
    today: NaiveDate,
) -> Result<Lookup<VulnHostsPage>, StoreError> {
    let t = match resolve(client, key, scope, today).await? {
        Lookup::Found(t) => t,
        Lookup::Missing => return Ok(Lookup::Missing),
        Lookup::SeveralCves(c) => return Ok(Lookup::SeveralCves(c)),
    };
    let rows = client
        .query(
            &sql::hosts(),
            &[
                &scope.is_global(),
                &scope.group_ids(),
                &t.advisories,
                &t.cve,
                &today,
                &segment.as_str(),
                &limit.clamp(1, 100),
                &offset.clamp(0, 100_000),
            ],
        )
        .await?;
    let counts: serde_json::Value = rows.first().map(|r| r.get(0)).unwrap_or_default();
    let segments: Segments = serde_json::from_value(counts).map_err(|_| StoreError::Query)?;
    if segments.all == 0 {
        return Ok(Lookup::Missing);
    }
    Ok(Lookup::Found(VulnHostsPage {
        total: match segment {
            HostSegment::All => segments.all,
            HostSegment::Open => segments.open,
            HostSegment::Mitigated => segments.mitigated,
            HostSegment::Resolved => segments.resolved,
        },
        segments,
        rows: rows
            .iter()
            .filter_map(|r| {
                let agent_id: String = r.get::<_, Option<String>>(1)?;
                let assignee: Option<String> = r.get(7);
                Some(VulnHostRow {
                    agent_id,
                    hostname: r.get(2),
                    os: r.get(3),
                    address: r.get(4),
                    installed: r.get::<_, Option<String>>(5).unwrap_or_default(),
                    state: r.get(6),
                    assignee: assignee.map(|id| (id, r.get(8))),
                    advisory_id: r.get(9),
                    triage_version: r.get(10),
                    reboot_needed: r.get(11),
                    first_seen: r.get(12),
                })
            })
            .collect(),
    }))
}
