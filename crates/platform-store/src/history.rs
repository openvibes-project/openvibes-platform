//! Daily per-host problem counts for the console's graphs (spec
//! 2026-10-07-overview-clarity-design §5). One query computes the counts;
//! maintenance stores them, the console sums them over visible hosts.

use chrono::{DateTime, Duration, NaiveDate, Utc};
use tokio_postgres::Client;

use crate::{StoreError, status::OFFLINE_AFTER_MINUTES};

/// The 16 count columns in table order, then `status` and `agent_id`.
pub const COLUMNS: [&str; 18] = [
    "alarms_critical",
    "alarms_high",
    "alarms_medium",
    "alarms_low",
    "alarms_info",
    "vulns_critical",
    "vulns_high",
    "vulns_medium",
    "vulns_low",
    "vulns_exploited",
    "vulns_no_fix",
    "needs_reboot",
    "compliance_critical",
    "compliance_high",
    "compliance_medium",
    "compliance_low",
    "status",
    "agent_id",
];

/// Current counts per host; `$1` is the "seen since" threshold. Definitions
/// match the console summaries and lists: active alarms are open or
/// investigating, of every severity (`info` has its own column), vulnerabilities
/// map important to high and moderate to medium (unrated is in no count),
/// exploited is live. Each kind is one grouped scan joined on `agent_id`: a
/// per-agent lateral probes every daily alarm partition once per host.
// ponytail: still a live count over every host per request; if it gets slow,
// let current() compute only the kinds the requested metric needs.
const HOST_COUNTS_SQL: &str = "
SELECT a.agent_id,
       CASE WHEN a.status IN ('revoked', 'imported') THEN a.status
            WHEN agent_seen_at(a.agent_id, a.last_seen_at) >= $1 THEN 'active'
            ELSE 'stale' END AS status,
       COALESCE(al.c, 0)::int AS alarms_critical, COALESCE(al.h, 0)::int AS alarms_high,
       COALESCE(al.m, 0)::int AS alarms_medium, COALESCE(al.l, 0)::int AS alarms_low,
       COALESCE(al.i, 0)::int AS alarms_info,
       COALESCE(v.critical, 0)::int AS vulns_critical, COALESCE(v.important, 0)::int AS vulns_high,
       COALESCE(v.moderate, 0)::int AS vulns_medium, COALESCE(v.low, 0)::int AS vulns_low,
       COALESCE(x.n, 0)::int AS vulns_exploited, COALESCE(v.no_fix, 0)::int AS vulns_no_fix,
       COALESCE(v.reboot, 0) > 0 AS needs_reboot,
       COALESCE(f.c, 0)::int AS compliance_critical, COALESCE(f.h, 0)::int AS compliance_high,
       COALESCE(f.m, 0)::int AS compliance_medium, COALESCE(f.l, 0)::int AS compliance_low
FROM agents a
LEFT JOIN (
    SELECT agent_id,
           count(*) FILTER (WHERE severity = 'critical') c, count(*) FILTER (WHERE severity = 'high') h,
           count(*) FILTER (WHERE severity = 'medium') m, count(*) FILTER (WHERE severity = 'low') l,
           count(*) FILTER (WHERE severity = 'info') i
    FROM alarms WHERE state IN ('open', 'investigating') GROUP BY agent_id) al ON al.agent_id = a.agent_id
LEFT JOIN host_vulnerability_counts v ON v.agent_id = a.agent_id
LEFT JOIN (
    SELECT agent_id, count(*) n FROM vulnerabilities
    WHERE fixed_at IS NULL AND NOT reboot_needed
      AND advisory_id = ANY(ARRAY(
          SELECT DISTINCT c.advisory_id FROM advisory_cves c
          JOIN cve_enrichment e ON e.cve_id = c.cve_id
          WHERE e.kev_added IS NOT NULL OR e.euvd_exploited))
    GROUP BY agent_id) x ON x.agent_id = a.agent_id
LEFT JOIN (
    SELECT agent_id,
           count(*) FILTER (WHERE severity = 'critical') c, count(*) FILTER (WHERE severity = 'high') h,
           count(*) FILTER (WHERE severity = 'medium') m, count(*) FILTER (WHERE severity = 'low') l
    FROM current_findings GROUP BY agent_id) f ON f.agent_id = a.agent_id";

/// How a metric is computed from one day's rows.
pub enum Expr {
    /// Sum of these count columns.
    Sum(&'static [&'static str]),
    /// Number of hosts matching this condition on the row (fixed strings
    /// from the catalogue, never user input).
    HostsWhere(&'static str),
}

impl Expr {
    fn select(&self) -> String {
        match self {
            Self::Sum(cols) => format!("COALESCE(sum({}), 0)::bigint", cols.join(" + ")),
            Self::HostsWhere(cond) => format!("count(*) FILTER (WHERE {cond})"),
        }
    }
}

fn threshold(now: DateTime<Utc>) -> DateTime<Utc> {
    now - Duration::minutes(OFFLINE_AFTER_MINUTES)
}

/// Stores every host's current counts under `day`, replacing that day. The
/// replace is one transaction: a failure leaves the previous rows intact.
pub async fn record(
    client: &mut Client,
    day: NaiveDate,
    now: DateTime<Utc>,
) -> Result<u64, StoreError> {
    let tx = client.transaction().await?;
    // Overlapping runs queue here; under READ COMMITTED the second would
    // otherwise miss the first's new rows and hit the primary key.
    tx.batch_execute("LOCK TABLE host_daily_counts IN SHARE ROW EXCLUSIVE MODE")
        .await?;
    tx.execute("DELETE FROM host_daily_counts WHERE day = $1", &[&day])
        .await?;
    let cols = COLUMNS[..16].join(", ");
    let n = tx
        .execute(
            &format!(
                "INSERT INTO host_daily_counts (day, agent_id, status, {cols})
                 SELECT $2::date, agent_id, status, {cols} FROM ({HOST_COUNTS_SQL}) h"
            ),
            &[&threshold(now), &day],
        )
        .await?;
    tx.commit().await?;
    Ok(n)
}

/// Removes every stored day before `cutoff`.
pub async fn delete_before(client: &Client, cutoff: NaiveDate) -> Result<u64, StoreError> {
    Ok(client
        .execute("DELETE FROM host_daily_counts WHERE day < $1", &[&cutoff])
        .await?)
}

/// Stored days from `since`, oldest first, summed over `agents` (all when
/// `None`). A day with no visible host has no row: a gap, by design.
pub async fn series(
    client: &Client,
    expr: &Expr,
    since: NaiveDate,
    agents: Option<&[String]>,
) -> Result<Vec<(NaiveDate, i64)>, StoreError> {
    let rows = client
        .query(
            &format!(
                "SELECT day, {} FROM host_daily_counts
                 WHERE day >= $1 AND ($2::text[] IS NULL OR agent_id = ANY($2))
                 GROUP BY day ORDER BY day",
                expr.select()
            ),
            &[&since, &agents],
        )
        .await?;
    Ok(rows.iter().map(|r| (r.get(0), r.get(1))).collect())
}

/// Today's value, live, from the same per-host query.
pub async fn current(
    client: &Client,
    expr: &Expr,
    now: DateTime<Utc>,
    agents: Option<&[String]>,
) -> Result<i64, StoreError> {
    Ok(client
        .query_one(
            &format!(
                "SELECT {} FROM ({HOST_COUNTS_SQL}) h
                 WHERE ($2::text[] IS NULL OR agent_id = ANY($2))",
                expr.select()
            ),
            &[&threshold(now), &agents],
        )
        .await?
        .get(0))
}

/// A host with open problems, for the "Most exposed hosts" list.
#[derive(Clone, Debug)]
pub struct TopHost {
    /// The host's agent id.
    pub agent_id: String,
    /// Its reported hostname, if any.
    pub hostname: Option<String>,
    /// Critical plus high, across alarms, vulnerabilities and compliance.
    pub serious: i64,
    /// Every open problem of those kinds (info alarms excluded).
    pub open: i64,
}

/// Hosts ranked by serious problems, then by all open problems, then id;
/// hosts with none are left out. `agents` limits the hosts as in [`series`].
pub async fn top_hosts(
    client: &Client,
    now: DateTime<Utc>,
    limit: i64,
    agents: Option<&[String]>,
) -> Result<Vec<TopHost>, StoreError> {
    let rows = client
        .query(
            &format!(
                "SELECT * FROM (
                   SELECT h.agent_id, a.hostname,
                          (alarms_critical + alarms_high + vulns_critical + vulns_high
                           + compliance_critical + compliance_high)::bigint AS serious,
                          (alarms_critical + alarms_high + alarms_medium + alarms_low
                           + vulns_critical + vulns_high + vulns_medium + vulns_low
                           + compliance_critical + compliance_high + compliance_medium
                           + compliance_low)::bigint AS open
                   FROM ({HOST_COUNTS_SQL}) h JOIN agents a USING (agent_id)
                   WHERE ($2::text[] IS NULL OR h.agent_id = ANY($2))) t
                 WHERE open > 0
                 ORDER BY serious DESC, open DESC, agent_id LIMIT $3"
            ),
            &[&threshold(now), &agents, &limit],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| TopHost {
            agent_id: r.get(0),
            hostname: r.get(1),
            serious: r.get(2),
            open: r.get(3),
        })
        .collect())
}
