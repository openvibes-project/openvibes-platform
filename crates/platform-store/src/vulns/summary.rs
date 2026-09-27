//! Fleet-wide counts of open vulnerabilities, aggregated in SQL.

use crate::{Client, StoreError};

/// Open vulnerabilities across the fleet.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Summary {
    /// Open count per severity, most severe first.
    pub by_severity: Vec<(String, i64)>,
    /// Hosts with at least one open.
    pub hosts: i64,
    /// Hosts with the most open: (agent id, hostname, open, critical+important).
    pub top_hosts: Vec<(String, Option<String>, i64, i64)>,
    /// Hosts whose only missing step is a reboot into an installed kernel
    /// fix; those are a state of their own, not counted as open.
    pub reboot_hosts: i64,
    /// Open ones where no affected package has a fixed version yet.
    pub no_fix: i64,
    /// Open ones (reboot-needed excluded) with a CVE on KEV or EUVD's list.
    pub exploited: i64,
}

/// Counts open vulnerabilities from each host's stored counts (refreshed
/// when it is matched); only "exploited" is counted live, because KEV and
/// EUVD change without a re-match, starting from the few exploited
/// advisories.
pub async fn summary(client: &Client) -> Result<Summary, StoreError> {
    summary_for_agents(client, None).await
}

/// Counts open vulnerabilities for hosts in a console asset scope. Only
/// precomputed per-host counters for visible agents are aggregated; exploited
/// state remains live because enrichment feeds can change without a rematch.
pub async fn summary_in_scope(
    client: &Client,
    scope: &crate::console_read::AgentScope,
) -> Result<Summary, StoreError> {
    let agents = match scope {
        crate::console_read::AgentScope::Global => None,
        _ => Some(crate::console_read::agent_ids_in_scope(client, scope).await?),
    };
    summary_for_agents(client, agents.as_deref()).await
}

async fn summary_for_agents(
    client: &Client,
    agents: Option<&[String]>,
) -> Result<Summary, StoreError> {
    let totals = client
        .query_one(
            "SELECT COALESCE(sum(critical), 0)::bigint, COALESCE(sum(important), 0)::bigint,
                    COALESCE(sum(moderate), 0)::bigint, COALESCE(sum(low), 0)::bigint,
                    COALESCE(sum(unrated), 0)::bigint,
                    count(*) FILTER (WHERE critical + important + moderate + low + unrated > 0),
                    count(*) FILTER (WHERE reboot > 0),
                    COALESCE(sum(no_fix), 0)::bigint
             FROM host_vulnerability_counts
             WHERE ($1::text[] IS NULL OR agent_id = ANY($1))",
            &[&agents],
        )
        .await?;
    let by_severity = ["critical", "important", "moderate", "low", "unrated"]
        .iter()
        .enumerate()
        .map(|(i, severity)| ((*severity).to_owned(), totals.get::<_, i64>(i)))
        .filter(|(_, count)| *count > 0)
        .collect();
    let top_hosts = client
        .query(
            "SELECT c.agent_id, g.hostname,
                    (c.critical + c.important + c.moderate + c.low + c.unrated)::bigint,
                    (c.critical + c.important)::bigint
             FROM host_vulnerability_counts c JOIN agents g ON g.agent_id = c.agent_id
             WHERE c.critical + c.important + c.moderate + c.low + c.unrated > 0
               AND ($1::text[] IS NULL OR c.agent_id = ANY($1))
             ORDER BY 4 DESC, 3 DESC, 1 LIMIT 10",
            &[&agents],
        )
        .await?
        .iter()
        .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3)))
        .collect();
    let exploited: i64 = client
        .query_one(
            "SELECT count(*) FROM vulnerabilities v
             WHERE v.fixed_at IS NULL AND NOT v.reboot_needed
               AND ($1::text[] IS NULL OR v.agent_id = ANY($1))
               AND v.advisory_id = ANY(ARRAY(
                   SELECT DISTINCT c.advisory_id FROM advisory_cves c
                   JOIN cve_enrichment x ON x.cve_id = c.cve_id
                   WHERE x.kev_added IS NOT NULL OR x.euvd_exploited))",
            &[&agents],
        )
        .await?
        .get(0);
    Ok(Summary {
        by_severity,
        hosts: totals.get(5),
        top_hosts,
        reboot_hosts: totals.get(6),
        exploited,
        no_fix: totals.get(7),
    })
}

/// Host and advisory pairs without a fix yet on one release, as last
/// counted.
pub async fn no_fix_count(
    client: &Client,
    os_id: &str,
    os_release: &str,
) -> Result<i64, StoreError> {
    no_fix_count_for_agents(client, os_id, os_release, None).await
}

/// Counts packages without a known fix for one OS release and console scope.
pub async fn no_fix_count_in_scope(
    client: &Client,
    os_id: &str,
    os_release: &str,
    scope: &crate::console_read::AgentScope,
) -> Result<i64, StoreError> {
    let agents = match scope {
        crate::console_read::AgentScope::Global => None,
        _ => Some(crate::console_read::agent_ids_in_scope(client, scope).await?),
    };
    no_fix_count_for_agents(client, os_id, os_release, agents.as_deref()).await
}

async fn no_fix_count_for_agents(
    client: &Client,
    os_id: &str,
    os_release: &str,
    agents: Option<&[String]>,
) -> Result<i64, StoreError> {
    Ok(client
        .query_one(
            "SELECT COALESCE(sum(c.no_fix), 0)::bigint FROM host_vulnerability_counts c
             JOIN agents g ON g.agent_id = c.agent_id
             WHERE g.os_id = $1 AND g.os_release = $2
               AND ($3::text[] IS NULL OR c.agent_id = ANY($3))",
            &[&os_id, &os_release, &agents],
        )
        .await?
        .get(0))
}

/// Recounts these hosts' open vulnerabilities by severity, their
/// reboot-needed ones, and the advisories without a fix among the package
/// versions they have, and stores the counts.
pub async fn refresh_counts(
    client: &Client,
    agents: &[String],
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), StoreError> {
    client
        .execute(
            "INSERT INTO host_vulnerability_counts (agent_id, no_fix, critical, important,
                 moderate, low, unrated, reboot, counted_at)
             SELECT h.agent_id, COALESCE(n.count, 0),
                    COALESCE(o.critical, 0), COALESCE(o.important, 0), COALESCE(o.moderate, 0),
                    COALESCE(o.low, 0), COALESCE(o.unrated, 0), COALESCE(o.reboot, 0), $2
             FROM unnest($1::text[]) AS h(agent_id)
             LEFT JOIN (SELECT hp.agent_id, count(DISTINCT vv.advisory_id)::int AS count
                        FROM host_packages hp
                        JOIN version_vulnerabilities vv
                          ON vv.package_version_id = hp.package_version_id
                        WHERE hp.agent_id = ANY($1)
                        GROUP BY hp.agent_id) n ON n.agent_id = h.agent_id
             LEFT JOIN (SELECT v.agent_id,
                            (count(*) FILTER (WHERE NOT v.reboot_needed AND a.severity = 'critical'))::int AS critical,
                            (count(*) FILTER (WHERE NOT v.reboot_needed AND a.severity = 'important'))::int AS important,
                            (count(*) FILTER (WHERE NOT v.reboot_needed AND a.severity = 'moderate'))::int AS moderate,
                            (count(*) FILTER (WHERE NOT v.reboot_needed AND a.severity = 'low'))::int AS low,
                            (count(*) FILTER (WHERE NOT v.reboot_needed AND a.severity = 'unrated'))::int AS unrated,
                            (count(*) FILTER (WHERE v.reboot_needed))::int AS reboot
                        FROM vulnerabilities v JOIN advisories a ON a.advisory_id = v.advisory_id
                        WHERE v.agent_id = ANY($1) AND v.fixed_at IS NULL
                        GROUP BY v.agent_id) o ON o.agent_id = h.agent_id
             ON CONFLICT (agent_id) DO UPDATE SET no_fix = EXCLUDED.no_fix,
                 critical = EXCLUDED.critical, important = EXCLUDED.important,
                 moderate = EXCLUDED.moderate, low = EXCLUDED.low, unrated = EXCLUDED.unrated,
                 reboot = EXCLUDED.reboot, counted_at = EXCLUDED.counted_at",
            &[&agents, &now],
        )
        .await?;
    Ok(())
}
