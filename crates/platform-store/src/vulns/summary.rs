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

/// Counts open vulnerabilities (aggregated in SQL, so any fleet size).
pub async fn summary(client: &Client) -> Result<Summary, StoreError> {
    let by_severity = client
        .query(
            "SELECT a.severity, count(*) FROM vulnerabilities v
             JOIN advisories a ON a.advisory_id = v.advisory_id
             WHERE v.fixed_at IS NULL AND NOT v.reboot_needed GROUP BY a.severity
             ORDER BY array_position(ARRAY['critical','important','moderate','low','unrated'],
                          a.severity)",
            &[],
        )
        .await?
        .iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect();
    let hosts = client
        .query_one(
            "SELECT count(DISTINCT agent_id) FILTER (WHERE NOT reboot_needed),
                    count(DISTINCT agent_id) FILTER (WHERE reboot_needed)
             FROM vulnerabilities WHERE fixed_at IS NULL",
            &[],
        )
        .await?;
    let top_hosts = client
        .query(
            "SELECT v.agent_id, g.hostname, count(*),
                    count(*) FILTER (WHERE a.severity IN ('critical', 'important'))
             FROM vulnerabilities v
             JOIN advisories a ON a.advisory_id = v.advisory_id
             JOIN agents g ON g.agent_id = v.agent_id
             WHERE v.fixed_at IS NULL AND NOT v.reboot_needed
             GROUP BY v.agent_id, g.hostname ORDER BY 4 DESC, 3 DESC, 1 LIMIT 10",
            &[],
        )
        .await?
        .iter()
        .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3)))
        .collect();
    let exploited: i64 = client
        .query_one(
            "SELECT count(*) FROM vulnerabilities v
             WHERE v.fixed_at IS NULL AND NOT v.reboot_needed
               AND EXISTS (SELECT 1 FROM advisory_cves c
                   JOIN cve_enrichment x ON x.cve_id = c.cve_id
                   WHERE c.advisory_id = v.advisory_id
                     AND (x.kev_added IS NOT NULL OR x.euvd_exploited))",
            &[],
        )
        .await?
        .get(0);
    let no_fix: i64 = client
        .query_one(
            "SELECT count(*) FROM vulnerabilities v
             WHERE v.fixed_at IS NULL AND NOT v.reboot_needed
               AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(v.packages) p
                               WHERE p->>'fixed' IS NOT NULL)",
            &[],
        )
        .await?
        .get(0);
    Ok(Summary {
        by_severity,
        hosts: hosts.get(0),
        top_hosts,
        reboot_hosts: hosts.get(1),
        exploited,
        no_fix,
    })
}
