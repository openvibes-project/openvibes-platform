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
    /// When an advisory feed last imported new content; `None` until one
    /// has, so zero counts can be told from "no feed yet". Enrichment
    /// feeds (`os_id = 'cve'`) don't count: they alone match nothing.
    pub feed_last_imported_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Counts open vulnerabilities from each host's stored counts, one per CVE
/// (refreshed when it is matched, and when enrichment changes: #590).
pub async fn summary(client: &Client) -> Result<Summary, StoreError> {
    summary_for_agents(client, None).await
}

/// Counts open vulnerabilities for hosts in a console asset scope, from the
/// visible agents' stored per-host counts.
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
            "SELECT COALESCE(sum(exploited), 0)::bigint FROM host_vulnerability_counts
             WHERE ($1::text[] IS NULL OR agent_id = ANY($1))",
            &[&agents],
        )
        .await?
        .get(0);
    let feed_last_imported_at = client
        .query_one(
            "SELECT max(last_changed_at) FROM feed_sources WHERE os_id <> 'cve'",
            &[],
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
        feed_last_imported_at,
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

/// Each host's open vulnerabilities in `$1` (agent ids), one row per host
/// and CVE (an advisory naming none is its own key), as the Vulnerabilities
/// list counts them by default (#590): fixable pairs whose triage is open
/// (an expired accepted risk is open again) from a known distribution's
/// advisory, pairs without a fix yet through the host's package versions,
/// and CPE matches of confidence 80 or more; reboot-pending pairs count.
/// `sev` is the CVE's severity (#622), `exploited` whether KEV or EUVD
/// lists it. `$2` is now.
pub(crate) const OPEN_KEYS: &str = "
SELECT k.agent_id, k.key,
       openvibes_severity(max(k.cvss), (ARRAY['critical','important','moderate','low','unrated'])[
           min(array_position(ARRAY['critical','important','moderate','low','unrated'], k.rated))]) AS sev,
       bool_or(k.exploited) AS exploited
FROM (
    SELECT v.agent_id, COALESCE(ac.cve_id, v.advisory_id) AS key, x.cvss_score AS cvss, a.severity AS rated,
           COALESCE(x.kev_added IS NOT NULL OR x.euvd_exploited, false) AS exploited
    FROM vulnerabilities v JOIN advisories a ON a.advisory_id = v.advisory_id
    LEFT JOIN advisory_cves ac ON ac.advisory_id = v.advisory_id
    LEFT JOIN cve_enrichment x ON x.cve_id = ac.cve_id
    WHERE v.agent_id = ANY($1) AND v.fixed_at IS NULL
      AND split_part(a.source, '-', 1) IN ('fedora', 'debian', 'ubuntu', 'rocky', 'almalinux')
      AND NOT EXISTS (
          SELECT 1 FROM vulnerability_triage t
          WHERE t.agent_id = v.agent_id AND t.advisory_id = v.advisory_id
            AND (t.state IN ('mitigated', 'false_positive')
                 OR (t.state = 'accepted_risk' AND t.accepted_until > $2)))
    UNION ALL
    SELECT hp.agent_id, COALESCE(ac.cve_id, vv.advisory_id), x.cvss_score, a.severity,
           COALESCE(x.kev_added IS NOT NULL OR x.euvd_exploited, false)
    FROM host_packages hp JOIN agents g ON g.agent_id = hp.agent_id
    JOIN version_vulnerabilities vv ON vv.package_version_id = hp.package_version_id
    JOIN advisories a ON a.advisory_id = vv.advisory_id AND a.os_id = g.os_id AND a.os_version = g.os_release
    LEFT JOIN advisory_cves ac ON ac.advisory_id = vv.advisory_id
    LEFT JOIN cve_enrichment x ON x.cve_id = ac.cve_id
    WHERE hp.agent_id = ANY($1)
    UNION ALL
    SELECT hp.agent_id, f.cve_id, f.cvss, NULL,
           COALESCE(x.kev_added IS NOT NULL OR x.euvd_exploited, false)
    FROM host_packages hp JOIN agents g ON g.agent_id = hp.agent_id
    JOIN cpe_findings f ON f.package_version_id = hp.package_version_id AND f.os_version = g.os_release
    LEFT JOIN cve_enrichment x ON x.cve_id = f.cve_id
    WHERE hp.agent_id = ANY($1) AND f.confidence >= 80
) k
GROUP BY k.agent_id, k.key";

/// Recounts these hosts' open vulnerabilities, one per CVE (as the list):
/// per severity, exploited, reboot-needed pairs, and advisories without a
/// fix among their package versions; stores them, and the Hosts list's
/// critical count with them.
pub async fn refresh_counts(
    client: &Client,
    agents: &[String],
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), StoreError> {
    client
        .execute(
            &format!(
                "WITH k AS ({OPEN_KEYS}),
                 o AS (SELECT agent_id,
                              (count(*) FILTER (WHERE sev = 'critical'))::int AS critical,
                              (count(*) FILTER (WHERE sev = 'important'))::int AS important,
                              (count(*) FILTER (WHERE sev = 'moderate'))::int AS moderate,
                              (count(*) FILTER (WHERE sev = 'low'))::int AS low,
                              (count(*) FILTER (WHERE sev = 'unrated'))::int AS unrated,
                              (count(*) FILTER (WHERE exploited))::int AS exploited
                       FROM k GROUP BY agent_id),
                 n AS (SELECT hp.agent_id, count(DISTINCT vv.advisory_id)::int AS count
                       FROM host_packages hp
                       JOIN version_vulnerabilities vv ON vv.package_version_id = hp.package_version_id
                       WHERE hp.agent_id = ANY($1) GROUP BY hp.agent_id),
                 r AS (SELECT v.agent_id, count(*)::int AS reboot FROM vulnerabilities v
                       WHERE v.agent_id = ANY($1) AND v.fixed_at IS NULL AND v.reboot_needed
                       GROUP BY v.agent_id)
                 INSERT INTO host_vulnerability_counts (agent_id, no_fix, critical, important,
                     moderate, low, unrated, reboot, exploited, counted_at)
                 SELECT h.agent_id, COALESCE(n.count, 0),
                        COALESCE(o.critical, 0), COALESCE(o.important, 0), COALESCE(o.moderate, 0),
                        COALESCE(o.low, 0), COALESCE(o.unrated, 0), COALESCE(r.reboot, 0),
                        COALESCE(o.exploited, 0), $2
                 FROM unnest($1::text[]) AS h(agent_id)
                 LEFT JOIN o ON o.agent_id = h.agent_id
                 LEFT JOIN n ON n.agent_id = h.agent_id
                 LEFT JOIN r ON r.agent_id = h.agent_id
                 ON CONFLICT (agent_id) DO UPDATE SET no_fix = EXCLUDED.no_fix,
                     critical = EXCLUDED.critical, important = EXCLUDED.important,
                     moderate = EXCLUDED.moderate, low = EXCLUDED.low, unrated = EXCLUDED.unrated,
                     reboot = EXCLUDED.reboot, exploited = EXCLUDED.exploited,
                     counted_at = EXCLUDED.counted_at"
            ),
            &[&agents, &now],
        )
        .await?;
    // The Hosts list's critical count (`host_listed_critical`, migration 58)
    // is the same count since #590. One upsert: a DELETE then INSERT pair
    // let two concurrent recounts of one host collide or briefly show 0.
    client
        .execute(
            "INSERT INTO host_listed_critical (agent_id, critical)
             SELECT agent_id, critical FROM host_vulnerability_counts WHERE agent_id = ANY($1)
             ON CONFLICT (agent_id) DO UPDATE SET critical = EXCLUDED.critical",
            &[&agents],
        )
        .await?;
    Ok(())
}

/// Recounts the hosts [`stale_counts`] names, `batch` at a time so a large
/// fleet doesn't hold one long query; how many there were.
pub async fn recount_stale(
    client: &Client,
    batch: usize,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<usize, StoreError> {
    let stale = stale_counts(client).await?;
    for hosts in stale.chunks(batch.max(1)) {
        refresh_counts(client, hosts, now).await?;
    }
    Ok(stale.len())
}

/// Hosts whose counts are older than the last change to `cve_enrichment`
/// (migration 80): a CVSS score or a KEV or EUVD listing changed what they
/// count, without a re-match.
pub async fn stale_counts(client: &Client) -> Result<Vec<String>, StoreError> {
    Ok(client
        .query(
            "SELECT c.agent_id FROM host_vulnerability_counts c, enrichment_changed e
             WHERE c.counted_at < e.changed_at ORDER BY c.agent_id",
            &[],
        )
        .await?
        .iter()
        .map(|row| row.get(0))
        .collect())
}

/// Rates advisories their distribution left `unrated` from their CVEs'
/// highest CVSS score, with the bands the Vulnerabilities list uses for
/// upstream matches: 9 and over critical, 7 important, 4 moderate, above 0
/// low (#579). Advisories with no score stay `unrated`. Returns the hosts
/// with an open match of an advisory it rated: their counts are stale.
// ponytail: a feed import writes `unrated` back until the next run, at most the vulns service's rating interval later.
pub async fn rate_unrated(client: &Client) -> Result<Vec<String>, StoreError> {
    let rows = client
        .query(
            "WITH rated AS (
               UPDATE advisories a
               SET severity = CASE WHEN s.score >= 9 THEN 'critical'
                                   WHEN s.score >= 7 THEN 'important'
                                   WHEN s.score >= 4 THEN 'moderate' ELSE 'low' END
               FROM (SELECT ac.advisory_id, max(x.cvss_score) AS score
                     FROM advisories u
                     JOIN advisory_cves ac ON ac.advisory_id = u.advisory_id
                     JOIN cve_enrichment x ON x.cve_id = ac.cve_id
                     WHERE u.severity = 'unrated' AND x.cvss_score > 0
                     GROUP BY ac.advisory_id) s
               WHERE a.advisory_id = s.advisory_id AND a.severity = 'unrated'
               RETURNING a.advisory_id)
             SELECT DISTINCT v.agent_id
             FROM vulnerabilities v JOIN rated r ON r.advisory_id = v.advisory_id
             WHERE v.fixed_at IS NULL",
            &[],
        )
        .await?;
    Ok(rows.iter().map(|row| row.get(0)).collect())
}
