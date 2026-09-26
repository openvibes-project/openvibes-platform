//! Read-only lookups for the console's assistant (assistant spec §5).
//!
//! Every query takes an [`AgentScope`](crate::assistant::AgentScope) applied in SQL, so nothing outside
//! the asking user's scope is read, counted, or summarised, and a `limit`,
//! so results stay small enough for a model prompt. Each page reports how
//! many matching items exist in total, so callers can say how much was left
//! out. Nothing here writes.

use chrono::{DateTime, Utc};

use crate::{Client, StoreError};

/// Which agents a lookup may see. The console resolves a user's asset
/// scope to this before calling.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentScope {
    /// Every agent (a globally authorised user).
    All,
    /// Only these agents.
    Only(Vec<String>),
}

impl AgentScope {
    /// The SQL parameter: `NULL` for every agent, else the allowed IDs.
    fn param(&self) -> Option<&[String]> {
        match self {
            Self::All => None,
            Self::Only(ids) => Some(ids),
        }
    }
}

/// Finding severities from lowest to highest (protocol `Severity`).
pub const FINDING_SEVERITIES: [&str; 5] = ["info", "low", "medium", "high", "critical"];
/// Advisory severities from highest to lowest (vulnerability spec).
pub const ADVISORY_SEVERITIES: [&str; 5] = ["critical", "important", "moderate", "low", "unrated"];

/// Escapes `%`, `_`, and `\` for a `LIKE` pattern and wraps it in `%`.
fn contains_pattern(text: &str) -> String {
    let mut pattern = String::from("%");
    for c in text.chars() {
        if matches!(c, '%' | '_' | '\\') {
            pattern.push('\\');
        }
        pattern.push(c);
    }
    pattern.push('%');
    pattern
}

fn limit_param(limit: u32) -> i64 {
    i64::from(limit.clamp(1, 100))
}

/// Filters for [`finding_groups`].
#[derive(Clone, Debug, Default)]
pub struct GroupFilter<'a> {
    /// Case-insensitive text in the rule set, rule, or latest message.
    pub text: Option<&'a str>,
    /// Lowest severity included (one of [`FINDING_SEVERITIES`]).
    pub min_severity: Option<&'a str>,
    /// One rule set.
    pub rule_set_id: Option<&'a str>,
}

/// One finding across the endpoints in scope (console decision 18).
#[derive(Clone, Debug, PartialEq)]
pub struct FindingGroup {
    /// Rule set (`""` for findings from before protocol P6).
    pub rule_set_id: String,
    /// Rule.
    pub rule_id: String,
    /// Highest severity among the endpoints (`unknown` if none is recognised).
    pub severity: String,
    /// Endpoints whose latest match is inside the window.
    pub endpoints: i64,
    /// Rule versions reported, newest first.
    pub rule_versions: Vec<i64>,
    /// Earliest first observation.
    pub first_observed_at: DateTime<Utc>,
    /// Latest observation.
    pub last_observed_at: DateTime<Utc>,
    /// Message of the latest observation, when still retained.
    pub message: Option<String>,
}

/// A bounded page of items and how many matched in total.
#[derive(Clone, Debug, PartialEq)]
pub struct Page<T> {
    /// At most `limit` items.
    pub items: Vec<T>,
    /// Every matching item, including those not returned.
    pub total: i64,
}

/// Findings in scope observed since `since`, one row per rule set and rule,
/// most severe and widespread first.
pub async fn finding_groups(
    client: &Client,
    scope: &AgentScope,
    filter: &GroupFilter<'_>,
    since: DateTime<Utc>,
    limit: u32,
) -> Result<Page<FindingGroup>, StoreError> {
    let min_rank = filter
        .min_severity
        .and_then(|s| FINDING_SEVERITIES.iter().position(|known| *known == s))
        .map(|index| i32::try_from(index + 1).unwrap_or(1));
    let text = filter.text.map(contains_pattern);
    let rows = client
        .query(
            "WITH g AS (
                 SELECT c.rule_set_id, c.rule_id, count(*) AS endpoints,
                        COALESCE(max(array_position($6::text[], c.severity)), 0) AS rank,
                        array_agg(DISTINCT c.rule_version ORDER BY c.rule_version DESC) AS versions,
                        min(c.first_observed_at) AS first_seen,
                        max(c.last_observed_at) AS last_seen,
                        (array_agg(c.last_finding_id ORDER BY c.last_observed_at DESC))[1] AS latest_id
                 FROM current_findings c
                 WHERE ($1::text[] IS NULL OR c.agent_id = ANY($1))
                   AND c.last_observed_at >= $2
                   AND ($3::text IS NULL OR c.rule_set_id = $3)
                 GROUP BY c.rule_set_id, c.rule_id),
             m AS (
                 SELECT g.*, f.message FROM g LEFT JOIN LATERAL (
                     SELECT message FROM findings f
                     WHERE f.finding_id = g.latest_id
                       AND f.observed_day = (g.last_seen AT TIME ZONE 'UTC')::date
                     LIMIT 1) f ON true)
             SELECT rule_set_id, rule_id,
                    CASE WHEN rank = 0 THEN 'unknown' ELSE ($6::text[])[rank] END, endpoints, versions,
                    first_seen, last_seen, message, count(*) OVER ()
             FROM m
             WHERE ($4::int IS NULL OR rank >= $4)
               AND ($5::text IS NULL OR rule_id ILIKE $5 OR rule_set_id ILIKE $5
                    OR message ILIKE $5)
             ORDER BY rank DESC, endpoints DESC, last_seen DESC, rule_set_id, rule_id
             LIMIT $7",
            &[
                &scope.param(),
                &since,
                &filter.rule_set_id,
                &min_rank,
                &text,
                &FINDING_SEVERITIES.as_slice(),
                &limit_param(limit),
            ],
        )
        .await?;
    Ok(Page {
        total: rows.first().map_or(0, |row| row.get(8)),
        items: rows
            .iter()
            .map(|row| FindingGroup {
                rule_set_id: row.get(0),
                rule_id: row.get(1),
                severity: row.get(2),
                endpoints: row.get(3),
                rule_versions: row.get(4),
                first_observed_at: row.get(5),
                last_observed_at: row.get(6),
                message: row.get(7),
            })
            .collect(),
    })
}

/// One endpoint reporting a finding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingEndpoint {
    /// Agent.
    pub agent_id: String,
    /// Host name label (spoofable).
    pub hostname: Option<String>,
    /// First observation.
    pub first_observed_at: DateTime<Utc>,
    /// Latest observation.
    pub last_observed_at: DateTime<Utc>,
    /// Rule version of the latest observation.
    pub rule_version: i64,
    /// Severity of the latest observation.
    pub severity: String,
}

/// Endpoints of one finding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointPage {
    /// Endpoints seen inside the window, most recent first.
    pub items: Vec<FindingEndpoint>,
    /// Every endpoint seen inside the window.
    pub total: i64,
    /// Endpoints whose latest match is older than the window ("not seen in
    /// the window", never "resolved").
    pub older: i64,
}

/// Endpoints in scope reporting `rule_set_id`/`rule_id` since `since`.
pub async fn finding_endpoints(
    client: &Client,
    scope: &AgentScope,
    rule_set_id: &str,
    rule_id: &str,
    since: DateTime<Utc>,
    limit: u32,
) -> Result<EndpointPage, StoreError> {
    let counts = client
        .query_one(
            "SELECT count(*) FILTER (WHERE last_observed_at >= $4),
                    count(*) FILTER (WHERE last_observed_at < $4)
             FROM current_findings
             WHERE ($1::text[] IS NULL OR agent_id = ANY($1))
               AND rule_set_id = $2 AND rule_id = $3",
            &[&scope.param(), &rule_set_id, &rule_id, &since],
        )
        .await?;
    let rows = client
        .query(
            "SELECT c.agent_id, a.hostname, c.first_observed_at, c.last_observed_at,
                    c.rule_version, c.severity
             FROM current_findings c JOIN agents a ON a.agent_id = c.agent_id
             WHERE ($1::text[] IS NULL OR c.agent_id = ANY($1))
               AND c.rule_set_id = $2 AND c.rule_id = $3 AND c.last_observed_at >= $4
             ORDER BY c.last_observed_at DESC, c.agent_id
             LIMIT $5",
            &[
                &scope.param(),
                &rule_set_id,
                &rule_id,
                &since,
                &limit_param(limit),
            ],
        )
        .await?;
    Ok(EndpointPage {
        total: counts.get(0),
        older: counts.get(1),
        items: rows
            .iter()
            .map(|row| FindingEndpoint {
                agent_id: row.get(0),
                hostname: row.get(1),
                first_observed_at: row.get(2),
                last_observed_at: row.get(3),
                rule_version: row.get(4),
                severity: row.get(5),
            })
            .collect(),
    })
}

/// An agent with its counts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentSummary {
    /// Agent.
    pub agent_id: String,
    /// Host name label (spoofable).
    pub hostname: Option<String>,
    /// `active` or `revoked`.
    pub status: String,
    /// Last heartbeat.
    pub last_seen_at: Option<DateTime<Utc>>,
    /// Agent version.
    pub scanner_version: Option<String>,
    /// Operating system (`os_id` and `os_version`), when reported.
    pub os: Option<(String, String)>,
    /// Running kernel, when reported.
    pub running_kernel: Option<String>,
    /// Enabled collectors and features.
    pub capabilities: Vec<String>,
    /// Findings whose latest match is since the window start.
    pub findings: i64,
    /// Open vulnerabilities.
    pub open_vulnerabilities: i64,
    /// Open vulnerabilities with an exploited CVE (KEV or EUVD).
    pub exploited_vulnerabilities: i64,
}

/// Agents in scope whose ID or host name (case-insensitive) is `key`, at
/// most `limit` (host names are labels and may repeat).
pub async fn agent_summaries(
    client: &Client,
    scope: &AgentScope,
    key: &str,
    since: DateTime<Utc>,
    limit: u32,
) -> Result<Page<AgentSummary>, StoreError> {
    let rows = client
        .query(
            "SELECT a.agent_id, a.hostname, a.status, a.last_seen_at, a.scanner_version,
                    a.os_id, a.os_version, a.running_kernel, a.capabilities,
                    (SELECT count(*) FROM current_findings c
                     WHERE c.agent_id = a.agent_id AND c.last_observed_at >= $3),
                    (SELECT count(*) FROM vulnerabilities v
                     WHERE v.agent_id = a.agent_id AND v.fixed_at IS NULL),
                    (SELECT count(DISTINCT v.advisory_id) FROM vulnerabilities v
                     JOIN advisory_cves y ON y.advisory_id = v.advisory_id
                     JOIN cve_enrichment x ON x.cve_id = y.cve_id
                     WHERE v.agent_id = a.agent_id AND v.fixed_at IS NULL
                       AND (x.kev_added IS NOT NULL OR COALESCE(x.euvd_exploited, false))),
                    count(*) OVER ()
             FROM agents a
             WHERE ($1::text[] IS NULL OR a.agent_id = ANY($1))
               AND (a.agent_id = $2 OR lower(a.hostname) = lower($2))
             ORDER BY a.agent_id
             LIMIT $4",
            &[&scope.param(), &key, &since, &limit_param(limit)],
        )
        .await?;
    Ok(Page {
        total: rows.first().map_or(0, |row| row.get(12)),
        items: rows
            .iter()
            .map(|row| AgentSummary {
                agent_id: row.get(0),
                hostname: row.get(1),
                status: row.get(2),
                last_seen_at: row.get(3),
                scanner_version: row.get(4),
                os: row
                    .get::<_, Option<String>>(5)
                    .zip(row.get::<_, Option<String>>(6)),
                running_kernel: row.get(7),
                capabilities: row.get(8),
                findings: row.get(9),
                open_vulnerabilities: row.get(10),
                exploited_vulnerabilities: row.get(11),
            })
            .collect(),
    })
}

/// One open vulnerability on a host.
#[derive(Clone, Debug, PartialEq)]
pub struct HostVulnerability {
    /// Advisory.
    pub advisory_id: String,
    /// Advisory severity.
    pub severity: String,
    /// Advisory title.
    pub title: String,
    /// CVE IDs (at most 10).
    pub cves: Vec<String>,
    /// A CVE is exploited in the wild (KEV or EUVD).
    pub exploited: bool,
    /// Highest EPSS percentile among its CVEs.
    pub epss_percentile: Option<f32>,
    /// Fix installed, reboot needed.
    pub reboot_needed: bool,
    /// First seen.
    pub first_seen_at: DateTime<Utc>,
}

/// Open vulnerabilities on `agent_id` (if in scope), by priority: exploited
/// first, then EPSS percentile, then severity, then oldest.
pub async fn host_vulnerabilities(
    client: &Client,
    scope: &AgentScope,
    agent_id: &str,
    min_severity: Option<&str>,
    limit: u32,
) -> Result<Page<HostVulnerability>, StoreError> {
    let max_rank = min_severity
        .and_then(|s| ADVISORY_SEVERITIES.iter().position(|known| *known == s))
        .map(|index| i32::try_from(index + 1).unwrap_or(5));
    let rows = client
        .query(
            "SELECT v.advisory_id, a.severity, a.title,
                    (SELECT COALESCE(array_agg(c.cve_id ORDER BY c.cve_id), '{}')
                     FROM (SELECT cve_id FROM advisory_cves WHERE advisory_id = v.advisory_id
                           ORDER BY cve_id LIMIT 10) c),
                    COALESCE(e.exploited, false), e.pct, v.reboot_needed, v.first_seen_at,
                    count(*) OVER ()
             FROM vulnerabilities v
             JOIN advisories a ON a.advisory_id = v.advisory_id
             LEFT JOIN LATERAL (
                 SELECT bool_or(x.kev_added IS NOT NULL OR COALESCE(x.euvd_exploited, false))
                            AS exploited,
                        max(x.epss_percentile) AS pct
                 FROM advisory_cves y JOIN cve_enrichment x ON x.cve_id = y.cve_id
                 WHERE y.advisory_id = v.advisory_id) e ON true
             WHERE v.fixed_at IS NULL AND v.agent_id = $2
               AND ($1::text[] IS NULL OR v.agent_id = ANY($1))
               AND ($3::int IS NULL
                    OR COALESCE(array_position($5::text[], a.severity), 5) <= $3)
             ORDER BY COALESCE(e.exploited, false) DESC, e.pct DESC NULLS LAST,
                      COALESCE(array_position($5::text[], a.severity), 5), v.first_seen_at,
                      v.advisory_id
             LIMIT $4",
            &[
                &scope.param(),
                &agent_id,
                &max_rank,
                &limit_param(limit),
                &ADVISORY_SEVERITIES.as_slice(),
            ],
        )
        .await?;
    Ok(Page {
        total: rows.first().map_or(0, |row| row.get(8)),
        items: rows
            .iter()
            .map(|row| HostVulnerability {
                advisory_id: row.get(0),
                severity: row.get(1),
                title: row.get(2),
                cves: row.get(3),
                exploited: row.get(4),
                epss_percentile: row.get(5),
                reboot_needed: row.get(6),
                first_seen_at: row.get(7),
            })
            .collect(),
    })
}

/// One host with an open vulnerability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VulnerableHost {
    /// Agent.
    pub agent_id: String,
    /// Host name label (spoofable).
    pub hostname: Option<String>,
    /// The advisory that affects it.
    pub advisory_id: String,
    /// First seen.
    pub first_seen_at: DateTime<Utc>,
    /// Fix installed, reboot needed.
    pub reboot_needed: bool,
}

/// Hosts in scope with an open vulnerability for `cve_or_advisory` (a CVE
/// ID or an advisory ID), oldest first.
pub async fn vulnerable_hosts(
    client: &Client,
    scope: &AgentScope,
    cve_or_advisory: &str,
    limit: u32,
) -> Result<Page<VulnerableHost>, StoreError> {
    let rows = client
        .query(
            "SELECT v.agent_id, g.hostname, v.advisory_id, v.first_seen_at, v.reboot_needed,
                    count(*) OVER ()
             FROM vulnerabilities v JOIN agents g ON g.agent_id = v.agent_id
             WHERE v.fixed_at IS NULL
               AND ($1::text[] IS NULL OR v.agent_id = ANY($1))
               AND (v.advisory_id = $2 OR EXISTS (SELECT 1 FROM advisory_cves c
                    WHERE c.advisory_id = v.advisory_id AND c.cve_id = $2))
             ORDER BY v.first_seen_at, v.agent_id, v.advisory_id
             LIMIT $3",
            &[&scope.param(), &cve_or_advisory, &limit_param(limit)],
        )
        .await?;
    Ok(Page {
        total: rows.first().map_or(0, |row| row.get(5)),
        items: rows
            .iter()
            .map(|row| VulnerableHost {
                agent_id: row.get(0),
                hostname: row.get(1),
                advisory_id: row.get(2),
                first_seen_at: row.get(3),
                reboot_needed: row.get(4),
            })
            .collect(),
    })
}

/// Agent counts by state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AgentCounts {
    /// Active, with a heartbeat within the offline threshold.
    pub seen_recently: i64,
    /// Active, silent for longer.
    pub offline: i64,
    /// Active, never sent a heartbeat.
    pub never_seen: i64,
    /// Revoked.
    pub revoked: i64,
}

/// One advisory across hosts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdvisoryHosts {
    /// Advisory.
    pub advisory_id: String,
    /// Severity.
    pub severity: String,
    /// Title.
    pub title: String,
    /// Hosts in scope where it is open.
    pub hosts: i64,
}

/// The fleet at a glance.
#[derive(Clone, Debug, PartialEq)]
pub struct Overview {
    /// Agents by state.
    pub agents: AgentCounts,
    /// Open host–advisory pairs.
    pub open_vulnerabilities: i64,
    /// Hosts with an open exploited vulnerability.
    pub hosts_with_exploited: i64,
    /// Most severe and widespread findings in the window.
    pub top_findings: Page<FindingGroup>,
    /// Advisories open on the most hosts.
    pub top_advisories: Page<AdvisoryHosts>,
}

/// Fleet overview for the agents in scope.
pub async fn overview(
    client: &Client,
    scope: &AgentScope,
    since: DateTime<Utc>,
    now: DateTime<Utc>,
    limit: u32,
) -> Result<Overview, StoreError> {
    let offline_before = now - chrono::Duration::minutes(crate::OFFLINE_AFTER_MINUTES);
    let agents = client
        .query_one(
            "SELECT count(*) FILTER (WHERE status = 'active' AND last_seen_at >= $2),
                    count(*) FILTER (WHERE status = 'active' AND last_seen_at < $2),
                    count(*) FILTER (WHERE status = 'active' AND last_seen_at IS NULL),
                    count(*) FILTER (WHERE status = 'revoked')
             FROM agents WHERE ($1::text[] IS NULL OR agent_id = ANY($1))",
            &[&scope.param(), &offline_before],
        )
        .await?;
    let vulns = client
        .query_one(
            "SELECT count(*),
                    count(DISTINCT v.agent_id) FILTER (WHERE EXISTS (
                        SELECT 1 FROM advisory_cves y JOIN cve_enrichment x ON x.cve_id = y.cve_id
                        WHERE y.advisory_id = v.advisory_id
                          AND (x.kev_added IS NOT NULL OR COALESCE(x.euvd_exploited, false))))
             FROM vulnerabilities v
             WHERE v.fixed_at IS NULL AND ($1::text[] IS NULL OR v.agent_id = ANY($1))",
            &[&scope.param()],
        )
        .await?;
    let advisories = client
        .query(
            "SELECT v.advisory_id, a.severity, a.title, count(*) AS hosts, count(*) OVER ()
             FROM vulnerabilities v JOIN advisories a ON a.advisory_id = v.advisory_id
             WHERE v.fixed_at IS NULL AND ($1::text[] IS NULL OR v.agent_id = ANY($1))
             GROUP BY v.advisory_id, a.severity, a.title
             ORDER BY hosts DESC, v.advisory_id
             LIMIT $2",
            &[&scope.param(), &limit_param(limit)],
        )
        .await?;
    Ok(Overview {
        agents: AgentCounts {
            seen_recently: agents.get(0),
            offline: agents.get(1),
            never_seen: agents.get(2),
            revoked: agents.get(3),
        },
        open_vulnerabilities: vulns.get(0),
        hosts_with_exploited: vulns.get(1),
        top_findings: finding_groups(client, scope, &GroupFilter::default(), since, limit).await?,
        top_advisories: Page {
            total: advisories.first().map_or(0, |row| row.get(4)),
            items: advisories
                .iter()
                .map(|row| AdvisoryHosts {
                    advisory_id: row.get(0),
                    severity: row.get(1),
                    title: row.get(2),
                    hosts: row.get(3),
                })
                .collect(),
        },
    })
}
