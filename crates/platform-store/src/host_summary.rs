//! The host page's summary (roles step 4, plan ruling 10): the header
//! facts, groups and labels, certificates, the inventory counts and the
//! top-three alarms, vulnerabilities and failing checks. A handful of
//! small queries on one host. Each problem section is `None` where its own
//! permission does not reach the host.

use chrono::{DateTime, Duration, Utc};

use crate::{
    Client, StoreError,
    check_list_sql::{WINDOW, open_failing},
    console_read::{
        Agent, AgentScope, Certificate, PageLimit, agent_in_scope, certificates_in_scope,
    },
    host_groups::GroupKind,
    host_labels,
    host_list::{HostScopes, HostStatus},
    status::OFFLINE_AFTER_MINUTES,
    vulns::{ListFilter, VulnRow, list_for_agents},
};

/// Items in each top list.
const TOP: usize = 3;
/// Certificates shown on the page.
const CERTIFICATES: u16 = 5;

/// The first `TOP` (three) items of a list and how many there are in all.
#[derive(Clone, Debug)]
pub struct Top<T> {
    /// Most severe first, then newest.
    pub items: Vec<T>,
    /// Every item.
    pub total: i64,
}

/// An open agent alarm.
#[derive(Clone, Debug)]
pub struct TopAlarm {
    /// The platform's id.
    pub id: i64,
    /// Rule.
    pub rule_id: String,
    /// The rule's message.
    pub message: String,
    /// Severity name.
    pub severity: String,
    /// Latest match.
    pub last_seen: DateTime<Utc>,
}

/// A failing compliance check.
#[derive(Clone, Debug)]
pub struct TopFailing {
    /// Rule set.
    pub rule_set_id: String,
    /// Rule.
    pub rule_id: String,
    /// Severity name.
    pub severity: String,
    /// The rule's message.
    pub message: String,
}

/// Everything above the fold on one host's page.
#[derive(Clone, Debug)]
pub struct HostSummary {
    /// The agent record.
    pub agent: Agent,
    /// Status (plan ruling 2).
    pub status: HostStatus,
    /// Address of the last connection.
    pub address: Option<String>,
    /// Display name, e.g. `Debian 12`.
    pub distribution: Option<String>,
    /// `linux` or `windows`.
    pub os_family: Option<String>,
    /// Older than the latest release; `None` when either is unknown.
    pub agent_older: Option<bool>,
    /// The groups holding the host: (id, name, kind), by name.
    pub groups: Vec<(String, String, GroupKind)>,
    /// Labels, in byte order.
    pub labels: Vec<String>,
    /// Open agent alarms, with `alarms.read` here.
    pub top_alarms: Option<Top<TopAlarm>>,
    /// Open advisories (one item each), with `vulnerabilities.read` here;
    /// in the Vulnerabilities list's priority order.
    pub top_vulnerabilities: Option<Top<VulnRow>>,
    /// Failing checks, with `compliance.read` here: the Compliance list's
    /// open failing pairs (`check_list_sql::open_failing`).
    pub top_failing: Option<Top<TopFailing>>,
    /// No report in the last day (the Compliance list's window): failing
    /// can't be counted, so the page says so instead of a count.
    pub compliance_stale: bool,
    /// Installed packages.
    pub packages: i64,
    /// Listening ports (protocol and port).
    pub listening_ports: i64,
    /// Of those, the ones reachable from outside the host.
    pub exposed_ports: i64,
    /// Running services.
    pub services: i64,
    /// The newest certificates.
    pub certificates: Vec<Certificate>,
    /// All its certificates.
    pub certificate_count: i64,
    /// The latest test alarm and test finding.
    pub last_test: (Option<DateTime<Utc>>, Option<DateTime<Utc>>),
}

impl HostSummary {
    /// Whether `scope` reaches this host: the same rule as
    /// `agent_visibility` (any of its groups, and imported hosts only
    /// globally), from the groups already read.
    #[must_use]
    pub fn reaches(&self, scope: &AgentScope) -> bool {
        match scope {
            AgentScope::Global => true,
            AgentScope::AssetGroups(ids) => {
                self.status != HostStatus::Imported
                    && self.groups.iter().any(|g| ids.contains(&g.0))
            }
        }
    }
}

/// Severity order for alarms and findings, most severe first.
pub(crate) const RANK: &str =
    "array_position(ARRAY['critical','high','medium','low','info'], severity)";

/// The summary of `agent_id`, or `None` when `scopes.hosts` does not reach it.
pub async fn summary(
    client: &Client,
    agent_id: &str,
    scopes: &HostScopes<'_>,
    latest: Option<&str>,
    now: DateTime<Utc>,
) -> Result<Option<HostSummary>, StoreError> {
    let Some(agent) = agent_in_scope(client, agent_id, now, scopes.hosts).await? else {
        return Ok(None);
    };
    let threshold = now - Duration::minutes(OFFLINE_AFTER_MINUTES);
    let f = client
        .query_one(
            &format!("SELECT host(a.last_address), console_distribution_name(a.distribution), a.os_family,
                    CASE WHEN a.status = 'imported' THEN 'imported' WHEN a.status = 'revoked' THEN 'revoked'
                         WHEN agent_seen_at(a.agent_id, a.last_seen_at) >= $2 THEN 'online'
                         ELSE 'offline' END,
                    console_version_older(a.scanner_version, $3),
                    (SELECT count(*) FROM host_packages WHERE agent_id = $1),
                    (SELECT count(DISTINCT (protocol, port)) FROM host_listeners WHERE agent_id = $1),
                    (SELECT count(DISTINCT (protocol, port)) FROM host_listeners
                      WHERE agent_id = $1 AND exposed),
                    (SELECT count(*) FROM host_services WHERE agent_id = $1),
                    (SELECT count(*) FROM certificates WHERE agent_id = $1),
                    COALESCE(agent_seen_at(a.agent_id, a.last_seen_at) < $4::timestamptz - {WINDOW}, true)
             FROM agents a WHERE a.agent_id = $1",
            ),
            &[&agent_id, &threshold, &latest, &now],
        )
        .await?;
    // Reach was checked by `agent_in_scope` above.
    let labels = host_labels::of_host(client, agent_id).await?;
    let certificates = certificates_in_scope(
        client,
        agent_id,
        None,
        PageLimit::new(CERTIFICATES).ok_or(StoreError::Query)?,
        scopes.hosts,
    )
    .await?
    .items;
    let mut s = HostSummary {
        agent,
        status: HostStatus::parse(f.get(3)).unwrap_or(HostStatus::Offline),
        address: f.get(0),
        distribution: f.get(1),
        os_family: f.get(2),
        agent_older: f.get(4),
        groups: labels.groups,
        labels: labels.labels,
        top_alarms: None,
        top_vulnerabilities: None,
        top_failing: None,
        compliance_stale: f.get(10),
        packages: f.get(5),
        listening_ports: f.get(6),
        exposed_ports: f.get(7),
        services: f.get(8),
        certificates,
        certificate_count: f.get(9),
        last_test: crate::rules::last_tests(client, agent_id).await?,
    };
    if scopes.alarms.is_some_and(|a| s.reaches(a)) {
        s.top_alarms = Some(top_alarms(client, agent_id, None, 3).await?);
    }
    if scopes.compliance.is_some_and(|c| s.reaches(c)) {
        s.top_failing = Some(top_failing(client, agent_id, now).await?);
    }
    if scopes.vulnerabilities.is_some_and(|v| s.reaches(v)) {
        s.top_vulnerabilities = Some(top_vulnerabilities(client, agent_id).await?);
    }
    Ok(Some(s))
}

/// Rows of a top-three query whose last column is `count(*) OVER ()`.
pub(crate) fn top<T>(
    rows: &[tokio_postgres::Row],
    item: impl Fn(&tokio_postgres::Row) -> T,
) -> Top<T> {
    let total = rows.first().map_or(0, |r| r.get(r.len() - 1));
    Top {
        items: rows.iter().map(item).collect(),
        total,
    }
}

/// The host's open agent alarms but `except`, most severe first: the first
/// `limit` and the total (also the alarm page's Related card).
pub(crate) async fn top_alarms(
    client: &Client,
    agent_id: &str,
    except: Option<i64>,
    limit: i64,
) -> Result<Top<TopAlarm>, StoreError> {
    let rows = client
        .query(
            &format!(
                "SELECT id, rule_id, message, severity, last_seen, count(*) OVER () FROM alarms
                 WHERE agent_id = $1 AND state = 'open' AND source = 'agent'
                   AND id IS DISTINCT FROM $2
                 ORDER BY {RANK}, last_seen DESC, id DESC LIMIT $3"
            ),
            &[&agent_id, &except, &limit],
        )
        .await?;
    Ok(top(&rows, |r| TopAlarm {
        id: r.get(0),
        rule_id: r.get(1),
        message: r.get(2),
        severity: r.get(3),
        last_seen: r.get(4),
    }))
}

async fn top_failing(
    client: &Client,
    agent_id: &str,
    now: DateTime<Utc>,
) -> Result<Top<TopFailing>, StoreError> {
    let failing = open_failing("$2");
    let rows = client
        .query(
            &format!(
                "SELECT f.rule_set_id, f.rule_id, f.severity, f.message, count(*) OVER ()
                 FROM current_findings f
                 LEFT JOIN console_finding_triage t USING (agent_id, rule_set_id, rule_id)
                 WHERE f.agent_id = $1 AND {failing}
                 ORDER BY {RANK}, f.last_observed_at DESC, f.rule_set_id, f.rule_id LIMIT 3"
            ),
            &[&agent_id, &now],
        )
        .await?;
    Ok(top(&rows, |r| TopFailing {
        rule_set_id: r.get(0),
        rule_id: r.get(1),
        severity: r.get(2),
        message: r.get(3),
    }))
}

/// What the Vulnerabilities list shows by default (`views/lists/rows.ts`):
/// mappings at or above this confidence.
const LIST_MIN_CONFIDENCE: u8 = 80;

/// The Vulnerabilities list's own query with this host as its filter and
/// the list's defaults (confidence at least [`LIST_MIN_CONFIDENCE`], triage
/// open), so the tile, the card and `/vulnerabilities?host=` show the same
/// advisories; the list's "Lower confidence" and "Include resolved" chips
/// show more there.
pub(crate) async fn top_vulnerabilities(
    client: &Client,
    agent_id: &str,
) -> Result<Top<VulnRow>, StoreError> {
    let filter = ListFilter {
        host: Some(agent_id),
        advisory: None,
        severity: None,
        cve: None,
        fixed: false,
        exploited: None,
        reboot_needed: None,
        min_confidence: Some(LIST_MIN_CONFIDENCE),
    };
    let mut rows = list_for_agents(client, &filter, Some(&[agent_id.to_owned()])).await?;
    // The host filter also matches a hostname: keep this agent's rows.
    rows.retain(|r| r.agent_id == agent_id);
    let pairs: Vec<_> = rows
        .iter()
        .map(|r| (r.agent_id.clone(), r.advisory_id.clone()))
        .collect();
    let triage = crate::vulnerability_triage::states(client, &pairs).await?;
    rows.retain(|r| {
        triage
            .get(&(r.agent_id.clone(), r.advisory_id.clone()))
            .is_none_or(|t| t.state == "open")
    });
    // One row per advisory: a host can hold an advisory both as a fixable
    // row and through a package version without a fix. Rows come in
    // priority order, so the first of each advisory stays.
    let mut seen = std::collections::HashSet::new();
    rows.retain(|r| seen.insert(r.advisory_id.clone()));
    let total = i64::try_from(rows.len()).unwrap_or(i64::MAX);
    rows.truncate(TOP);
    Ok(Top { items: rows, total })
}
