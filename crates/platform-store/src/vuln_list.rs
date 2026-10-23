//! The Vulnerabilities list (roles spec §10.3; step 5b rulings 2–6): one
//! row per CVE (or per advisory without one) over the host and advisory
//! pairs in the viewer's `vulnerabilities.read` scope, with search, filters
//! that AND together, the count for every value of every filter with the
//! other filters applied, the summary line and offset paging. One
//! statement, so rows, total, counts and summary always agree.

use std::collections::BTreeMap;

use chrono::NaiveDate;
use tokio_postgres::Row;

use crate::{
    Client, StoreError,
    alarm_list::Assignee,
    console_read::{AgentScope, MAX_PAGE_SIZE},
    host_groups::GroupKind,
    host_list::values,
    vuln_list_sql::statement,
};

values!(
    /// The State filter (ruling 3): a row matches when one of its pairs is
    /// in that state.
    VulnState {
        /// Triage open (or an expired accepted risk), not fixed.
        Open = "open",
        /// Mitigated.
        Mitigated = "mitigated",
        /// Accepted until a date.
        AcceptedRisk = "accepted_risk",
        /// Not a real vulnerability.
        FalsePositive = "false_positive",
        /// Fixed by an update.
        Resolved = "resolved",
        /// Every state.
        All = "all",
    }
);

values!(
    /// A severity, most severe first.
    VulnSeverity {
        /// Critical.
        Critical = "critical",
        /// Important.
        Important = "important",
        /// Moderate.
        Moderate = "moderate",
        /// Low.
        Low = "low",
        /// Unrated.
        Unrated = "unrated",
    }
);

values!(
    /// The Signals filter (ruling 3).
    Signal {
        /// On CISA KEV or EUVD's exploited list.
        Exploited = "exploited",
        /// A KEV due date within 30 days of today, overdue included.
        Due30 = "due30",
        /// No pair has a fix.
        NoFix = "nofix",
        /// A fix is installed and waits for a reboot.
        Reboot = "reboot",
        /// Only lower-confidence matches (below 80), shown instead of the others.
        LowConf = "lowconf",
    }
);

values!(
    /// The sort column; ties are broken by key in the same direction (ruling 5).
    VulnSort {
        /// Exploited, EPSS percentile, severity, CVSS.
        Priority = "priority",
        /// Severity.
        Severity = "severity",
        /// CVSS base score.
        Cvss = "cvss",
        /// EPSS score.
        Epss = "epss",
        /// Open pairs.
        Open = "open",
        /// KEV due date.
        Due = "due",
    }
);

/// What the list asks for. `offset` is held to 0–100000 and `limit` to 1–100.
#[derive(Clone, Debug)]
pub struct VulnQuery<'a> {
    /// CVE, advisory id, title or package name (contains, any case).
    pub q: Option<&'a str>,
    /// State.
    pub state: VulnState,
    /// Row severity.
    pub severity: Option<VulnSeverity>,
    /// Signal.
    pub signal: Option<Signal>,
    /// A package name.
    pub package: Option<&'a str>,
    /// An asset group id.
    pub group: Option<&'a str>,
    /// An agent id.
    pub host: Option<&'a str>,
    /// An advisory id: rows of the CVEs it names.
    pub advisory: Option<&'a str>,
    /// Assignee.
    pub assignee: Option<Assignee<'a>>,
    /// Sort column.
    pub sort: VulnSort,
    /// Sort direction.
    pub descending: bool,
    /// Rows to skip.
    pub offset: i64,
    /// Rows to return.
    pub limit: i64,
}

/// The fixed version under the package (ruling 2).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Fixed {
    /// Every pair with a fix names this version.
    One(String),
    /// Pairs name this many fixed versions.
    Several(u32),
    /// No pair has a fix.
    None,
}

/// Who the open pairs are assigned to (ruling 2).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AssigneeSummary {
    /// No open pair is assigned.
    None,
    /// One person: (user id, display name).
    One(String, String),
    /// This many people.
    Several(u32),
}

/// One row: a CVE, or an advisory without CVEs.
#[derive(Clone, Debug)]
pub struct VulnListRow {
    /// The CVE id, or the advisory id.
    pub key: String,
    /// The title of the covering advisory with the most pairs in reach.
    pub title: String,
    /// The worst severity among the covering advisories in reach.
    pub severity: VulnSeverity,
    /// On KEV or EUVD's exploited list.
    pub exploited: bool,
    /// KEV due date.
    pub kev_due: Option<NaiveDate>,
    /// CVSS base score.
    pub cvss: Option<f32>,
    /// EPSS score.
    pub epss: Option<f32>,
    /// EPSS percentile.
    pub epss_percentile: Option<f32>,
    /// Affected package names, sorted.
    pub packages: Vec<String>,
    /// The fixed version.
    pub fixed: Fixed,
    /// Open pairs (triage open, not fixed).
    pub open: i64,
    /// Every pair, whatever its state.
    pub total: i64,
    /// A pair waits for a reboot.
    pub reboot: bool,
    /// The row shows lower-confidence matches (the `lowconf` signal).
    pub low_confidence: bool,
    /// The covering advisories in reach, sorted.
    pub advisories: Vec<String>,
    /// Other CVEs those advisories name, sorted, at most 10.
    pub also_covers: Vec<String>,
    /// Who the open pairs are assigned to.
    pub assignee: AssigneeSummary,
}

/// Rows per filter value, each with the other filters applied.
#[derive(Clone, Debug, Default)]
pub struct VulnCounts {
    /// Every state.
    pub state: Vec<(VulnState, i64)>,
    /// Every severity.
    pub severity: Vec<(VulnSeverity, i64)>,
    /// Every signal.
    pub signal: Vec<(Signal, i64)>,
    /// The 50 package names with the most rows, plus the chosen one when in
    /// reach: (name, rows), most rows first.
    pub packages: Vec<(String, i64)>,
    /// Groups holding a host with a matching pair, plus the chosen one when
    /// the scope reaches it: (id, name, kind, rows), by name.
    pub groups: Vec<(String, String, GroupKind, i64)>,
    /// Assigned to the viewer.
    pub me: i64,
    /// With an unassigned pair.
    pub unassigned: i64,
    /// People with a pair in reach: (user id, display name, rows), by name.
    pub people: Vec<(String, String, i64)>,
}

/// "N open on N hosts · N known exploited · N with a due date · N without
/// a fix · N unassigned" (ruling 6), over the rows matching every filter
/// but the state's that have an open pair. Counts are rows, except hosts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Deserialize)]
pub struct VulnSummary {
    /// Rows with an open pair.
    pub open_rows: i64,
    /// Hosts with an open pair in those rows.
    pub hosts: i64,
    /// Of those rows, exploited.
    pub exploited: i64,
    /// With a KEV due date.
    pub with_due: i64,
    /// Without a fix.
    pub no_fix: i64,
    /// With no open pair assigned.
    pub unassigned: i64,
}

/// One page of the list.
#[derive(Clone, Debug)]
pub struct VulnListPage {
    /// The page.
    pub rows: Vec<VulnListRow>,
    /// Rows matching every filter.
    pub total: i64,
    /// Per-value counts.
    pub counts: VulnCounts,
    /// The summary line.
    pub summary: VulnSummary,
}

const NOBODY: &str = "00000000-0000-0000-0000-000000000000";

fn is_uuid(s: &str) -> bool {
    s.len() == 36
        && s.char_indices().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        })
}

#[derive(serde::Deserialize)]
struct RawCounts {
    state: BTreeMap<String, i64>,
    severity: BTreeMap<String, i64>,
    signal: BTreeMap<String, i64>,
    packages: Vec<(String, i64)>,
    groups: Vec<(String, String, String, i64)>,
    unassigned: i64,
    people: Vec<(String, String, i64)>,
}

#[derive(serde::Deserialize)]
struct Meta {
    total: i64,
    counts: RawCounts,
    summary: VulnSummary,
}

/// One page of the Vulnerabilities list for `actor_id` (a console user id)
/// within `scope` (`vulnerabilities.read`); `today` dates the due-within-30
/// signal and expired accepted risks.
pub async fn vuln_list(
    client: &Client,
    query: &VulnQuery<'_>,
    scope: &AgentScope,
    actor_id: &str,
    today: NaiveDate,
) -> Result<VulnListPage, StoreError> {
    let q = query.q.map(str::trim).filter(|q| !q.is_empty());
    let user = match query.assignee {
        Some(Assignee::Me) => Some(actor_id),
        Some(Assignee::User(id)) => Some(id),
        _ => None,
    }
    .map(|id| if is_uuid(id) { id } else { NOBODY });
    let unassigned = query.assignee == Some(Assignee::Unassigned);
    let state = (query.state != VulnState::All).then(|| query.state.as_str());
    let rows = client
        .query(
            &statement(query.sort, query.descending),
            &[
                &scope.is_global(),
                &scope.group_ids(),
                &q,
                &state,
                &query.severity.map(VulnSeverity::as_str),
                &query.signal.map(Signal::as_str),
                &query.package,
                &query.group,
                &query.host,
                &query.advisory,
                &user,
                &unassigned,
                &today,
                &query.limit.clamp(1, i64::from(MAX_PAGE_SIZE)),
                &query.offset.clamp(0, 100_000),
            ],
        )
        .await?;
    let meta: serde_json::Value = rows.first().and_then(|r| r.get(0)).unwrap_or_default();
    let meta: Meta = serde_json::from_value(meta).map_err(|_| StoreError::Query)?;
    Ok(VulnListPage {
        rows: rows.iter().filter_map(vuln_row).collect(),
        total: meta.total,
        summary: meta.summary,
        counts: vuln_counts(meta.counts, actor_id),
    })
}

fn vuln_row(row: &Row) -> Option<VulnListRow> {
    let key: String = row.get::<_, Option<String>>(1)?;
    let mut fixed: Vec<String> = row.get(10);
    let people: i64 = row.get(17);
    let one: Option<String> = row.get(18);
    Some(VulnListRow {
        key,
        title: row.get(2),
        severity: VulnSeverity::parse(row.get(3)).unwrap_or(VulnSeverity::Unrated),
        exploited: row.get(4),
        kev_due: row.get(5),
        cvss: row.get(6),
        epss: row.get(7),
        epss_percentile: row.get(8),
        packages: row.get(9),
        fixed: match fixed.len() {
            0 => Fixed::None,
            1 => Fixed::One(fixed.remove(0)),
            n => Fixed::Several(u32::try_from(n).unwrap_or(u32::MAX)),
        },
        open: row.get(11),
        total: row.get(12),
        reboot: row.get(13),
        low_confidence: row.get(14),
        advisories: row.get(15),
        also_covers: row.get(16),
        assignee: match (people, one) {
            (1, Some(id)) => AssigneeSummary::One(id, row.get(19)),
            (0, _) | (_, None) => AssigneeSummary::None,
            (n, _) => AssigneeSummary::Several(u32::try_from(n).unwrap_or(u32::MAX)),
        },
    })
}

fn vuln_counts(raw: RawCounts, actor_id: &str) -> VulnCounts {
    let n = |map: &BTreeMap<String, i64>, key: &str| map.get(key).copied().unwrap_or(0);
    let mut groups: Vec<_> = raw
        .groups
        .into_iter()
        .map(|(id, name, kind, n)| (id, name, GroupKind::parse(&kind), n))
        .collect();
    groups.sort_by(|a, b| (a.1.to_lowercase(), &a.0).cmp(&(b.1.to_lowercase(), &b.0)));
    let mut people = raw.people;
    people.sort_by(|a, b| (a.1.to_lowercase(), &a.0).cmp(&(b.1.to_lowercase(), &b.0)));
    VulnCounts {
        state: VulnState::ALL
            .iter()
            .map(|s| (*s, n(&raw.state, s.as_str())))
            .collect(),
        severity: VulnSeverity::ALL
            .iter()
            .map(|s| (*s, n(&raw.severity, s.as_str())))
            .collect(),
        signal: Signal::ALL
            .iter()
            .map(|s| (*s, n(&raw.signal, s.as_str())))
            .collect(),
        packages: raw.packages,
        groups,
        me: people.iter().find(|p| p.0 == actor_id).map_or(0, |p| p.2),
        unassigned: raw.unassigned,
        people,
    }
}
