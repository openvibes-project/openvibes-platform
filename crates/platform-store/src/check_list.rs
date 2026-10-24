//! The Compliance list (roles spec §10.3; step 5c rulings 2–7, user
//! decision 1): one row per check (a rule of a rule set) over the hosts in
//! the viewer's scope that fail it (an open current finding seen within
//! the window) or pass it (inferred from heartbeat health), with search,
//! filters that AND together, the count for every value of every filter
//! with the other filters applied, the summary line and offset paging.
//! One statement, so rows, total, counts and summary always agree.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use tokio_postgres::Row;

use crate::{
    Client, StoreError,
    alarm_list::{AlarmSeverity, Assignee},
    check_list_sql::statement,
    console_read::{AgentScope, MAX_PAGE_SIZE},
    host_groups::GroupKind,
    host_list::values,
    vuln_list::AssigneeSummary,
};

/// A finding severity, most severe first (the five levels).
pub type CheckSeverity = AlarmSeverity;

values!(
    /// The State filter (ruling 4): a row matches when one of its pairs is
    /// in that state.
    CheckState {
        /// Failing, triage open (or an expired accepted risk; no triage row).
        Open = "open",
        /// Failing, mitigated.
        Mitigated = "mitigated",
        /// Failing, accepted until a date.
        AcceptedRisk = "accepted_risk",
        /// Failing, not a real problem.
        FalsePositive = "false_positive",
        /// An inferred passing host.
        Passing = "passing",
        /// Every state.
        All = "all",
    }
);

values!(
    /// The sort column; ties are broken by key in the same direction (ruling 6).
    CheckSort {
        /// Severity, then failing hosts.
        Severity = "severity",
        /// Failing hosts.
        Failing = "failing",
        /// The earliest first-seen time of the failing pairs.
        Since = "since",
        /// Title (any case).
        Title = "title",
    }
);

/// What the list asks for. `offset` is held to 0–100000 and `limit` to 1–100.
#[derive(Clone, Debug)]
pub struct CheckQuery<'a> {
    /// Title, rule ID or rule set (contains, any case).
    pub q: Option<&'a str>,
    /// State.
    pub state: CheckState,
    /// Row severity.
    pub severity: Option<CheckSeverity>,
    /// A rule set id.
    pub rule_set: Option<&'a str>,
    /// An area ([`crate::check_area::check_area`]).
    pub area: Option<&'a str>,
    /// An asset group id.
    pub group: Option<&'a str>,
    /// An agent id.
    pub host: Option<&'a str>,
    /// Assignee. Passing pairs have none and match only no filter.
    pub assignee: Option<Assignee<'a>>,
    /// Sort column.
    pub sort: CheckSort,
    /// Sort direction.
    pub descending: bool,
    /// Rows to skip.
    pub offset: i64,
    /// Rows to return.
    pub limit: i64,
}

/// One row: a check.
#[derive(Clone, Debug)]
pub struct CheckListRow {
    /// Rule set.
    pub rule_set_id: String,
    /// Rule.
    pub rule_id: String,
    /// From `console_rule_meta` (the newest indexed version), else the rule ID.
    pub title: String,
    /// The newest finding's in reach (failing first, then ended); `None`
    /// when no host in reach has a finding for it.
    pub severity: Option<CheckSeverity>,
    /// The area.
    pub area: String,
    /// Failing hosts.
    pub failing: i64,
    /// Inferred passing hosts.
    pub passing: i64,
    /// Failing pairs by triage state.
    pub open: i64,
    /// Mitigated.
    pub mitigated: i64,
    /// Accepted risk (not expired).
    pub accepted_risk: i64,
    /// False positive.
    pub false_positive: i64,
    /// The earliest first-seen time of the failing pairs.
    pub since: Option<DateTime<Utc>>,
    /// Who the open failing pairs are assigned to.
    pub assignee: AssigneeSummary,
}

/// Rows per filter value, each with the other filters applied.
#[derive(Clone, Debug, Default)]
pub struct CheckCounts {
    /// Every state.
    pub state: Vec<(CheckState, i64)>,
    /// Every severity.
    pub severity: Vec<(CheckSeverity, i64)>,
    /// Rule sets of rows in reach (chosen ones included): (id, rows), by id.
    pub rule_sets: Vec<(String, i64)>,
    /// Areas of rows in reach: (area, rows), by area.
    pub areas: Vec<(String, i64)>,
    /// Groups holding a host with a matching pair, plus the chosen one when
    /// the scope reaches it: (id, name, kind, rows), by name.
    pub groups: Vec<(String, String, GroupKind, i64)>,
    /// Assigned to the viewer.
    pub me: i64,
    /// With an unassigned failing pair.
    pub unassigned: i64,
    /// People with a pair in reach: (user id, display name, rows), by name.
    pub people: Vec<(String, String, i64)>,
}

/// "N checks failing on N hosts · N critical · N unassigned", then a count
/// per rule set (ruling 7), over the rows matching every filter but the
/// state's that have an open failing pair (matching the Assignee filter).
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Deserialize)]
pub struct CheckSummary {
    /// Rows with an open failing pair.
    pub failing_checks: i64,
    /// Hosts with an open failing pair in those rows.
    pub hosts: i64,
    /// Of those rows, critical.
    pub critical: i64,
    /// With no open failing pair assigned.
    pub unassigned: i64,
    /// Those rows per rule set: (id, rows), by id.
    pub rule_sets: Vec<(String, i64)>,
}

/// One page of the list.
#[derive(Clone, Debug)]
pub struct CheckListPage {
    /// The page.
    pub rows: Vec<CheckListRow>,
    /// Rows matching every filter.
    pub total: i64,
    /// Per-value counts.
    pub counts: CheckCounts,
    /// The summary line.
    pub summary: CheckSummary,
}

pub use crate::check_list_sql::passing_hosts_sql;

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
    rule_sets: Vec<(String, i64)>,
    areas: Vec<(String, i64)>,
    groups: Vec<(String, String, String, i64)>,
    unassigned: i64,
    people: Vec<(String, String, i64)>,
}

#[derive(serde::Deserialize)]
struct Meta {
    total: i64,
    counts: RawCounts,
    summary: CheckSummary,
}

/// One page of the Compliance list for `actor_id` (a console user id)
/// within `scope` (`compliance.read`); `now` dates the failing window,
/// heartbeat freshness and expired accepted risks.
pub async fn check_list(
    client: &Client,
    query: &CheckQuery<'_>,
    scope: &AgentScope,
    actor_id: &str,
    now: DateTime<Utc>,
) -> Result<CheckListPage, StoreError> {
    let q = query.q.map(str::trim).filter(|q| !q.is_empty());
    let user = match query.assignee {
        Some(Assignee::Me) => Some(actor_id),
        Some(Assignee::User(id)) => Some(id),
        _ => None,
    }
    .map(|id| if is_uuid(id) { id } else { NOBODY });
    let unassigned = query.assignee == Some(Assignee::Unassigned);
    let state = (query.state != CheckState::All).then(|| query.state.as_str());
    let rows = client
        .query(
            &statement(query.sort, query.descending),
            &[
                &scope.is_global(),
                &scope.group_ids(),
                &q,
                &state,
                &query.severity.map(CheckSeverity::as_str),
                &query.rule_set,
                &query.area,
                &query.group,
                &query.host,
                &user,
                &unassigned,
                &now,
                &query.limit.clamp(1, i64::from(MAX_PAGE_SIZE)),
                &query.offset.clamp(0, 100_000),
            ],
        )
        .await?;
    let meta: serde_json::Value = rows.first().and_then(|r| r.get(0)).unwrap_or_default();
    let meta: Meta = serde_json::from_value(meta).map_err(|_| StoreError::Query)?;
    Ok(CheckListPage {
        rows: rows.iter().filter_map(check_row).collect(),
        total: meta.total,
        summary: meta.summary,
        counts: check_counts(meta.counts, actor_id),
    })
}

fn check_row(row: &Row) -> Option<CheckListRow> {
    let rule_set_id: String = row.get::<_, Option<String>>(1)?;
    let people: i64 = row.get(14);
    let one: Option<String> = row.get(15);
    Some(CheckListRow {
        rule_set_id,
        rule_id: row.get(2),
        title: row.get(3),
        severity: row.get::<_, Option<&str>>(4).and_then(CheckSeverity::parse),
        area: row.get(5),
        failing: row.get(6),
        passing: row.get(7),
        open: row.get(8),
        mitigated: row.get(9),
        accepted_risk: row.get(10),
        false_positive: row.get(11),
        since: row.get(12),
        assignee: match (people, one) {
            (1, Some(id)) => AssigneeSummary::One(id, row.get(13)),
            (0, _) | (_, None) => AssigneeSummary::None,
            (n, _) => AssigneeSummary::Several(u32::try_from(n).unwrap_or(u32::MAX)),
        },
    })
}

fn check_counts(raw: RawCounts, actor_id: &str) -> CheckCounts {
    let n = |map: &BTreeMap<String, i64>, key: &str| map.get(key).copied().unwrap_or(0);
    let by_name = |a: &(String, String, i64), b: &(String, String, i64)| {
        (a.1.to_lowercase(), &a.0).cmp(&(b.1.to_lowercase(), &b.0))
    };
    let mut groups: Vec<_> = raw
        .groups
        .into_iter()
        .map(|(id, name, kind, n)| (id, name, GroupKind::parse(&kind), n))
        .collect();
    groups.sort_by(|a, b| (a.1.to_lowercase(), &a.0).cmp(&(b.1.to_lowercase(), &b.0)));
    let mut people = raw.people;
    people.sort_by(by_name);
    CheckCounts {
        state: CheckState::ALL
            .iter()
            .map(|s| (*s, n(&raw.state, s.as_str())))
            .collect(),
        severity: CheckSeverity::ALL
            .iter()
            .map(|s| (*s, n(&raw.severity, s.as_str())))
            .collect(),
        rule_sets: raw.rule_sets,
        areas: raw.areas,
        groups,
        me: people.iter().find(|p| p.0 == actor_id).map_or(0, |p| p.2),
        unassigned: raw.unassigned,
        people,
    }
}
