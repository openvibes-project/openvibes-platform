//! The Cases list (roles plan 2026-10-25 step 5d, rulings 2, 4, 6–10): one
//! row per case the viewer sees, with search, filters that AND together,
//! the count for every value of every filter with the other filters
//! applied, the summary line and offset paging. Items, hosts and counts
//! are only those the viewer sees. One statement, so rows, total, counts
//! and summary always agree.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use tokio_postgres::Row;

use crate::{
    Client, StoreError,
    alarm_list::Assignee,
    case_list_sql::statement,
    console_cases::{UserRef, case_number},
    console_read::{AgentScope, MAX_PAGE_SIZE},
    host_groups::GroupKind,
    host_list::values,
};

values!(
    /// The Status filter (ruling 6).
    CaseStatus {
        /// Not closed (the default).
        Active = "active",
        /// Open.
        Open = "open",
        /// Investigating.
        Investigating = "investigating",
        /// Closed.
        Closed = "closed",
        /// Every status.
        All = "all",
    }
);

values!(
    /// A case severity.
    CaseSeverity {
        /// Critical.
        Critical = "critical",
        /// High.
        High = "high",
        /// Medium.
        Medium = "medium",
        /// Low.
        Low = "low",
    }
);

values!(
    /// The Contains filter: at least one visible item of that kind.
    CaseContains {
        /// Alarms.
        Alarms = "alarms",
        /// Vulnerabilities.
        Vulnerabilities = "vulnerabilities",
        /// Compliance findings.
        Findings = "findings",
    }
);

values!(
    /// The Updated filter. Today is since midnight UTC of `now`, the same
    /// day for every viewer whatever their time zone.
    CaseUpdated {
        /// Since midnight UTC.
        Today = "today",
        /// Within the last 7 days.
        Week = "week",
        /// Not for 7 days or more.
        Quiet = "quiet",
    }
);

values!(
    /// The sort column; ties are broken by case id in the same direction.
    CaseSort {
        /// Last change (the default, newest first).
        Updated = "updated",
        /// Severity.
        Severity = "severity",
        /// Case number.
        Number = "number",
        /// Creation time.
        Opened = "opened",
    }
);

impl CaseContains {
    fn kind(self) -> &'static str {
        match self {
            Self::Alarms => "alarm",
            Self::Vulnerabilities => "vulnerability",
            Self::Findings => "compliance_finding",
        }
    }
}

/// What the list asks for. `offset` is held to 0–100000 and `limit` to 1–100.
#[derive(Clone, Debug)]
pub struct CaseQuery<'a> {
    /// Title, `C-<number>`, the number, or the opener's name (contains, any case).
    pub q: Option<&'a str>,
    /// Status.
    pub status: CaseStatus,
    /// Severity.
    pub severity: Option<CaseSeverity>,
    /// Assignee.
    pub assignee: Option<Assignee<'a>>,
    /// An item kind the case holds visibly.
    pub contains: Option<CaseContains>,
    /// An agent id: a visible item on that host.
    pub host: Option<&'a str>,
    /// An asset group id: a visible item on a host in it.
    pub group: Option<&'a str>,
    /// Last change.
    pub updated: Option<CaseUpdated>,
    /// Sort column.
    pub sort: CaseSort,
    /// Sort direction.
    pub descending: bool,
    /// Rows to skip.
    pub offset: i64,
    /// Rows to return.
    pub limit: i64,
}

/// The newest note on a case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseNote {
    /// Its first 120 characters.
    pub text: String,
    /// When it was written.
    pub at: DateTime<Utc>,
}

/// Visible items per kind.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CaseKinds {
    /// Alarms.
    pub alarms: i64,
    /// Compliance findings.
    pub findings: i64,
    /// Vulnerabilities.
    pub vulnerabilities: i64,
    /// Hosts.
    pub hosts: i64,
    /// Software.
    pub software: i64,
}

/// One row: a case (ruling 9).
#[derive(Clone, Debug)]
pub struct CaseListRow {
    /// Stable UUID.
    pub case_id: String,
    /// Shown as `C-<number>`.
    pub number: i64,
    /// Title.
    pub title: String,
    /// `open`, `investigating` or `closed`.
    pub status: String,
    /// `critical`, `high`, `medium` or `low`.
    pub severity: String,
    /// Who opened it.
    pub opened_by: UserRef,
    /// Who works on it.
    pub assignee: Option<UserRef>,
    /// The newest note.
    pub latest_note: Option<CaseNote>,
    /// The first five distinct hosts of visible items: (agent id, host
    /// name), by name.
    pub hosts: Vec<(String, Option<String>)>,
    /// Distinct hosts of visible items.
    pub host_count: i64,
    /// Visible items per kind.
    pub kinds: CaseKinds,
    /// Visible items that take an outcome and have one.
    pub with_outcome: i64,
    /// Visible items that take an outcome (alarms, findings, vulnerabilities).
    pub takes_outcome: i64,
    /// Not closed, and close would take it: no item, visible or hidden,
    /// still blocks (close's own rule).
    pub ready: bool,
    /// Last change.
    pub updated_at: DateTime<Utc>,
    /// How a case closed before step 5d ended (`mitigated`, `false_positive`,
    /// `accepted_risk`); new closes set none.
    pub resolution: Option<String>,
}

/// Cases per filter value, each with the other filters applied.
#[derive(Clone, Debug, Default)]
pub struct CaseCounts {
    /// Every status.
    pub status: Vec<(CaseStatus, i64)>,
    /// Every severity.
    pub severity: Vec<(CaseSeverity, i64)>,
    /// Every Contains value.
    pub contains: Vec<(CaseContains, i64)>,
    /// Every Updated value.
    pub updated: Vec<(CaseUpdated, i64)>,
    /// Groups holding a host the viewer sees, plus the chosen one when the
    /// scope reaches it: (id, name, kind, cases), by name.
    pub groups: Vec<(String, String, GroupKind, i64)>,
    /// Assigned to the viewer.
    pub me: i64,
    /// Assigned to nobody.
    pub unassigned: i64,
    /// People assigned a case the viewer sees: (user id, display name,
    /// cases), by name.
    pub people: Vec<(String, String, i64)>,
}

/// "N open · N investigating · N unassigned · N ready to close" (ruling
/// 10), over the cases matching every filter except status (the status
/// filter never empties it) that are not closed. Ready uses close's own
/// rule: no item, visible or hidden, lacks an outcome or is resolved with
/// its evidence back.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Deserialize)]
pub struct CaseSummaryLine {
    /// Open.
    pub open: i64,
    /// Investigating.
    pub investigating: i64,
    /// Not assigned.
    pub unassigned: i64,
    /// Ready to close.
    pub ready_to_close: i64,
}

/// One page of the list.
#[derive(Clone, Debug)]
pub struct CaseListPage {
    /// The page.
    pub rows: Vec<CaseListRow>,
    /// Cases matching every filter.
    pub total: i64,
    /// Per-value counts.
    pub counts: CaseCounts,
    /// The summary line.
    pub summary: CaseSummaryLine,
}

const NOBODY: &str = "00000000-0000-0000-0000-000000000000";

fn uuid_or_nobody(id: &str) -> &str {
    let ok = id.len() == 36
        && id.char_indices().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        });
    if ok { id } else { NOBODY }
}

#[derive(serde::Deserialize)]
struct RawCounts {
    status: BTreeMap<String, i64>,
    severity: BTreeMap<String, i64>,
    contains: BTreeMap<String, i64>,
    updated: BTreeMap<String, i64>,
    groups: Vec<(String, String, String, i64)>,
    unassigned: i64,
    people: Vec<(String, String, i64)>,
}

#[derive(serde::Deserialize)]
struct Meta {
    total: i64,
    counts: RawCounts,
    summary: CaseSummaryLine,
}

/// One page of the Cases list for `actor_id` (a console user id) within
/// `scope` (`cases.read`); `now` dates the Updated filter.
pub async fn case_list(
    client: &Client,
    query: &CaseQuery<'_>,
    scope: &AgentScope,
    actor_id: &str,
    now: DateTime<Utc>,
) -> Result<CaseListPage, StoreError> {
    let q = query.q.map(str::trim).filter(|q| !q.is_empty());
    let actor = uuid_or_nobody(actor_id);
    let user = match query.assignee {
        Some(Assignee::Me) => Some(actor),
        Some(Assignee::User(id)) => Some(uuid_or_nobody(id)),
        _ => None,
    };
    let rows = client
        .query(
            &statement(query.sort, query.descending),
            &[
                &scope.is_global(),
                &scope.group_ids(),
                &actor,
                &q,
                &q.and_then(case_number),
                &query.status.as_str(),
                &query.severity.map(CaseSeverity::as_str),
                &user,
                &(query.assignee == Some(Assignee::Unassigned)),
                &query.contains.map(CaseContains::kind),
                &query.host,
                &query.group,
                &query.updated.map(CaseUpdated::as_str),
                &now,
                &query.limit.clamp(1, i64::from(MAX_PAGE_SIZE)),
                &query.offset.clamp(0, 100_000),
            ],
        )
        .await?;
    let meta: serde_json::Value = rows.first().and_then(|r| r.get(0)).unwrap_or_default();
    let meta: Meta = serde_json::from_value(meta).map_err(|_| StoreError::Query)?;
    Ok(CaseListPage {
        rows: rows.iter().filter_map(case_row).collect(),
        total: meta.total,
        summary: meta.summary,
        counts: case_counts(meta.counts, actor),
    })
}

fn user(id: Option<String>, username: Option<String>, name: Option<String>) -> Option<UserRef> {
    Some(UserRef {
        user_id: id?,
        username: username.unwrap_or_default(),
        display_name: name.unwrap_or_default(),
    })
}

fn case_row(row: &Row) -> Option<CaseListRow> {
    let case_id: String = row.get::<_, Option<String>>(1)?;
    let hosts: Option<serde_json::Value> = row.get(14);
    Some(CaseListRow {
        case_id,
        number: row.get(2),
        title: row.get(3),
        status: row.get(4),
        severity: row.get(5),
        opened_by: user(row.get(6), row.get(7), row.get(8))?,
        assignee: user(row.get(9), row.get(10), row.get(11)),
        latest_note: row.get::<_, Option<String>>(12).map(|text| CaseNote {
            text,
            at: row.get(13),
        }),
        hosts: hosts
            .and_then(|h| serde_json::from_value(h).ok())
            .unwrap_or_default(),
        kinds: CaseKinds {
            alarms: row.get(15),
            findings: row.get(16),
            vulnerabilities: row.get(17),
            hosts: row.get(18),
            software: row.get(19),
        },
        takes_outcome: row.get(20),
        with_outcome: row.get(21),
        updated_at: row.get(22),
        host_count: row.get::<_, Option<i64>>(23).unwrap_or(0),
        ready: row.get::<_, Option<bool>>(24).unwrap_or(false),
        resolution: row.get(25),
    })
}

fn each<T: Copy>(
    all: &[T],
    name: fn(T) -> &'static str,
    map: &BTreeMap<String, i64>,
) -> Vec<(T, i64)> {
    all.iter()
        .map(|v| (*v, map.get(name(*v)).copied().unwrap_or(0)))
        .collect()
}

fn case_counts(raw: RawCounts, actor_id: &str) -> CaseCounts {
    let mut groups: Vec<_> = raw
        .groups
        .into_iter()
        .map(|(id, name, kind, n)| (id, name, GroupKind::parse(&kind), n))
        .collect();
    groups.sort_by(|a, b| (a.1.to_lowercase(), &a.0).cmp(&(b.1.to_lowercase(), &b.0)));
    let mut people = raw.people;
    people.sort_by(|a, b| (a.1.to_lowercase(), &a.0).cmp(&(b.1.to_lowercase(), &b.0)));
    CaseCounts {
        status: each(CaseStatus::ALL, CaseStatus::as_str, &raw.status),
        severity: each(CaseSeverity::ALL, CaseSeverity::as_str, &raw.severity),
        contains: each(CaseContains::ALL, CaseContains::as_str, &raw.contains),
        updated: each(CaseUpdated::ALL, CaseUpdated::as_str, &raw.updated),
        groups,
        me: people.iter().find(|p| p.0 == actor_id).map_or(0, |p| p.2),
        unassigned: raw.unassigned,
        people,
    }
}
