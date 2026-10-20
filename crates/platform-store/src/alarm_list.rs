//! The Alarms list (roles spec §10.3; plan rulings 2–5): search, filters
//! that AND together, the count for every value of every filter with the
//! other filters applied, the summary line and offset paging, over agent
//! alarms only. One statement, so the rows, total, counts and summary
//! always agree, and every part sees only alarms on hosts in the viewer's
//! `alarms.read` scope.

use chrono::{DateTime, Duration, Utc};
use tokio_postgres::Row;

use crate::{
    Client, StoreError,
    alarm_list_sql::statement,
    alarms_status::{AlarmsStatus, alarms_status},
    console_read::{AgentScope, MAX_PAGE_SIZE},
    host_groups::GroupKind,
    host_list::values,
    status::OFFLINE_AFTER_MINUTES,
};

values!(
    /// An alarm's triage state (ruling 2).
    AlarmState {
        /// Not yet handled.
        Open = "open",
        /// Handled.
        Mitigated = "mitigated",
        /// Accepted until a date.
        AcceptedRisk = "accepted_risk",
        /// Not a real threat.
        FalsePositive = "false_positive",
    }
);

values!(
    /// An alarm's severity, most severe first.
    AlarmSeverity {
        /// Critical.
        Critical = "critical",
        /// High.
        High = "high",
        /// Medium.
        Medium = "medium",
        /// Low.
        Low = "low",
        /// Informational.
        Info = "info",
    }
);

values!(
    /// The sort column; ties are broken by alarm id in the same direction
    /// (ruling 4).
    AlarmSort {
        /// Last start that matched.
        LastSeen = "last_seen",
        /// First start that matched.
        FirstSeen = "first_seen",
        /// Starts matched.
        Count = "count",
        /// Severity.
        Severity = "severity",
    }
);

/// The Assignee filter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Assignee<'a> {
    /// The viewer.
    Me,
    /// Nobody.
    Unassigned,
    /// A console user id; one that is not a user id matches nothing.
    User(&'a str),
}

/// What the list asks for. `offset` is held to 0–100000 and `limit` to 1–100.
#[derive(Clone, Debug)]
pub struct AlarmQuery<'a> {
    /// Message, rule id, host name, program or parent program (contains, any case).
    pub q: Option<&'a str>,
    /// State; `None` is every state (the URL's `state=all`).
    pub state: Option<AlarmState>,
    /// Severity.
    pub severity: Option<AlarmSeverity>,
    /// Include alarms closed by a suppression (hidden by default).
    pub suppressed: bool,
    /// An agent id.
    pub host: Option<&'a str>,
    /// An asset group id.
    pub group: Option<&'a str>,
    /// An ATT&CK technique id; an alarm whose rule is not indexed has none.
    pub technique: Option<&'a str>,
    /// In an open case, or not.
    pub case: Option<bool>,
    /// Assignee.
    pub assignee: Option<Assignee<'a>>,
    /// Sort column.
    pub sort: AlarmSort,
    /// Sort direction.
    pub descending: bool,
    /// Rows to skip.
    pub offset: i64,
    /// Rows to return.
    pub limit: i64,
}

/// One alarm row.
#[derive(Clone, Debug)]
pub struct AlarmListRow {
    /// The platform's id.
    pub id: i64,
    /// Agent that raised it.
    pub agent_id: String,
    /// Its host name.
    pub hostname: Option<String>,
    /// `linux` or `windows`.
    pub os_family: Option<String>,
    /// Display name, e.g. `Debian 12`.
    pub distribution: Option<String>,
    /// Rule set.
    pub rule_set_id: String,
    /// Rule.
    pub rule_id: String,
    /// Severity.
    pub severity: AlarmSeverity,
    /// The rule's message.
    pub message: String,
    /// The process's exe.
    pub exe: String,
    /// Its parent's exe, when known.
    pub parent_exe: Option<String>,
    /// ATT&CK technique ids from the rule-metadata index (empty when not indexed).
    pub techniques: Vec<String>,
    /// Starts matched.
    pub count: i64,
    /// First start that matched.
    pub first_seen: DateTime<Utc>,
    /// Last start that matched.
    pub last_seen: DateTime<Utc>,
    /// Triage state.
    pub state: AlarmState,
    /// (user id, display name).
    pub assignee: Option<(String, String)>,
    /// The open case holding it: (case id, number).
    pub case: Option<(String, i64)>,
    /// The suppression that closed it.
    pub suppressed_by: Option<i64>,
}

/// Alarms per filter value, each with the other filters applied.
#[derive(Clone, Debug, Default)]
pub struct AlarmCounts {
    /// Every state.
    pub state: Vec<(AlarmState, i64)>,
    /// Every severity.
    pub severity: Vec<(AlarmSeverity, i64)>,
    /// Suppressed hidden (the default).
    pub suppressed_hidden: i64,
    /// Suppressed shown.
    pub suppressed_shown: i64,
    /// In an open case.
    pub in_case: i64,
    /// In no open case.
    pub not_in_case: i64,
    /// Groups holding a host with an alarm in reach, plus the chosen one when
    /// the scope reaches it: (id, name, kind, alarms), by name.
    pub groups: Vec<(String, String, GroupKind, i64)>,
    /// Techniques of alarms in reach, by id.
    pub techniques: Vec<(String, i64)>,
    /// Assigned to the viewer.
    pub me: i64,
    /// Unassigned.
    pub unassigned: i64,
    /// People with an alarm in reach: (user id, display name, alarms), by name.
    pub people: Vec<(String, String, i64)>,
}

/// "N open · N critical or high · N on hosts with alarms off", over the
/// alarms matching every filter.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AlarmSummaryLine {
    /// Open.
    pub open: i64,
    /// Open and critical or high.
    pub critical_or_high: i64,
    /// Open, on hosts online with threat alarms off by a fault (the Hosts
    /// list's `alarms_off`). The console shows it only with `hosts.read`.
    pub on_alarms_off_hosts: i64,
}

/// One page of the list.
#[derive(Clone, Debug)]
pub struct AlarmListPage {
    /// The page.
    pub rows: Vec<AlarmListRow>,
    /// Alarms matching every filter.
    pub total: i64,
    /// Per-value counts.
    pub counts: AlarmCounts,
    /// Summary over the matching alarms.
    pub summary: AlarmSummaryLine,
}

const NOBODY: &str = "00000000-0000-0000-0000-000000000000";

fn is_uuid(s: &str) -> bool {
    s.len() == 36
        && s.char_indices().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        })
}

type CountLine = (String, String, Option<String>, Option<String>, i64);

#[derive(serde::Deserialize)]
struct Meta {
    total: i64,
    open: i64,
    severe: i64,
    /// (a host's `health -> 'alarms'` with its counters zeroed, open alarms).
    health: Vec<(serde_json::Value, i64)>,
    counts: Vec<CountLine>,
}

/// One page of the Alarms list for `actor_id` (a console user id) within
/// `scope` (`alarms.read`).
pub async fn alarm_list(
    client: &Client,
    query: &AlarmQuery<'_>,
    scope: &AgentScope,
    actor_id: &str,
    now: DateTime<Utc>,
) -> Result<AlarmListPage, StoreError> {
    let threshold = now - Duration::minutes(OFFLINE_AFTER_MINUTES);
    let q = query.q.map(str::trim).filter(|q| !q.is_empty());
    // A user id binds as a uuid; text that is not one matches nobody.
    let user = match query.assignee {
        Some(Assignee::Me) => Some(actor_id),
        Some(Assignee::User(id)) => Some(id),
        _ => None,
    }
    .map(|id| if is_uuid(id) { id } else { NOBODY });
    let unassigned = query.assignee == Some(Assignee::Unassigned);
    let rows = client
        .query(
            &statement(query.sort, query.descending),
            &[
                &scope.is_global(),
                &scope.group_ids(),
                &threshold,
                &q,
                &query.state.map(AlarmState::as_str),
                &query.severity.map(AlarmSeverity::as_str),
                &query.suppressed,
                &query.host,
                &query.group,
                &query.technique,
                &query.case,
                &user,
                &query.limit.clamp(1, i64::from(MAX_PAGE_SIZE)),
                &query.offset.clamp(0, 100_000),
                &unassigned,
            ],
        )
        .await?;
    let meta: serde_json::Value = rows.first().and_then(|r| r.get(0)).unwrap_or_default();
    let meta: Meta = serde_json::from_value(meta).map_err(|_| StoreError::Query)?;
    let off = meta
        .health
        .iter()
        .filter(|(health, _)| {
            matches!(
                alarms_status(true, Some(health)),
                Some(AlarmsStatus::Off { fault: true, .. })
            )
        })
        .map(|(_, n)| n)
        .sum();
    Ok(AlarmListPage {
        rows: rows.iter().filter_map(alarm_row).collect(),
        total: meta.total,
        summary: AlarmSummaryLine {
            open: meta.open,
            critical_or_high: meta.severe,
            on_alarms_off_hosts: off,
        },
        counts: alarm_counts(&meta.counts, actor_id),
    })
}

fn alarm_row(row: &Row) -> Option<AlarmListRow> {
    let id: i64 = row.get::<_, Option<i64>>(1)?;
    let assignee: Option<String> = row.get(17);
    let case: Option<String> = row.get(19);
    Some(AlarmListRow {
        id,
        agent_id: row.get(2),
        hostname: row.get(3),
        os_family: row.get(4),
        distribution: row.get(5),
        rule_set_id: row.get(6),
        rule_id: row.get(7),
        severity: AlarmSeverity::parse(row.get(8)).unwrap_or(AlarmSeverity::Info),
        message: row.get(9),
        exe: row.get::<_, Option<String>>(10).unwrap_or_default(),
        parent_exe: row.get(11),
        techniques: row.get(12),
        count: row.get(13),
        first_seen: row.get(14),
        last_seen: row.get(15),
        state: AlarmState::parse(row.get(16)).unwrap_or(AlarmState::Open),
        assignee: assignee.map(|id| (id, row.get(18))),
        case: case.map(|id| (id, row.get(20))),
        suppressed_by: row.get(21),
    })
}

fn alarm_counts(lines: &[CountLine], actor_id: &str) -> AlarmCounts {
    let facet = |name: &'static str| lines.iter().filter(move |l| l.0 == name);
    let n = |name: &'static str, key: &str| facet(name).find(|l| l.1 == key).map_or(0, |l| l.4);
    let mut groups: Vec<_> = facet("group")
        .map(|l| {
            let name = l.2.clone().unwrap_or_default();
            let kind = GroupKind::parse(l.3.as_deref().unwrap_or_default());
            (l.1.clone(), name, kind, l.4)
        })
        .collect();
    groups.sort_by(|a, b| (a.1.to_lowercase(), &a.0).cmp(&(b.1.to_lowercase(), &b.0)));
    let mut techniques: Vec<_> = facet("technique").map(|l| (l.1.clone(), l.4)).collect();
    techniques.sort();
    let mut people: Vec<_> = facet("person")
        .map(|l| (l.1.clone(), l.2.clone().unwrap_or_default(), l.4))
        .collect();
    people.sort_by(|a, b| (a.1.to_lowercase(), &a.0).cmp(&(b.1.to_lowercase(), &b.0)));
    AlarmCounts {
        state: AlarmState::ALL
            .iter()
            .map(|s| (*s, n("state", s.as_str())))
            .collect(),
        severity: AlarmSeverity::ALL
            .iter()
            .map(|s| (*s, n("severity", s.as_str())))
            .collect(),
        suppressed_hidden: n("suppressed", "hidden"),
        suppressed_shown: n("suppressed", "shown"),
        in_case: n("case", "yes"),
        not_in_case: n("case", "no"),
        groups,
        techniques,
        me: n("person", actor_id),
        unassigned: n("unassigned", "unassigned"),
        people,
    }
}
