//! The Alarms list answer (`GET /v1/alarm-list`).

use platform_store::alarm_list::{AlarmListPage, AlarmListRow};
use serde::Serialize;
use utoipa::ToSchema;

use crate::hosts::list_types::{CountView, GroupCountView};

/// The host that raised the alarm.
#[derive(Serialize, ToSchema)]
pub(crate) struct AlarmListHostView {
    /// Agent id.
    pub id: String,
    /// Host name.
    pub name: Option<String>,
    /// `linux` or `windows`.
    pub os_family: Option<String>,
    /// Display name, such as `Debian 12`.
    pub distribution: Option<String>,
}

/// Who an alarm is assigned to.
#[derive(Serialize, ToSchema)]
pub(crate) struct AlarmListPersonView {
    /// User id.
    pub id: String,
    /// Display name.
    pub name: String,
}

/// The open case holding an alarm.
#[derive(Serialize, ToSchema)]
pub(crate) struct AlarmListCaseView {
    /// Case id.
    pub id: String,
    /// Case number.
    pub number: i64,
}

/// One row of the Alarms list.
#[derive(Serialize, ToSchema)]
pub(crate) struct AlarmListRowView {
    /// The platform's alarm id.
    pub id: i64,
    /// Host.
    pub host: AlarmListHostView,
    /// Rule set.
    pub rule_set_id: String,
    /// Rule.
    pub rule_id: String,
    /// `critical`, `high`, `medium`, `low` or `info`.
    pub severity: String,
    /// The rule's message.
    pub message: String,
    /// The process's program (exe).
    pub program: String,
    /// Its parent's program, when known.
    pub parent_program: Option<String>,
    /// ATT&CK technique ids (empty when the rule is not indexed).
    pub techniques: Vec<String>,
    /// Starts matched.
    pub count: i64,
    /// First start that matched, RFC 3339.
    pub first_seen: String,
    /// Last start that matched, RFC 3339.
    pub last_seen: String,
    /// `open`, `mitigated`, `accepted_risk` or `false_positive`.
    pub state: String,
    /// Assignee.
    pub assignee: Option<AlarmListPersonView>,
    /// The open case holding it.
    pub case: Option<AlarmListCaseView>,
    /// Closed by a suppression.
    pub suppressed: bool,
}

/// A person with alarms in reach.
#[derive(Serialize, ToSchema)]
pub(crate) struct PersonCountView {
    /// User id (the `assignee` value).
    pub value: String,
    /// Display name.
    pub name: String,
    /// Alarms matching with the other filters applied.
    pub count: i64,
}

/// The Assignee filter's values.
#[derive(Serialize, ToSchema)]
pub(crate) struct AssigneeCountsView {
    /// Assigned to the viewer (`assignee=me`).
    pub me: i64,
    /// Assigned to nobody (`assignee=unassigned`).
    pub unassigned: i64,
    /// People with an alarm in reach.
    pub people: Vec<PersonCountView>,
}

/// Per-value counts for every filter.
#[derive(Serialize, ToSchema)]
pub(crate) struct AlarmCountsView {
    /// By state.
    pub state: Vec<CountView>,
    /// By severity.
    pub severity: Vec<CountView>,
    /// `hidden` and `shown`.
    pub suppressed: Vec<CountView>,
    /// `yes` (in an open case) and `no`.
    pub case: Vec<CountView>,
    /// By group.
    pub group: Vec<GroupCountView>,
    /// By ATT&CK technique.
    pub technique: Vec<CountView>,
    /// By assignee.
    pub assignee: AssigneeCountsView,
}

/// The line above the list: over open alarms matching every filter but state.
#[derive(Serialize, ToSchema)]
pub(crate) struct AlarmSummaryLineView {
    /// Open alarms.
    pub open: i64,
    /// Open and critical or high.
    pub critical_or_high: i64,
    /// Open, on hosts online with threat alarms off by a fault; absent
    /// without `hosts.read`.
    pub on_alarms_off_hosts: Option<i64>,
}

/// One page of the Alarms list.
#[derive(Serialize, ToSchema)]
pub(crate) struct AlarmListView {
    /// The page.
    pub items: Vec<AlarmListRowView>,
    /// Alarms matching every filter.
    pub total: i64,
    /// Per-value counts.
    pub counts: AlarmCountsView,
    /// Summary line.
    pub summary: AlarmSummaryLineView,
    /// RFC 3339.
    pub generated_at: String,
}

impl From<AlarmListRow> for AlarmListRowView {
    fn from(r: AlarmListRow) -> Self {
        Self {
            id: r.id,
            host: AlarmListHostView {
                id: r.agent_id,
                name: r.hostname,
                os_family: r.os_family,
                distribution: r.distribution,
            },
            rule_set_id: r.rule_set_id,
            rule_id: r.rule_id,
            severity: r.severity.as_str().into(),
            message: r.message,
            program: r.exe,
            parent_program: r.parent_exe,
            techniques: r.techniques,
            count: r.count,
            first_seen: r.first_seen.to_rfc3339(),
            last_seen: r.last_seen.to_rfc3339(),
            state: r.state.as_str().into(),
            assignee: r
                .assignee
                .map(|(id, name)| AlarmListPersonView { id, name }),
            case: r.case.map(|(id, number)| AlarmListCaseView { id, number }),
            suppressed: r.suppressed_by.is_some(),
        }
    }
}

fn counts<T>(
    rows: impl IntoIterator<Item = (T, i64)>,
    name: impl Fn(T) -> String,
) -> Vec<CountView> {
    rows.into_iter()
        .map(|(v, count)| CountView {
            value: name(v),
            count,
        })
        .collect()
}

impl AlarmListView {
    pub(crate) fn new(
        page: AlarmListPage,
        show_alarms_off: bool,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        let c = page.counts;
        Self {
            items: page.rows.into_iter().map(Into::into).collect(),
            total: page.total,
            counts: AlarmCountsView {
                state: counts(c.state, |v| v.as_str().into()),
                severity: counts(c.severity, |v| v.as_str().into()),
                suppressed: counts(
                    [
                        ("hidden", c.suppressed_hidden),
                        ("shown", c.suppressed_shown),
                    ],
                    Into::into,
                ),
                case: counts([("yes", c.in_case), ("no", c.not_in_case)], Into::into),
                group: c
                    .groups
                    .into_iter()
                    .map(|(value, name, kind, count)| GroupCountView {
                        value,
                        name,
                        kind: kind.into(),
                        count,
                    })
                    .collect(),
                technique: counts(c.techniques, |v| v),
                assignee: AssigneeCountsView {
                    me: c.me,
                    unassigned: c.unassigned,
                    people: c
                        .people
                        .into_iter()
                        .map(|(value, name, count)| PersonCountView { value, name, count })
                        .collect(),
                },
            },
            summary: AlarmSummaryLineView {
                open: page.summary.open,
                critical_or_high: page.summary.critical_or_high,
                on_alarms_off_hosts: show_alarms_off.then_some(page.summary.on_alarms_off_hosts),
            },
            generated_at: now.to_rfc3339(),
        }
    }
}
