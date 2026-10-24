//! The Compliance list answer (`GET /v1/compliance-list`).

use platform_store::check_list::{CheckListPage, CheckListRow};
use serde::Serialize;
use utoipa::ToSchema;

use crate::{
    alarms::list_types::PersonCountView,
    hosts::list_types::{CountView, GroupCountView},
    vulnerabilities::list_page_types::{VulnAssigneeCountsView, VulnAssigneeView, counts},
};

/// One row: a check (a rule of a rule set).
#[derive(Serialize, ToSchema)]
pub(crate) struct CheckListRowView {
    /// Rule set id.
    pub rule_set_id: String,
    /// Rule id.
    pub rule_id: String,
    /// The rule's title (its newest indexed version), else the rule id.
    pub title: String,
    /// `critical`, `high`, `medium`, `low` or `info`: the newest finding's,
    /// else the rule's indexed severity; absent with neither.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// What the check is about (derived from the rule id).
    pub area: String,
    /// Hosts failing the check.
    pub failing: i64,
    /// Hosts inferred to pass it.
    pub passing: i64,
    /// Failing hosts by triage state: open (an expired acceptance counts).
    pub open: i64,
    /// Mitigated.
    pub mitigated: i64,
    /// Accepted risk (not expired).
    pub accepted_risk: i64,
    /// False positive.
    pub false_positive: i64,
    /// RFC 3339: the earliest first-seen time of the failing hosts.
    pub since: Option<String>,
    /// Who the open failing hosts are assigned to.
    pub assignee: VulnAssigneeView,
}

/// Rows per filter value, each with the other filters applied.
#[derive(Serialize, ToSchema)]
pub(crate) struct CheckCountsView {
    /// By state.
    pub state: Vec<CountView>,
    /// By severity.
    pub severity: Vec<CountView>,
    /// By rule set (every set of rows in reach).
    pub rule_set: Vec<CountView>,
    /// By area (every area of rows in reach).
    pub area: Vec<CountView>,
    /// By group.
    pub group: Vec<GroupCountView>,
    /// By assignee.
    pub assignee: VulnAssigneeCountsView,
}

/// "N checks failing on N hosts · N critical · N unassigned", then a count
/// per rule set, over rows with an open failing host matching every filter
/// but state.
#[derive(Serialize, ToSchema)]
pub(crate) struct CheckSummaryLineView {
    /// Rows with an open failing host.
    pub failing_checks: i64,
    /// Hosts with an open failing pair in those rows.
    pub hosts: i64,
    /// Of those rows, critical.
    pub critical: i64,
    /// With no open failing host assigned.
    pub unassigned: i64,
    /// Those rows per rule set, by id.
    pub rule_sets: Vec<CountView>,
}

/// One page of the Compliance list.
#[derive(Serialize, ToSchema)]
pub(crate) struct CheckListView {
    /// The page.
    pub items: Vec<CheckListRowView>,
    /// Rows matching every filter.
    pub total: i64,
    /// Per-value counts.
    pub counts: CheckCountsView,
    /// Summary line.
    pub summary: CheckSummaryLineView,
    /// RFC 3339.
    pub generated_at: String,
}

impl From<CheckListRow> for CheckListRowView {
    fn from(r: CheckListRow) -> Self {
        Self {
            rule_set_id: r.rule_set_id,
            rule_id: r.rule_id,
            title: r.title,
            severity: r.severity.map(|s| s.as_str().into()),
            area: r.area,
            failing: r.failing,
            passing: r.passing,
            open: r.open,
            mitigated: r.mitigated,
            accepted_risk: r.accepted_risk,
            false_positive: r.false_positive,
            since: r.since.map(|t| t.to_rfc3339()),
            assignee: r.assignee.into(),
        }
    }
}

impl CheckListView {
    pub(crate) fn new(page: CheckListPage, now: chrono::DateTime<chrono::Utc>) -> Self {
        let c = page.counts;
        let s = page.summary;
        Self {
            items: page.rows.into_iter().map(Into::into).collect(),
            total: page.total,
            counts: CheckCountsView {
                state: counts(c.state, |v| v.as_str().into()),
                severity: counts(c.severity, |v| v.as_str().into()),
                rule_set: counts(c.rule_sets, |v| v),
                area: counts(c.areas, |v| v),
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
                assignee: VulnAssigneeCountsView {
                    me: c.me,
                    unassigned: c.unassigned,
                    people: c
                        .people
                        .into_iter()
                        .map(|(value, name, count)| PersonCountView { value, name, count })
                        .collect(),
                },
            },
            summary: CheckSummaryLineView {
                failing_checks: s.failing_checks,
                hosts: s.hosts,
                critical: s.critical,
                unassigned: s.unassigned,
                rule_sets: counts(s.rule_sets, |v| v),
            },
            generated_at: now.to_rfc3339(),
        }
    }
}
