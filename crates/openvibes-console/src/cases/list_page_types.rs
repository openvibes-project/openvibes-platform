//! The Cases list answer (`GET /v1/case-list`).

use platform_store::case_list::{CaseListPage, CaseListRow};
use serde::Serialize;
use utoipa::ToSchema;

use super::{
    types::CaseUserView,
    views::{time, user_view},
};
use crate::{
    alarms::list_types::PersonCountView,
    hosts::list_types::{CountView, GroupCountView},
    vulnerabilities::list_page_types::{VulnAssigneeCountsView, counts},
};

/// The newest note on a case.
#[derive(Serialize, ToSchema)]
pub(crate) struct CaseNoteView {
    /// Its first 120 characters.
    pub text: String,
    /// RFC 3339.
    pub at: String,
}

/// A host of a visible item.
#[derive(Serialize, ToSchema)]
pub(crate) struct CaseHostView {
    /// Agent id.
    pub agent_id: String,
    /// Host name, when known.
    pub hostname: Option<String>,
}

/// Visible items per kind.
#[derive(Serialize, ToSchema)]
pub(crate) struct CaseKindsView {
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

/// One row: a case. Items, hosts and counts are only those the viewer sees.
#[derive(Serialize, ToSchema)]
pub(crate) struct CaseListRowView {
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
    pub opened_by: CaseUserView,
    /// Who works on it.
    pub assignee: Option<CaseUserView>,
    /// The newest note.
    pub latest_note: Option<CaseNoteView>,
    /// The first five distinct hosts of visible items, by name.
    pub hosts: Vec<CaseHostView>,
    /// Distinct hosts of visible items.
    pub host_count: i64,
    /// Visible items per kind.
    pub kinds: CaseKindsView,
    /// Visible alarms, findings and vulnerabilities with an outcome.
    pub with_outcome: i64,
    /// Visible alarms, findings and vulnerabilities (the items that take one).
    pub takes_outcome: i64,
    /// Not closed, and close would take it now (close's own rule: hidden
    /// items count too; only this boolean is revealed).
    pub ready: bool,
    /// Last change (RFC 3339).
    pub updated_at: String,
}

/// Cases per filter value, each with the other filters applied.
#[derive(Serialize, ToSchema)]
pub(crate) struct CaseCountsView {
    /// By status.
    pub status: Vec<CountView>,
    /// By severity.
    pub severity: Vec<CountView>,
    /// By Contains value.
    pub contains: Vec<CountView>,
    /// By Updated value.
    pub updated: Vec<CountView>,
    /// By group (groups with a host the viewer sees, plus the chosen one).
    pub group: Vec<GroupCountView>,
    /// By assignee.
    pub assignee: VulnAssigneeCountsView,
}

/// "N open · N investigating · N unassigned · N ready to close", over the
/// cases matching every filter but status that are not closed. Ready uses
/// close's own rule, hidden items included.
#[derive(Serialize, ToSchema)]
pub(crate) struct CaseSummaryLineView {
    /// Open.
    pub open: i64,
    /// Investigating.
    pub investigating: i64,
    /// Not assigned.
    pub unassigned: i64,
    /// Ready to close.
    pub ready_to_close: i64,
}

/// One page of the Cases list.
#[derive(Serialize, ToSchema)]
pub(crate) struct CaseListView {
    /// The page.
    pub items: Vec<CaseListRowView>,
    /// Cases matching every filter.
    pub total: i64,
    /// Per-value counts.
    pub counts: CaseCountsView,
    /// Summary line.
    pub summary: CaseSummaryLineView,
    /// RFC 3339.
    pub generated_at: String,
}

impl From<CaseListRow> for CaseListRowView {
    fn from(r: CaseListRow) -> Self {
        Self {
            case_id: r.case_id,
            number: r.number,
            title: r.title,
            status: r.status,
            severity: r.severity,
            opened_by: user_view(r.opened_by),
            assignee: r.assignee.map(user_view),
            latest_note: r.latest_note.map(|n| CaseNoteView {
                text: n.text,
                at: time(n.at),
            }),
            hosts: r
                .hosts
                .into_iter()
                .map(|(agent_id, hostname)| CaseHostView { agent_id, hostname })
                .collect(),
            host_count: r.host_count,
            kinds: CaseKindsView {
                alarms: r.kinds.alarms,
                findings: r.kinds.findings,
                vulnerabilities: r.kinds.vulnerabilities,
                hosts: r.kinds.hosts,
                software: r.kinds.software,
            },
            with_outcome: r.with_outcome,
            takes_outcome: r.takes_outcome,
            ready: r.ready,
            updated_at: time(r.updated_at),
        }
    }
}

impl CaseListView {
    pub(crate) fn new(page: CaseListPage, now: chrono::DateTime<chrono::Utc>) -> Self {
        let c = page.counts;
        let s = page.summary;
        Self {
            items: page.rows.into_iter().map(Into::into).collect(),
            total: page.total,
            counts: CaseCountsView {
                status: counts(c.status, |v| v.as_str().into()),
                severity: counts(c.severity, |v| v.as_str().into()),
                contains: counts(c.contains, |v| v.as_str().into()),
                updated: counts(c.updated, |v| v.as_str().into()),
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
            summary: CaseSummaryLineView {
                open: s.open,
                investigating: s.investigating,
                unassigned: s.unassigned,
                ready_to_close: s.ready_to_close,
            },
            generated_at: now.to_rfc3339(),
        }
    }
}
