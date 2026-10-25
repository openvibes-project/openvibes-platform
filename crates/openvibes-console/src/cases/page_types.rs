//! A case's page answer (`GET /v1/cases/{id}/summary`, step 5d ruling 12).

use platform_store::case_summary::{CaseHost, CasePageSummary};
use serde::Serialize;
use utoipa::ToSchema;

use super::{
    types::CaseUserView,
    views::{time, user_view},
};
use crate::hosts::list_types::HostOsView;

/// The header facts.
#[derive(Serialize, ToSchema)]
pub(crate) struct CasePageHeaderView {
    /// Stable UUID.
    pub case_id: String,
    /// Shown as `C-<number>`.
    pub number: i64,
    /// 1 to 120 characters.
    pub title: String,
    /// `open`, `investigating` or `closed`.
    pub status: String,
    /// `critical`, `high`, `medium` or `low`.
    pub severity: String,
    /// Who opened it.
    pub opened_by: CaseUserView,
    /// RFC 3339.
    pub created_at: String,
    /// Who works on it.
    pub assignee: Option<CaseUserView>,
    /// Version for `If-Match`.
    pub version: u64,
}

/// The tiles. Counts are of the items the viewer sees.
#[derive(Serialize, ToSchema)]
pub(crate) struct CasePageTilesView {
    /// Visible items.
    pub items: i64,
    /// Visible alarms, findings and vulnerabilities without an outcome.
    pub need_outcome: i64,
    /// Distinct hosts of visible items.
    pub hosts: i64,
    /// Created to now, or to when it closed.
    pub open_for_seconds: i64,
    /// Not closed, and close's own rule passes over every item, hidden ones
    /// included ("Ready to close").
    pub ready: bool,
}

/// The details card.
#[derive(Serialize, ToSchema)]
pub(crate) struct CasePageDetailsView {
    /// Title.
    pub title: String,
    /// Severity.
    pub severity: String,
    /// Status.
    pub status: String,
    /// Who opened it.
    pub opened_by: CaseUserView,
    /// RFC 3339.
    pub created_at: String,
    /// RFC 3339.
    pub updated_at: String,
    /// RFC 3339, once closed.
    pub closed_at: Option<String>,
    /// How a case closed before step 5d ended; new closes set none.
    pub resolution: Option<String>,
    /// The closing note.
    pub resolution_note: Option<String>,
}

/// A host's open problems; null where the viewer may not read that kind
/// on the host.
#[derive(Serialize, ToSchema)]
pub(crate) struct CasePageProblemsView {
    /// Open alarms (`alarms.read`).
    pub alarms: Option<i64>,
    /// Critical vulnerabilities (`vulnerabilities.read`).
    pub critical_vulns: Option<i64>,
    /// Open failing checks (`compliance.read`).
    pub failing_checks: Option<i64>,
}

/// A host of a visible item.
#[derive(Serialize, ToSchema)]
pub(crate) struct CasePageHostView {
    /// Agent id.
    pub agent_id: String,
    /// Host name.
    pub hostname: Option<String>,
    /// Operating system.
    pub os: HostOsView,
    /// Its open problems.
    pub problems: CasePageProblemsView,
}

/// Who can see the case.
#[derive(Serialize, ToSchema)]
pub(crate) struct CasePagePeopleView {
    /// The first 20 by name, with `access.read` only; null otherwise.
    pub names: Option<Vec<CaseUserView>>,
    /// How many people can see it.
    pub total: i64,
}

/// What the viewer may do here.
#[derive(Serialize, ToSchema)]
pub(crate) struct CasePageActionsView {
    /// Change title and severity (`cases.write` on the case).
    pub edit: bool,
    /// Change the assignee (also `cases.assign`).
    pub assign: bool,
    /// Close it (`cases.write`, not closed).
    pub close: bool,
    /// Reopen it (`cases.write`, closed).
    pub reopen: bool,
    /// Add a note (`cases.write`).
    pub note: bool,
    /// Set item outcomes (`cases.write`, not closed).
    pub outcome: bool,
    /// Ask the assistant about it: always false, as the assistant takes no
    /// case reference yet.
    pub ask: bool,
    /// Export it (`cases.read`).
    pub export: bool,
}

/// Everything above the fold on a case's page.
#[derive(Serialize, ToSchema)]
pub(crate) struct CasePageSummaryView {
    /// Header facts.
    pub header: CasePageHeaderView,
    /// Tiles.
    pub tiles: CasePageTilesView,
    /// Details card.
    pub details: CasePageDetailsView,
    /// Hosts of visible items, by name.
    pub hosts: Vec<CasePageHostView>,
    /// Who can see it.
    pub people: CasePagePeopleView,
    /// Actions.
    pub can: CasePageActionsView,
}

fn host_view(h: CaseHost) -> CasePageHostView {
    CasePageHostView {
        agent_id: h.agent_id,
        hostname: h.hostname,
        os: HostOsView {
            id: h.os_id,
            version: h.os_version,
            distribution: h.distribution,
            family: h.os_family,
        },
        problems: CasePageProblemsView {
            alarms: h.problems.alarms,
            critical_vulns: h.problems.critical_vulns,
            failing_checks: h.problems.failing_checks,
        },
    }
}

impl CasePageSummaryView {
    /// The view; `names` says whether the viewer may see who.
    pub(crate) fn new(s: CasePageSummary, names: bool, can: CasePageActionsView) -> Self {
        let c = s.case;
        Self {
            header: CasePageHeaderView {
                case_id: c.case_id,
                number: c.number,
                title: c.title.clone(),
                status: c.status.clone(),
                severity: c.severity.clone(),
                opened_by: user_view(c.opened_by.clone()),
                created_at: time(c.created_at),
                assignee: c.assignee.map(user_view),
                version: c.version.try_into().unwrap_or_default(),
            },
            tiles: CasePageTilesView {
                items: c.items,
                need_outcome: c.pending_items,
                hosts: i64::try_from(s.hosts.len()).unwrap_or(i64::MAX),
                open_for_seconds: s.open_for_seconds,
                ready: s.ready,
            },
            details: CasePageDetailsView {
                title: c.title,
                severity: c.severity,
                status: c.status,
                opened_by: user_view(c.opened_by),
                created_at: time(c.created_at),
                updated_at: time(c.updated_at),
                closed_at: c.closed_at.map(time),
                resolution: c.resolution,
                resolution_note: s.resolution_note,
            },
            hosts: s.hosts.into_iter().map(host_view).collect(),
            people: CasePagePeopleView {
                names: names.then(|| s.people.names.into_iter().map(user_view).collect()),
                total: s.people.total,
            },
            can,
        }
    }
}
