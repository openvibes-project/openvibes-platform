//! The Vulnerabilities list answer (`GET /v1/vulnerability-list`).

use platform_store::vuln_list::{AssigneeSummary, Fixed, VulnListPage, VulnListRow};
use serde::Serialize;
use utoipa::ToSchema;

use crate::{
    alarms::list_types::PersonCountView,
    hosts::list_types::{CountView, GroupCountView},
};

/// The fixed version under the package.
#[derive(Serialize, ToSchema)]
pub(crate) struct VulnFixedView {
    /// `one` (every pair with a fix names `version`), `several` (`count`
    /// different fixed versions) or `none` (no pair has a fix).
    pub kind: String,
    /// The fixed version, for `one`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The number of fixed versions, for `several`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
}

/// Who the open pairs are assigned to.
#[derive(Serialize, ToSchema)]
pub(crate) struct VulnAssigneeView {
    /// `none`, `one` (`id` and `name`) or `several` (`count` people).
    pub kind: String,
    /// User id, for `one`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Display name, for `one`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// People, for `several`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
}

/// One row: a CVE, or an advisory without CVEs.
#[derive(Serialize, ToSchema)]
pub(crate) struct VulnListRowView {
    /// The CVE id, or the advisory id.
    pub key: String,
    /// Title of the covering advisory with the most hosts in reach.
    pub title: String,
    /// Worst severity among the covering advisories: `critical`,
    /// `important`, `moderate`, `low` or `unrated`.
    pub severity: String,
    /// On CISA KEV or EUVD's exploited list.
    pub exploited: bool,
    /// KEV due date, `YYYY-MM-DD`.
    pub due: Option<String>,
    /// CVSS base score.
    pub cvss: Option<f32>,
    /// EPSS score.
    pub epss: Option<f32>,
    /// EPSS percentile.
    pub epss_percentile: Option<f32>,
    /// Affected package names, sorted.
    pub packages: Vec<String>,
    /// The fixed version.
    pub fixed: VulnFixedView,
    /// Open pairs (triage open, not fixed).
    pub open: i64,
    /// Every pair, whatever its state.
    pub total: i64,
    /// A pair waits for a reboot.
    pub reboot: bool,
    /// A lower-confidence match (shown with the `lowconf` signal).
    pub low_confidence: bool,
    /// The covering advisories in reach, sorted.
    pub advisories: Vec<String>,
    /// Other CVEs those advisories name, sorted, at most 10.
    pub also_covers: Vec<String>,
    /// Who the open pairs are assigned to.
    pub assignee: VulnAssigneeView,
}

/// The Assignee filter's values.
#[derive(Serialize, ToSchema)]
pub(crate) struct VulnAssigneeCountsView {
    /// Rows assigned to the viewer (`assignee=me`).
    pub me: i64,
    /// Rows with an unassigned pair (`assignee=unassigned`).
    pub unassigned: i64,
    /// People with a pair in reach.
    pub people: Vec<PersonCountView>,
}

/// Rows per filter value, each with the other filters applied.
#[derive(Serialize, ToSchema)]
pub(crate) struct VulnCountsView {
    /// By state.
    pub state: Vec<CountView>,
    /// By severity.
    pub severity: Vec<CountView>,
    /// By signal.
    pub signal: Vec<CountView>,
    /// The 50 packages with the most rows, plus the chosen one.
    pub package: Vec<CountView>,
    /// By group.
    pub group: Vec<GroupCountView>,
    /// By assignee.
    pub assignee: VulnAssigneeCountsView,
}

/// The line above the list, over rows with an open pair matching every
/// filter but state. Counts are rows, except `hosts`.
#[derive(Serialize, ToSchema)]
pub(crate) struct VulnSummaryLineView {
    /// Rows with an open pair.
    pub open_rows: i64,
    /// Hosts with an open pair in those rows.
    pub hosts: i64,
    /// Of those rows, known exploited.
    pub exploited: i64,
    /// With a KEV due date.
    pub with_due: i64,
    /// Without a fix.
    pub no_fix: i64,
    /// With no open pair assigned.
    pub unassigned: i64,
}

/// One page of the Vulnerabilities list.
#[derive(Serialize, ToSchema)]
pub(crate) struct VulnListView {
    /// The page.
    pub items: Vec<VulnListRowView>,
    /// Rows matching every filter.
    pub total: i64,
    /// Per-value counts.
    pub counts: VulnCountsView,
    /// Summary line.
    pub summary: VulnSummaryLineView,
    /// RFC 3339.
    pub generated_at: String,
}

impl From<VulnListRow> for VulnListRowView {
    fn from(r: VulnListRow) -> Self {
        let fixed = |kind: &str, version, count| VulnFixedView {
            kind: kind.into(),
            version,
            count,
        };
        let who = |kind: &str, id, name, count| VulnAssigneeView {
            kind: kind.into(),
            id,
            name,
            count,
        };
        Self {
            key: r.key,
            title: r.title,
            severity: r.severity.as_str().into(),
            exploited: r.exploited,
            due: r.kev_due.map(|d| d.to_string()),
            cvss: r.cvss,
            epss: r.epss,
            epss_percentile: r.epss_percentile,
            packages: r.packages,
            fixed: match r.fixed {
                Fixed::One(v) => fixed("one", Some(v), None),
                Fixed::Several(n) => fixed("several", None, Some(n)),
                Fixed::None => fixed("none", None, None),
            },
            open: r.open,
            total: r.total,
            reboot: r.reboot,
            low_confidence: r.low_confidence,
            advisories: r.advisories,
            also_covers: r.also_covers,
            assignee: match r.assignee {
                AssigneeSummary::None => who("none", None, None, None),
                AssigneeSummary::One(id, name) => who("one", Some(id), Some(name), None),
                AssigneeSummary::Several(n) => who("several", None, None, Some(n)),
            },
        }
    }
}

pub(crate) fn counts<T>(rows: Vec<(T, i64)>, name: impl Fn(T) -> String) -> Vec<CountView> {
    rows.into_iter()
        .map(|(v, count)| CountView {
            value: name(v),
            count,
        })
        .collect()
}

impl VulnListView {
    pub(crate) fn new(page: VulnListPage, now: chrono::DateTime<chrono::Utc>) -> Self {
        let c = page.counts;
        let s = page.summary;
        Self {
            items: page.rows.into_iter().map(Into::into).collect(),
            total: page.total,
            counts: VulnCountsView {
                state: counts(c.state, |v| v.as_str().into()),
                severity: counts(c.severity, |v| v.as_str().into()),
                signal: counts(c.signal, |v| v.as_str().into()),
                package: counts(c.packages, |v| v),
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
            summary: VulnSummaryLineView {
                open_rows: s.open_rows,
                hosts: s.hosts,
                exploited: s.exploited,
                with_due: s.with_due,
                no_fix: s.no_fix,
                unassigned: s.unassigned,
            },
            generated_at: now.to_rfc3339(),
        }
    }
}
