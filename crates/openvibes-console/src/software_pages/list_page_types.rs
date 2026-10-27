//! The Software list answer (`GET /v1/software-list`).

use platform_store::software_list::{
    SoftwareListPage, SoftwareListRow, SoftwareListSummary, UsedBy,
};
use serde::Serialize;
use utoipa::ToSchema;

use crate::{
    hosts::list_types::{CountView, GroupCountView},
    vulnerabilities::list_page_types::counts,
};

/// A service that uses the package, matched by name.
#[derive(Serialize, ToSchema)]
pub(crate) struct UsedByView {
    /// The unit, e.g. `nginx.service`.
    pub unit: String,
    /// Hosts in reach running it.
    pub hosts: i64,
}

/// One row: a package name.
#[derive(Serialize, ToSchema)]
pub(crate) struct SoftwareListRowView {
    /// The package name.
    pub name: String,
    /// Hosts in reach that have it, under any package database.
    pub hosts: i64,
    /// Versions in use (distinct epoch, version and release).
    pub versions: i64,
    /// The oldest version in use, `epoch:version-release`.
    pub oldest: String,
    /// The newest.
    pub newest: String,
    /// Reported from dpkg.
    pub dpkg: bool,
    /// Reported from rpm.
    pub rpm: bool,
    /// Open advisories on the hosts in reach.
    pub advisories: i64,
    /// Of those, advisories no update fixes.
    pub no_fix: i64,
    /// The worst severity among them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worst_severity: Option<String>,
    /// One of them is known to be exploited.
    pub exploited: bool,
    /// Hosts where an update fixes an open advisory.
    pub update_hosts: i64,
    /// Services using it, most hosts first, at most 3.
    pub used_by: Vec<UsedByView>,
    /// How many services use it in all.
    pub used_by_total: i64,
    /// Hosts that installed it in the last 7 days.
    pub week_added: i64,
    /// Hosts that changed its version in the last 7 days.
    pub week_updated: i64,
    /// Hosts that removed it in the last 7 days.
    pub week_removed: i64,
}

/// Rows per filter value, each with the other filters applied.
#[derive(Serialize, ToSchema)]
pub(crate) struct SoftwareCountsView {
    /// `exploited`, `critical_high`, `any`, `none`.
    pub vulns: Vec<CountView>,
    /// `available`, `none`.
    pub fix: Vec<CountView>,
    /// `one`, `several`.
    pub versions: Vec<CountView>,
    /// `dpkg`, `rpm`.
    #[serde(rename = "type")]
    pub kind: Vec<CountView>,
    /// `new`, `updated`, `removed`.
    pub changes: Vec<CountView>,
    /// Groups with a host in reach; `count` is the hosts of the group in
    /// reach, not packages (a package count per group would read every
    /// package of every host).
    pub group: Vec<GroupCountView>,
}

/// "N with an exploited vulnerability · N with a fix available · N in several
/// versions · N new this week · from N hosts' last reports".
#[derive(Serialize, ToSchema)]
pub(crate) struct SoftwareSummaryLineView {
    /// Rows with an exploited open advisory.
    pub exploited: i64,
    /// Rows with an update that fixes an open advisory somewhere.
    pub fixable: i64,
    /// Rows in more than one version.
    pub several_versions: i64,
    /// Rows installed on a host this week.
    pub new_this_week: i64,
    /// Active hosts in reach that have sent a package report (the "m" of
    /// "n of m").
    pub reporting_hosts: i64,
}

/// One page of the Software list.
#[derive(Serialize, ToSchema)]
pub(crate) struct SoftwareListView {
    /// The page.
    pub items: Vec<SoftwareListRowView>,
    /// Rows matching every filter.
    pub total: i64,
    /// Per-value counts.
    pub counts: SoftwareCountsView,
    /// Summary line.
    pub summary: SoftwareSummaryLineView,
    /// RFC 3339.
    pub generated_at: String,
}

impl From<UsedBy> for UsedByView {
    fn from(u: UsedBy) -> Self {
        Self {
            unit: u.unit,
            hosts: u.hosts,
        }
    }
}

impl From<SoftwareListRow> for SoftwareListRowView {
    fn from(r: SoftwareListRow) -> Self {
        Self {
            name: r.name,
            hosts: r.hosts,
            versions: r.versions,
            oldest: r.oldest,
            newest: r.newest,
            dpkg: r.dpkg,
            rpm: r.rpm,
            advisories: r.advisories,
            no_fix: r.no_fix,
            worst_severity: r.worst_severity,
            exploited: r.exploited,
            update_hosts: r.update_hosts,
            used_by: r.used_by.into_iter().map(Into::into).collect(),
            used_by_total: r.used_by_total,
            week_added: r.week_added,
            week_updated: r.week_updated,
            week_removed: r.week_removed,
        }
    }
}

impl From<SoftwareListSummary> for SoftwareSummaryLineView {
    fn from(s: SoftwareListSummary) -> Self {
        Self {
            exploited: s.exploited,
            fixable: s.fixable,
            several_versions: s.several_versions,
            new_this_week: s.new_this_week,
            reporting_hosts: s.reporting_hosts,
        }
    }
}

impl SoftwareListView {
    pub(crate) fn new(page: SoftwareListPage, now: chrono::DateTime<chrono::Utc>) -> Self {
        let c = page.counts;
        Self {
            items: page.rows.into_iter().map(Into::into).collect(),
            total: page.total,
            counts: SoftwareCountsView {
                vulns: counts(c.vulns, |v| v.as_str().into()),
                fix: counts(c.fix, |v| v.as_str().into()),
                versions: counts(c.versions, |v| v.as_str().into()),
                kind: counts(c.kind, |v| v.as_str().into()),
                changes: counts(c.changes, |v| v.as_str().into()),
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
            },
            summary: page.summary.into(),
            generated_at: now.to_rfc3339(),
        }
    }
}
