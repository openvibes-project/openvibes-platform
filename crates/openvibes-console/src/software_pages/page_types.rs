//! A package's page answers (`GET /v1/software-pages/{name}/summary` and
//! `/hosts`).

use platform_store::{
    port_summary::GroupShare,
    software_summary::{
        PackageAdvisory, PackageEvent, SoftwareHostRow, SoftwareHostsPage, SoftwareSummary,
        VersionInUse,
    },
};
use serde::Serialize;
use utoipa::ToSchema;

use super::list_page_types::UsedByView;
use crate::hosts::groups_types::HostGroupKind;

/// When the package was first seen.
#[derive(Serialize, ToSchema)]
pub(crate) struct SoftwareFirstSeenView {
    /// RFC 3339: the earliest the log or an enrolment can tell.
    pub at: String,
    /// The package was there before the log began (or before its 90 days):
    /// shown as "Before {date}".
    pub before: bool,
}

/// The header: the facts line.
#[derive(Serialize, ToSchema)]
pub(crate) struct SoftwareHeaderView {
    /// The package name.
    pub name: String,
    /// The package databases it is reported from (`dpkg`, `rpm`), sorted.
    pub managers: Vec<String>,
    /// Hosts in reach that have it.
    pub hosts: i64,
    /// Active hosts in reach that have sent a package report.
    pub of: i64,
    /// First seen.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<SoftwareFirstSeenView>,
}

/// Hosts that installed, changed the version of and removed it in the last 7 days.
#[derive(Serialize, ToSchema)]
pub(crate) struct SoftwareWeekView {
    /// Installed.
    pub added: i64,
    /// Changed version.
    pub updated: i64,
    /// Removed.
    pub removed: i64,
}

/// The tiles.
#[derive(Serialize, ToSchema)]
pub(crate) struct SoftwareTilesView {
    /// Hosts that have it (of the header's `of`).
    pub hosts: i64,
    /// Open advisories on it.
    pub vulnerabilities: i64,
    /// Hosts where an update fixes an open advisory.
    pub update_hosts: i64,
    /// Versions in use.
    pub versions: i64,
}

/// One version in use.
#[derive(Serialize, ToSchema)]
pub(crate) struct SoftwarePageVersionView {
    /// `epoch:version-release`, epoch and release only when present.
    pub version: String,
    /// Architecture.
    pub arch: String,
    /// `dpkg` or `rpm`.
    pub manager: String,
    /// Hosts in reach that have it.
    pub hosts: i64,
    /// Open advisories that affect it.
    pub advisories: i64,
    /// Some of their CVE ids, at most four.
    pub cves: Vec<String>,
}

/// One open advisory on the package.
#[derive(Serialize, ToSchema)]
pub(crate) struct SoftwarePageAdvisoryView {
    /// The advisory id.
    pub advisory_id: String,
    /// Severity.
    pub severity: String,
    /// Title.
    pub title: String,
    /// Its CVE ids.
    pub cves: Vec<String>,
    /// On the CISA KEV or EUVD exploited list.
    pub exploited: bool,
    /// EPSS probability.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epss: Option<f32>,
    /// CVSS base score.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss: Option<f32>,
    /// The version that fixes it; absent when nothing does yet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixed_in: Option<String>,
    /// Hosts in reach it is open on.
    pub hosts: i64,
}

/// One bar of By group.
#[derive(Serialize, ToSchema)]
pub(crate) struct SoftwareGroupShareView {
    /// Group id.
    pub group_id: String,
    /// Group name.
    pub name: String,
    /// How the group gets its hosts.
    pub kind: HostGroupKind,
    /// Members in reach that have the package.
    pub have: i64,
    /// Members in reach.
    pub of: i64,
}

/// One entry of Recent changes.
#[derive(Serialize, ToSchema)]
pub(crate) struct SoftwareChangeView {
    /// RFC 3339.
    pub at: String,
    /// The host.
    pub agent_id: String,
    /// Its hostname.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// `appeared` or `went_away`.
    pub change: String,
    /// The version it concerns, when the log has it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// What the caller may do here.
#[derive(Serialize, ToSchema)]
pub(crate) struct SoftwareActionsView {
    /// Export the hosts (`hosts.export`).
    pub export: bool,
    /// Add the package to a case (`cases.write` and `cases.read`).
    pub add_to_case: bool,
}

/// A package's page above the Hosts table.
#[derive(Serialize, ToSchema)]
pub(crate) struct SoftwarePageSummaryView {
    /// Header.
    pub header: SoftwareHeaderView,
    /// Tiles.
    pub tiles: SoftwareTilesView,
    /// Installed, changed and removed this week.
    pub week: SoftwareWeekView,
    /// The versions in use, most hosts first.
    pub versions: Vec<SoftwarePageVersionView>,
    /// Open advisories, most urgent first, at most 50.
    pub advisories: Vec<SoftwarePageAdvisoryView>,
    /// Open advisories without a fix.
    pub no_fix: i64,
    /// Services using it, matched by name.
    pub used_by: Vec<UsedByView>,
    /// By group.
    pub by_group: Vec<SoftwareGroupShareView>,
    /// The 20 newest changes in reach.
    pub changes: Vec<SoftwareChangeView>,
    /// Actions.
    pub can: SoftwareActionsView,
}

/// A version of the package on a host.
#[derive(Serialize, ToSchema)]
pub(crate) struct SoftwareHostVersionView {
    /// `dpkg` or `rpm`.
    pub manager: String,
    /// `epoch:version-release`, epoch and release only when present.
    pub version: String,
    /// Architecture.
    pub arch: String,
}

/// One host that has the package.
#[derive(Serialize, ToSchema)]
pub(crate) struct SoftwarePageHostView {
    /// The host.
    pub agent_id: String,
    /// Its hostname.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Its operating system.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    /// Its last address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// The versions it has, newest first.
    pub versions: Vec<SoftwareHostVersionView>,
    /// The version an update would bring; absent when it is up to date.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_to: Option<String>,
    /// Services running there that use the package.
    pub used_by: Vec<String>,
    /// RFC 3339: its last package report; the web warns after 24 hours.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reported_at: Option<String>,
}

/// Hosts in each segment.
#[derive(Serialize, ToSchema)]
pub(crate) struct SoftwareSegmentsView {
    /// All.
    pub all: i64,
    /// An update fixes an open advisory there.
    pub update: i64,
    /// No update is waiting.
    pub current: i64,
}

/// One page of the Hosts table.
#[derive(Serialize, ToSchema)]
pub(crate) struct SoftwarePageHostsView {
    /// The page.
    pub items: Vec<SoftwarePageHostView>,
    /// Hosts in the chosen segment.
    pub total: i64,
    /// Every segment's size.
    pub segments: SoftwareSegmentsView,
}

fn rfc(t: chrono::DateTime<chrono::Utc>) -> String {
    t.to_rfc3339()
}

impl From<VersionInUse> for SoftwarePageVersionView {
    fn from(v: VersionInUse) -> Self {
        Self {
            version: v.full(),
            arch: v.arch,
            manager: v.manager,
            hosts: v.hosts,
            advisories: v.advisories,
            cves: v.cves,
        }
    }
}

impl From<PackageAdvisory> for SoftwarePageAdvisoryView {
    fn from(a: PackageAdvisory) -> Self {
        Self {
            advisory_id: a.advisory_id,
            severity: a.severity,
            title: a.title,
            cves: a.cves,
            exploited: a.exploited,
            epss: a.epss,
            cvss: a.cvss,
            fixed_in: a.fixed_in,
            hosts: a.hosts,
        }
    }
}

impl From<GroupShare> for SoftwareGroupShareView {
    fn from(g: GroupShare) -> Self {
        Self {
            group_id: g.id,
            name: g.name,
            kind: g.kind.into(),
            have: g.listening,
            of: g.of,
        }
    }
}

impl From<PackageEvent> for SoftwareChangeView {
    fn from(e: PackageEvent) -> Self {
        Self {
            at: rfc(e.at),
            agent_id: e.agent_id,
            hostname: e.hostname,
            change: e.change,
            version: e.version,
        }
    }
}

impl SoftwarePageSummaryView {
    pub(crate) fn new(s: SoftwareSummary, can: SoftwareActionsView) -> Self {
        Self {
            tiles: SoftwareTilesView {
                hosts: s.hosts,
                vulnerabilities: s.advisory_total,
                update_hosts: s.update_hosts,
                versions: i64::try_from(s.versions.len()).unwrap_or(i64::MAX),
            },
            header: SoftwareHeaderView {
                name: s.name,
                managers: s.managers,
                hosts: s.hosts,
                of: s.of,
                first_seen: s.first_seen.map(|f| SoftwareFirstSeenView {
                    at: rfc(f.at),
                    before: f.before,
                }),
            },
            week: SoftwareWeekView {
                added: s.week_added,
                updated: s.week_updated,
                removed: s.week_removed,
            },
            versions: s.versions.into_iter().map(Into::into).collect(),
            advisories: s.advisories.into_iter().map(Into::into).collect(),
            no_fix: s.no_fix,
            used_by: s.used_by.into_iter().map(Into::into).collect(),
            by_group: s.by_group.into_iter().map(Into::into).collect(),
            changes: s.changes.into_iter().map(Into::into).collect(),
            can,
        }
    }
}

impl From<SoftwareHostRow> for SoftwarePageHostView {
    fn from(r: SoftwareHostRow) -> Self {
        Self {
            agent_id: r.agent_id,
            hostname: r.hostname,
            os: r.os,
            ip: r.ip,
            versions: r
                .versions
                .into_iter()
                .map(|v| SoftwareHostVersionView {
                    manager: v.manager,
                    version: v.version,
                    arch: v.arch,
                })
                .collect(),
            update_to: r.update_to,
            used_by: r.used_by,
            reported_at: r.reported_at.map(rfc),
        }
    }
}

impl From<SoftwareHostsPage> for SoftwarePageHostsView {
    fn from(p: SoftwareHostsPage) -> Self {
        Self {
            items: p.rows.into_iter().map(Into::into).collect(),
            total: p.total,
            segments: SoftwareSegmentsView {
                all: p.segments.all,
                update: p.segments.update,
                current: p.segments.current,
            },
        }
    }
}
