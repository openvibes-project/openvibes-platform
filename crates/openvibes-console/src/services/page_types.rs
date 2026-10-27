//! A service's page answers (`GET /v1/services/{unit}/summary` and
//! `/hosts`).

use platform_store::{
    port_related::{RelatedCheck, RelatedChecks, RelatedPackage},
    port_summary::GroupShare,
    service_related::{ServiceAlarms, ServiceRelated, ServiceVulnerabilities},
    service_summary::{ServiceEvent, ServiceHostRow, ServiceHostsPage, ServiceSummary},
};
use serde::Serialize;
use utoipa::ToSchema;

use super::list_page_types::OwnedPortView;
use crate::hosts::groups_types::HostGroupKind;

/// When the service was first seen.
#[derive(Serialize, ToSchema)]
pub(crate) struct ServiceFirstSeenView {
    /// RFC 3339: the earliest the log or an enrolment can tell.
    pub at: String,
    /// The service was there before the log began (or before its 90 days):
    /// shown as "Before {date}".
    pub before: bool,
}

/// The header: the facts line.
#[derive(Serialize, ToSchema)]
pub(crate) struct ServiceHeaderView {
    /// The unit as reported.
    pub unit: String,
    /// What it usually is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Its usual use.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usual_use: Option<String>,
    /// Hosts in reach running it.
    pub running: i64,
    /// Active hosts in reach that have sent a services report.
    pub of: i64,
    /// Of the running hosts, those where it runs as root or SYSTEM.
    pub root: i64,
    /// Of the running hosts, those where it owns an exposed port.
    pub exposed: i64,
    /// First seen.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<ServiceFirstSeenView>,
}

/// Hosts that started and stopped running it in the last 7 days.
#[derive(Serialize, ToSchema)]
pub(crate) struct ServiceWeekView {
    /// Started.
    pub added: i64,
    /// Stopped.
    pub removed: i64,
}

/// The tiles. A tile that needs a permission the caller lacks is absent.
#[derive(Serialize, ToSchema)]
pub(crate) struct ServiceTilesView {
    /// Hosts running it (of the header's `of`).
    pub running: i64,
    /// Open alarms from its programs (`alarms.read`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alarms: Option<i64>,
    /// Open vulnerabilities in its matched packages
    /// (`vulnerabilities.read`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vulnerabilities: Option<i64>,
    /// Versions of its matched package in use; absent when no package
    /// matched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub versions: Option<i64>,
}

/// A user it runs as, with the hosts where it does.
#[derive(Serialize, ToSchema)]
pub(crate) struct ServiceRunAsView {
    /// The user name (or uid).
    pub user: String,
    /// Hosts where it runs as this user.
    pub hosts: i64,
}

/// A package matched to it by name.
#[derive(Serialize, ToSchema)]
pub(crate) struct ServicePackageView {
    /// The installed package's name.
    pub name: String,
    /// Hosts running the service that have it.
    pub hosts: i64,
}

/// The Details card.
#[derive(Serialize, ToSchema)]
pub(crate) struct ServiceDetailsView {
    /// Users it runs as, most hosts first.
    pub run_as: Vec<ServiceRunAsView>,
    /// Distinct programs, sorted.
    pub programs: Vec<String>,
    /// Packages matched to it by name.
    pub packages: Vec<ServicePackageView>,
    /// Hosts running it that have any matched package.
    pub package_hosts: i64,
    /// Processes it runs across those hosts.
    pub processes: i64,
    /// This week.
    pub week: ServiceWeekView,
}

/// One bar of By group.
#[derive(Serialize, ToSchema)]
pub(crate) struct ServiceGroupShareView {
    /// Group id.
    pub group_id: String,
    /// Group name.
    pub name: String,
    /// How the group gets its hosts.
    pub kind: HostGroupKind,
    /// Members in reach running the service.
    pub running: i64,
    /// Members in reach.
    pub of: i64,
}

/// One entry of Recent changes.
#[derive(Serialize, ToSchema)]
pub(crate) struct ServiceChangeView {
    /// RFC 3339.
    pub at: String,
    /// The host.
    pub agent_id: String,
    /// Its hostname.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// `appeared` or `went_away`.
    pub change: String,
}

/// A failing check concerning the service.
#[derive(Serialize, ToSchema)]
pub(crate) struct ServiceRelatedCheckView {
    /// Rule set.
    pub rule_set_id: String,
    /// Rule.
    pub rule_id: String,
    /// Title.
    pub title: String,
    /// The worst open failing finding's severity.
    pub severity: String,
    /// Hosts running the service that fail it.
    pub hosts: i64,
}

/// Failing checks.
#[derive(Serialize, ToSchema)]
pub(crate) struct ServiceRelatedChecksView {
    /// Worst first, at most five.
    pub items: Vec<ServiceRelatedCheckView>,
    /// All failing checks concerning the service.
    pub total: i64,
    /// The compliance area the card links to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub area: Option<String>,
}

/// Open advisories of one matched package.
#[derive(Serialize, ToSchema)]
pub(crate) struct ServiceRelatedPackageView {
    /// The package name.
    pub package: String,
    /// Open advisories with a fix.
    pub advisories: i64,
    /// Hosts running the service with one.
    pub hosts: i64,
}

/// Open advisories of the matched packages.
#[derive(Serialize, ToSchema)]
pub(crate) struct ServiceRelatedVulnerabilitiesView {
    /// One entry per matched package.
    pub packages: Vec<ServiceRelatedPackageView>,
    /// Distinct open advisories across them.
    pub advisories: i64,
    /// Hosts with at least one.
    pub hosts: i64,
}

/// Open alarms from the service's programs.
#[derive(Serialize, ToSchema)]
pub(crate) struct ServiceRelatedAlarmsView {
    /// No host running it names a program.
    pub programs_not_collected: bool,
    /// Open alarms.
    pub open: i64,
    /// Hosts with one.
    pub hosts: i64,
}

/// The Related card; a section is absent without its permission.
#[derive(Serialize, ToSchema)]
pub(crate) struct ServiceRelatedView {
    /// With `compliance.read`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compliance: Option<ServiceRelatedChecksView>,
    /// With `vulnerabilities.read`; no packages for a service with no
    /// matched package.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vulnerabilities: Option<ServiceRelatedVulnerabilitiesView>,
    /// With `alarms.read`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alarms: Option<ServiceRelatedAlarmsView>,
}

/// What the caller may do here.
#[derive(Serialize, ToSchema)]
pub(crate) struct ServiceActionsView {
    /// Export the hosts (`hosts.export`).
    pub export: bool,
    /// Add the service to a case (`cases.write` and `cases.read`).
    pub add_to_case: bool,
}

/// A service's page above the Hosts table.
#[derive(Serialize, ToSchema)]
pub(crate) struct ServicePageSummaryView {
    /// Header.
    pub header: ServiceHeaderView,
    /// Tiles.
    pub tiles: ServiceTilesView,
    /// Details.
    pub details: ServiceDetailsView,
    /// The ports it owns, exposed first.
    pub ports: Vec<OwnedPortView>,
    /// By group.
    pub by_group: Vec<ServiceGroupShareView>,
    /// The 20 newest changes in reach.
    pub changes: Vec<ServiceChangeView>,
    /// Related.
    pub related: ServiceRelatedView,
    /// Actions.
    pub can: ServiceActionsView,
}

/// A package on a host and its version.
#[derive(Serialize, ToSchema)]
pub(crate) struct ServiceHostPackageView {
    /// The installed package's name.
    pub name: String,
    /// `epoch:version-release`, epoch and release only when present.
    pub version: String,
}

/// A port the service owns on a host.
#[derive(Serialize, ToSchema)]
pub(crate) struct ServiceHostPortView {
    /// `tcp` or `udp`.
    pub protocol: String,
    /// 1 to 65535.
    pub port: i32,
    /// Bound to a non-loopback address.
    pub exposed: bool,
}

/// Open problems on a host; a count is absent without its permission.
#[derive(Serialize, ToSchema)]
pub(crate) struct ServiceHostProblemsView {
    /// Open alarms from the service's programs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alarms: Option<i64>,
    /// Open advisories of the matched package.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vulnerabilities: Option<i64>,
}

/// One host running the service.
#[derive(Serialize, ToSchema)]
pub(crate) struct ServicePageHostView {
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
    /// The matched package and its version there.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package: Option<ServiceHostPackageView>,
    /// Processes it runs there.
    pub processes: i32,
    /// Its programs there.
    pub programs: Vec<String>,
    /// The user it runs as there.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_as: Option<String>,
    /// Ports it owns there.
    pub ports: Vec<ServiceHostPortView>,
    /// Open problems.
    pub problems: ServiceHostProblemsView,
    /// The host's report leaves some owners out, so a missing port may just
    /// not be collected.
    pub owners_partial: bool,
    /// RFC 3339: its last services report; the web warns after 24 hours.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reported_at: Option<String>,
}

/// Hosts in each segment.
#[derive(Serialize, ToSchema)]
pub(crate) struct ServiceSegmentsView {
    /// All.
    pub all: i64,
    /// It owns an exposed port.
    pub exposed: i64,
    /// It runs as root or SYSTEM.
    pub root: i64,
}

/// One page of the Hosts table.
#[derive(Serialize, ToSchema)]
pub(crate) struct ServicePageHostsView {
    /// The page.
    pub items: Vec<ServicePageHostView>,
    /// Hosts in the chosen segment.
    pub total: i64,
    /// Every segment's size.
    pub segments: ServiceSegmentsView,
}

fn rfc(t: chrono::DateTime<chrono::Utc>) -> String {
    t.to_rfc3339()
}

impl From<RelatedCheck> for ServiceRelatedCheckView {
    fn from(c: RelatedCheck) -> Self {
        Self {
            rule_set_id: c.rule_set_id,
            rule_id: c.rule_id,
            title: c.title,
            severity: c.severity,
            hosts: c.hosts,
        }
    }
}

impl From<RelatedChecks> for ServiceRelatedChecksView {
    fn from(c: RelatedChecks) -> Self {
        Self {
            items: c.items.into_iter().map(Into::into).collect(),
            total: c.total,
            area: c.area.map(str::to_owned),
        }
    }
}

impl From<RelatedPackage> for ServiceRelatedPackageView {
    fn from(p: RelatedPackage) -> Self {
        Self {
            package: p.package,
            advisories: p.advisories,
            hosts: p.hosts,
        }
    }
}

impl From<ServiceVulnerabilities> for ServiceRelatedVulnerabilitiesView {
    fn from(v: ServiceVulnerabilities) -> Self {
        Self {
            packages: v.packages.into_iter().map(Into::into).collect(),
            advisories: v.advisories,
            hosts: v.hosts,
        }
    }
}

impl From<ServiceAlarms> for ServiceRelatedAlarmsView {
    fn from(a: ServiceAlarms) -> Self {
        Self {
            programs_not_collected: a.programs_not_collected,
            open: a.open,
            hosts: a.hosts,
        }
    }
}

impl From<ServiceRelated> for ServiceRelatedView {
    fn from(r: ServiceRelated) -> Self {
        Self {
            compliance: r.compliance.map(Into::into),
            vulnerabilities: r.vulnerabilities.map(Into::into),
            alarms: r.alarms.map(Into::into),
        }
    }
}

impl From<GroupShare> for ServiceGroupShareView {
    fn from(g: GroupShare) -> Self {
        Self {
            group_id: g.id,
            name: g.name,
            kind: g.kind.into(),
            running: g.listening,
            of: g.of,
        }
    }
}

impl From<ServiceEvent> for ServiceChangeView {
    fn from(e: ServiceEvent) -> Self {
        Self {
            at: rfc(e.at),
            agent_id: e.agent_id,
            hostname: e.hostname,
            change: e.change,
        }
    }
}

impl ServicePageSummaryView {
    pub(crate) fn new(s: ServiceSummary, can: ServiceActionsView) -> Self {
        let related: ServiceRelatedView = s.related.into();
        Self {
            tiles: ServiceTilesView {
                running: s.running,
                alarms: related.alarms.as_ref().map(|a| a.open),
                vulnerabilities: related.vulnerabilities.as_ref().map(|v| v.advisories),
                versions: s.versions,
            },
            header: ServiceHeaderView {
                unit: s.unit,
                name: s.name.map(str::to_owned),
                usual_use: s.usual_use.map(str::to_owned),
                running: s.running,
                of: s.of,
                root: s.root,
                exposed: s.exposed,
                first_seen: s.first_seen.map(|f| ServiceFirstSeenView {
                    at: rfc(f.at),
                    before: f.before,
                }),
            },
            details: ServiceDetailsView {
                run_as: s
                    .run_as
                    .into_iter()
                    .map(|(user, hosts)| ServiceRunAsView { user, hosts })
                    .collect(),
                programs: s.programs,
                packages: s
                    .packages
                    .into_iter()
                    .map(|p| ServicePackageView {
                        name: p.name,
                        hosts: p.hosts,
                    })
                    .collect(),
                package_hosts: s.package_hosts,
                processes: s.processes,
                week: ServiceWeekView {
                    added: s.week_added,
                    removed: s.week_removed,
                },
            },
            ports: s.ports.into_iter().map(Into::into).collect(),
            by_group: s.by_group.into_iter().map(Into::into).collect(),
            changes: s.changes.into_iter().map(Into::into).collect(),
            related,
            can,
        }
    }
}

impl From<ServiceHostRow> for ServicePageHostView {
    fn from(r: ServiceHostRow) -> Self {
        Self {
            agent_id: r.agent_id,
            hostname: r.hostname,
            os: r.os,
            ip: r.ip,
            package: r
                .package
                .map(|(name, version)| ServiceHostPackageView { name, version }),
            processes: r.processes,
            programs: r.programs,
            run_as: r.run_as,
            ports: r
                .ports
                .into_iter()
                .map(|(protocol, port, exposed)| ServiceHostPortView {
                    protocol,
                    port,
                    exposed,
                })
                .collect(),
            problems: ServiceHostProblemsView {
                alarms: r.problems.alarms,
                vulnerabilities: r.problems.vulnerabilities,
            },
            owners_partial: r.owners_partial,
            reported_at: r.reported_at.map(rfc),
        }
    }
}

impl From<ServiceHostsPage> for ServicePageHostsView {
    fn from(p: ServiceHostsPage) -> Self {
        Self {
            items: p.rows.into_iter().map(Into::into).collect(),
            total: p.total,
            segments: ServiceSegmentsView {
                all: p.segments.all,
                exposed: p.segments.exposed,
                root: p.segments.root,
            },
        }
    }
}
