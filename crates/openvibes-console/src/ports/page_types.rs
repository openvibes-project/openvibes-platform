//! A port's page answers (`GET /v1/ports/{protocol}/{port}/summary` and
//! `/hosts`).

use platform_store::{
    port_related::{PortRelated, RelatedAlarms, RelatedCheck, RelatedChecks, RelatedPackage},
    port_summary::{GroupShare, PortEvent, PortHostRow, PortHostsPage, PortSummary},
};
use serde::Serialize;
use utoipa::ToSchema;

use crate::hosts::groups_types::HostGroupKind;

/// When the port was first seen.
#[derive(Serialize, ToSchema)]
pub(crate) struct PortFirstSeenView {
    /// RFC 3339: the earliest the log or an enrolment can tell.
    pub at: String,
    /// The port was there before the log began (or before its 90 days):
    /// shown as "Before {date}".
    pub before: bool,
}

/// The header: the facts line.
#[derive(Serialize, ToSchema)]
pub(crate) struct PortHeaderView {
    /// `tcp` or `udp`.
    pub protocol: String,
    /// 1 to 65535.
    pub port: u16,
    /// The usual name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The usual use.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usual_use: Option<String>,
    /// Hosts in reach listening on it.
    pub listening: i64,
    /// Active hosts in reach that have sent a services report.
    pub of: i64,
    /// Of the listening hosts, exposed ones.
    pub exposed: i64,
    /// Distinct owner units seen on it.
    pub services: i64,
    /// First seen.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<PortFirstSeenView>,
}

/// Hosts that started and stopped listening in the last 7 days.
#[derive(Serialize, ToSchema)]
pub(crate) struct PortWeekView {
    /// Started.
    pub added: i64,
    /// Stopped.
    pub removed: i64,
}

/// The four tiles.
#[derive(Serialize, ToSchema)]
pub(crate) struct PortTilesView {
    /// Hosts listening (of the header's `of`).
    pub listening: i64,
    /// Exposed: reachable from the network.
    pub exposed: i64,
    /// Local only: bound to loopback.
    pub local: i64,
    /// This week.
    pub week: PortWeekView,
}

/// How many listening hosts reported an owner.
#[derive(Serialize, ToSchema)]
pub(crate) struct PortOwnersView {
    /// Listening hosts whose owner was collected.
    pub collected: i64,
    /// Listening hosts.
    pub of: i64,
}

/// The Details card.
#[derive(Serialize, ToSchema)]
pub(crate) struct PortDetailsView {
    /// Distinct programs, sorted.
    pub programs: Vec<String>,
    /// Owners collected.
    pub owners: PortOwnersView,
}

/// One bar of By group.
#[derive(Serialize, ToSchema)]
pub(crate) struct PortGroupShareView {
    /// Group id.
    pub group_id: String,
    /// Group name.
    pub name: String,
    /// How the group gets its hosts.
    pub kind: HostGroupKind,
    /// Members in reach listening on the port.
    pub listening: i64,
    /// Members in reach.
    pub of: i64,
}

/// One entry of Recent changes.
#[derive(Serialize, ToSchema)]
pub(crate) struct PortChangeView {
    /// RFC 3339.
    pub at: String,
    /// The host.
    pub agent_id: String,
    /// Its hostname.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// `appeared`, `went_away`, `exposed` or `local`.
    pub change: String,
}

/// A failing check concerning the port.
#[derive(Serialize, ToSchema)]
pub(crate) struct PortRelatedCheckView {
    /// Rule set.
    pub rule_set_id: String,
    /// Rule.
    pub rule_id: String,
    /// Title.
    pub title: String,
    /// The worst open failing finding's severity.
    pub severity: String,
    /// Listening hosts failing it.
    pub hosts: i64,
}

/// Failing checks.
#[derive(Serialize, ToSchema)]
pub(crate) struct PortRelatedChecksView {
    /// Worst first, at most five.
    pub items: Vec<PortRelatedCheckView>,
    /// All failing checks concerning the port.
    pub total: i64,
    /// The compliance area the card links to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub area: Option<String>,
}

/// Open advisories of one package of the usual server.
#[derive(Serialize, ToSchema)]
pub(crate) struct PortRelatedPackageView {
    /// The package name.
    pub package: String,
    /// Open advisories with a fix.
    pub advisories: i64,
    /// Listening hosts with one.
    pub hosts: i64,
}

/// Open alarms from the port's program.
#[derive(Serialize, ToSchema)]
pub(crate) struct PortRelatedAlarmsView {
    /// No listening host names its program.
    pub program_not_collected: bool,
    /// Open alarms.
    pub open: i64,
    /// Hosts with one.
    pub hosts: i64,
}

/// The Related card; a section is absent without its permission.
#[derive(Serialize, ToSchema)]
pub(crate) struct PortRelatedView {
    /// With `compliance.read`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compliance: Option<PortRelatedChecksView>,
    /// With `vulnerabilities.read`; empty for a port with no package in the map.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vulnerabilities: Option<Vec<PortRelatedPackageView>>,
    /// With `alarms.read`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alarms: Option<PortRelatedAlarmsView>,
}

/// What the caller may do here.
#[derive(Serialize, ToSchema)]
pub(crate) struct PortActionsView {
    /// Export the hosts (`hosts.export`).
    pub export: bool,
    /// Add the port to a case (`cases.write` and `cases.read`).
    pub add_to_case: bool,
    /// Ask the assistant (`assistant.use`, and the assistant is on).
    pub ask: bool,
}

/// A port's page above the Hosts table.
#[derive(Serialize, ToSchema)]
pub(crate) struct PortPageSummaryView {
    /// Header.
    pub header: PortHeaderView,
    /// Tiles.
    pub tiles: PortTilesView,
    /// Details.
    pub details: PortDetailsView,
    /// By group.
    pub by_group: Vec<PortGroupShareView>,
    /// The 20 newest changes in reach.
    pub changes: Vec<PortChangeView>,
    /// Related.
    pub related: PortRelatedView,
    /// Actions.
    pub can: PortActionsView,
}

/// One host listening on the port.
#[derive(Serialize, ToSchema)]
pub(crate) struct PortPageHostView {
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
    /// Every address it binds.
    pub bound: Vec<String>,
    /// Exposed on any of them.
    pub exposed: bool,
    /// The owning unit, when collected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// The owning program, when collected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    /// The host's report leaves some owners out, so a missing owner is
    /// "not collected".
    pub owners_partial: bool,
    /// RFC 3339: its last services report; the web warns after 24 hours.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reported_at: Option<String>,
}

/// Hosts in each segment.
#[derive(Serialize, ToSchema)]
pub(crate) struct PortSegmentsView {
    /// All.
    pub all: i64,
    /// Exposed.
    pub exposed: i64,
    /// Local only.
    pub local: i64,
}

/// One page of the Hosts table.
#[derive(Serialize, ToSchema)]
pub(crate) struct PortPageHostsView {
    /// The page.
    pub items: Vec<PortPageHostView>,
    /// Hosts in the chosen segment.
    pub total: i64,
    /// Every segment's size.
    pub segments: PortSegmentsView,
}

fn rfc(t: chrono::DateTime<chrono::Utc>) -> String {
    t.to_rfc3339()
}

impl From<RelatedCheck> for PortRelatedCheckView {
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

impl From<RelatedChecks> for PortRelatedChecksView {
    fn from(c: RelatedChecks) -> Self {
        Self {
            items: c.items.into_iter().map(Into::into).collect(),
            total: c.total,
            area: c.area.map(str::to_owned),
        }
    }
}

impl From<RelatedPackage> for PortRelatedPackageView {
    fn from(p: RelatedPackage) -> Self {
        Self {
            package: p.package,
            advisories: p.advisories,
            hosts: p.hosts,
        }
    }
}

impl From<RelatedAlarms> for PortRelatedAlarmsView {
    fn from(a: RelatedAlarms) -> Self {
        Self {
            program_not_collected: a.program_not_collected,
            open: a.open,
            hosts: a.hosts,
        }
    }
}

impl From<PortRelated> for PortRelatedView {
    fn from(r: PortRelated) -> Self {
        Self {
            compliance: r.compliance.map(Into::into),
            vulnerabilities: r
                .vulnerabilities
                .map(|v| v.into_iter().map(Into::into).collect()),
            alarms: r.alarms.map(Into::into),
        }
    }
}

impl From<GroupShare> for PortGroupShareView {
    fn from(g: GroupShare) -> Self {
        Self {
            group_id: g.id,
            name: g.name,
            kind: g.kind.into(),
            listening: g.listening,
            of: g.of,
        }
    }
}

impl From<PortEvent> for PortChangeView {
    fn from(e: PortEvent) -> Self {
        Self {
            at: rfc(e.at),
            agent_id: e.agent_id,
            hostname: e.hostname,
            change: e.change,
        }
    }
}

impl PortPageSummaryView {
    pub(crate) fn new(s: PortSummary, can: PortActionsView) -> Self {
        Self {
            header: PortHeaderView {
                protocol: s.protocol,
                port: s.port,
                name: s.name.map(str::to_owned),
                usual_use: s.usual_use.map(str::to_owned),
                listening: s.listening,
                of: s.of,
                exposed: s.exposed,
                services: s.services,
                first_seen: s.first_seen.map(|f| PortFirstSeenView {
                    at: rfc(f.at),
                    before: f.before,
                }),
            },
            tiles: PortTilesView {
                listening: s.listening,
                exposed: s.exposed,
                local: s.local,
                week: PortWeekView {
                    added: s.week_added,
                    removed: s.week_removed,
                },
            },
            details: PortDetailsView {
                programs: s.programs,
                owners: PortOwnersView {
                    collected: s.owners_collected,
                    of: s.listening,
                },
            },
            by_group: s.by_group.into_iter().map(Into::into).collect(),
            changes: s.changes.into_iter().map(Into::into).collect(),
            related: s.related.into(),
            can,
        }
    }
}

impl From<PortHostRow> for PortPageHostView {
    fn from(r: PortHostRow) -> Self {
        Self {
            agent_id: r.agent_id,
            hostname: r.hostname,
            os: r.os,
            ip: r.ip,
            bound: r.bound,
            exposed: r.exposed,
            service: r.service,
            program: r.program,
            owners_partial: r.owners_partial,
            reported_at: r.reported_at.map(rfc),
        }
    }
}

impl From<PortHostsPage> for PortPageHostsView {
    fn from(p: PortHostsPage) -> Self {
        Self {
            items: p.rows.into_iter().map(Into::into).collect(),
            total: p.total,
            segments: PortSegmentsView {
                all: p.segments.all,
                exposed: p.segments.exposed,
                local: p.segments.local,
            },
        }
    }
}
