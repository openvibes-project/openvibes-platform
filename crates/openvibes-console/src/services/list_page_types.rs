//! The Services list answer (`GET /v1/service-list`).

use platform_store::service_list::{
    OwnedPort, ServiceGroup, ServiceListPage, ServiceListRow,
};
use serde::Serialize;
use utoipa::ToSchema;

use crate::{
    hosts::{groups_types::HostGroupKind, list_types::GroupCountView},
    vulnerabilities::list_page_types::counts,
};

/// A group named in a row.
#[derive(Serialize, ToSchema)]
pub(crate) struct ServiceGroupView {
    /// Group id.
    pub id: String,
    /// Group name.
    pub name: String,
    /// How the group gets its hosts (automatic or rule).
    pub kind: HostGroupKind,
    /// Hosts of the group running the service.
    pub hosts: i64,
}

/// A port a service owns.
#[derive(Serialize, ToSchema)]
pub(crate) struct OwnedPortView {
    /// `tcp` or `udp`.
    pub protocol: String,
    /// 1 to 65535.
    pub port: i32,
    /// Exposed on at least one host in reach.
    pub exposed: bool,
    /// Hosts in reach where the service owns it.
    pub hosts: i64,
}

/// One row: a service (a unit).
#[derive(Serialize, ToSchema)]
pub(crate) struct ServiceListRowView {
    /// The unit as reported, e.g. `sshd.service`.
    pub unit: String,
    /// What it usually is; absent for a service that is not well known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Its usual use.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usual_use: Option<String>,
    /// Hosts in reach running it (the "n" of "n of m").
    pub hosts: i64,
    /// Of those, hosts where it runs as root or SYSTEM.
    pub root_hosts: i64,
    /// Of those, hosts with a package matched to it by name.
    pub package_hosts: i64,
    /// Of those, hosts where it owns an exposed port.
    pub exposed_hosts: i64,
    /// Of those, hosts where it owns a port.
    pub listening_hosts: i64,
    /// The users it runs as, sorted, at most 4.
    pub run_as: Vec<String>,
    /// Its programs, sorted, at most 4.
    pub programs: Vec<String>,
    /// The package matched to it by name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
    /// Automatic and rule groups with a host running it, most hosts first,
    /// at most 3.
    pub groups: Vec<ServiceGroupView>,
    /// How many such groups there are in all.
    pub groups_total: i64,
    /// Ports it owns, exposed first, at most 4.
    pub ports: Vec<OwnedPortView>,
    /// How many ports it owns in all.
    pub ports_total: i64,
    /// Hosts that started running it in the last 7 days.
    pub week_added: i64,
    /// Hosts that stopped running it in the last 7 days.
    pub week_removed: i64,
    /// Needs a look codes, in rule order: `root_unpackaged`,
    /// `database_exposed`, `remote_admin_exposed`, `new_unusual`.
    pub look: Vec<String>,
}

/// Rows per filter value, each with the other filters applied.
#[derive(Serialize, ToSchema)]
pub(crate) struct ServiceCountsView {
    /// `root`, `other`.
    pub runs_as: Vec<crate::hosts::list_types::CountView>,
    /// `exposed`, `local`, `none`.
    pub listens: Vec<crate::hosts::list_types::CountView>,
    /// `yes`, `no`.
    pub packaged: Vec<crate::hosts::list_types::CountView>,
    /// `new`, `look`.
    pub changes: Vec<crate::hosts::list_types::CountView>,
    /// Groups holding a host running a service.
    pub group: Vec<GroupCountView>,
}

/// "N run as root · N listen on an exposed port · N not from a package · N
/// new this week · N need a look · from N hosts' last reports".
#[derive(Serialize, ToSchema)]
pub(crate) struct ServiceSummaryLineView {
    /// Rows running as root or SYSTEM on at least one host.
    pub root: i64,
    /// Rows owning an exposed port on at least one host.
    pub exposed: i64,
    /// Rows not from a package on at least one host.
    pub not_packaged: i64,
    /// Rows with a host that started running them this week.
    pub new_this_week: i64,
    /// Rows with a Needs a look code.
    pub need_a_look: i64,
    /// Active hosts in reach that have sent a services report (the "m" of
    /// "n of m").
    pub reporting_hosts: i64,
}

/// One page of the Services list.
#[derive(Serialize, ToSchema)]
pub(crate) struct ServiceListView {
    /// The page.
    pub items: Vec<ServiceListRowView>,
    /// Rows matching every filter.
    pub total: i64,
    /// Per-value counts.
    pub counts: ServiceCountsView,
    /// Summary line.
    pub summary: ServiceSummaryLineView,
    /// RFC 3339.
    pub generated_at: String,
}

impl From<ServiceGroup> for ServiceGroupView {
    fn from(g: ServiceGroup) -> Self {
        Self {
            id: g.id,
            name: g.name,
            kind: g.kind.into(),
            hosts: g.hosts,
        }
    }
}

impl From<OwnedPort> for OwnedPortView {
    fn from(p: OwnedPort) -> Self {
        Self {
            protocol: p.protocol,
            port: p.port,
            exposed: p.exposed,
            hosts: p.hosts,
        }
    }
}

impl From<ServiceListRow> for ServiceListRowView {
    fn from(r: ServiceListRow) -> Self {
        Self {
            unit: r.unit,
            name: r.name.map(str::to_owned),
            usual_use: r.usual_use.map(str::to_owned),
            hosts: r.hosts,
            root_hosts: r.root_hosts,
            package_hosts: r.package_hosts,
            exposed_hosts: r.exposed_hosts,
            listening_hosts: r.listening_hosts,
            run_as: r.run_as,
            programs: r.programs,
            package: r.package,
            groups: r.groups.into_iter().map(Into::into).collect(),
            groups_total: r.groups_total,
            ports: r.ports.into_iter().map(Into::into).collect(),
            ports_total: r.ports_total,
            week_added: r.week_added,
            week_removed: r.week_removed,
            look: r.look,
        }
    }
}

impl ServiceListView {
    pub(crate) fn new(page: ServiceListPage, now: chrono::DateTime<chrono::Utc>) -> Self {
        let c = page.counts;
        let s = page.summary;
        Self {
            items: page.rows.into_iter().map(Into::into).collect(),
            total: page.total,
            counts: ServiceCountsView {
                runs_as: counts(c.runs_as, |v| v.as_str().into()),
                listens: counts(c.listens, |v| v.as_str().into()),
                packaged: counts(c.packaged, |v| v.as_str().into()),
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
            summary: ServiceSummaryLineView {
                root: s.root,
                exposed: s.exposed,
                not_packaged: s.not_packaged,
                new_this_week: s.new_this_week,
                need_a_look: s.need_a_look,
                reporting_hosts: s.reporting_hosts,
            },
            generated_at: now.to_rfc3339(),
        }
    }
}
