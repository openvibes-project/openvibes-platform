//! The Ports list answer (`GET /v1/port-list`).

use platform_store::port_list::{PortGroup, PortListPage, PortListRow, ServiceFilter};
use serde::Serialize;
use utoipa::ToSchema;

use crate::{
    hosts::{
        groups_types::HostGroupKind,
        list_types::{CountView, GroupCountView},
    },
    vulnerabilities::list_page_types::counts,
};

/// A group named in a row.
#[derive(Serialize, ToSchema)]
pub(crate) struct PortGroupView {
    /// Group id.
    pub id: String,
    /// Group name.
    pub name: String,
    /// How the group gets its hosts (automatic or rule).
    pub kind: HostGroupKind,
    /// Hosts of the group listening on the port.
    pub hosts: i64,
}

/// One row: a port.
#[derive(Serialize, ToSchema)]
pub(crate) struct PortListRowView {
    /// `tcp` or `udp`.
    pub protocol: String,
    /// 1 to 65535.
    pub port: i32,
    /// The usual name; absent for a port that is not well known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Hosts in reach listening on it (the "n" of "n of m").
    pub hosts: i64,
    /// Of those, hosts where it is exposed (reachable from the network).
    pub exposed_hosts: i64,
    /// Owner units seen on it, sorted, at most 8.
    pub services: Vec<String>,
    /// A listening host's owner is not collected.
    pub owners_missing: bool,
    /// Automatic and rule groups with a listening host, most hosts first,
    /// at most 3.
    pub groups: Vec<PortGroupView>,
    /// How many such groups there are in all.
    pub groups_total: i64,
    /// Hosts that started listening in the last 7 days.
    pub week_added: i64,
    /// Hosts that stopped listening in the last 7 days.
    pub week_removed: i64,
    /// Needs a look codes, in rule order: `database_exposed`,
    /// `remote_admin_exposed`, `new_unusual`.
    pub look: Vec<String>,
}

/// Rows per filter value, each with the other filters applied.
#[derive(Serialize, ToSchema)]
pub(crate) struct PortCountsView {
    /// `exposed`, `local`.
    pub exposure: Vec<CountView>,
    /// `tcp`, `udp`.
    pub protocol: Vec<CountView>,
    /// `new`, `look`.
    pub changes: Vec<CountView>,
    /// Groups holding a listening host.
    pub group: Vec<GroupCountView>,
    /// Owner units, then `~none` ("Owner not collected").
    pub service: Vec<CountView>,
}

/// "N exposed on some host · N with new hosts this week · N need a look ·
/// from N hosts' last reports".
#[derive(Serialize, ToSchema)]
pub(crate) struct PortSummaryLineView {
    /// Rows exposed on at least one host.
    pub exposed: i64,
    /// Rows with a host that started listening this week.
    pub new_this_week: i64,
    /// Rows with a Needs a look code.
    pub need_a_look: i64,
    /// Active hosts in reach that have sent a services report (the "m" of
    /// "n of m").
    pub reporting_hosts: i64,
}

/// One page of the Ports list.
#[derive(Serialize, ToSchema)]
pub(crate) struct PortListView {
    /// The page.
    pub items: Vec<PortListRowView>,
    /// Rows matching every filter.
    pub total: i64,
    /// Per-value counts.
    pub counts: PortCountsView,
    /// Summary line.
    pub summary: PortSummaryLineView,
    /// RFC 3339.
    pub generated_at: String,
}

impl From<PortGroup> for PortGroupView {
    fn from(g: PortGroup) -> Self {
        Self {
            id: g.id,
            name: g.name,
            kind: g.kind.into(),
            hosts: g.hosts,
        }
    }
}

impl From<PortListRow> for PortListRowView {
    fn from(r: PortListRow) -> Self {
        Self {
            protocol: r.protocol,
            port: r.port,
            name: r.name.map(str::to_owned),
            hosts: r.hosts,
            exposed_hosts: r.exposed_hosts,
            services: r.services,
            owners_missing: r.owners_missing,
            groups: r.groups.into_iter().map(Into::into).collect(),
            groups_total: r.groups_total,
            week_added: r.week_added,
            week_removed: r.week_removed,
            look: r.look,
        }
    }
}

impl PortListView {
    pub(crate) fn new(page: PortListPage, now: chrono::DateTime<chrono::Utc>) -> Self {
        let c = page.counts;
        let s = page.summary;
        let mut service = counts(c.services, |v| v);
        service.push(CountView {
            value: ServiceFilter::NOT_COLLECTED.into(),
            count: c.owner_not_collected,
        });
        Self {
            items: page.rows.into_iter().map(Into::into).collect(),
            total: page.total,
            counts: PortCountsView {
                exposure: counts(c.exposure, |v| v.as_str().into()),
                protocol: counts(c.protocol, |v| v.as_str().into()),
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
                service,
            },
            summary: PortSummaryLineView {
                exposed: s.exposed,
                new_this_week: s.new_this_week,
                need_a_look: s.need_a_look,
                reporting_hosts: s.reporting_hosts,
            },
            generated_at: now.to_rfc3339(),
        }
    }
}
