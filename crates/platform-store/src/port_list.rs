//! The Ports list (roles spec §10.3; step 5e rulings 11–17): one row per
//! port (protocol and number) over the hosts in the viewer's scope that
//! listen on it, one host counted once however many addresses it binds,
//! with search, filters that AND together, the count for every value of
//! every filter with the other filters applied, the summary line and offset
//! paging. One statement, so rows, total, counts and summary always agree.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use tokio_postgres::Row;

use crate::{
    Client, StoreError,
    console_read::{AgentScope, MAX_PAGE_SIZE},
    host_groups::GroupKind,
    host_list::values,
    port_list_sql::statement,
    port_names::{self, PortClass},
};

values!(
    /// The Exposure filter (ruling 13).
    Exposure {
        /// Exposed on at least one host in reach.
        Exposed = "exposed",
        /// Exposed on none.
        Local = "local",
    }
);

values!(
    /// The Protocol filter.
    ProtocolFilter {
        /// TCP.
        Tcp = "tcp",
        /// UDP.
        Udp = "udp",
    }
);

values!(
    /// The Changes filter.
    Changes {
        /// A host started listening in the last 7 days.
        New = "new",
        /// Any Needs a look code.
        Look = "look",
    }
);

values!(
    /// The sort column; ties are broken by port, then protocol, in the same
    /// direction (ruling 15).
    PortSort {
        /// Port number, then protocol.
        Port = "port",
        /// Hosts listening.
        Hosts = "hosts",
        /// Hosts it is exposed on.
        Exposed = "exposed",
        /// Hosts that started listening this week.
        Week = "week",
    }
);

/// The Service filter: an owner unit, or hosts whose owner is not collected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceFilter<'a> {
    /// A systemd unit.
    Unit(&'a str),
    /// A listening host with no owner (`~none` in the URL).
    NotCollected,
}

impl<'a> ServiceFilter<'a> {
    /// The URL spelling of "not collected".
    pub const NOT_COLLECTED: &'static str = "~none";

    /// Parses the URL value.
    #[must_use]
    pub fn parse(text: &'a str) -> Self {
        if text == Self::NOT_COLLECTED {
            Self::NotCollected
        } else {
            Self::Unit(text)
        }
    }

    fn as_param(self) -> &'a str {
        match self {
            Self::Unit(unit) => unit,
            Self::NotCollected => Self::NOT_COLLECTED,
        }
    }
}

/// What the list asks for. `offset` is held to 0–100000 and `limit` to 1–100.
#[derive(Clone, Debug)]
pub struct PortQuery<'a> {
    /// Port, `22/tcp`, usual name or owner unit (contains, any case).
    pub q: Option<&'a str>,
    /// Exposure.
    pub exposure: Option<Exposure>,
    /// Protocol.
    pub protocol: Option<ProtocolFilter>,
    /// An asset group id.
    pub group: Option<&'a str>,
    /// Owner unit.
    pub service: Option<ServiceFilter<'a>>,
    /// Changes.
    pub changes: Option<Changes>,
    /// An agent id.
    pub host: Option<&'a str>,
    /// Sort column.
    pub sort: PortSort,
    /// Sort direction.
    pub descending: bool,
    /// Rows to skip.
    pub offset: i64,
    /// Rows to return.
    pub limit: i64,
}

/// A group named in a row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortGroup {
    /// The group id.
    pub id: String,
    /// Its name.
    pub name: String,
    /// Automatic or rule (manual groups are left out, ruling 16).
    pub kind: GroupKind,
    /// Hosts of the group listening on the port.
    pub hosts: i64,
}

/// One row: a port.
#[derive(Clone, Debug)]
pub struct PortListRow {
    /// `tcp` or `udp`.
    pub protocol: String,
    /// 1 to 65535.
    pub port: i32,
    /// The usual name, from the map.
    pub name: Option<&'static str>,
    /// Hosts in reach listening on it.
    pub hosts: i64,
    /// Of those, hosts where it is exposed.
    pub exposed_hosts: i64,
    /// Owner units seen on it, sorted, at most 8.
    pub services: Vec<String>,
    /// A listening host's owner is not collected.
    pub owners_missing: bool,
    /// Automatic and rule groups with a listening host, most hosts first,
    /// at most 3.
    pub groups: Vec<PortGroup>,
    /// How many groups there are in all.
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
#[derive(Clone, Debug, Default)]
pub struct PortCounts {
    /// Exposed, local.
    pub exposure: Vec<(Exposure, i64)>,
    /// TCP, UDP.
    pub protocol: Vec<(ProtocolFilter, i64)>,
    /// New this week, needs a look.
    pub changes: Vec<(Changes, i64)>,
    /// Groups holding a listening host, plus the chosen one when the scope
    /// reaches it: (id, name, kind, rows), by name.
    pub groups: Vec<(String, String, GroupKind, i64)>,
    /// Owner units: (unit, rows), by unit.
    pub services: Vec<(String, i64)>,
    /// Rows with a listening host whose owner is not collected.
    pub owner_not_collected: i64,
}

/// "N exposed on some host · N with new hosts this week · N need a look ·
/// from N hosts' last reports", over the rows matching every filter.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Deserialize)]
pub struct PortListSummary {
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

/// One page of the list.
#[derive(Clone, Debug)]
pub struct PortListPage {
    /// The page.
    pub rows: Vec<PortListRow>,
    /// Rows matching every filter.
    pub total: i64,
    /// Per-value counts.
    pub counts: PortCounts,
    /// The summary line.
    pub summary: PortListSummary,
}

#[derive(serde::Deserialize)]
struct RawCounts {
    exposure: BTreeMap<String, i64>,
    protocol: BTreeMap<String, i64>,
    changes: BTreeMap<String, i64>,
    unowned: i64,
    services: Vec<(String, i64)>,
    groups: Vec<(String, String, String, i64)>,
}

#[derive(serde::Deserialize)]
struct Meta {
    total: i64,
    counts: RawCounts,
    summary: PortListSummary,
}

/// One page of the Ports list within `scope` (`hosts.read`); `now` dates
/// "this week".
pub async fn port_list(
    client: &Client,
    query: &PortQuery<'_>,
    scope: &AgentScope,
    now: DateTime<Utc>,
) -> Result<PortListPage, StoreError> {
    let q = query.q.map(str::trim).filter(|q| !q.is_empty());
    let name_keys = q.map(port_names::keys_named).unwrap_or_default();
    let rows = client
        .query(
            &statement(query.sort, query.descending),
            &[
                &scope.is_global(),
                &scope.group_ids(),
                &q,
                &name_keys,
                &query.exposure.map(Exposure::as_str),
                &query.protocol.map(ProtocolFilter::as_str),
                &query.group,
                &query.service.map(ServiceFilter::as_param),
                &query.changes.map(Changes::as_str),
                &query.host,
                &now,
                &query.limit.clamp(1, i64::from(MAX_PAGE_SIZE)),
                &query.offset.clamp(0, 100_000),
                &port_names::keys_of(PortClass::Database),
                &port_names::keys_of(PortClass::RemoteAdmin),
                &port_names::known_keys(),
            ],
        )
        .await?;
    let meta: serde_json::Value = rows.first().and_then(|r| r.get(0)).unwrap_or_default();
    let meta: Meta = serde_json::from_value(meta).map_err(|_| StoreError::Query)?;
    Ok(PortListPage {
        rows: rows.iter().filter_map(port_row).collect(),
        total: meta.total,
        summary: meta.summary,
        counts: port_counts(meta.counts),
    })
}

fn port_row(row: &Row) -> Option<PortListRow> {
    // The page is empty: one row holding only the meta.
    let protocol: String = row.get::<_, Option<String>>(1)?;
    let port: i32 = row.get(2);
    let mut services: Vec<String> = row.get(5);
    services.truncate(8);
    let groups: Vec<(String, String, String, i64)> =
        serde_json::from_value(row.get::<_, serde_json::Value>(10)).unwrap_or_default();
    let groups_total = i64::try_from(groups.len()).unwrap_or(i64::MAX);
    Some(PortListRow {
        name: u16::try_from(port)
            .ok()
            .and_then(|n| port_names::port_info(&protocol, n))
            .map(|info| info.name),
        protocol,
        port,
        hosts: row.get(3),
        exposed_hosts: row.get(4),
        services,
        owners_missing: row.get(6),
        groups: groups
            .into_iter()
            .take(3)
            .map(|(id, name, kind, hosts)| PortGroup {
                id,
                name,
                kind: GroupKind::parse(&kind),
                hosts,
            })
            .collect(),
        groups_total,
        week_added: row.get(7),
        week_removed: row.get(8),
        look: row.get(9),
    })
}

fn port_counts(raw: RawCounts) -> PortCounts {
    let n = |map: &BTreeMap<String, i64>, key: &str| map.get(key).copied().unwrap_or(0);
    let mut groups: Vec<_> = raw
        .groups
        .into_iter()
        .map(|(id, name, kind, n)| (id, name, GroupKind::parse(&kind), n))
        .collect();
    groups.sort_by(|a, b| (a.1.to_lowercase(), &a.0).cmp(&(b.1.to_lowercase(), &b.0)));
    PortCounts {
        exposure: Exposure::ALL
            .iter()
            .map(|v| (*v, n(&raw.exposure, v.as_str())))
            .collect(),
        protocol: ProtocolFilter::ALL
            .iter()
            .map(|v| (*v, n(&raw.protocol, v.as_str())))
            .collect(),
        changes: Changes::ALL
            .iter()
            .map(|v| (*v, n(&raw.changes, v.as_str())))
            .collect(),
        groups,
        services: raw.services,
        owner_not_collected: raw.unowned,
    }
}
