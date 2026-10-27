//! The Services list (roles spec §10.3; step 5f rulings 1–10): one row per
//! unit over the hosts in the viewer's scope that run it, one host counted
//! once, with search, filters that AND together, the count for every value
//! of every filter with the other filters applied, the summary line and
//! offset paging. One statement, so rows, total, counts and summary always
//! agree.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use tokio_postgres::Row;

use crate::{
    Client, StoreError,
    console_read::{AgentScope, MAX_PAGE_SIZE},
    host_groups::GroupKind,
    host_list::values,
    service_list_sql::statement,
    service_names::{self, ServiceClass},
};

values!(
    /// The Runs as filter (ruling 6).
    RunsAs {
        /// Root or SYSTEM on at least one host in reach.
        Root = "root",
        /// On none.
        Other = "other",
    }
);

values!(
    /// The Listens filter.
    Listens {
        /// Owns an exposed listener on at least one host.
        Exposed = "exposed",
        /// Owns listeners, none exposed.
        Local = "local",
        /// Owns no listener.
        None = "none",
    }
);

values!(
    /// The Package filter.
    Packaged {
        /// From a package on every host.
        Yes = "yes",
        /// Not from a package on at least one host.
        No = "no",
    }
);

values!(
    /// The Changes filter.
    Changes {
        /// A host started running it in the last 7 days.
        New = "new",
        /// Any Needs a look code.
        Look = "look",
    }
);

values!(
    /// The sort column; ties are broken by unit in the same direction.
    ServiceSort {
        /// The unit.
        Service = "service",
        /// Hosts running it.
        Hosts = "hosts",
        /// Hosts that started running it this week.
        Week = "week",
    }
);

/// What the list asks for. `offset` is held to 0–100000 and `limit` to 1–100.
#[derive(Clone, Debug)]
pub struct ServiceQuery<'a> {
    /// Unit, usual name, program, package or owned port (contains, any case).
    pub q: Option<&'a str>,
    /// Runs as.
    pub runs_as: Option<RunsAs>,
    /// Listens.
    pub listens: Option<Listens>,
    /// From a package.
    pub packaged: Option<Packaged>,
    /// An asset group id.
    pub group: Option<&'a str>,
    /// Changes.
    pub changes: Option<Changes>,
    /// An agent id.
    pub host: Option<&'a str>,
    /// Sort column.
    pub sort: ServiceSort,
    /// Sort direction.
    pub descending: bool,
    /// Rows to skip.
    pub offset: i64,
    /// Rows to return.
    pub limit: i64,
}

/// A group named in a row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceGroup {
    /// The group id.
    pub id: String,
    /// Its name.
    pub name: String,
    /// Automatic or rule (manual groups are left out).
    pub kind: GroupKind,
    /// Hosts of the group running the unit.
    pub hosts: i64,
}

/// A port a unit owns.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedPort {
    /// `tcp` or `udp`.
    pub protocol: String,
    /// 1 to 65535.
    pub port: i32,
    /// Exposed on at least one host in reach.
    pub exposed: bool,
    /// Hosts in reach where the unit owns it.
    pub hosts: i64,
}

/// One row: a unit.
#[derive(Clone, Debug)]
pub struct ServiceListRow {
    /// The unit as reported.
    pub unit: String,
    /// The map's usual name.
    pub name: Option<&'static str>,
    /// The map's usual use.
    pub usual_use: Option<&'static str>,
    /// Hosts in reach running it.
    pub hosts: i64,
    /// Of those, hosts where it runs as root or SYSTEM.
    pub root_hosts: i64,
    /// Of those, hosts with a package matched to it by name.
    pub package_hosts: i64,
    /// Of those, hosts where it owns an exposed listener.
    pub exposed_hosts: i64,
    /// Of those, hosts where it owns a listener.
    pub listening_hosts: i64,
    /// The users it runs as, sorted, at most 4.
    pub run_as: Vec<String>,
    /// Its programs, sorted, at most 4.
    pub programs: Vec<String>,
    /// The package matched to it by name (first alphabetically).
    pub package: Option<String>,
    /// Automatic and rule groups with a host running it, most hosts first,
    /// at most 3.
    pub groups: Vec<ServiceGroup>,
    /// How many groups there are in all.
    pub groups_total: i64,
    /// Ports it owns, exposed first, at most 4.
    pub ports: Vec<OwnedPort>,
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
#[derive(Clone, Debug, Default)]
pub struct ServiceCounts {
    /// Root, other.
    pub runs_as: Vec<(RunsAs, i64)>,
    /// Exposed, local, none.
    pub listens: Vec<(Listens, i64)>,
    /// From a package, not.
    pub packaged: Vec<(Packaged, i64)>,
    /// New this week, needs a look.
    pub changes: Vec<(Changes, i64)>,
    /// Groups holding a host running a unit, plus the chosen one when the
    /// scope reaches it: (id, name, kind, rows), by name.
    pub groups: Vec<(String, String, GroupKind, i64)>,
}

/// "N run as root · N listen on an exposed port · N not from a package · N
/// new this week · N need a look · from N hosts' last reports", over the
/// rows matching every filter.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Deserialize)]
pub struct ServiceListSummary {
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

/// One page of the list.
#[derive(Clone, Debug)]
pub struct ServiceListPage {
    /// The page.
    pub rows: Vec<ServiceListRow>,
    /// Rows matching every filter.
    pub total: i64,
    /// Per-value counts.
    pub counts: ServiceCounts,
    /// The summary line.
    pub summary: ServiceListSummary,
}

#[derive(serde::Deserialize)]
struct RawCounts {
    runs_as: BTreeMap<String, i64>,
    listens: BTreeMap<String, i64>,
    packaged: BTreeMap<String, i64>,
    changes: BTreeMap<String, i64>,
    groups: Vec<(String, String, String, i64)>,
}

#[derive(serde::Deserialize)]
struct Meta {
    total: i64,
    counts: RawCounts,
    summary: ServiceListSummary,
}

/// One page of the Services list within `scope` (`hosts.read`); `now` dates
/// "this week".
pub async fn service_list(
    client: &mut Client,
    query: &ServiceQuery<'_>,
    scope: &AgentScope,
    now: DateTime<Utc>,
) -> Result<ServiceListPage, StoreError> {
    let q = query.q.map(str::trim).filter(|q| !q.is_empty());
    let name_bases = q.map(service_names::bases_named).unwrap_or_default();
    let (map_bases, map_packages) = service_names::package_pairs();
    // The statement's estimated cost crosses the server's JIT threshold, and
    // compiling it costs more than running it (1.5 s of a 0.4 s query on a
    // 2,500-host reach), so it runs without JIT. The setting is local to a
    // transaction, so a dropped request cannot leave the pooled connection
    // with JIT off.
    let tx = client.transaction().await?;
    tx.batch_execute("SET LOCAL jit = off").await?;
    let rows = tx
        .query(
            &statement(query.sort, query.descending),
            &[
                &scope.is_global(),
                &scope.group_ids(),
                &q,
                &name_bases,
                &query.runs_as.map(RunsAs::as_str),
                &query.listens.map(Listens::as_str),
                &query.packaged.map(Packaged::as_str),
                &query.group,
                &query.changes.map(Changes::as_str),
                &query.host,
                &now,
                &query.limit.clamp(1, i64::from(MAX_PAGE_SIZE)),
                &query.offset.clamp(0, 100_000),
                &service_names::bases_of(ServiceClass::Database),
                &service_names::bases_of(ServiceClass::RemoteAdmin),
                &service_names::known_bases(),
                &map_bases,
                &map_packages,
            ],
        )
        .await?;
    tx.commit().await?;
    let meta: serde_json::Value = rows.first().and_then(|r| r.get(0)).unwrap_or_default();
    let meta: Meta = serde_json::from_value(meta).map_err(|_| StoreError::Query)?;
    Ok(ServiceListPage {
        rows: rows.iter().filter_map(service_row).collect(),
        total: meta.total,
        summary: meta.summary,
        counts: service_counts(meta.counts),
    })
}

fn service_row(row: &Row) -> Option<ServiceListRow> {
    // The page is empty: one row holding only the meta.
    let unit: String = row.get::<_, Option<String>>(1)?;
    let mut run_as: Vec<String> = row.get(7);
    run_as.truncate(4);
    let mut programs: Vec<String> = row.get(8);
    programs.truncate(4);
    let groups: Vec<(String, String, String, i64)> =
        serde_json::from_value(row.get::<_, serde_json::Value>(13)).unwrap_or_default();
    let groups_total = i64::try_from(groups.len()).unwrap_or(i64::MAX);
    let ports: Vec<(String, i32, bool, i64)> =
        serde_json::from_value(row.get::<_, serde_json::Value>(14)).unwrap_or_default();
    let ports_total = i64::try_from(ports.len()).unwrap_or(i64::MAX);
    let info = service_names::service_info(&unit);
    Some(ServiceListRow {
        name: info.map(|i| i.name),
        usual_use: info.map(|i| i.usual_use),
        unit,
        hosts: row.get(2),
        root_hosts: row.get(3),
        package_hosts: row.get(4),
        exposed_hosts: row.get(5),
        listening_hosts: row.get(6),
        run_as,
        programs,
        package: row.get(9),
        groups: groups
            .into_iter()
            .take(3)
            .map(|(id, name, kind, hosts)| ServiceGroup {
                id,
                name,
                kind: GroupKind::parse(&kind),
                hosts,
            })
            .collect(),
        groups_total,
        ports: ports
            .into_iter()
            .take(4)
            .map(|(protocol, port, exposed, hosts)| OwnedPort {
                protocol,
                port,
                exposed,
                hosts,
            })
            .collect(),
        ports_total,
        week_added: row.get(10),
        week_removed: row.get(11),
        look: row.get(12),
    })
}

fn service_counts(raw: RawCounts) -> ServiceCounts {
    let n = |map: &BTreeMap<String, i64>, key: &str| map.get(key).copied().unwrap_or(0);
    let mut groups: Vec<_> = raw
        .groups
        .into_iter()
        .map(|(id, name, kind, n)| (id, name, GroupKind::parse(&kind), n))
        .collect();
    groups.sort_by(|a, b| (a.1.to_lowercase(), &a.0).cmp(&(b.1.to_lowercase(), &b.0)));
    ServiceCounts {
        runs_as: RunsAs::ALL
            .iter()
            .map(|v| (*v, n(&raw.runs_as, v.as_str())))
            .collect(),
        listens: Listens::ALL
            .iter()
            .map(|v| (*v, n(&raw.listens, v.as_str())))
            .collect(),
        packaged: Packaged::ALL
            .iter()
            .map(|v| (*v, n(&raw.packaged, v.as_str())))
            .collect(),
        changes: Changes::ALL
            .iter()
            .map(|v| (*v, n(&raw.changes, v.as_str())))
            .collect(),
        groups,
    }
}
