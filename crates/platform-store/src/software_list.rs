//! The Software list (roles spec §10.3; step 5g rulings 1–10): one row per
//! package name over the hosts in the viewer's scope that have it, rpm and
//! dpkg together, with search, filters that AND together, the count for
//! every value of every filter with the other filters applied, the summary
//! line and offset paging. One statement, so rows, total, counts and
//! summary always agree.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use tokio_postgres::Row;

use crate::{
    Client, StoreError,
    console_read::{AgentScope, MAX_PAGE_SIZE},
    host_groups::GroupKind,
    host_list::values,
    service_names,
    software_list_sql::statement,
    software_version::{full_version, order_key},
};

values!(
    /// The Vulnerabilities filter (ruling 5): by the package's open advisories.
    Vulns {
        /// An open advisory is known to be exploited.
        Exploited = "exploited",
        /// The worst open advisory is critical or important.
        CriticalHigh = "critical_high",
        /// At least one open advisory.
        Any = "any",
        /// None.
        None = "none",
    }
);

values!(
    /// The Fix filter.
    Fix {
        /// An update fixes an open advisory on at least one host.
        Available = "available",
        /// An open advisory has no fix yet.
        None = "none",
    }
);

values!(
    /// The Versions filter.
    Versions {
        /// One version in use.
        One = "one",
        /// More than one.
        Several = "several",
    }
);

values!(
    /// The Type filter: the package database a host reports it from.
    PackageType {
        /// Debian packages.
        Dpkg = "dpkg",
        /// RPM packages.
        Rpm = "rpm",
    }
);

values!(
    /// The Changes filter (ruling 8).
    Changes {
        /// Installed on a host in the last 7 days.
        New = "new",
        /// Changed version on a host in the last 7 days.
        Updated = "updated",
        /// Removed from a host in the last 7 days.
        Removed = "removed",
    }
);

values!(
    /// The sort column; ties are broken by name in the same direction.
    SoftwareSort {
        /// The package name.
        Package = "package",
        /// Hosts having it.
        Hosts = "hosts",
        /// Exploited, then the worst severity, then how many advisories.
        Vulnerabilities = "vulnerabilities",
        /// Versions in use.
        Versions = "versions",
        /// Hosts that changed it this week.
        Week = "week",
    }
);

/// What the list asks for. `offset` is held to 0–100000 and `limit` to 1–100.
#[derive(Clone, Debug)]
pub struct SoftwareQuery<'a> {
    /// Name or a service using it (contains, any case).
    pub q: Option<&'a str>,
    /// Vulnerabilities.
    pub vulns: Option<Vulns>,
    /// Fix.
    pub fix: Option<Fix>,
    /// Versions.
    pub versions: Option<Versions>,
    /// Type.
    pub kind: Option<PackageType>,
    /// An asset group id.
    pub group: Option<&'a str>,
    /// Changes.
    pub changes: Option<Changes>,
    /// An agent id.
    pub host: Option<&'a str>,
    /// Sort column.
    pub sort: SoftwareSort,
    /// Sort direction.
    pub descending: bool,
    /// Rows to skip.
    pub offset: i64,
    /// Rows to return.
    pub limit: i64,
}

/// A service that uses the package (matched by name).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UsedBy {
    /// The unit.
    pub unit: String,
    /// Hosts in reach running it.
    pub hosts: i64,
}

/// One row: a package name.
#[derive(Clone, Debug)]
pub struct SoftwareListRow {
    /// The package name.
    pub name: String,
    /// Hosts in reach that have it, under any manager.
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
    pub worst_severity: Option<String>,
    /// One of them is known to be exploited.
    pub exploited: bool,
    /// Hosts where an update fixes an open advisory.
    pub update_hosts: i64,
    /// Services using it, most hosts first, at most 3.
    pub used_by: Vec<UsedBy>,
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
#[derive(Clone, Debug, Default)]
pub struct SoftwareCounts {
    /// Exploited, critical or high, any, none.
    pub vulns: Vec<(Vulns, i64)>,
    /// Available, none.
    pub fix: Vec<(Fix, i64)>,
    /// One, several.
    pub versions: Vec<(Versions, i64)>,
    /// Dpkg, rpm.
    pub kind: Vec<(PackageType, i64)>,
    /// New, updated, removed.
    pub changes: Vec<(Changes, i64)>,
    /// Groups with a host in reach: (id, name, kind, hosts in reach). The
    /// package counts of a group would read every package of every host, so
    /// the list gives its hosts instead.
    pub groups: Vec<(String, String, GroupKind, i64)>,
}

/// "N with an exploited vulnerability · N with a fix available · N in
/// several versions · N new this week · from N hosts' last reports", over
/// the rows matching every filter.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Deserialize)]
pub struct SoftwareListSummary {
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

/// One page of the list.
#[derive(Clone, Debug)]
pub struct SoftwareListPage {
    /// The page.
    pub rows: Vec<SoftwareListRow>,
    /// Rows matching every filter.
    pub total: i64,
    /// Per-value counts.
    pub counts: SoftwareCounts,
    /// The summary line.
    pub summary: SoftwareListSummary,
}

#[derive(serde::Deserialize)]
struct RawCounts {
    vulns: BTreeMap<String, i64>,
    fix: BTreeMap<String, i64>,
    versions: BTreeMap<String, i64>,
    kind: BTreeMap<String, i64>,
    changes: BTreeMap<String, i64>,
    groups: Vec<(String, String, String, i64)>,
}

#[derive(serde::Deserialize)]
struct Meta {
    total: i64,
    counts: RawCounts,
    summary: SoftwareListSummary,
}

/// The severity names, worst first (`position - 1` indexes it).
pub(crate) const SEVERITIES: [&str; 5] = ["critical", "important", "moderate", "low", "unrated"];

/// One page of the Software list within `scope` (`hosts.read`); `now` dates
/// "this week" and the expiry of an accepted risk.
pub async fn software_list(
    client: &mut Client,
    query: &SoftwareQuery<'_>,
    scope: &AgentScope,
    now: DateTime<Utc>,
) -> Result<SoftwareListPage, StoreError> {
    let q = query.q.map(str::trim).filter(|q| !q.is_empty());
    let (map_bases, map_packages) = service_names::package_pairs();
    // As the Services list: the statement's estimated cost crosses the
    // server's JIT threshold and compiling it costs more than running it.
    let tx = client.transaction().await?;
    tx.batch_execute("SET LOCAL jit = off").await?;
    let rows = tx
        .query(
            &statement(query.sort, query.descending),
            &[
                &scope.is_global(),
                &scope.group_ids(),
                &q,
                &query.vulns.map(Vulns::as_str),
                &query.fix.map(Fix::as_str),
                &query.versions.map(Versions::as_str),
                &query.kind.map(PackageType::as_str),
                &query.group,
                &query.changes.map(Changes::as_str),
                &query.host,
                &now,
                &query.limit.clamp(1, i64::from(MAX_PAGE_SIZE)),
                &query.offset.clamp(0, 100_000),
                &map_bases,
                &map_packages,
                &service_names::SYSTEMD,
            ],
        )
        .await?;
    tx.commit().await?;
    let meta: serde_json::Value = rows.first().and_then(|r| r.get(0)).unwrap_or_default();
    let meta: Meta = serde_json::from_value(meta).map_err(|_| StoreError::Query)?;
    Ok(SoftwareListPage {
        rows: rows.iter().filter_map(software_row).collect(),
        total: meta.total,
        summary: meta.summary,
        counts: software_counts(meta.counts),
    })
}

/// The oldest and newest of `versions` (`[epoch, version, release]`).
fn version_range(versions: &[(i64, String, String)]) -> (String, String) {
    let key = |v: &&(i64, String, String)| order_key(v.0, &v.1, &v.2);
    let show = |v: Option<&(i64, String, String)>| {
        v.map(|(e, v, r)| full_version(*e, v, r))
            .unwrap_or_default()
    };
    (
        show(versions.iter().min_by_key(key)),
        show(versions.iter().max_by_key(key)),
    )
}

fn software_row(row: &Row) -> Option<SoftwareListRow> {
    // The page is empty: one row holding only the meta.
    let name: String = row.get::<_, Option<String>>(1)?;
    let versions: Vec<(i64, String, String)> =
        serde_json::from_value(row.get::<_, serde_json::Value>(15)).unwrap_or_default();
    let (oldest, newest) = version_range(&versions);
    let used_by: Vec<(String, i64)> =
        serde_json::from_value(row.get::<_, serde_json::Value>(14)).unwrap_or_default();
    let used_by_total = i64::try_from(used_by.len()).unwrap_or(i64::MAX);
    let severity: Option<i32> = row.get(7);
    Some(SoftwareListRow {
        name,
        hosts: row.get(2),
        versions: row.get(3),
        oldest,
        newest,
        dpkg: row.get(4),
        rpm: row.get(5),
        advisories: row.get(6),
        worst_severity: severity
            .and_then(|rank| usize::try_from(rank).ok()?.checked_sub(1))
            .and_then(|i| SEVERITIES.get(i))
            .map(|s| (*s).to_owned()),
        exploited: row.get(8),
        no_fix: row.get(9),
        update_hosts: row.get(10),
        week_added: row.get(11),
        week_updated: row.get(12),
        week_removed: row.get(13),
        used_by: used_by
            .into_iter()
            .take(3)
            .map(|(unit, hosts)| UsedBy { unit, hosts })
            .collect(),
        used_by_total,
    })
}

fn software_counts(raw: RawCounts) -> SoftwareCounts {
    let n = |map: &BTreeMap<String, i64>, key: &str| map.get(key).copied().unwrap_or(0);
    let mut groups: Vec<_> = raw
        .groups
        .into_iter()
        .map(|(id, name, kind, n)| (id, name, GroupKind::parse(&kind), n))
        .collect();
    groups.sort_by(|a, b| (a.1.to_lowercase(), &a.0).cmp(&(b.1.to_lowercase(), &b.0)));
    SoftwareCounts {
        vulns: Vulns::ALL
            .iter()
            .map(|v| (*v, n(&raw.vulns, v.as_str())))
            .collect(),
        fix: Fix::ALL
            .iter()
            .map(|v| (*v, n(&raw.fix, v.as_str())))
            .collect(),
        versions: Versions::ALL
            .iter()
            .map(|v| (*v, n(&raw.versions, v.as_str())))
            .collect(),
        kind: PackageType::ALL
            .iter()
            .map(|v| (*v, n(&raw.kind, v.as_str())))
            .collect(),
        changes: Changes::ALL
            .iter()
            .map(|v| (*v, n(&raw.changes, v.as_str())))
            .collect(),
        groups,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_range_runs_from_the_oldest_to_the_newest() {
        let v = |e, version: &str, r: &str| (e, version.to_owned(), r.to_owned());
        let (oldest, newest) =
            version_range(&[v(0, "3.0.10", "1"), v(0, "3.0.9", "2"), v(0, "3.1.0", "")]);
        assert_eq!((oldest.as_str(), newest.as_str()), ("3.0.9-2", "3.1.0"));
        assert_eq!(version_range(&[]), (String::new(), String::new()));
    }
}
