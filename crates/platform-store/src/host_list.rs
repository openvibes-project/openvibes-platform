//! The Hosts list (roles spec §10.1, §10.3; plan rulings 2–7): search,
//! single-value filters that AND together, the count for every value of
//! every filter with the other filters applied, the summary line and
//! offset paging. One statement, so the rows, total, counts and summary
//! always agree, and every part sees only hosts inside the viewer's scope;
//! each problem kind is counted only where its own permission reaches.

use std::net::IpAddr;

use chrono::{DateTime, Duration, Utc};
use tokio_postgres::Row;

use crate::{
    Client, StoreError,
    console_read::{AgentScope, MAX_PAGE_SIZE, agent_visibility},
    host_groups::GroupKind,
    host_list_counts::{counts, except, members},
    status::OFFLINE_AFTER_MINUTES,
};

/// Declares a URL-facing value list with its stored spelling.
macro_rules! values {
    ($(#[$doc:meta])* $name:ident { $($(#[$vdoc:meta])* $variant:ident = $text:literal),+ $(,)? }) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name { $($(#[$vdoc])* $variant),+ }

        impl $name {
            /// Every value, in display order.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            /// The URL and SQL spelling.
            #[must_use]
            pub fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $text),+ }
            }

            /// Parses the URL spelling.
            #[must_use]
            pub fn parse(text: &str) -> Option<Self> {
                Self::ALL.iter().copied().find(|v| v.as_str() == text)
            }
        }
    };
}

values!(
    /// A host's state (ruling 2).
    HostStatus {
        /// Heartbeat within the offline window.
        Online = "online",
        /// Enrolled, no recent heartbeat.
        Offline = "offline",
        /// Revoked by an operator.
        Revoked = "revoked",
        /// Imported from a file.
        Imported = "imported",
    }
);

values!(
    /// The Problems filter (ruling 4).
    Problems {
        /// At least one critical vulnerability.
        Critical = "critical",
        /// At least one open agent alarm.
        OpenAlarms = "open_alarms",
        /// No open alarm, critical vulnerability or failing check visible.
        NoneOpen = "none_open",
    }
);

values!(
    /// The Agent filter (ruling 7); an unknown version matches neither.
    AgentAge {
        /// Older than the latest agent release.
        Older = "older",
        /// The latest release (or newer).
        Latest = "latest",
    }
);

values!(
    /// The sort column; ties are broken by agent ID (ruling 6).
    HostSort {
        /// Host name, case-insensitive.
        Host = "host",
        /// Last heartbeat.
        Heartbeat = "heartbeat",
        /// Agent version.
        Version = "version",
        /// Open alarms + critical vulnerabilities + failing checks in reach.
        Problems = "problems",
    }
);

/// What the list asks for. `offset` is held to 0–100000 and `limit` to 1–100.
#[derive(Clone, Debug)]
pub struct HostQuery<'a> {
    /// Host name (contains, any case), IP prefix, or CIDR containment.
    pub q: Option<&'a str>,
    /// Status.
    pub status: Option<HostStatus>,
    /// `linux` or `windows`.
    pub os_family: Option<&'a str>,
    /// An asset group id.
    pub group: Option<&'a str>,
    /// A label.
    pub label: Option<&'a str>,
    /// Problems.
    pub problems: Option<Problems>,
    /// Agent age.
    pub agent: Option<AgentAge>,
    /// Sort column.
    pub sort: HostSort,
    /// Sort direction.
    pub descending: bool,
    /// Rows to skip.
    pub offset: i64,
    /// Rows to return.
    pub limit: i64,
}

/// The viewer's reach per kind: `hosts.read` decides the rows; `None` for a
/// kind the viewer may not read anywhere.
#[derive(Clone, Copy, Debug)]
pub struct HostScopes<'a> {
    /// `hosts.read`.
    pub hosts: &'a AgentScope,
    /// `alarms.read`.
    pub alarms: Option<&'a AgentScope>,
    /// `vulnerabilities.read`.
    pub vulnerabilities: Option<&'a AgentScope>,
    /// `compliance.read`.
    pub compliance: Option<&'a AgentScope>,
}

/// One host row. A problem count is `None` where its permission does not
/// reach the host; `agent_older` is `None` when either version is unknown.
#[derive(Clone, Debug)]
pub struct HostRow {
    /// Agent id.
    pub agent_id: String,
    /// Host name.
    pub hostname: Option<String>,
    /// Source address of its last connection.
    pub address: Option<String>,
    /// OS id (os-release `ID`).
    pub os_id: Option<String>,
    /// OS version.
    pub os_version: Option<String>,
    /// Display name, e.g. `Debian 12`.
    pub distribution: Option<String>,
    /// `linux` or `windows`.
    pub os_family: Option<String>,
    /// Status.
    pub status: HostStatus,
    /// Last heartbeat.
    pub last_seen_at: Option<DateTime<Utc>>,
    /// The first two groups by name: (id, name, kind).
    pub groups: Vec<(String, String, GroupKind)>,
    /// All its groups.
    pub group_count: i64,
    /// Labels.
    pub labels: Vec<String>,
    /// Open agent alarms.
    pub open_alarms: Option<i64>,
    /// Critical vulnerabilities.
    pub critical: Option<i64>,
    /// Failing compliance checks.
    pub failing: Option<i64>,
    /// Agent version.
    pub scanner_version: Option<String>,
    /// Older than the latest agent release.
    pub agent_older: Option<bool>,
}

/// Hosts per filter value, each with the other filters applied.
#[derive(Clone, Debug, Default)]
pub struct HostCounts {
    /// Every status.
    pub status: Vec<(HostStatus, i64)>,
    /// Families present, by name.
    pub os_family: Vec<(String, i64)>,
    /// Groups with a matching host in scope, plus the chosen one: (id,
    /// name, kind, hosts), by name.
    pub groups: Vec<(String, String, GroupKind, i64)>,
    /// The 50 most-used labels, plus the chosen one; most used first.
    pub labels: Vec<(String, i64)>,
    /// Every problems value.
    pub problems: Vec<(Problems, i64)>,
    /// Older and latest.
    pub agent: Vec<(AgentAge, i64)>,
}

/// "9 online · 4 with an older agent · 4 with critical vulnerabilities".
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HostSummaryLine {
    /// Online.
    pub online: i64,
    /// With an older agent.
    pub older_agent: i64,
    /// With critical vulnerabilities (in vulnerability reach).
    pub critical: i64,
}

/// One page of the list.
#[derive(Clone, Debug)]
pub struct HostListPage {
    /// The page.
    pub rows: Vec<HostRow>,
    /// Hosts matching every filter.
    pub total: i64,
    /// Per-value counts.
    pub counts: HostCounts,
    /// Summary over the matching hosts.
    pub summary: HostSummaryLine,
}

/// CTE `base`: hosts in the hosts scope (`$2`,`$3`) matching the search
/// (`$11` text, `$12` CIDR), with status (`$1` online threshold), agent age
/// (`$10` latest) and each problem count gated by its own scope (`$4`–`$9`).
fn base() -> String {
    let hosts = agent_visibility("a.agent_id", "$2", "$3");
    let alarms = agent_visibility("a.agent_id", "$4", "$5");
    let vulns = agent_visibility("a.agent_id", "$6", "$7");
    let compliance = agent_visibility("a.agent_id", "$8", "$9");
    format!(
        "base AS MATERIALIZED (
  SELECT a.agent_id, a.hostname, a.last_address, a.os_id, a.os_version, a.distribution,
         a.os_family, a.scanner_version, s.seen,
         CASE WHEN a.status = 'imported' THEN 'imported' WHEN a.status = 'revoked' THEN 'revoked'
              WHEN s.seen IS NULL OR s.seen < $1 THEN 'offline' ELSE 'online' END AS status,
         console_version_older(a.scanner_version, $10) AS older,
         CASE WHEN {alarms} THEN (SELECT count(*) FROM alarms al WHERE al.agent_id = a.agent_id
                                    AND al.state = 'open' AND al.source = 'agent') END AS open_alarms,
         CASE WHEN {vulns} THEN COALESCE((SELECT v.critical FROM host_vulnerability_counts v
                                           WHERE v.agent_id = a.agent_id), 0)::bigint END AS critical,
         CASE WHEN {compliance} THEN (SELECT count(*) FROM current_findings cf
                                        WHERE cf.agent_id = a.agent_id) END AS failing
  FROM agents a CROSS JOIN LATERAL (SELECT agent_seen_at(a.agent_id, a.last_seen_at) AS seen) s
  WHERE {hosts}
    AND ($11::text IS NULL OR strpos(lower(a.hostname), lower($11)) > 0
         OR starts_with(host(a.last_address), $11) OR a.last_address <<= $12::text::inet))"
    )
}

/// The sort keys over a `filtered f` row, ending in the agent-id tie-break.
fn order(sort: HostSort, descending: bool) -> String {
    let dir = if descending { "DESC" } else { "ASC" };
    let key = match sort {
        HostSort::Host => format!("COALESCE(lower(f.hostname), '') {dir}"),
        HostSort::Heartbeat => format!("f.seen {dir} NULLS LAST"),
        HostSort::Version => format!(
            "console_version_parts(f.scanner_version) {dir} NULLS LAST,
             strpos(split_part(f.scanner_version, '+', 1), '-') = 0 {dir}"
        ),
        HostSort::Problems => format!(
            "COALESCE(f.open_alarms, 0) + COALESCE(f.critical, 0) + COALESCE(f.failing, 0) {dir}"
        ),
    };
    format!("{key}, f.agent_id")
}

/// The statement: `filtered` is `base` with every filter; `meta` holds the
/// total, summary and counts as JSON on the first row only; the page rows
/// (`$19` limit, `$20` offset) carry their groups and labels. An empty page
/// still returns one row, with the meta and no host.
fn statement(sort: HostSort, descending: bool) -> String {
    format!(
        "WITH {base}, {members}, {counts},
filtered AS (SELECT * FROM base b WHERE {all}),
meta AS (
  SELECT jsonb_build_object(
    'total', count(*), 'online', count(*) FILTER (WHERE status = 'online'),
    'older', count(*) FILTER (WHERE older), 'critical', count(*) FILTER (WHERE critical > 0),
    'counts', (SELECT COALESCE(jsonb_agg(jsonb_build_array(facet, key, name, kind, n)), '[]') FROM counts)) AS meta
  FROM filtered),
page AS (SELECT f.*, row_number() OVER (ORDER BY {order}) AS ord FROM filtered f ORDER BY ord LIMIT $19 OFFSET $20)
SELECT CASE WHEN p.ord IS NOT DISTINCT FROM (SELECT min(ord) FROM page) THEN m.meta END,
       p.agent_id, p.hostname, host(p.last_address), p.os_id, p.os_version,
       console_distribution_name(p.distribution), p.os_family, p.status, p.seen,
       gr.ids, gr.names, gr.kinds, gr.n,
       ARRAY(SELECT l.label FROM console_host_labels l WHERE l.agent_id = p.agent_id ORDER BY l.label COLLATE \"C\"),
       p.open_alarms, p.critical, p.failing, p.scanner_version, p.older
FROM meta m LEFT JOIN page p ON true
LEFT JOIN LATERAL (
  SELECT (array_agg(g.asset_group_id::text ORDER BY lower(g.name), g.asset_group_id))[1:2] AS ids,
         (array_agg(g.name ORDER BY lower(g.name), g.asset_group_id))[1:2] AS names,
         (array_agg(g.kind ORDER BY lower(g.name), g.asset_group_id))[1:2] AS kinds, count(*) AS n
  FROM console_asset_groups g WHERE console_host_in_group(p.agent_id, g.asset_group_id)) gr ON true
ORDER BY p.ord",
        base = base(),
        members = members(),
        counts = counts(),
        all = except(None),
        order = order(sort, descending),
    )
}

/// `q` as a CIDR when it is one (`10.0.0.0/16`), so the cast never fails.
fn cidr(q: &str) -> Option<&str> {
    let (addr, prefix) = q.split_once('/')?;
    let addr: IpAddr = addr.parse().ok()?;
    let prefix: u8 = prefix.parse().ok()?;
    (prefix <= if addr.is_ipv4() { 32 } else { 128 }).then_some(q)
}

fn scope_params(scope: Option<&AgentScope>) -> (bool, Vec<String>) {
    scope.map_or((false, Vec::new()), |s| (s.is_global(), s.group_ids()))
}

#[derive(serde::Deserialize)]
struct Meta {
    total: i64,
    online: i64,
    older: i64,
    critical: i64,
    counts: Vec<CountLine>,
}

/// One page of the Hosts list for a viewer with `scopes`, judged against
/// the `latest` agent release (unknown: no host is older or latest).
pub async fn hosts(
    client: &Client,
    query: &HostQuery<'_>,
    scopes: &HostScopes<'_>,
    latest: Option<&str>,
    now: DateTime<Utc>,
) -> Result<HostListPage, StoreError> {
    let threshold = now - Duration::minutes(OFFLINE_AFTER_MINUTES);
    let hosts = scope_params(Some(scopes.hosts));
    let alarms = scope_params(scopes.alarms);
    let vulns = scope_params(scopes.vulnerabilities);
    let compliance = scope_params(scopes.compliance);
    let q = query.q.map(str::trim).filter(|q| !q.is_empty());
    let cidr = q.and_then(cidr);
    let rows = client
        .query(
            &statement(query.sort, query.descending),
            &[
                &threshold,
                &hosts.0,
                &hosts.1,
                &alarms.0,
                &alarms.1,
                &vulns.0,
                &vulns.1,
                &compliance.0,
                &compliance.1,
                &latest,
                &q,
                &cidr,
                &query.status.map(HostStatus::as_str),
                &query.os_family,
                &query.group,
                &query.label,
                &query.problems.map(Problems::as_str),
                &query.agent.map(AgentAge::as_str),
                &query.limit.clamp(1, i64::from(MAX_PAGE_SIZE)),
                &query.offset.clamp(0, 100_000),
            ],
        )
        .await?;
    let meta: serde_json::Value = rows.first().and_then(|r| r.get(0)).unwrap_or_default();
    let meta: Meta = serde_json::from_value(meta).map_err(|_| StoreError::Query)?;
    Ok(HostListPage {
        rows: rows.iter().filter_map(host_row).collect(),
        total: meta.total,
        summary: HostSummaryLine {
            online: meta.online,
            older_agent: meta.older,
            critical: meta.critical,
        },
        counts: host_counts(&meta.counts),
    })
}

fn host_row(row: &Row) -> Option<HostRow> {
    let agent_id: String = row.get::<_, Option<String>>(1)?;
    let ids: Vec<String> = row.get::<_, Option<_>>(10).unwrap_or_default();
    let names: Vec<String> = row.get::<_, Option<_>>(11).unwrap_or_default();
    let kinds: Vec<String> = row.get::<_, Option<_>>(12).unwrap_or_default();
    Some(HostRow {
        agent_id,
        hostname: row.get(2),
        address: row.get(3),
        os_id: row.get(4),
        os_version: row.get(5),
        distribution: row.get(6),
        os_family: row.get(7),
        status: HostStatus::parse(row.get(8)).unwrap_or(HostStatus::Offline),
        last_seen_at: row.get(9),
        groups: ids
            .into_iter()
            .zip(names)
            .zip(kinds)
            .map(|((id, name), kind)| (id, name, GroupKind::parse(&kind)))
            .collect(),
        group_count: row.get(13),
        labels: row.get(14),
        open_alarms: row.get(15),
        critical: row.get(16),
        failing: row.get(17),
        scanner_version: row.get(18),
        agent_older: row.get(19),
    })
}

type CountLine = (String, String, Option<String>, Option<String>, i64);

fn host_counts(lines: &[CountLine]) -> HostCounts {
    let facet = |name: &'static str| lines.iter().filter(move |l| l.0 == name);
    let n = |name: &'static str, key: &str| facet(name).find(|l| l.1 == key).map_or(0, |l| l.4);
    let mut os_family: Vec<_> = facet("os").map(|l| (l.1.clone(), l.4)).collect();
    os_family.sort();
    let mut groups: Vec<_> = facet("group")
        .map(|l| {
            let name = l.2.clone().unwrap_or_default();
            (
                l.1.clone(),
                name,
                GroupKind::parse(l.3.as_deref().unwrap_or_default()),
                l.4,
            )
        })
        .collect();
    groups.sort_by(|a, b| (a.1.to_lowercase(), &a.0).cmp(&(b.1.to_lowercase(), &b.0)));
    let mut labels: Vec<_> = facet("label").map(|l| (l.1.clone(), l.4)).collect();
    labels.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    HostCounts {
        status: HostStatus::ALL
            .iter()
            .map(|s| (*s, n("status", s.as_str())))
            .collect(),
        os_family,
        groups,
        labels,
        problems: Problems::ALL
            .iter()
            .map(|p| (*p, n("problems", p.as_str())))
            .collect(),
        agent: AgentAge::ALL
            .iter()
            .map(|a| (*a, n("agent", a.as_str())))
            .collect(),
    }
}
