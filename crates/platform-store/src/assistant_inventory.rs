//! Read-only inventory lookups for the console's assistant: open ports,
//! running services, and installed software. Same rules as
//! [`crate::assistant`]: the asking user's
//! [`AgentScope`](crate::assistant::AgentScope) applied in SQL, a `limit`,
//! and totals so callers can say how much was left out. Each read runs in
//! its own transaction with a 5 s statement timeout (the pool's is 10 s):
//! a model's question must not hold a connection for long.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use tokio_postgres::{Row, types::ToSql};

use crate::{
    Client, StoreError,
    assistant::{AgentScope, Page, limit_param},
    host_services::{Listener, Service},
};

/// Runs one query with `SET LOCAL statement_timeout = '5s'`.
async fn query(
    client: &mut Client,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
) -> Result<Vec<Row>, StoreError> {
    let tx = client.transaction().await?;
    tx.batch_execute("SET LOCAL statement_timeout = '5s'")
        .await?;
    let rows = tx.query(sql, params).await?;
    tx.commit().await?;
    Ok(rows)
}

/// A page of per-host rows: `total` rows matched, on `hosts` distinct hosts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostRows<T> {
    /// At most `limit` rows.
    pub items: Vec<T>,
    /// Every matching row, including those not returned.
    pub total: i64,
    /// Distinct hosts among every matching row.
    pub hosts: i64,
}

/// What a host last reported about its ports and services (migration 31).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostReport {
    /// Agent status (`active`, `revoked`, `imported`).
    pub status: String,
    /// When it last reported; `None`: never (no ports collector, or not yet).
    pub reported_at: Option<DateTime<Utc>>,
    /// `complete` or `partial` (some owners not visible to the agent).
    pub owners: Option<String>,
    /// The agent cut a list to the protocol limits.
    pub truncated: bool,
}

/// One host's report state, if in scope (revoked hosts included).
pub async fn host_report(
    client: &mut Client,
    scope: &AgentScope,
    agent_id: &str,
) -> Result<Option<HostReport>, StoreError> {
    let rows = query(
        client,
        "SELECT status, services_at, services_owners, services_truncated FROM agents
         WHERE agent_id = $2 AND ($1::text[] IS NULL OR agent_id = ANY($1))",
        &[&scope.param(), &agent_id],
    )
    .await?;
    Ok(rows.first().map(|r| HostReport {
        status: r.get(0),
        reported_at: r.get(1),
        owners: r.get(2),
        truncated: r.get(3),
    }))
}

/// One host's listening sockets (if in scope), exposed first, then by port;
/// `port` keeps only that port.
pub async fn host_listeners(
    client: &mut Client,
    scope: &AgentScope,
    agent_id: &str,
    port: Option<i32>,
    limit: u32,
) -> Result<Page<Listener>, StoreError> {
    let rows = query(
        client,
        "SELECT protocol, address, port, exposed, service, program, count(*) OVER ()
         FROM host_listeners
         WHERE agent_id = $2 AND ($1::text[] IS NULL OR agent_id = ANY($1))
           AND ($3::int IS NULL OR port = $3)
         ORDER BY exposed DESC, port, protocol, address
         LIMIT $4",
        &[&scope.param(), &agent_id, &port, &limit_param(limit)],
    )
    .await?;
    Ok(Page {
        total: rows.first().map_or(0, |row| row.get(6)),
        items: rows
            .iter()
            .map(|r| Listener {
                protocol: r.get(0),
                address: r.get(1),
                port: r.get(2),
                exposed: r.get(3),
                service: r.get(4),
                program: r.get(5),
            })
            .collect(),
    })
}

/// One host's running services (if in scope), by unit.
pub async fn host_services(
    client: &mut Client,
    scope: &AgentScope,
    agent_id: &str,
    limit: u32,
) -> Result<Page<Service>, StoreError> {
    let rows = query(
        client,
        "SELECT unit, programs, processes, run_as, count(*) OVER ()
         FROM host_services
         WHERE agent_id = $2 AND ($1::text[] IS NULL OR agent_id = ANY($1))
         ORDER BY unit
         LIMIT $3",
        &[&scope.param(), &agent_id, &limit_param(limit)],
    )
    .await?;
    Ok(Page {
        total: rows.first().map_or(0, |row| row.get(4)),
        items: rows
            .iter()
            .map(|r| Service {
                unit: r.get(0),
                programs: r.get(1),
                processes: r.get(2),
                run_as: r.get(3),
            })
            .collect(),
    })
}

/// A host in scope listening on a port, once per protocol and address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortListener {
    /// Agent.
    pub agent_id: String,
    /// Host name label (spoofable).
    pub hostname: Option<String>,
    /// `tcp` or `udp`.
    pub protocol: String,
    /// The bound address.
    pub address: IpAddr,
    /// Bound to a non-loopback address.
    pub exposed: bool,
    /// The owning systemd unit, when visible.
    pub service: Option<String>,
    /// The owning program, when visible.
    pub program: Option<String>,
}

/// Non-revoked hosts in scope listening on `port` (TCP or UDP), exposed
/// first, then by host name.
pub async fn port_listeners(
    client: &mut Client,
    scope: &AgentScope,
    port: i32,
    limit: u32,
) -> Result<HostRows<PortListener>, StoreError> {
    // `protocol IN (…)` lets the (protocol, port) index serve the lookup.
    let rows = query(
        client,
        "WITH m AS (
            SELECT a.agent_id, a.hostname, l.protocol, l.address, l.exposed, l.service,
                   l.program
            FROM host_listeners l JOIN agents a ON a.agent_id = l.agent_id
            WHERE l.protocol IN ('tcp', 'udp') AND l.port = $2 AND a.status <> 'revoked'
              AND ($1::text[] IS NULL OR a.agent_id = ANY($1))
         )
         SELECT m.*, count(*) OVER (), (SELECT count(DISTINCT agent_id) FROM m)
         FROM m
         ORDER BY exposed DESC, coalesce(hostname, ''), agent_id, protocol, address
         LIMIT $3",
        &[&scope.param(), &port, &limit_param(limit)],
    )
    .await?;
    Ok(HostRows {
        total: rows.first().map_or(0, |row| row.get(7)),
        hosts: rows.first().map_or(0, |row| row.get(8)),
        items: rows
            .iter()
            .map(|r| PortListener {
                agent_id: r.get(0),
                hostname: r.get(1),
                protocol: r.get(2),
                address: r.get(3),
                exposed: r.get(4),
                service: r.get(5),
                program: r.get(6),
            })
            .collect(),
    })
}

/// One installed package version on a host in scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstalledPackage {
    /// Agent.
    pub agent_id: String,
    /// Host name label (spoofable).
    pub hostname: Option<String>,
    /// Package manager (`rpm`, `dpkg`).
    pub manager: String,
    /// Package name.
    pub name: String,
    /// `epoch:version-release`, epoch and release only when present.
    pub version: String,
    /// Architecture.
    pub arch: String,
}

/// Installed packages for [`installed_packages`]: host rows of the first
/// `limit` matching names only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Installed {
    /// Rows of those names; `total` and `hosts` cover those names only.
    pub rows: HostRows<InstalledPackage>,
    /// Matching names read (at most `limit`).
    pub names: i64,
    /// More names match than were read.
    pub more_names: bool,
}

/// Packages whose name contains `name` (literally, case-insensitive, like
/// the Software page): the first `limit` matching names installed on a host
/// in scope, by name, and their hosts by name then host name. Revoked hosts
/// are left out unless `agent_id` names one.
pub async fn installed_packages(
    client: &mut Client,
    scope: &AgentScope,
    name: &str,
    agent_id: Option<&str>,
    limit: u32,
) -> Result<Installed, StoreError> {
    // Names first (bounded), so a short text such as "lib" never sorts every
    // host's packages: rows are at most `limit` names × the hosts in scope.
    // ponytail: the name scan reads package_versions in full (no trigram
    // index); it holds distinct versions, not hosts × packages.
    let rows = query(
        client,
        "WITH visible AS (
            SELECT a.agent_id, a.hostname FROM agents a
            WHERE ($1::text[] IS NULL OR a.agent_id = ANY($1))
              AND (a.status <> 'revoked' OR $3::text IS NOT NULL)
              AND ($3::text IS NULL OR a.agent_id = $3)
         ),
         names AS (
            SELECT DISTINCT pv.name FROM package_versions pv
            WHERE strpos(lower(pv.name), lower($2)) > 0
              AND EXISTS (SELECT 1 FROM package_versions p2
                          JOIN host_packages hp ON hp.package_version_id = p2.id
                          JOIN visible v ON v.agent_id = hp.agent_id
                          WHERE p2.name = pv.name)
            ORDER BY pv.name LIMIT $4::bigint + 1
         ),
         page AS (SELECT name FROM names ORDER BY name LIMIT $4),
         m AS (
            SELECT v.agent_id, v.hostname, pv.manager, pv.name,
                   CASE WHEN pv.epoch <> 0 THEN pv.epoch || ':' ELSE '' END || pv.version
                       || CASE WHEN pv.release <> '' THEN '-' || pv.release ELSE '' END
                       AS version,
                   pv.arch, pv.id
            FROM page JOIN package_versions pv ON pv.name = page.name
            JOIN host_packages hp ON hp.package_version_id = pv.id
            JOIN visible v ON v.agent_id = hp.agent_id
         )
         SELECT agent_id, hostname, manager, name, version, arch, count(*) OVER (),
                (SELECT count(DISTINCT agent_id) FROM m),
                (SELECT count(*) FROM page), (SELECT count(*) FROM names)
         FROM m
         ORDER BY name, coalesce(hostname, ''), agent_id, id
         LIMIT $4",
        &[&scope.param(), &name, &agent_id, &limit_param(limit)],
    )
    .await?;
    let count = |i: usize| rows.first().map_or(0, |row| row.get::<_, i64>(i));
    Ok(Installed {
        names: count(8),
        more_names: count(9) > count(8),
        rows: HostRows {
            total: count(6),
            hosts: count(7),
            items: rows
                .iter()
                .map(|r| InstalledPackage {
                    agent_id: r.get(0),
                    hostname: r.get(1),
                    manager: r.get(2),
                    name: r.get(3),
                    version: r.get(4),
                    arch: r.get(5),
                })
                .collect(),
        },
    })
}
