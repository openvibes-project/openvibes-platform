//! Read-only inventory lookups for the console's assistant: open ports,
//! running services, and installed software. Same rules as
//! [`crate::assistant`]: the asking user's [`AgentScope`](crate::assistant::AgentScope) applied in SQL, a
//! `limit`, and totals so callers can say how much was left out.

use std::net::IpAddr;

use crate::{
    Client, StoreError,
    assistant::{AgentScope, Page, limit_param},
    host_services::{Listener, Service},
};

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

/// One host's listening sockets (if in scope), exposed first, then by port;
/// `port` keeps only that port.
pub async fn host_listeners(
    client: &Client,
    scope: &AgentScope,
    agent_id: &str,
    port: Option<i32>,
    limit: u32,
) -> Result<Page<Listener>, StoreError> {
    let rows = client
        .query(
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
    client: &Client,
    scope: &AgentScope,
    agent_id: &str,
    limit: u32,
) -> Result<Page<Service>, StoreError> {
    let rows = client
        .query(
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
    client: &Client,
    scope: &AgentScope,
    port: i32,
    limit: u32,
) -> Result<HostRows<PortListener>, StoreError> {
    let rows = client
        .query(
            "WITH m AS (
                SELECT a.agent_id, a.hostname, l.protocol, l.address, l.exposed, l.service,
                       l.program
                FROM host_listeners l JOIN agents a ON a.agent_id = l.agent_id
                WHERE l.port = $2 AND a.status <> 'revoked'
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

/// Packages whose name contains `name` (case-insensitive, like the
/// Software page) on non-revoked hosts in scope, or only on `agent_id`;
/// by package name, then host name.
// ponytail: counts every match before the limit; a short `name` such as
// "lib" scans a large share of host_packages. Upgrade: a trigram index.
pub async fn installed_packages(
    client: &Client,
    scope: &AgentScope,
    name: &str,
    agent_id: Option<&str>,
    limit: u32,
) -> Result<HostRows<InstalledPackage>, StoreError> {
    let rows = client
        .query(
            "WITH m AS (
                SELECT a.agent_id, a.hostname, pv.manager, pv.name,
                       CASE WHEN pv.epoch <> 0 THEN pv.epoch || ':' ELSE '' END || pv.version
                           || CASE WHEN pv.release <> '' THEN '-' || pv.release ELSE '' END
                           AS version,
                       pv.arch, pv.id
                FROM host_packages hp
                JOIN package_versions pv ON pv.id = hp.package_version_id
                JOIN agents a ON a.agent_id = hp.agent_id
                WHERE strpos(lower(pv.name), lower($2)) > 0 AND a.status <> 'revoked'
                  AND ($1::text[] IS NULL OR a.agent_id = ANY($1))
                  AND ($3::text IS NULL OR a.agent_id = $3)
             )
             SELECT agent_id, hostname, manager, name, version, arch, count(*) OVER (),
                    (SELECT count(DISTINCT agent_id) FROM m)
             FROM m
             ORDER BY name, coalesce(hostname, ''), agent_id, id
             LIMIT $4",
            &[&scope.param(), &name, &agent_id, &limit_param(limit)],
        )
        .await?;
    Ok(HostRows {
        total: rows.first().map_or(0, |row| row.get(6)),
        hosts: rows.first().map_or(0, |row| row.get(7)),
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
    })
}
