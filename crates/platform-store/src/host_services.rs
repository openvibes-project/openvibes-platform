//! Open ports and running services per host (protocol P15, Assets v2):
//! what ingest stores from a `HostServices` report, and the console's
//! scoped reads. A report replaces the host's rows, like an inventory.

use chrono::{DateTime, Utc};

use crate::{
    Client, StoreError,
    console_read::{AgentScope, agent_visibility},
};

/// One listening socket.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Listener {
    /// `tcp` or `udp`.
    pub protocol: String,
    /// The bound address (an IP literal; `0.0.0.0` or `::` for any).
    pub address: std::net::IpAddr,
    /// 1 to 65535.
    pub port: i32,
    /// Bound to a non-loopback address.
    pub exposed: bool,
    /// The owning systemd unit, when visible.
    pub service: Option<String>,
    /// The owning program, when visible.
    pub program: Option<String>,
}

/// One running service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Service {
    /// The systemd unit, e.g. `nginx.service`.
    pub unit: String,
    /// Its programs (short names), sorted.
    pub programs: Vec<String>,
    /// How many processes it runs.
    pub processes: i32,
    /// The user it runs as (a name, or the uid when unknown).
    pub run_as: Option<String>,
}

/// A host's report, checked by ingest.
#[derive(Clone, Debug)]
pub struct Report {
    /// The services digest (64 hex).
    pub sha256: String,
    /// `complete` or `partial` (are owners named wherever they exist?).
    pub owners: String,
    /// Listening sockets.
    pub listeners: Vec<Listener>,
    /// Running services.
    pub services: Vec<Service>,
}

/// Replaces `agent_id`'s listeners and services with `report` in one
/// transaction; an unchanged digest only touches `services_at`.
pub async fn replace(
    client: &mut Client,
    agent_id: &str,
    report: &Report,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let tx = client.transaction().await?;
    let current: Option<String> = tx
        .query_opt(
            "SELECT services_sha256 FROM agents WHERE agent_id = $1 FOR UPDATE",
            &[&agent_id],
        )
        .await?
        .and_then(|row| row.get(0));
    if current.as_deref() != Some(report.sha256.as_str()) {
        tx.execute(
            "DELETE FROM host_listeners WHERE agent_id = $1",
            &[&agent_id],
        )
        .await?;
        tx.execute(
            "DELETE FROM host_services WHERE agent_id = $1",
            &[&agent_id],
        )
        .await?;
        // ponytail: one INSERT per row (at most 4,096 + 2,048 per report,
        // only when the digest changed); a COPY if hosts change constantly.
        for l in &report.listeners {
            tx.execute(
                "INSERT INTO host_listeners (agent_id, protocol, address, port, exposed, service, program)
                 VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING",
                &[&agent_id, &l.protocol, &l.address, &l.port, &l.exposed, &l.service, &l.program],
            )
            .await?;
        }
        for s in &report.services {
            tx.execute(
                "INSERT INTO host_services (agent_id, unit, programs, processes, run_as)
                 VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
                &[&agent_id, &s.unit, &s.programs, &s.processes, &s.run_as],
            )
            .await?;
        }
    }
    // A good report clears the last refusal.
    tx.execute(
        "UPDATE agents SET services_sha256 = $2, services_at = $3, services_owners = $4,
             services_refused_at = NULL, services_refused = NULL
         WHERE agent_id = $1",
        &[&agent_id, &report.sha256, &now, &report.owners],
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Why ingest refused a report (stored on the host until a good one).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// Over 512 KiB uncompressed (413).
    TooLarge,
    /// Not a valid `HostServices` (400).
    Invalid,
    /// Its `agent_id` is not the authenticated agent's (400).
    WrongAgent,
}

impl Refusal {
    /// The stored code.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Refusal::TooLarge => "too_large",
            Refusal::Invalid => "invalid",
            Refusal::WrongAgent => "wrong_agent",
        }
    }
}

/// Records that `agent_id`'s report was refused; its stored lists stay.
pub async fn refused(
    client: &Client,
    agent_id: &str,
    refusal: Refusal,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    client
        .execute(
            "UPDATE agents SET services_refused_at = $2, services_refused = $3 WHERE agent_id = $1",
            &[&agent_id, &now, &refusal.code()],
        )
        .await?;
    Ok(())
}

fn scope_params(scope: &AgentScope) -> (bool, Vec<String>) {
    match scope {
        AgentScope::Global => (true, Vec::new()),
        AgentScope::AssetGroups(groups) => (false, groups.clone()),
    }
}

/// What the console shows for one host.
#[derive(Clone, Debug)]
pub struct HostServices {
    /// When the host last reported (None: never).
    pub reported_at: Option<DateTime<Utc>>,
    /// `complete` or `partial`.
    pub owners: Option<String>,
    /// The last refused report since the last good one: when, and the
    /// code (`too_large`, `invalid`, `wrong_agent`).
    pub refused: Option<(DateTime<Utc>, String)>,
    /// Its listeners, exposed first, then by port.
    pub listeners: Vec<Listener>,
    /// Its services, by unit.
    pub services: Vec<Service>,
}

/// One host's listeners and services, if the caller may see the host
/// (revoked hosts included: the page of a revoked host still opens).
pub async fn for_host(
    client: &Client,
    scope: &AgentScope,
    agent_id: &str,
) -> Result<Option<HostServices>, StoreError> {
    let (global, groups) = scope_params(scope);
    let visible = agent_visibility("a.agent_id", "$1", "$2");
    let Some(agent) = client
        .query_opt(
            &format!(
                "SELECT a.services_at, a.services_owners, a.services_refused_at, a.services_refused
                 FROM agents a
                 WHERE a.agent_id = $3 AND {visible}"
            ),
            &[&global, &groups, &agent_id],
        )
        .await?
    else {
        return Ok(None);
    };
    let listeners = client
        .query(
            "SELECT protocol, address, port, exposed, service, program FROM host_listeners
             WHERE agent_id = $1 ORDER BY exposed DESC, port, protocol, address",
            &[&agent_id],
        )
        .await?
        .iter()
        .map(|r| Listener {
            protocol: r.get(0),
            address: r.get(1),
            port: r.get(2),
            exposed: r.get(3),
            service: r.get(4),
            program: r.get(5),
        })
        .collect();
    let services = client
        .query(
            "SELECT unit, programs, processes, run_as FROM host_services
             WHERE agent_id = $1 ORDER BY unit",
            &[&agent_id],
        )
        .await?
        .iter()
        .map(|r| Service {
            unit: r.get(0),
            programs: r.get(1),
            processes: r.get(2),
            run_as: r.get(3),
        })
        .collect();
    Ok(Some(HostServices {
        reported_at: agent.get(0),
        owners: agent.get(1),
        refused: agent
            .get::<_, Option<DateTime<Utc>>>(2)
            .zip(agent.get::<_, Option<String>>(3)),
        listeners,
        services,
    }))
}

/// One port across the caller's (non-revoked) hosts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortRow {
    /// `tcp` or `udp`.
    pub protocol: String,
    /// The port.
    pub port: i32,
    /// Hosts listening on it.
    pub hosts: i64,
    /// Of those, hosts where it is exposed (non-loopback).
    pub exposed_hosts: i64,
    /// Owning services seen for it (where visible), sorted, at most 8.
    pub services: Vec<String>,
}

/// Ports across the caller's hosts, by protocol and port; `exposed_only`
/// keeps ports exposed on at least one host.
pub async fn fleet_ports(
    client: &Client,
    scope: &AgentScope,
    exposed_only: bool,
) -> Result<Vec<PortRow>, StoreError> {
    let (global, groups) = scope_params(scope);
    let visible = agent_visibility("a.agent_id", "$1", "$2");
    // ponytail: one grouped scan, no paging: distinct (protocol, port)
    // pairs across a fleet stay in the low thousands.
    let rows = client
        .query(
            &format!(
                "SELECT l.protocol, l.port, count(DISTINCT l.agent_id),
                    count(DISTINCT l.agent_id) FILTER (WHERE l.exposed),
                    (array_agg(DISTINCT l.service) FILTER (WHERE l.service IS NOT NULL))[1:8]
                 FROM host_listeners l JOIN agents a ON a.agent_id = l.agent_id
                 WHERE a.status <> 'revoked' AND {visible}
                 GROUP BY l.protocol, l.port
                 HAVING NOT $3 OR bool_or(l.exposed)
                 ORDER BY l.port, l.protocol"
            ),
            &[&global, &groups, &exposed_only],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| PortRow {
            protocol: r.get(0),
            port: r.get(1),
            hosts: r.get(2),
            exposed_hosts: r.get(3),
            services: r.get::<_, Option<Vec<String>>>(4).unwrap_or_default(),
        })
        .collect())
}

/// One service unit across the caller's (non-revoked) hosts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnitRow {
    /// The systemd unit.
    pub unit: String,
    /// Hosts running it.
    pub hosts: i64,
}

/// Running services across the caller's hosts, by unit.
pub async fn fleet_services(
    client: &Client,
    scope: &AgentScope,
) -> Result<Vec<UnitRow>, StoreError> {
    let (global, groups) = scope_params(scope);
    let visible = agent_visibility("a.agent_id", "$1", "$2");
    let rows = client
        .query(
            &format!(
                "SELECT s.unit, count(*) FROM host_services s
                 JOIN agents a ON a.agent_id = s.agent_id
                 WHERE a.status <> 'revoked' AND {visible}
                 GROUP BY s.unit ORDER BY s.unit"
            ),
            &[&global, &groups],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| UnitRow {
            unit: r.get(0),
            hosts: r.get(1),
        })
        .collect())
}
