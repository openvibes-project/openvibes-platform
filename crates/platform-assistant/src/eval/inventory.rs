//! The evaluation fleet's open ports, running services, and installed
//! packages, answered as `platform_store::assistant_inventory` would (same
//! ordering, revoked hosts left out of fleet-wide reads, hidden hosts
//! dropped as scope would).

use std::{collections::BTreeSet, net::IpAddr};

use platform_store::{
    StoreError,
    assistant::Page,
    assistant_inventory::{HostReport, HostRows, Installed, InstalledPackage, PortListener},
    host_services::{Listener, Service},
};
use serde::Deserialize;

use super::{Fleet, page};

fn tcp() -> String {
    "tcp".into()
}

fn rpm() -> String {
    "rpm".into()
}

fn x86_64() -> String {
    "x86_64".into()
}

/// A listening socket in the fleet file.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ListenerRow {
    host: String,
    #[serde(default = "tcp")]
    protocol: String,
    address: IpAddr,
    port: i32,
    service: Option<String>,
    program: Option<String>,
}

/// A running service in the fleet file.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ServiceRow {
    host: String,
    unit: String,
    programs: Vec<String>,
    processes: i32,
    run_as: Option<String>,
}

/// An installed package in the fleet file.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PackageRow {
    host: String,
    name: String,
    version: String,
    #[serde(default = "rpm")]
    manager: String,
    #[serde(default = "x86_64")]
    arch: String,
}

/// The inventory of the visible agents, keyed by agent ID.
#[derive(Clone, Default)]
pub(super) struct Inventory {
    listeners: Vec<(String, Listener)>,
    services: Vec<(String, Service)>,
    packages: Vec<(String, InstalledPackage)>,
}

impl Inventory {
    /// Resolves host names with `agent_of`, dropping `hidden` hosts.
    pub(super) fn parse(
        listeners: Vec<ListenerRow>,
        services: Vec<ServiceRow>,
        packages: Vec<PackageRow>,
        agent_of: impl Fn(&str) -> Result<String, String>,
        hidden: &BTreeSet<&str>,
    ) -> Result<Self, String> {
        let mut inventory = Self::default();
        for l in listeners {
            let agent = agent_of(&l.host)?;
            if !hidden.contains(l.host.as_str()) {
                let exposed = !l.address.is_loopback();
                inventory.listeners.push((
                    agent,
                    Listener {
                        protocol: l.protocol,
                        address: l.address,
                        port: l.port,
                        exposed,
                        service: l.service,
                        program: l.program,
                    },
                ));
            }
        }
        for s in services {
            let agent = agent_of(&s.host)?;
            if !hidden.contains(s.host.as_str()) {
                inventory.services.push((
                    agent,
                    Service {
                        unit: s.unit,
                        programs: s.programs,
                        processes: s.processes,
                        run_as: s.run_as,
                    },
                ));
            }
        }
        for p in packages {
            let agent_id = agent_of(&p.host)?;
            if !hidden.contains(p.host.as_str()) {
                inventory.packages.push((
                    agent_id.clone(),
                    InstalledPackage {
                        agent_id,
                        hostname: Some(p.host),
                        manager: p.manager,
                        name: p.name,
                        version: p.version,
                        arch: p.arch,
                    },
                ));
            }
        }
        Ok(inventory)
    }
}

fn count(n: usize) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

fn host_rows<T>(items: Vec<T>, agent: impl Fn(&T) -> &str, limit: u32) -> HostRows<T> {
    let hosts = count(items.iter().map(&agent).collect::<BTreeSet<_>>().len());
    let page = page(items, limit);
    HostRows {
        items: page.items,
        total: page.total,
        hosts,
    }
}

impl Fleet {
    fn active(&self, agent: &str) -> bool {
        self.agents.iter().any(|a| a.id == agent && !a.revoked)
    }

    /// A host has reported when it has any listener or service row (the
    /// fleet file has no separate report time); owners are complete.
    pub(super) fn host_report(&self, agent_id: &str) -> Result<Option<HostReport>, StoreError> {
        let reported = self.inventory.listeners.iter().any(|(a, _)| a == agent_id)
            || self.inventory.services.iter().any(|(a, _)| a == agent_id);
        Ok(self
            .agents
            .iter()
            .find(|a| a.id == agent_id)
            .map(|a| HostReport {
                status: if a.revoked { "revoked" } else { "active" }.into(),
                reported_at: a.last_seen.filter(|_| reported),
                owners: reported.then(|| "complete".into()),
                truncated: false,
            }))
    }

    pub(super) fn host_listeners(
        &self,
        agent_id: &str,
        port: Option<i32>,
        limit: u32,
    ) -> Result<Page<Listener>, StoreError> {
        let mut found: Vec<Listener> = self
            .inventory
            .listeners
            .iter()
            .filter(|(a, l)| a == agent_id && port.is_none_or(|p| p == l.port))
            .map(|(_, l)| l.clone())
            .collect();
        found.sort_by(|a, b| {
            (!a.exposed, a.port, &a.protocol, a.address).cmp(&(
                !b.exposed,
                b.port,
                &b.protocol,
                b.address,
            ))
        });
        Ok(page(found, limit))
    }

    pub(super) fn host_services(
        &self,
        agent_id: &str,
        limit: u32,
    ) -> Result<Page<Service>, StoreError> {
        let mut found: Vec<Service> = self
            .inventory
            .services
            .iter()
            .filter(|(a, _)| a == agent_id)
            .map(|(_, s)| s.clone())
            .collect();
        found.sort_by(|a, b| a.unit.cmp(&b.unit));
        Ok(page(found, limit))
    }

    pub(super) fn port_listeners(
        &self,
        port: i32,
        limit: u32,
    ) -> Result<HostRows<PortListener>, StoreError> {
        let mut found: Vec<PortListener> = self
            .inventory
            .listeners
            .iter()
            .filter(|(a, l)| l.port == port && self.active(a))
            .map(|(a, l)| PortListener {
                agent_id: a.clone(),
                hostname: self.hostname(a),
                protocol: l.protocol.clone(),
                address: l.address,
                exposed: l.exposed,
                service: l.service.clone(),
                program: l.program.clone(),
            })
            .collect();
        found.sort_by(|a, b| {
            (!a.exposed, &a.hostname, &a.agent_id, &a.protocol, a.address).cmp(&(
                !b.exposed,
                &b.hostname,
                &b.agent_id,
                &b.protocol,
                b.address,
            ))
        });
        Ok(host_rows(found, |l| &l.agent_id, limit))
    }

    pub(super) fn installed_packages(
        &self,
        name: &str,
        agent_id: Option<&str>,
        limit: u32,
    ) -> Result<Installed, StoreError> {
        let text = name.to_lowercase();
        let visible = |a: &str| agent_id.map_or_else(|| self.active(a), |id| id == a);
        let names: BTreeSet<&str> = self
            .inventory
            .packages
            .iter()
            .filter(|(a, p)| p.name.to_lowercase().contains(&text) && visible(a))
            .map(|(_, p)| p.name.as_str())
            .collect();
        let limit = limit.clamp(1, 100) as usize;
        let page: BTreeSet<&str> = names.iter().take(limit).copied().collect();
        let mut found: Vec<InstalledPackage> = self
            .inventory
            .packages
            .iter()
            .filter(|(a, p)| page.contains(p.name.as_str()) && visible(a))
            .map(|(_, p)| p.clone())
            .collect();
        found.sort_by(|a, b| (&a.name, &a.hostname).cmp(&(&b.name, &b.hostname)));
        Ok(Installed {
            names: count(page.len()),
            more_names: names.len() > page.len(),
            rows: host_rows(found, |p| &p.agent_id, limit as u32),
        })
    }
}
