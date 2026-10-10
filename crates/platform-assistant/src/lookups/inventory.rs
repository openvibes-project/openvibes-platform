//! The inventory lookups (issue #241): open ports and running services
//! (`host_services`), and installed software (`software`). Notes here are
//! fixed text; model text is only compared with host data, never echoed
//! except as the validated arguments.

use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::{
    Lookup, LookupError, LookupOutput, Lookups, Source, agent_arg, agent_cite, args, object,
    required, text_schema,
};
use crate::client::ToolSpec;

// Result notes (fixed text).
const NOTE_NEVER_REPORTED: &str = "this host has never reported ports or services: it does not run the ports collector or has not reported yet, so nothing is known about its ports";
const NOTE_PARTIAL_OWNERS: &str = "some owning services or programs were not visible to the agent";
const NOTE_TRUNCATED: &str = "the agent cut its lists to the protocol limits";
const NOTE_MORE_NAMES: &str = "more package names match; ask with a longer name";
/// Shortest `software` name: one character matches nearly every package.
const MIN_NAME: usize = 2;

pub(super) fn specs() -> Vec<ToolSpec> {
    vec![
        ToolSpec {
            name: "host_services".into(),
            description: "Open ports and running services: what listens on a port (and its service or program) across hosts, or which ports and services one host has. Give agent, port, or both.".into(),
            parameters: object(
                json!({
                    "agent": text_schema("Agent ID or host name. Omit to search every host; never put a placeholder like all or unknown here."),
                    "port": { "type": "integer", "minimum": 1, "maximum": 65535,
                              "description": "Port number, e.g. 22." },
                }),
                &[],
            ),
        },
        ToolSpec {
            name: "software".into(),
            description: "Installed software: is a program installed, on which hosts, which version.".into(),
            parameters: object(
                json!({
                    "name": text_schema("A short package name, one word, e.g. chrome or openssh, not the product's full name."),
                    "agent": text_schema("Agent ID or host name. Omit to search every host; never put a placeholder like all or unknown here."),
                }),
                &["name"],
            ),
        },
    ]
}

pub(super) fn parse(name: &str, arguments: &str) -> Result<Lookup, LookupError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Services {
        agent: Option<String>,
        port: Option<u16>,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Software {
        name: String,
        agent: Option<String>,
    }
    match name {
        "host_services" => {
            let a: Services = args(arguments)?;
            let agent = agent_arg(a.agent)?;
            if a.port == Some(0) || (agent.is_none() && a.port.is_none()) {
                return Err(LookupError::InvalidArguments);
            }
            Ok(Lookup::HostServices {
                agent,
                port: a.port,
            })
        }
        "software" => {
            let a: Software = args(arguments)?;
            let name = required(a.name)?;
            if name.chars().count() < MIN_NAME {
                return Err(LookupError::InvalidArguments);
            }
            Ok(Lookup::Software {
                name,
                agent: agent_arg(a.agent)?,
            })
        }
        _ => Err(LookupError::Unknown),
    }
}

/// How many of `items` go to listeners and services: about half each, the
/// rest to whichever has more.
fn split(items: usize, listeners: usize, services: usize) -> (usize, usize) {
    let services = services.min((items / 2).max(items.saturating_sub(listeners)));
    (listeners.min(items - services), services)
}

impl<S: Source> Lookups<S> {
    /// `host_services`: one host's listeners (and, without a port, its
    /// services) in one list with its report state, or every host on `port`.
    pub(super) async fn host_services_lookup(
        &self,
        mut summary: Map<String, Value>,
        agent: Option<&str>,
        port: Option<u16>,
        items: u32,
    ) -> Result<LookupOutput, LookupError> {
        let store_error = |_| LookupError::Store;
        let port = port.map(i32::from);
        summary.insert("port".into(), json!(port));
        let Some(agent) = agent else {
            // Parsing guarantees a port when no agent is named.
            let rows = self
                .source
                .port_listeners(port.unwrap_or_default(), items)
                .await
                .map_err(store_error)?;
            summary.insert("hosts".into(), json!(rows.hosts));
            let listeners = rows
                .items
                .iter()
                .map(|l| {
                    json!({
                        "cite": agent_cite(&l.agent_id),
                        "hostname": l.hostname,
                        "protocol": l.protocol,
                        "address": l.address.to_string(),
                        "exposed": l.exposed,
                        "service": l.service,
                        "program": l.program,
                    })
                })
                .collect();
            return Ok(LookupOutput::page(summary, listeners, rows.total));
        };
        let report = match self.resolve_agent(agent).await? {
            Some(id) => self
                .source
                .host_report(&id)
                .await
                .map_err(store_error)?
                .map(|report| (id, report)),
            None => None,
        };
        let Some((agent_id, report)) = report else {
            summary.insert("agent".into(), Value::Null);
            return Ok(LookupOutput::page(summary, Vec::new(), 0));
        };
        summary.insert("agent".into(), json!(agent_cite(&agent_id)));
        if report.status == "revoked" {
            summary.insert("state".into(), json!("revoked"));
        }
        summary.insert(
            "reported_at".into(),
            json!(report.reported_at.map(super::time)),
        );
        let mut notes = Vec::new();
        match report.reported_at {
            None => notes.push(NOTE_NEVER_REPORTED),
            Some(_) => {
                if report.owners.as_deref() == Some("partial") {
                    notes.push(NOTE_PARTIAL_OWNERS);
                }
                if report.truncated {
                    notes.push(NOTE_TRUNCATED);
                }
            }
        }
        if !notes.is_empty() {
            summary.insert("notes".into(), json!(notes));
        }
        let listeners = self
            .source
            .host_listeners(&agent_id, port, items)
            .await
            .map_err(store_error)?;
        let services = match port {
            Some(_) => None,
            None => Some(
                self.source
                    .host_services(&agent_id, items)
                    .await
                    .map_err(store_error)?,
            ),
        };
        let (services, services_total) =
            services.map_or((Vec::new(), 0), |page| (page.items, page.total));
        let (take_listeners, take_services) =
            split(items as usize, listeners.items.len(), services.len());
        let list = listeners
            .items
            .iter()
            .take(take_listeners)
            .map(|l| {
                json!({
                    "kind": "listening port",
                    "port": l.port,
                    "protocol": l.protocol,
                    "address": l.address.to_string(),
                    "exposed": l.exposed,
                    "service": l.service,
                    "program": l.program,
                })
            })
            .chain(services.iter().take(take_services).map(|s| {
                json!({
                    "kind": "running service",
                    "service": s.unit,
                    "programs": s.programs,
                    "processes": s.processes,
                    "run_as": s.run_as,
                })
            }))
            .collect();
        Ok(LookupOutput::page(
            summary,
            list,
            listeners.total + services_total,
        ))
    }

    /// `software`: installed packages matching `name`, on every host in
    /// scope or on one.
    pub(super) async fn software_lookup(
        &self,
        mut summary: Map<String, Value>,
        name: &str,
        agent: Option<&str>,
        items: u32,
    ) -> Result<LookupOutput, LookupError> {
        let agent_id = match agent {
            None => None,
            Some(agent) => {
                let Some(agent_id) = self.resolve_agent(agent).await? else {
                    summary.insert("agent".into(), Value::Null);
                    return Ok(LookupOutput::page(summary, Vec::new(), 0));
                };
                summary.insert("agent".into(), json!(agent_cite(&agent_id)));
                let report = self
                    .source
                    .host_report(&agent_id)
                    .await
                    .map_err(|_| LookupError::Store)?;
                if report.is_some_and(|r| r.status == "revoked") {
                    summary.insert("state".into(), json!("revoked"));
                }
                Some(agent_id)
            }
        };
        let found = self
            .source
            .installed_packages(name, agent_id.as_deref(), items)
            .await
            .map_err(|_| LookupError::Store)?;
        // Counts cover the package names read, not every name that matches.
        summary.insert("package_names".into(), json!(found.names));
        summary.insert("hosts_with_these_names".into(), json!(found.rows.hosts));
        if found.more_names {
            summary.insert("note".into(), json!(NOTE_MORE_NAMES));
        }
        let packages = found
            .rows
            .items
            .iter()
            .map(|p| {
                json!({
                    "cite": agent_cite(&p.agent_id),
                    "hostname": p.hostname,
                    "package": p.name,
                    "version": p.version,
                    "arch": p.arch,
                    "manager": p.manager,
                })
            })
            .collect();
        Ok(LookupOutput::page(summary, packages, found.rows.total))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_services_needs_an_agent_or_a_port() {
        assert_eq!(
            parse("host_services", "{}"),
            Err(LookupError::InvalidArguments)
        );
        assert_eq!(
            parse("host_services", r#"{"agent":" "}"#),
            Err(LookupError::InvalidArguments)
        );
        for bad in [r#"{"port":0}"#, r#"{"port":70000}"#, r#"{"port":"22"}"#] {
            assert_eq!(
                parse("host_services", bad),
                Err(LookupError::InvalidArguments),
                "{bad}"
            );
        }
        assert_eq!(
            parse("host_services", r#"{"port":22}"#),
            Ok(Lookup::HostServices {
                agent: None,
                port: Some(22)
            })
        );
        assert_eq!(
            parse("host_services", r#"{"agent":"web-01","port":443}"#),
            Ok(Lookup::HostServices {
                agent: Some("web-01".into()),
                port: Some(443)
            })
        );
    }

    #[test]
    fn placeholder_agents_mean_every_host() {
        // The calls qwen3-4b made in the #241 lab run.
        assert_eq!(
            parse("host_services", r#"{"agent":"unknown","port":22}"#),
            Ok(Lookup::HostServices {
                agent: None,
                port: Some(22)
            })
        );
        assert_eq!(
            parse("software", r#"{"name":"openssh","agent":"all"}"#),
            Ok(Lookup::Software {
                name: "openssh".into(),
                agent: None
            })
        );
        for placeholder in [" ALL HOSTS ", "Any", "*", "n/a", "everywhere", "null"] {
            let arguments = format!(r#"{{"agent":"{placeholder}","port":443}}"#);
            assert_eq!(
                parse("host_services", &arguments),
                Ok(Lookup::HostServices {
                    agent: None,
                    port: Some(443)
                }),
                "{placeholder}"
            );
        }
        // Without a port there is nothing left to ask.
        assert_eq!(
            parse("host_services", r#"{"agent":"unknown"}"#),
            Err(LookupError::InvalidArguments)
        );
        // A required agent refuses a placeholder rather than finding nothing.
        for name in ["agent_summary", "host_vulnerabilities"] {
            assert_eq!(
                Lookup::parse(name, r#"{"agent":"all"}"#),
                Err(LookupError::InvalidArguments),
                "{name}"
            );
        }
        assert!(parse("software", r#"{"name":"x1","agent":"web-01"}"#).is_ok());
    }

    #[test]
    fn items_are_split_between_listeners_and_services() {
        assert_eq!(split(10, 30, 30), (5, 5));
        assert_eq!(split(10, 2, 30), (2, 8));
        assert_eq!(split(10, 30, 2), (8, 2));
        assert_eq!(split(10, 3, 4), (3, 4));
        assert_eq!(split(1, 5, 5), (1, 0));
    }

    #[test]
    fn software_needs_a_name() {
        for bad in [
            "{}",
            r#"{"name":""}"#,
            r#"{"name":"x"}"#,
            r#"{"name":"xy","host":"y"}"#,
        ] {
            assert_eq!(
                parse("software", bad),
                Err(LookupError::InvalidArguments),
                "{bad}"
            );
        }
        assert_eq!(
            parse("software", r#"{"name":" chrome ","agent":"web-01"}"#),
            Ok(Lookup::Software {
                name: "chrome".into(),
                agent: Some("web-01".into())
            })
        );
    }
}
