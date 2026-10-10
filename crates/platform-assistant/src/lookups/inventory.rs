//! The inventory lookups (issue #241): open ports and running services
//! (`host_services`), and installed software (`software`). Notes here are
//! fixed text; model text is only compared with host data, never echoed
//! except as the validated arguments.

use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::{
    Lookup, LookupError, LookupOutput, Lookups, Source, agent_cite, args, object, required,
    text_arg, text_schema,
};
use crate::client::ToolSpec;

// Result note when a host has no port or service rows.
const NOTE_NOTHING_REPORTED: &str = "nothing reported for this host; it may not run the ports collector (see agent_summary capabilities)";

pub(super) fn specs() -> Vec<ToolSpec> {
    vec![
        ToolSpec {
            name: "host_services".into(),
            description: "Open ports and running services: what listens on a port (and its service or program) across hosts, or which ports and services one host has. Give agent, port, or both.".into(),
            parameters: object(
                json!({
                    "agent": text_schema("Agent ID or host name."),
                    "port": { "type": "integer", "minimum": 1, "maximum": 65535,
                              "description": "Port number, e.g. 22." },
                }),
                &[],
            ),
        },
        ToolSpec {
            name: "software".into(),
            description: "Installed software: is a program installed, on which hosts, which version. Matches part of the package name, e.g. chrome or openssh.".into(),
            parameters: object(
                json!({
                    "name": text_schema("Part of the package name."),
                    "agent": text_schema("Agent ID or host name."),
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
            let agent = text_arg(a.agent)?;
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
            Ok(Lookup::Software {
                name: required(a.name)?,
                agent: text_arg(a.agent)?,
            })
        }
        _ => Err(LookupError::Unknown),
    }
}

impl<S: Source> Lookups<S> {
    /// `host_services`: one host's listeners (and, without a port, its
    /// services) in one list, or every host on `port`.
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
        let Some(agent_id) = self.resolve_agent(agent).await? else {
            summary.insert("agent".into(), Value::Null);
            return Ok(LookupOutput::page(summary, Vec::new(), 0));
        };
        summary.insert("agent".into(), json!(agent_cite(&agent_id)));
        let listeners = self
            .source
            .host_listeners(&agent_id, port, items)
            .await
            .map_err(store_error)?;
        let mut total = listeners.total;
        let mut list: Vec<Value> = listeners
            .items
            .iter()
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
            .collect();
        if port.is_none() {
            let services = self
                .source
                .host_services(&agent_id, items)
                .await
                .map_err(store_error)?;
            total += services.total;
            list.extend(services.items.iter().map(|s| {
                json!({
                    "kind": "running service",
                    "service": s.unit,
                    "programs": s.programs,
                    "processes": s.processes,
                    "run_as": s.run_as,
                })
            }));
            if total == 0 {
                summary.insert("note".into(), json!(NOTE_NOTHING_REPORTED));
            }
        }
        list.truncate(items as usize);
        Ok(LookupOutput::page(summary, list, total))
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
                Some(agent_id)
            }
        };
        let rows = self
            .source
            .installed_packages(name, agent_id.as_deref(), items)
            .await
            .map_err(|_| LookupError::Store)?;
        summary.insert("hosts".into(), json!(rows.hosts));
        let packages = rows
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
        Ok(LookupOutput::page(summary, packages, rows.total))
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
    fn software_needs_a_name() {
        for bad in ["{}", r#"{"name":""}"#, r#"{"name":"x","host":"y"}"#] {
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
