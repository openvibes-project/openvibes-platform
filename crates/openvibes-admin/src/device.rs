//! `openvibes-admin device …`: routers and firewalls that send events to
//! openvibes-netlog (spec 2026-10-10-network-device-alarms §6). Database
//! work only; netlog reloads devices every 30 seconds.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use clap::Subcommand;
use platform_store::{
    alarm_suppressions::{self, Change, Suppression},
    console_read::AgentScope,
    devices::{self, Device},
};

fn parse_address(s: &str) -> Result<IpAddr, String> {
    s.parse::<IpAddr>()
        .map(|ip| ip.to_canonical())
        .map_err(|_| format!("{s} is not an IP address"))
}

#[derive(Subcommand)]
pub enum DeviceCommand {
    /// Add a device; it is accepted within 30 seconds.
    Add {
        /// Shown in the console (1 to 64 characters).
        #[arg(long)]
        name: String,
        /// The address its syslog comes from.
        #[arg(long, value_parser = parse_address)]
        address: IpAddr,
        /// Device kind.
        #[arg(long, default_value = "unifi")]
        kind: String,
    },
    /// List devices with their counters.
    List,
    /// Remove a device by id; its alarms stay.
    Remove {
        /// Device id from `device list`.
        id: i64,
    },
    /// Quiet a device alarm's rule from now on: on its device, or on every
    /// device. New matches arrive closed as false positives.
    Suppress {
        /// The alarm's id (as the console shows it).
        alarm: i64,
        /// `device` (this device) or `signature` (every device).
        #[arg(long)]
        scope: String,
        /// Why (1 to 4000 characters).
        #[arg(long)]
        note: String,
    },
    /// List active device suppressions.
    Suppressions,
    /// Remove a suppression by id; it stays as history.
    Unsuppress {
        /// Suppression id from `device suppressions`.
        id: i64,
    },
}

impl DeviceCommand {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Add { .. } => "device add",
            Self::List => "device list",
            Self::Remove { .. } => "device remove",
            Self::Suppress { .. } => "device suppress",
            Self::Suppressions => "device suppressions",
            Self::Unsuppress { .. } => "device unsuppress",
        }
    }
}

pub async fn run(
    command: &DeviceCommand,
    client: &mut platform_store::Client,
    actor: &str,
) -> (Result<String, String>, Option<String>) {
    let now = Utc::now();
    match command {
        DeviceCommand::Add {
            name,
            address,
            kind,
        } => match devices::add(client, name, kind, *address, actor, now).await {
            Ok(Ok(id)) => (
                Ok(format!(
                    "device {id} added: {name} ({address}); point its SIEM server at this host, \
                     UDP port 514\n"
                )),
                Some(id.to_string()),
            ),
            Ok(Err(error)) => (Err(error), None),
            Err(error) => (Err(error.to_string()), None),
        },
        DeviceCommand::List => match devices::list(client).await {
            Ok(list) => (Ok(render(&list, now)), None),
            Err(error) => (Err(error.to_string()), None),
        },
        DeviceCommand::Remove { id } => match devices::remove(client, *id, actor, now).await {
            Ok(true) => (Ok(format!("device {id} removed\n")), Some(id.to_string())),
            Ok(false) => (Err(format!("no device {id}")), None),
            Err(error) => (Err(error.to_string()), None),
        },
        DeviceCommand::Suppress { alarm, scope, note } => {
            match alarm_suppressions::create_for_device(client, *alarm, scope, note, actor, now)
                .await
            {
                Ok(Change::Done(s)) => (
                    Ok(format!("suppression {} created: {}\n", s.id, describe(&s))),
                    Some(s.id.to_string()),
                ),
                Ok(Change::NotFound) => (Err(format!("no device alarm {alarm}")), None),
                Ok(_) => (
                    Err("--scope is device or signature, and --note 1 to 4000 characters".into()),
                    None,
                ),
                Err(error) => (Err(error.to_string()), None),
            }
        }
        DeviceCommand::Suppressions => {
            match alarm_suppressions::list(client, &AgentScope::Global).await {
                Ok(list) => {
                    let rows: Vec<String> = list
                        .iter()
                        .filter(|s| matches!(s.scope.as_str(), "device" | "signature"))
                        .map(|s| {
                            format!(
                                "{}  {}  {}  {}\n",
                                s.id,
                                s.scope,
                                describe_target(s),
                                s.note
                            )
                        })
                        .collect();
                    (
                        Ok(if rows.is_empty() {
                            "no device suppressions\n".into()
                        } else {
                            rows.concat()
                        }),
                        None,
                    )
                }
                Err(error) => (Err(error.to_string()), None),
            }
        }
        DeviceCommand::Unsuppress { id } => {
            match alarm_suppressions::remove(client, &AgentScope::Global, *id, actor, now).await {
                Ok(Change::Done(_)) => (
                    Ok(format!("suppression {id} removed\n")),
                    Some(id.to_string()),
                ),
                Ok(_) => (Err(format!("no active suppression {id}")), None),
                Err(error) => (Err(error.to_string()), None),
            }
        }
    }
}

/// `ips.2008983  device 3` or `ips.2008983  every device`.
fn describe_target(s: &Suppression) -> String {
    match s.device_id {
        Some(device) => format!("{}  device {device}", s.rule_id),
        None => format!("{}  every device", s.rule_id),
    }
}

fn describe(s: &Suppression) -> String {
    match s.device_id {
        Some(device) => format!("{} on device {device}", s.rule_id),
        None => format!("{} on every device", s.rule_id),
    }
}

/// One line per device, then its heads-up if any.
#[must_use]
pub fn render(list: &[Device], now: DateTime<Utc>) -> String {
    if list.is_empty() {
        return "no devices\n".into();
    }
    let mut out = String::new();
    for d in list {
        let seen = d.last_seen.map_or_else(
            || "never".to_owned(),
            |t| t.format("%Y-%m-%d %H:%M UTC").to_string(),
        );
        out.push_str(&format!(
            "{}  {}  {}  {}  {}  received {} alarms {} not-cef {} unparsed {} other {} mismatch {}\n",
            d.id, d.name, d.address, d.kind, seen, d.received, d.alarms, d.not_cef, d.unparsed, d.dropped_other, d.mismatch
        ));
        if let Some(note) = devices::heads_up(d, now) {
            out.push_str(&format!("    {note}\n"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct Cli {
        #[command(subcommand)]
        command: DeviceCommand,
    }

    #[test]
    fn add_parses_and_canonicalises_a_mapped_address() {
        let cli = Cli::try_parse_from([
            "x",
            "add",
            "--name",
            "UCG Max",
            "--address",
            "::ffff:192.168.1.1",
        ])
        .unwrap();
        let DeviceCommand::Add { address, kind, .. } = cli.command else {
            panic!()
        };
        assert_eq!(
            (address.to_string().as_str(), kind.as_str()),
            ("192.168.1.1", "unifi")
        );
        assert!(Cli::try_parse_from(["x", "add", "--name", "r", "--address", "nope"]).is_err());
    }

    #[test]
    fn list_shows_counters_and_the_heads_up() {
        let now = Utc::now();
        let device = Device {
            id: 3,
            name: "UCG Max".into(),
            kind: "unifi".into(),
            address: "192.168.1.1".parse().unwrap(),
            created_at: now - Duration::minutes(30),
            last_seen: None,
            received: 0,
            alarms: 0,
            not_cef: 0,
            unparsed: 0,
            dropped_other: 0,
            mismatch: 0,
            dropped_classes: serde_json::json!({}),
        };
        let out = render(&[device], now);
        assert!(
            out.contains("3  UCG Max  192.168.1.1  unifi  never"),
            "{out}"
        );
        assert!(out.contains(platform_store::devices::NO_EVENTS), "{out}");
        assert_eq!(render(&[], now), "no devices\n");
    }
}
