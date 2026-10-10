//! `openvibes-admin device …`: routers and firewalls that send events to
//! openvibes-netlog (spec 2026-10-10-network-device-alarms §6). Database
//! work only; netlog reloads devices every 30 seconds.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use clap::Subcommand;
use platform_store::devices::{self, Device};

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
}

impl DeviceCommand {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Add { .. } => "device add",
            Self::List => "device list",
            Self::Remove { .. } => "device remove",
        }
    }
}

pub async fn run(
    command: &DeviceCommand,
    client: &platform_store::Client,
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
