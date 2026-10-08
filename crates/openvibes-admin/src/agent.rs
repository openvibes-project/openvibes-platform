//! `openvibes-admin agent …`: list, inspect, and revoke agents.

use chrono::{DateTime, Utc};
use clap::Subcommand;
use platform_store::{
    agents::{self, AgentInfo, Filter, Revoke},
    alarms_status::AlarmsStatus,
    health::HealthStatus,
};

fn health_arg(value: &str) -> Result<HealthStatus, String> {
    HealthStatus::parse(value)
        .ok_or_else(|| "one of: healthy, degraded, offline, unknown".to_owned())
}

#[derive(Subcommand)]
pub enum AgentCommand {
    /// List agents (all by default).
    List {
        /// Only active agents with no heartbeat for 3 minutes.
        #[arg(long, conflicts_with = "revoked")]
        offline: bool,
        /// Only revoked agents.
        #[arg(long, conflicts_with = "imported")]
        revoked: bool,
        /// Only hosts imported from export files.
        #[arg(long, conflicts_with = "offline")]
        imported: bool,
        /// Only active agents with this health (protocol P12): healthy,
        /// degraded, offline, unknown.
        #[arg(long, value_parser = health_arg, conflicts_with_all = ["revoked", "imported"])]
        health: Option<HealthStatus>,
    },
    /// Show one agent.
    Show {
        /// Agent id.
        id: String,
    },
    /// Revoke an agent; its next request gets `identity_revoked`.
    Revoke {
        /// Agent id.
        id: String,
    },
    /// Print the one-line command that installs and enrolls an agent on
    /// another host, with the standing token.
    Command {
        /// This platform's name as agents reach it (default: Setup's hostname).
        #[arg(long)]
        platform: Option<String>,
        /// The root certificate agents will trust.
        #[arg(long, default_value = "/etc/openvibes/pki/root.crt")]
        root_cert: std::path::PathBuf,
    },
}

impl AgentCommand {
    pub fn name(&self) -> &'static str {
        match self {
            Self::List { .. } => "agent list",
            Self::Show { .. } => "agent show",
            Self::Revoke { .. } => "agent revoke",
            Self::Command { .. } => "agent command",
        }
    }
}

fn when(time: Option<DateTime<Utc>>) -> String {
    time.map_or_else(
        || "never".into(),
        |time| time.format("%Y-%m-%d %H:%M UTC").to_string(),
    )
}

/// `health <status>[ (<reason>, …)]` for an active agent.
fn health_text(agent: &AgentInfo, now: DateTime<Utc>) -> Option<String> {
    let (status, reasons) = agent.health_status(now)?;
    Some(if reasons.is_empty() {
        format!("health {}", status.as_str())
    } else {
        format!("health {} ({})", status.as_str(), reasons.join(", "))
    })
}

fn line(agent: &AgentInfo, now: DateTime<Utc>) -> String {
    let claims = agent
        .claimed_agent_id
        .as_ref()
        .map_or_else(String::new, |id| format!("  claims {id}"));
    let health = health_text(agent, now).map_or_else(String::new, |text| format!("  {text}"));
    format!(
        "{}  {}  last seen {}  version {}{claims}{health}\n",
        agent.agent_id,
        agent.status,
        when(agent.last_seen_at),
        agent.scanner_version.as_deref().unwrap_or("unknown"),
    )
}

fn when_ms(unix_ms: i64) -> String {
    when(DateTime::from_timestamp_millis(unix_ms))
}

/// The report's lines for `agent show`; lines without data are left out.
fn health_lines(agent: &AgentInfo, now: DateTime<Utc>) -> String {
    let mut out = String::new();
    let Some((status, reasons)) = agent.health_status(now) else {
        return out;
    };
    out.push_str(&format!("health {}\n", status.as_str()));
    if !reasons.is_empty() {
        out.push_str(&format!("reasons {}\n", reasons.join(", ")));
    }
    let Some(health) = &agent.health else {
        return out;
    };
    let queue = &health.queue;
    let rejected: Vec<String> = queue
        .rejected_total
        .iter()
        .map(|(reason, n)| format!("{}={n}", reason.as_str()))
        .collect();
    out.push_str(&format!(
        "queue {} pending, oldest {} s, {} dropped{}\n",
        queue.pending,
        queue.oldest_pending_age_s.unwrap_or(0),
        queue.dropped_total,
        if rejected.is_empty() {
            String::new()
        } else {
            format!(", rejected {}", rejected.join(" "))
        },
    ));
    if let Some(scan) = &health.last_scan {
        out.push_str(&format!(
            "last scan {}, {} rules ({} unavailable, {} failed)\n",
            when_ms(scan.finished_at_unix_ms),
            scan.rules_evaluated,
            scan.rules_unavailable,
            scan.rules_failed,
        ));
        let collectors: Vec<String> = scan
            .collectors
            .iter()
            .map(|(name, outcome)| {
                let outcome = serde_json::to_value(outcome)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_default();
                format!("{}={outcome}", name.as_str())
            })
            .collect();
        if !collectors.is_empty() {
            out.push_str(&format!("collectors {}\n", collectors.join(" ")));
        }
    }
    for set in &health.rule_sets {
        let refused = set
            .refused
            .and_then(|r| serde_json::to_value(r).ok())
            .and_then(|v| v.as_str().map(|s| format!(" refused {s}")))
            .unwrap_or_default();
        out.push_str(&format!(
            "rule set {} version {} expires {}{refused}\n",
            set.id.as_str(),
            set.version
                .map_or_else(|| "none".to_owned(), |v| v.to_string()),
            set.expires_at_unix_ms
                .map_or_else(|| "never".to_owned(), when_ms),
        ));
    }
    let alarms = serde_json::to_value(&health.alarms).ok();
    match platform_store::alarms_status::alarms_status(true, alarms.as_ref()) {
        Some(AlarmsStatus::On { source }) => out.push_str(&format!(
            "alarms on ({})\n",
            if source == "ebpf" { "eBPF" } else { "audit" }
        )),
        Some(AlarmsStatus::Off { text, fix, .. }) => {
            out.push_str(&format!("alarms off: {text}; fix: {fix}\n"));
        }
        None => {}
    }
    out.push_str(&format!("storage errors {}\n", health.storage_errors));
    if let Some(jump) = health.clock_jump_s {
        out.push_str(&format!("clock jump {jump} s\n"));
    }
    out.push_str(&format!("health report {}\n", when(agent.health_at)));
    out
}

/// Runs an agent command; returns the output and the audit target.
pub async fn run(
    command: &AgentCommand,
    client: &platform_store::Client,
    actor: &str,
) -> (Result<String, String>, Option<String>) {
    let store = |error: platform_store::StoreError| error.to_string();
    match command {
        AgentCommand::List {
            offline,
            revoked,
            imported,
            health,
        } => {
            let filter = if *offline {
                Filter::Offline
            } else if *revoked {
                Filter::Revoked
            } else if *imported {
                Filter::Imported
            } else {
                Filter::All
            };
            let now = Utc::now();
            let listed = agents::list(client, filter, now).await.map_err(store);
            let wanted = |agent: &&AgentInfo| {
                health.is_none_or(|wanted| {
                    agent
                        .health_status(now)
                        .is_some_and(|(status, _)| status == wanted)
                })
            };
            (
                listed.map(|agents| {
                    agents
                        .iter()
                        .filter(wanted)
                        .map(|agent| line(agent, now))
                        .collect()
                }),
                None,
            )
        }
        AgentCommand::Show { id } => {
            let target = Some(id.clone());
            let shown = match agents::show(client, id).await {
                Ok(Some(agent)) => Ok(format!(
                    "agent {}\nstatus {}\nenrolled {}\nrevoked {}\nlast seen {}\nversion {}\ncertificates {}\n{}{}",
                    agent.agent_id,
                    agent.status,
                    when(Some(agent.enrolled_at)),
                    when(agent.revoked_at),
                    when(agent.last_seen_at),
                    agent.scanner_version.as_deref().unwrap_or("unknown"),
                    agent.certificates,
                    agent
                        .claimed_agent_id
                        .as_ref()
                        .map_or_else(String::new, |id| format!("claims {id}\n")),
                    health_lines(&agent, Utc::now()),
                )),
                Ok(None) => Err("unknown agent".into()),
                Err(error) => Err(store(error)),
            };
            (shown, target)
        }
        AgentCommand::Revoke { id } => {
            let target = Some(id.clone());
            let revoked = match agents::revoke(client, id, Utc::now()).await {
                Ok(Revoke::Revoked) => Ok(format!("revoked {id}\n")),
                Ok(Revoke::AlreadyRevoked) => Err("agent already revoked".into()),
                Ok(Revoke::Unknown) => Err("unknown agent".into()),
                Ok(Revoke::Imported) => Err("imported hosts have no identity to revoke".into()),
                Err(error) => Err(store(error)),
            };
            (revoked, target)
        }
        AgentCommand::Command {
            platform,
            root_cert,
        } => agent_command(platform.as_deref(), root_cert, client, actor).await,
    }
}

/// What the platform serves for `set`: its current, non-retired bundle's
/// issuer and that issuer's active trusted key.
async fn served(client: &platform_store::Client, set: &str) -> Option<crate::setup::Served> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use platform_store::rules;
    rules::list(client).await.ok()?.into_iter().find(|row| {
        row.rule_set_id == set && row.current_version.is_some() && row.retired_at.is_none()
    })?;
    let issuer = rules::bundles(client, set)
        .await
        .ok()?
        .into_iter()
        .next()?
        .issuer_key_id;
    let (key, _) = rules::active_trust_keys(client, set)
        .await
        .ok()?
        .into_iter()
        .find(|(_, id)| *id == issuer)?;
    Some(crate::setup::Served {
        set: set.to_owned(),
        issuer,
        key: URL_SAFE_NO_PAD.encode(key),
    })
}

/// `agent command`: the standing token and the install line around it.
async fn agent_command(
    platform: Option<&str>,
    root_cert: &std::path::Path,
    client: &platform_store::Client,
    actor: &str,
) -> (Result<String, String>, Option<String>) {
    // The plan's ports (defaults without a plan) travel with the line.
    let plan = crate::setup::plan::Plan::load(std::path::Path::new("/")).ok();
    let ports = plan.as_ref().map_or(
        (
            crate::setup::ports::INGEST_DEFAULT,
            crate::setup::ports::DISTRIBUTION_DEFAULT,
        ),
        |plan| (plan.ingest_port, plan.distribution_port),
    );
    let platform = match (platform, plan) {
        (Some(name), _) => name.to_owned(),
        (None, Some(plan)) => plan.hostname,
        (None, None) => {
            return (
                Err("--platform is required (no Setup plan on this host)".into()),
                None,
            );
        }
    };
    if platform.parse::<std::net::IpAddr>().is_err()
        && let Err(error) = crate::setup::plan::check_name(&platform)
    {
        return (Err(format!("--platform: {error}")), None);
    }
    let fingerprint = match std::fs::read_to_string(root_cert)
        .map_err(|error| format!("{}: {error}", root_cert.display()))
        .and_then(|pem| crate::setup::fingerprint(&pem))
    {
        Ok(fingerprint) => fingerprint,
        Err(error) => return (Err(error), None),
    };
    let (created, target) = match crate::token::fleet(client, actor).await {
        Ok((id, token, _)) => (Ok(format!("token {token}\n")), Some(id)),
        Err(error) => (Err(error), None),
    };
    let key_line = std::fs::read_to_string(crate::setup::BASELINE_KEY).ok();
    let set = key_line
        .as_deref()
        .and_then(|line| line.split_whitespace().next())
        .unwrap_or("baseline");
    let baseline_served: Vec<crate::setup::Served> =
        served(client, set).await.into_iter().collect();
    let rules = key_line
        .as_deref()
        .and_then(|line| crate::setup::published_rules_arg(line, &baseline_served));
    let alarm_line = std::fs::read_to_string(crate::setup::ALARMS_KEY).ok();
    let alarm_rules = match alarm_line.as_deref() {
        Some(line) => {
            let set = line.split_whitespace().next().unwrap_or("baseline-alarms");
            let alarm_served: Vec<crate::setup::Served> =
                served(client, set).await.into_iter().collect();
            crate::setup::published_rules_arg(line, &alarm_served)
        }
        None => None,
    };
    // The site's own rules (board #107): installers don't take them yet,
    // so the lines to paste, for agents that fetch rules (--rules).
    let site = std::fs::read_to_string(crate::setup::SITE_KEY)
        .ok()
        .and_then(|trust| crate::setup::site_rules_block(&trust))
        .filter(|_| rules.is_some())
        .map(|block| {
            format!(
                "\nYour own rules: add these lines to /etc/openvibes-agent/agent.toml on each agent \
                 installed with the line above (and on older agents with --rules), then restart \
                 openvibes-agent. The agent restricts both sets.\n\n{block}\n\
                 After the signer is reinstalled its key is new: replace these lines on every agent, \
                 or it refuses the site rules.\n"
            )
        })
        .unwrap_or_default();
    let output = created.and_then(|out| crate::setup::token_from(&out)).map(|token| {
        format!(
            "{}\nthe standing token never expires and has no use limit (revoke it with `openvibes-admin token revoke` to replace it; enrolled agents keep working); it is visible in the host's process list while the command runs\n{site}",
            crate::setup::agent_install_command(&platform, ports, &token, &fingerprint, rules.as_deref(), alarm_rules.as_deref())
        )
    });
    (output, target)
}
