//! `openvibes-admin agent …`: list, inspect, and revoke agents.

use chrono::{DateTime, Utc};
use clap::Subcommand;
use platform_store::agents::{self, AgentInfo, Filter, Revoke};

#[derive(Subcommand)]
pub enum AgentCommand {
    /// List agents (all by default).
    List {
        /// Only active agents with no heartbeat for 15 minutes.
        #[arg(long, conflicts_with = "revoked")]
        offline: bool,
        /// Only revoked agents.
        #[arg(long, conflicts_with = "imported")]
        revoked: bool,
        /// Only hosts imported from export files.
        #[arg(long, conflicts_with = "offline")]
        imported: bool,
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
}

impl AgentCommand {
    pub fn name(&self) -> &'static str {
        match self {
            Self::List { .. } => "agent list",
            Self::Show { .. } => "agent show",
            Self::Revoke { .. } => "agent revoke",
        }
    }
}

fn when(time: Option<DateTime<Utc>>) -> String {
    time.map_or_else(
        || "never".into(),
        |time| time.format("%Y-%m-%d %H:%M UTC").to_string(),
    )
}

fn line(agent: &AgentInfo) -> String {
    let claims = agent
        .claimed_agent_id
        .as_ref()
        .map_or_else(String::new, |id| format!("  claims {id}"));
    format!(
        "{}  {}  last seen {}  version {}{claims}\n",
        agent.agent_id,
        agent.status,
        when(agent.last_seen_at),
        agent.scanner_version.as_deref().unwrap_or("unknown"),
    )
}

/// Runs an agent command; returns the output and the audit target.
pub async fn run(
    command: &AgentCommand,
    client: &platform_store::Client,
) -> (Result<String, String>, Option<String>) {
    let store = |error: platform_store::StoreError| error.to_string();
    match command {
        AgentCommand::List {
            offline,
            revoked,
            imported,
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
            let listed = agents::list(client, filter, Utc::now())
                .await
                .map_err(store);
            (listed.map(|agents| agents.iter().map(line).collect()), None)
        }
        AgentCommand::Show { id } => {
            let target = Some(id.clone());
            let shown = match agents::show(client, id).await {
                Ok(Some(agent)) => Ok(format!(
                    "agent {}\nstatus {}\nenrolled {}\nrevoked {}\nlast seen {}\nversion {}\ncertificates {}\n{}",
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
    }
}
