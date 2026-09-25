#![forbid(unsafe_code)]

//! `openvibes-admin`: local operator CLI. Running it with the admin database
//! role is break-glass access with full rights; every command is audited
//! with the invoking OS user, including commands that fail.

mod agent;
mod assistant;
mod ca;
mod files;
mod model;
mod rules;
mod token;
mod vulns;

use std::{path::PathBuf, process::ExitCode};

use chrono::{Duration, Utc};
use clap::{Parser, Subcommand};
use platform_store::{SCHEMA_VERSION, StoreError};
use serde::Deserialize;

/// Days of finding partitions created ahead of today.
const PARTITIONS_AHEAD: u32 = 7;

#[derive(Parser)]
#[command(name = "openvibes-admin", about = "OpenVIBES platform administration")]
struct Cli {
    /// Admin configuration file.
    #[arg(long, default_value = "/etc/openvibes/admin.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Apply pending schema migrations.
    Migrate,
    /// Summarise agents, tokens, and finding partitions.
    Status,
    /// Create upcoming finding partitions and drop expired ones.
    Maintenance {
        /// Keep findings for this many days (1 to 36500).
        #[arg(long, default_value_t = 90, value_parser = clap::value_parser!(u32).range(1..=36500))]
        retention_days: u32,
    },
    /// Built-in CA: root, intermediate, server certificates.
    Ca {
        #[command(subcommand)]
        command: ca::CaCommand,
    },
    /// Agents: list, show, revoke.
    Agent {
        #[command(subcommand)]
        command: agent::AgentCommand,
    },
    /// Enrollment tokens.
    Token {
        #[command(subcommand)]
        command: token::TokenCommand,
    },
    /// Rule sets: trusted keys and signed bundles for distribution.
    Rules {
        #[command(subcommand)]
        command: rules::RulesCommand,
    },
    /// Vulnerability feeds: import (offline) and status.
    Feeds {
        #[command(subcommand)]
        command: vulns::FeedsCommand,
    },
    /// Vulnerabilities found on hosts.
    Vulns {
        #[command(subcommand)]
        command: vulns::VulnsCommand,
    },
    /// The console's assistant: check its model backend and run the
    /// quality gate.
    Assistant {
        #[command(subcommand)]
        command: assistant::AssistantCommand,
    },
}

impl Command {
    fn name(&self) -> &'static str {
        match self {
            Self::Migrate => "migrate",
            Self::Status => "status",
            Self::Maintenance { .. } => "maintenance",
            Self::Ca { command } => command.name(),
            Self::Token { command } => command.name(),
            Self::Agent { command } => command.name(),
            Self::Rules { command } => command.name(),
            Self::Feeds { command } => command.name(),
            Self::Vulns { command } => command.name(),
            Self::Assistant { command } => command.name(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminConfig {
    database_url: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    // Offline CA commands run where no platform exists: no config, no
    // database, no audit row.
    if let Command::Ca { command } = &cli.command
        && command.is_offline()
    {
        return match ca::run_offline(command) {
            Ok(output) => {
                print!("{output}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("openvibes-admin: {error}");
                ExitCode::FAILURE
            }
        };
    }
    let config: AdminConfig = match platform_config::load(&cli.config) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("openvibes-admin: {error}");
            return ExitCode::FAILURE;
        }
    };
    let pool = match platform_store::connect(&config.database_url).await {
        Ok(pool) => pool,
        Err(error) => {
            eprintln!("openvibes-admin: {error}");
            return ExitCode::FAILURE;
        }
    };
    let mut client = match pool.get().await {
        Ok(client) => client,
        Err(_) => {
            eprintln!("openvibes-admin: {}", StoreError::Unavailable);
            return ExitCode::FAILURE;
        }
    };
    let actor = actor();
    let (result, target) = match &cli.command {
        Command::Ca { command } => match require_current_schema(&client).await {
            Ok(()) => ca::run_host(command, &client).await,
            Err(error) => (Err(error), command.target()),
        },
        Command::Token { command } => match require_current_schema(&client).await {
            Ok(()) => token::run(command, &client, &actor).await,
            Err(error) => (Err(error), None),
        },
        Command::Agent { command } => match require_current_schema(&client).await {
            Ok(()) => agent::run(command, &client).await,
            Err(error) => (Err(error), None),
        },
        Command::Rules { command } => match require_current_schema(&client).await {
            Ok(()) => rules::run(command, &mut client, &actor).await,
            Err(error) => (Err(error), None),
        },
        Command::Feeds { command } => match require_current_schema(&client).await {
            Ok(()) => vulns::run_feeds(command, &mut client).await,
            Err(error) => (Err(error), None),
        },
        Command::Vulns { command } => match require_current_schema(&client).await {
            Ok(()) => vulns::run_vulns(command, &client).await,
            Err(error) => (Err(error), None),
        },
        Command::Assistant { command } => match require_current_schema(&client).await {
            Ok(()) => assistant::run(command).await,
            Err(error) => (Err(error), None),
        },
        other => (run(other, &mut client).await, None),
    };
    let outcome = if result.is_ok() { "ok" } else { "error" };
    let audited = platform_store::audit::record(
        &client,
        &actor,
        cli.command.name(),
        target.as_deref(),
        outcome,
    )
    .await;
    match (result, audited) {
        (Ok(output), Ok(())) => {
            print!("{output}");
            ExitCode::SUCCESS
        }
        (Ok(output), Err(error)) => {
            print!("{output}");
            eprintln!("openvibes-admin: warning: audit entry not written: {error}");
            ExitCode::FAILURE
        }
        (Err(error), audited) => {
            eprintln!("openvibes-admin: {error}");
            if let Err(audit_error) = audited {
                eprintln!("openvibes-admin: warning: audit entry not written: {audit_error}");
            }
            ExitCode::FAILURE
        }
    }
}

/// The invoking OS user for the audit log: the real uid, which the caller
/// cannot choose, with `$USER` (which it can) only as a readable hint.
fn actor() -> String {
    #[cfg(unix)]
    let uid = {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata("/proc/self").map_or_else(|_| "unknown".into(), |m| m.uid().to_string())
    };
    #[cfg(not(unix))]
    let uid = String::from("unknown");
    let actor = match std::env::var("USER") {
        Ok(user) if !user.is_empty() => format!("{user} (uid {uid})"),
        _ => format!("uid {uid}"),
    };
    // Run as `sudo -u openvibes_admin`, the uid is the service account; sudo
    // names the person in SUDO_USER. Like USER it is only a readable hint
    // (the uid is the fact); sudo's own log is authoritative.
    match std::env::var("SUDO_USER") {
        Ok(person) if !person.is_empty() => {
            let person: String = person.chars().take(64).collect();
            format!("{actor} via sudo by {person}")
        }
        _ => actor,
    }
}

fn store_error(error: StoreError) -> String {
    match error {
        StoreError::NewerSchema(_) => format!("{error}; upgrade openvibes-admin"),
        other => other.to_string(),
    }
}

/// Refuses to act on a database that is not at this build's schema.
async fn require_current_schema(client: &platform_store::Client) -> Result<(), String> {
    match platform_store::schema_version(client)
        .await
        .map_err(store_error)?
    {
        Some(version) if version == SCHEMA_VERSION => Ok(()),
        Some(version) if version > SCHEMA_VERSION => {
            Err(store_error(StoreError::NewerSchema(version)))
        }
        _ => Err("schema is not current; run openvibes-admin migrate".into()),
    }
}

/// Runs one command and returns what to print.
async fn run(command: &Command, client: &mut platform_store::Client) -> Result<String, String> {
    let fail = store_error;
    if let Command::Migrate = command {
        let version = platform_store::migrate(client).await.map_err(fail)?;
        return Ok(format!("schema version {version}\n"));
    }
    require_current_schema(client).await?;
    match command {
        Command::Migrate
        | Command::Ca { .. }
        | Command::Token { .. }
        | Command::Agent { .. }
        | Command::Rules { .. }
        | Command::Feeds { .. }
        | Command::Vulns { .. }
        | Command::Assistant { .. } => {
            unreachable!("handled by the caller")
        }
        Command::Status => {
            let status = platform_store::status(client, Utc::now())
                .await
                .map_err(fail)?;
            let partitions = match (status.oldest_partition, status.newest_partition) {
                (Some(oldest), Some(newest)) => format!("{oldest}..{newest}"),
                _ => "none".into(),
            };
            Ok(format!(
                "schema version {}\nagents active {}\nagents offline {}\nagents revoked {}\n\
                 tokens usable {}\npartitions {partitions}\n",
                SCHEMA_VERSION,
                status.agents_active,
                status.agents_offline,
                status.agents_revoked,
                status.tokens_usable,
            ))
        }
        Command::Maintenance { retention_days } => {
            let today = Utc::now().date_naive();
            let cutoff = today
                .checked_sub_signed(Duration::days(i64::from(*retention_days)))
                .ok_or("retention window out of range")?;
            // Every day in the retention window gets a partition, so a late
            // or backlogged finding always has somewhere to go.
            let created = platform_store::ensure_partitions(
                client,
                cutoff,
                retention_days + PARTITIONS_AHEAD,
            )
            .await
            .map_err(fail)?;
            let dropped = platform_store::drop_partitions_before(client, cutoff)
                .await
                .map_err(fail)?;
            Ok(format!("created {created} partitions, dropped {dropped}\n"))
        }
    }
}
