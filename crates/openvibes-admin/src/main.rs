#![forbid(unsafe_code)]

//! `openvibes-admin`: local operator CLI. Running it with the admin database
//! role is break-glass access with full rights; every command is audited
//! with the invoking OS user, including commands that fail.

mod agent;
mod assistant;
mod assistant_setup;
mod ca;
mod config_file;
mod configs;
mod fields;
mod files;
mod helper;
mod import;
mod model;
mod model_fetch;
mod model_upgrade;
mod rules;
mod rules_sign;
mod rules_site;
#[cfg(unix)]
mod run_as;
mod setup;
mod token;
mod tui;
mod tune;
mod tune_run;
mod user;
mod vulns;

use std::{path::PathBuf, process::ExitCode};

use chrono::{Duration, Utc};
use clap::{Parser, Subcommand};
use platform_store::{SCHEMA_VERSION, StoreError};

/// Days of finding partitions created ahead of today.
const PARTITIONS_AHEAD: u32 = 7;

#[derive(Parser)]
#[command(name = "openvibes-admin", about = "OpenVIBES platform administration")]
struct Cli {
    /// Admin configuration file.
    #[arg(long, default_value = "/etc/openvibes/admin.toml")]
    config: PathBuf,
    /// Without a subcommand, the administration TUI opens.
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Apply pending schema migrations.
    Migrate {
        /// Only additive ones: stop, applying nothing, before a migration
        /// that changes stored data (the unit that runs after a package
        /// upgrade, board #77; Update backs up first and applies all).
        #[arg(long)]
        additive: bool,
    },
    /// Summarise agents, tokens, and finding partitions.
    Status,
    /// Create upcoming finding partitions and drop expired ones.
    Maintenance {
        /// Keep findings for this many days (1 to 36500).
        #[arg(long, default_value_t = 90, value_parser = clap::value_parser!(u32).range(1..=36500))]
        retention_days: u32,
        /// Keep daily count history for this many days (30 to 3650).
        #[arg(long, default_value_t = 400, value_parser = clap::value_parser!(u32).range(30..=3650))]
        history_days: u32,
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
    /// Local console accounts: create, list, disable, unlock, and reset passwords.
    User {
        #[command(subcommand)]
        command: user::UserCommand,
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
    /// Import agent export files (FindingExport, InventoryExport) as
    /// imported hosts.
    Import {
        /// Keep findings for this many days (1 to 36500); must match
        /// `maintenance --retention-days`.
        #[arg(long, default_value_t = 90, value_parser = clap::value_parser!(u32).range(1..=36500))]
        retention_days: u32,
        /// Export files, or directories whose *.json files are imported.
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
    /// Set up, repair, update or uninstall the platform on this host without
    /// screens (as root). Without an action, run openvibes-admin with no
    /// arguments for the Setup screen.
    #[command(group(clap::ArgGroup::new("action").args(["quick", "repair", "update", "uninstall"]).required(true)))]
    Setup {
        /// Install and set up (needs --components and --hostname).
        #[arg(long)]
        quick: bool,
        /// Check every step and fix what failed (never a new CA).
        #[arg(long)]
        repair: bool,
        /// Upgrade the OpenVIBES packages (the local agent too).
        #[arg(long)]
        update: bool,
        /// Remove the platform: with --keep-data or --everything.
        #[arg(long)]
        uninstall: bool,
        /// With --uninstall: keep the database, CA and configuration.
        #[arg(long, conflicts_with = "everything")]
        keep_data: bool,
        /// With --uninstall: also delete the database, CA, configuration and accounts.
        #[arg(long)]
        everything: bool,
        /// With --everything: this host's name, to confirm.
        #[arg(long)]
        confirm: Option<String>,
        /// With --update or --uninstall: write a database backup here first.
        #[arg(long)]
        backup: Option<PathBuf>,
        /// With --update: upgrade from this folder of package files.
        #[arg(long)]
        update_repo_dir: Option<PathBuf>,
        /// With --repair and --ingest-port or --distribution-port: move them
        /// although agents on other hosts keep calling the old port until
        /// their install line is run again.
        #[arg(long)]
        move_agent_ports: bool,
        #[command(flatten)]
        plan: setup::plan::PlanArgs,
    },
    /// Audit entries for the administration TUI's actions (spec §7).
    #[command(hide = true)]
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    /// Root-only verbs for the administration TUI (run through sudo).
    #[command(hide = true)]
    Helper {
        #[command(subcommand)]
        command: helper::HelperCommand,
    },
    /// The console's assistant: check its model backend and run the
    /// quality gate.
    Assistant {
        #[command(subcommand)]
        command: assistant::AssistantCommand,
    },
}

#[derive(Subcommand)]
enum AuditCommand {
    /// Record one action the TUI took, as the operator (via sudo) did it.
    Note {
        /// What was done, e.g. `restart`.
        #[arg(value_parser = short_text)]
        action: String,
        /// What it was done to, e.g. a unit name.
        #[arg(value_parser = short_text)]
        target: String,
        /// How it went.
        #[arg(value_parser = ["ok", "failed", "waiting", "todo"])]
        result: String,
    },
}

/// A printable audit field of at most 128 characters.
fn short_text(value: &str) -> Result<String, String> {
    if value.is_empty() || value.chars().count() > 128 || value.chars().any(char::is_control) {
        return Err("1 to 128 printable characters".into());
    }
    Ok(value.to_owned())
}

impl Command {
    fn name(&self) -> &'static str {
        match self {
            Self::Migrate { .. } => "migrate",
            Self::Status => "status",
            Self::Maintenance { .. } => "maintenance",
            Self::Ca { command } => command.name(),
            Self::Token { command } => command.name(),
            Self::Agent { command } => command.name(),
            Self::Rules { command } => command.name(),
            Self::User { command } => command.name(),
            Self::Feeds { command } => command.name(),
            Self::Vulns { command } => command.name(),
            Self::Import { .. } => "import",
            Self::Assistant { command } => command.name(),
            Self::Helper { .. } => "helper",
            Self::Audit { .. } => "audit note",
            Self::Setup { .. } => "setup",
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    // No subcommand: the administration TUI, which needs no config file.
    let Some(command) = &cli.command else {
        return tui::run();
    };
    // The root helper runs before any config or database access.
    if let Command::Helper { command } = command {
        return helper::run(command);
    }
    if let Command::Setup {
        quick,
        repair,
        update,
        uninstall,
        keep_data,
        everything,
        confirm,
        backup,
        update_repo_dir,
        move_agent_ports,
        plan,
    } = command
    {
        return match (*quick, *repair, *update, *uninstall) {
            (true, ..) => setup::quick(plan),
            (_, true, ..) => setup::repair_all(
                (plan.console_port, plan.ingest_port, plan.distribution_port),
                *move_agent_ports,
            ),
            (_, _, true, _) => setup::update_all(&setup::update::UpdateArgs {
                backup: backup.clone(),
                repo_dir: update_repo_dir.clone(),
            }),
            _ if !keep_data && !everything => {
                eprintln!("openvibes-admin: --uninstall needs --keep-data or --everything");
                ExitCode::from(2)
            }
            _ if *everything && confirm.is_none() => {
                eprintln!(
                    "openvibes-admin: --everything needs --confirm HOSTNAME (this host's name)"
                );
                ExitCode::from(2)
            }
            _ => setup::uninstall_all(*everything, confirm.clone(), backup.clone()),
        };
    }
    // Offline rule signing runs on the signer's machine: no config, no
    // database, no audit row.
    if let Command::Rules { command } = command
        && command.is_offline()
    {
        return match rules::run_offline(command) {
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
    // Offline CA commands run where no platform exists: no config, no
    // database, no audit row.
    if let Command::Ca { command } = command
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
    // Backend check and evaluation read only the console's configuration and
    // its owner-only API key, so they run as `openvibes-console` (or root):
    // no admin config, no database, no audit row.
    if let Command::Assistant { command } = command
        && command.is_offline()
    {
        return match assistant::run(command).await.0 {
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
    let loaded = platform_config::load::<configs::AdminConfig>(&cli.config);
    // Board #79: as the operator or root, start again as the service account.
    #[cfg(unix)]
    {
        let how = run_as::choose(
            run_as::uid().unwrap_or(u32::MAX),
            cli.config == std::path::Path::new(run_as::DEFAULT_CONFIG),
            loaded.as_ref().map(|_| ()),
        );
        if how != run_as::RunAs::Here {
            return run_as::rerun(&how);
        }
    }
    let config = match loaded {
        Ok(config) => config,
        Err(error) => {
            eprintln!("openvibes-admin: {}: {error}", cli.config.display());
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
    // The note is the audit entry; it needs no current schema (audit_log is
    // in the first migration).
    if let Command::Audit {
        command:
            AuditCommand::Note {
                action,
                target,
                result,
            },
    } = command
    {
        return match platform_store::audit::record(&client, &actor, action, Some(target), result)
            .await
        {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("openvibes-admin: {error}");
                ExitCode::FAILURE
            }
        };
    }
    let (result, target) = match command {
        Command::Ca { command } => match require_current_schema(&client).await {
            Ok(()) => ca::run_host(command, &client).await,
            Err(error) => (Err(error), command.target()),
        },
        Command::Token { command } => match require_current_schema(&client).await {
            Ok(()) => token::run(command, &client, &actor).await,
            Err(error) => (Err(error), None),
        },
        Command::Agent { command } => match require_current_schema(&client).await {
            Ok(()) => agent::run(command, &client, &actor).await,
            Err(error) => (Err(error), None),
        },
        Command::Rules { command } => match require_current_schema(&client).await {
            Ok(()) => rules::run(command, &mut client, &actor).await,
            Err(error) => (Err(error), None),
        },
        Command::User { command } => match require_current_schema(&client).await {
            Ok(()) => user::run(command, &mut client, &actor).await,
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
        Command::Import {
            retention_days,
            paths,
        } => match require_current_schema(&client).await {
            Ok(()) => import::run(paths, *retention_days, &mut client).await,
            Err(error) => (Err(error), None),
        },
        Command::Assistant { command } => match require_current_schema(&client).await {
            Ok(()) => assistant::run(command).await,
            Err(error) => (Err(error), None),
        },
        other => (run(other, &mut client).await, None),
    };
    let outcome = if result.is_ok() { "ok" } else { "error" };
    // A successful status read shows platform state, not host or finding
    // data; auditing it only buried real entries under Health's refreshes
    // (board #20). Failures and every other command stay audited.
    let audited = if result.is_ok() && STATUS_READS.contains(&command.name()) {
        Ok(())
    } else {
        platform_store::audit::record(&client, &actor, command.name(), target.as_deref(), outcome)
            .await
    };
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
    // Run as `sudo -u openvibes-admin`, the uid is the service account; sudo
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
        // Board #77: say when the pending schema change needs Update's backup.
        Some(version) => match platform_store::needs_backup_after(version) {
            Some(needs) => Err(StoreError::NeedsBackup(needs).to_string()),
            None => Err("schema is not current; run openvibes-admin migrate".into()),
        },
        None => Err("schema is not current; run openvibes-admin migrate".into()),
    }
}

/// Runs one command and returns what to print.
/// Commands whose successful runs write no audit row: status reads that
/// show no host or finding data (board #20). Data reads (`agent show`,
/// `vulns …`, `token list`, `user …`) stay audited.
const STATUS_READS: &[&str] = &[
    "status",
    "feeds status",
    "rules list",
    "rules show",
    "rules trust list",
    "agent list",
];

async fn run(command: &Command, client: &mut platform_store::Client) -> Result<String, String> {
    let fail = store_error;
    if let Command::Migrate { additive } = command {
        let version = if *additive {
            platform_store::migrate_additive(client).await
        } else {
            platform_store::migrate(client).await
        }
        .map_err(fail)?;
        // A table added by this migration (alarms, schema 29) must accept
        // rows before the daily maintenance timer next runs.
        platform_store::ensure_partitions(client, Utc::now().date_naive(), PARTITIONS_AHEAD)
            .await
            .map_err(fail)?;
        return Ok(format!("schema version {version}\n"));
    }
    require_current_schema(client).await?;
    match command {
        Command::Migrate { .. }
        | Command::Ca { .. }
        | Command::Token { .. }
        | Command::Agent { .. }
        | Command::Rules { .. }
        | Command::User { .. }
        | Command::Feeds { .. }
        | Command::Vulns { .. }
        | Command::Import { .. }
        | Command::Helper { .. }
        | Command::Audit { .. }
        | Command::Setup { .. }
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
                 imported hosts {}\ntokens usable {}\npartitions {partitions}\n\
                 partition count {}\ndatabase size {} MiB\n",
                SCHEMA_VERSION,
                status.agents_active,
                status.agents_offline,
                status.agents_revoked,
                status.imported_hosts,
                status.tokens_usable,
                status.partitions,
                status.database_bytes / (1024 * 1024),
            ))
        }
        Command::Maintenance {
            retention_days,
            history_days,
        } => {
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
            let audit_deleted = platform_store::audit::cleanup_expired_events(client, Utc::now())
                .await
                .map_err(fail)?;
            let recorded = platform_store::history::record(client, today, Utc::now())
                .await
                .map_err(fail)?;
            let history_cutoff = today
                .checked_sub_signed(Duration::days(i64::from(*history_days)))
                .ok_or("history window out of range")?;
            let pruned = platform_store::history::delete_before(client, history_cutoff)
                .await
                .map_err(fail)?;
            Ok(format!(
                "created {created} partitions, dropped {dropped}, deleted {audit_deleted} expired audit events\n\
                 recorded history for {recorded} hosts, deleted {pruned} old rows\n"
            ))
        }
    }
}
