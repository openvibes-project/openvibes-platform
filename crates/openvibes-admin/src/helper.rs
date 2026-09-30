//! `openvibes-admin helper VERB …`: the root helper of the administration
//! TUI (admin TUI spec §3): `logs`, `config-read`, `config-write` (through
//! the RPM's sudoers drop-in), and Setup's `setup-plan`, `setup-status`,
//! `setup-step`, `update-step`, `remove-step`, `unit-enable`,
//! `unit-disable` (only with the user's own
//! sudo rights and password). A closed set of verbs, each its own function;
//! arguments are checked against the allow-lists before anything else, and
//! nothing runs unless the effective uid is 0. Operators reach it through
//! the RPM's sudoers drop-in. No shell, no paths, no free unit names.

use std::{io::Read, path::Path, process::ExitCode};

use clap::Subcommand;
use platform_host::{CONFIG_DIR, RemoveStep, Service, Step, Unit, UpdateStep, runner::Runner};

use crate::{config_file, configs::MAX_BYTES};

#[derive(Subcommand)]
pub enum HelperCommand {
    /// The last LINES journal lines of an OpenVIBES unit.
    Logs {
        /// An allow-listed unit name, e.g. openvibes-ingest.service.
        unit: String,
        /// 1 to 500.
        lines: String,
    },
    /// Prints a service's configuration file.
    ConfigRead {
        /// ingest, distribution, vulns, console or admin.
        service: String,
    },
    /// Replaces a service's configuration file with standard input, checked
    /// as the service checks it; keeps owner, group, mode and a .bak copy.
    ConfigWrite {
        /// ingest, distribution, vulns, console or admin.
        service: String,
    },
    /// Checks Setup's arguments and writes /etc/openvibes/setup.toml.
    SetupPlan {
        #[command(flatten)]
        args: crate::setup::plan::PlanArgs,
    },
    /// Prints every Setup step's state.
    SetupStatus,
    /// Checks one Setup step and runs it unless it is done.
    SetupStep {
        /// packages, postgres, operators, database, schema, ca,
        /// certificates, console, services, firewall, rules, agent, ready.
        step: String,
        /// Repair: never makes a new CA.
        #[arg(long)]
        repair: bool,
    },
    /// Runs one Update step.
    UpdateStep {
        /// backup, stop, upgrade, migrate, start, ready.
        step: String,
        #[command(flatten)]
        args: crate::setup::update::UpdateArgs,
    },
    /// Runs one step of removing components or uninstalling.
    RemoveStep {
        /// backup, stop, firewall, packages, purge.
        step: String,
        #[command(flatten)]
        args: crate::setup::remove::RemoveArgs,
    },
    /// Starts an OpenVIBES unit at boot.
    UnitEnable { unit: String },
    /// Stops starting an OpenVIBES unit at boot.
    UnitDisable { unit: String },
}

/// A verb whose arguments passed the allow-lists.
enum Verb {
    Logs(Unit, u16),
    ConfigRead(Service),
    ConfigWrite(Service),
    SetupPlan(Box<crate::setup::plan::Plan>),
    SetupStatus,
    SetupStep(Step, bool),
    UpdateStep(UpdateStep, crate::setup::update::UpdateArgs),
    RemoveStep(RemoveStep, crate::setup::remove::RemoveArgs),
    UnitFile(Unit, bool),
}

fn verb(command: &HelperCommand) -> Result<Verb, String> {
    let service =
        |name: &str| Service::parse(name).ok_or_else(|| "not an OpenVIBES service".to_owned());
    Ok(match command {
        HelperCommand::Logs { unit, lines } => {
            let unit = Unit::parse(unit).ok_or_else(|| "not an OpenVIBES unit".to_owned())?;
            match lines.parse::<u16>() {
                Ok(n @ 1..=500) => Verb::Logs(unit, n),
                _ => return Err("lines must be 1 to 500".into()),
            }
        }
        HelperCommand::ConfigRead { service: name } => Verb::ConfigRead(service(name)?),
        HelperCommand::ConfigWrite { service: name } => Verb::ConfigWrite(service(name)?),
        HelperCommand::SetupPlan { args } => {
            // The plan's own checks; SUDO_USER is set by sudo, not the caller.
            match args.plan(crate::setup::plan::operator_from_env()) {
                Ok(plan) => Verb::SetupPlan(Box::new(plan)),
                Err(reason) => return Err(format!("invalid Setup arguments: {reason}")),
            }
        }
        HelperCommand::SetupStatus => Verb::SetupStatus,
        HelperCommand::SetupStep { step, repair } => Verb::SetupStep(
            Step::parse(step).ok_or_else(|| "not a Setup step".to_owned())?,
            *repair,
        ),
        HelperCommand::UpdateStep { step, args } => {
            args.check()?;
            Verb::UpdateStep(
                UpdateStep::parse(step).ok_or_else(|| "not an update step".to_owned())?,
                args.clone(),
            )
        }
        HelperCommand::RemoveStep { step, args } => {
            args.check()?;
            Verb::RemoveStep(
                RemoveStep::parse(step).ok_or_else(|| "not a remove step".to_owned())?,
                args.clone(),
            )
        }
        HelperCommand::UnitEnable { unit } => Verb::UnitFile(
            Unit::parse(unit).ok_or_else(|| "not an OpenVIBES unit".to_owned())?,
            true,
        ),
        HelperCommand::UnitDisable { unit } => Verb::UnitFile(
            Unit::parse(unit).ok_or_else(|| "not an OpenVIBES unit".to_owned())?,
            false,
        ),
    })
}

/// The effective uid, from `/proc/self/status` (no `unsafe`).
pub(crate) fn effective_uid() -> Option<String> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let ids = status.lines().find_map(|line| line.strip_prefix("Uid:"))?;
    ids.split_whitespace().nth(1).map(str::to_owned)
}

fn refuse(reason: &str) -> ExitCode {
    eprintln!("openvibes-admin helper: not allowed: {reason}");
    ExitCode::from(2)
}

pub fn run(command: &HelperCommand) -> ExitCode {
    let verb = match verb(command) {
        Ok(verb) => verb,
        Err(reason) => return refuse(&reason),
    };
    if effective_uid().as_deref() != Some("0") {
        eprintln!("openvibes-admin: helper must run as root (through sudo)");
        return ExitCode::from(1);
    }
    let dir = Path::new(CONFIG_DIR);
    match verb {
        Verb::SetupPlan(plan) => match crate::setup::lock(Path::new("/")).and_then(|lock| {
            // Ports the new plan leaves are closed once the run is ready (#69).
            // A 0.1.1 plan has no port fields: the ports in use, not defaults.
            if let Ok((old, _)) = crate::setup::plan::Plan::load_filled(Path::new("/")) {
                crate::setup::ports::remember_moved(Path::new("/"), &old, &plan)?;
            }
            plan.save(Path::new("/"))?;
            drop(lock);
            Ok(())
        }) {
            Ok(()) => {
                println!("{} written", platform_host::SETUP_FILE);
                ExitCode::SUCCESS
            }
            Err(error) => failed(&error),
        },
        Verb::SetupStatus => crate::setup::status(),
        Verb::SetupStep(step, repair) => crate::setup::step(step, repair),
        Verb::UpdateStep(step, args) => crate::setup::update(step, &args),
        Verb::RemoveStep(step, args) => crate::setup::remove(step, &args),
        Verb::UnitFile(unit, enable) => {
            let action = if enable { "enable" } else { "disable" };
            match platform_host::runner::SystemRunner.run(
                platform_host::runner::Program::Systemctl,
                &[action, unit.name()],
            ) {
                Ok(out) if out.status == 0 => ExitCode::SUCCESS,
                Ok(out) => failed(out.stderr.trim()),
                Err(error) => failed(&error.to_string()),
            }
        }
        Verb::Logs(unit, lines) => logs(unit, lines),
        Verb::ConfigRead(service) => match config_file::read(dir, service) {
            Ok(text) => {
                print!("{text}");
                ExitCode::SUCCESS
            }
            Err(error) => failed(&error),
        },
        Verb::ConfigWrite(service) => {
            match stdin_text().and_then(|text| config_file::replace(dir, service, &text)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => failed(&format!("not saved: {error}")),
            }
        }
    }
}

fn failed(error: &str) -> ExitCode {
    eprintln!("openvibes-admin helper: {error}");
    ExitCode::FAILURE
}

/// Standard input: at most 64 KiB of UTF-8.
fn stdin_text() -> Result<String, String> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(u64::try_from(MAX_BYTES + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("reading standard input: {error}"))?;
    if bytes.len() > MAX_BYTES {
        return Err("the file would exceed 64 KiB".into());
    }
    String::from_utf8(bytes).map_err(|_| "not UTF-8".to_owned())
}

// One of the two places the platform starts a process (clippy.toml): a fixed
// journalctl argument vector for an allow-listed unit.
#[allow(clippy::disallowed_types)]
fn logs(unit: Unit, lines: u16) -> ExitCode {
    let status = std::process::Command::new("/usr/bin/journalctl")
        .args(["-u", unit.name(), "-n", &lines.to_string()])
        .args(["-o", "short-iso", "--no-pager"])
        .status();
    match status {
        Ok(status) if status.success() => ExitCode::SUCCESS,
        Ok(_) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("openvibes-admin helper: journalctl: {error}");
            ExitCode::FAILURE
        }
    }
}
