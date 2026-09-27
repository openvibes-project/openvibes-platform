//! `openvibes-admin helper VERB …`: the root helper of the administration
//! TUI (admin TUI spec §3): `logs`, `config-read`, `config-write`. A closed
//! set of verbs, each its own function;
//! arguments are checked against the allow-lists before anything else, and
//! nothing runs unless the effective uid is 0. Operators reach it through
//! the RPM's sudoers drop-in. No shell, no paths, no free unit names.

use std::{io::Read, path::Path, process::ExitCode};

use clap::Subcommand;
use platform_host::{CONFIG_DIR, Service, Unit};

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
}

/// A verb whose arguments passed the allow-lists.
enum Verb {
    Logs(Unit, u16),
    ConfigRead(Service),
    ConfigWrite(Service),
}

fn verb(command: &HelperCommand) -> Result<Verb, &'static str> {
    let service = |name: &str| Service::parse(name).ok_or("not an OpenVIBES service");
    Ok(match command {
        HelperCommand::Logs { unit, lines } => {
            let unit = Unit::parse(unit).ok_or("not an OpenVIBES unit")?;
            match lines.parse::<u16>() {
                Ok(n @ 1..=500) => Verb::Logs(unit, n),
                _ => return Err("lines must be 1 to 500"),
            }
        }
        HelperCommand::ConfigRead { service: name } => Verb::ConfigRead(service(name)?),
        HelperCommand::ConfigWrite { service: name } => Verb::ConfigWrite(service(name)?),
    })
}

/// The effective uid, from `/proc/self/status` (no `unsafe`).
fn effective_uid() -> Option<String> {
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
        Err(reason) => return refuse(reason),
    };
    if effective_uid().as_deref() != Some("0") {
        eprintln!("openvibes-admin: helper must run as root (through sudo)");
        return ExitCode::from(1);
    }
    let dir = Path::new(CONFIG_DIR);
    match verb {
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
