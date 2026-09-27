//! `openvibes-admin helper VERB …`: the root helper of the administration
//! TUI (admin TUI spec §3). A closed set of verbs, each its own function;
//! arguments are checked against the allow-lists before anything else, and
//! nothing runs unless the effective uid is 0. Operators reach it through
//! the RPM's sudoers drop-in. No shell, no paths, no free unit names.

use std::process::ExitCode;

use clap::Subcommand;
use platform_host::Unit;

#[derive(Subcommand)]
pub enum HelperCommand {
    /// The last LINES journal lines of an OpenVIBES unit.
    Logs {
        /// An allow-listed unit name, e.g. openvibes-ingest.service.
        unit: String,
        /// 1 to 500.
        lines: String,
    },
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
    let HelperCommand::Logs { unit, lines } = command;
    let Some(unit) = Unit::parse(unit) else {
        return refuse("not an OpenVIBES unit");
    };
    let lines = match lines.parse::<u16>() {
        Ok(n @ 1..=500) => n,
        _ => return refuse("lines must be 1 to 500"),
    };
    if effective_uid().as_deref() != Some("0") {
        eprintln!("openvibes-admin: helper must run as root (through sudo)");
        return ExitCode::from(1);
    }
    logs(unit, lines)
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
