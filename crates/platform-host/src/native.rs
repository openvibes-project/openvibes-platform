//! [`Host`] on a native (RPM, systemd) install. Operators act through the
//! polkit rule (start, stop, restart of the allow-listed units) and the root
//! helper (`openvibes-admin helper logs`) the RPM installs (admin TUI §3).

use crate::{
    Host, HostError, ServiceAction, ServiceStatus, Unit,
    runner::{
        Program::{Curl, Logger, Sudo, Systemctl},
        Runner,
    },
};

const ADMIN: &str = "/usr/bin/openvibes-admin";
const PROPERTIES: &str = "--property=Id,LoadState,ActiveState,UnitFileState,ActiveEnterTimestamp";

/// The systemd backend.
pub struct Native<R: Runner> {
    /// Runs every command.
    pub runner: R,
}

/// Error text for a screen: trimmed, control characters escaped.
fn printable(text: &str) -> String {
    text.trim()
        .chars()
        .map(|c| {
            if c.is_control() && c != '\n' {
                c.escape_default().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// The invoking user for the journal: `$USER` as a hint, the real uid as
/// the fact (from `/proc/self/status`).
fn who() -> String {
    let user = std::env::var("USER").unwrap_or_default();
    let uid = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("Uid:"))
                .and_then(|ids| ids.split_whitespace().next().map(str::to_owned))
        })
        .unwrap_or_else(|| "unknown".into());
    format!("user={user} uid={uid}")
}

impl<R: Runner> Native<R> {
    fn run(
        &self,
        program: crate::runner::Program,
        args: &[&str],
    ) -> Result<crate::runner::Output, HostError> {
        self.runner
            .run(program, args)
            .map_err(|error| HostError::Io(format!("{}: {error}", program.path())))
    }

    // ponytail: default ports; read them from each service's config once the
    // Configuration screen (PR 2) parses configs.
    fn ready(&self, unit: Unit) -> Option<bool> {
        let url = unit.ready_url()?;
        let args = [
            "--silent",
            "--fail",
            "--max-time",
            "1",
            "--output",
            "/dev/null",
            url,
        ];
        Some(self.run(Curl, &args).is_ok_and(|out| out.status == 0))
    }
}

impl<R: Runner> Host for Native<R> {
    fn services(&self) -> Result<Vec<ServiceStatus>, HostError> {
        let mut args = vec!["show", PROPERTIES];
        args.extend(Unit::ALL.map(Unit::name));
        let out = self.run(Systemctl, &args)?;
        if out.status != 0 {
            return Err(HostError::Failed(printable(&out.stderr)));
        }
        let mut services = Vec::new();
        for block in out.stdout.split("\n\n") {
            let field = |name: &str| {
                block
                    .lines()
                    .find_map(|line| line.strip_prefix(name)?.strip_prefix('='))
                    .unwrap_or("")
            };
            let Some(unit) = Unit::parse(field("Id")) else {
                continue;
            };
            let active = field("ActiveState").to_owned();
            let since = field("ActiveEnterTimestamp");
            let running = active == "active";
            services.push(ServiceStatus {
                unit,
                installed: field("LoadState") != "not-found",
                enabled: field("UnitFileState") == "enabled",
                ready: if running { self.ready(unit) } else { None },
                since: (running && !since.is_empty()).then(|| since.to_owned()),
                active,
            });
        }
        Ok(services)
    }

    fn service_action(&self, unit: Unit, action: ServiceAction) -> Result<(), HostError> {
        let out = self.run(
            Systemctl,
            // --no-block: the job is queued and the screen stays responsive;
            // the next refresh shows how it went.
            &[
                "--no-ask-password",
                "--no-block",
                action.verb(),
                unit.name(),
            ],
        )?;
        let outcome = if out.status == 0 { "ok" } else { "failed" };
        let entry = format!("{} {} {} {outcome}", who(), action.verb(), unit.name());
        // ponytail: a journal write that fails is not reported; the action's
        // own outcome is what the operator needs to see.
        let _ = self.run(Logger, &["-t", "openvibes-admin", &entry]);
        if out.status == 0 {
            return Ok(());
        }
        if out.stderr.contains("Access denied")
            || out.stderr.contains("Interactive authentication required")
        {
            return Err(HostError::NotOperator);
        }
        Err(HostError::Failed(printable(&out.stderr)))
    }

    fn logs(&self, unit: Unit, lines: u16) -> Result<Vec<String>, HostError> {
        let count = lines.to_string();
        let out = self.run(Sudo, &["-n", ADMIN, "helper", "logs", unit.name(), &count])?;
        if out.status != 0 {
            if out.stderr.contains("password is required")
                || out.stderr.contains("is not allowed to execute")
            {
                return Err(HostError::NotOperator);
            }
            return Err(HostError::Failed(printable(&out.stderr)));
        }
        Ok(out.stdout.lines().map(printable).collect())
    }
}
