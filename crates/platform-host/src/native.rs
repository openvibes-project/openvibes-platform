//! [`Host`] on a native (RPM, systemd) install. Operators act through the
//! polkit rule (start, stop, restart of the allow-listed units) and the root
//! helper (`openvibes-admin helper logs`) the RPM installs (admin TUI §3).

use crate::{
    Host, HostError, Service, ServiceAction, ServiceStatus, Unit,
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

    // ponytail: packaged default ports: the configs are readable only through
    // the root helper, and a sudo call per refresh would flood the auth log.
    /// `sudo -n openvibes-admin helper ARGS…`, stdin from `input`.
    fn helper(
        &self,
        args: &[&str],
        input: Option<&[u8]>,
    ) -> Result<crate::runner::Output, HostError> {
        let mut argv = vec!["-n", ADMIN, "helper"];
        argv.extend_from_slice(args);
        let out = match input {
            Some(input) => self.runner.run_with_input(Sudo, &argv, input),
            None => self.runner.run(Sudo, &argv),
        }
        .map_err(|error| HostError::Io(format!("{}: {error}", Sudo.path())))?;
        if out.status == 0 {
            Ok(out)
        } else if out.stderr.contains("password is required")
            || out.stderr.contains("is not allowed to execute")
        {
            Err(HostError::NotOperator)
        } else {
            Err(HostError::Failed(printable(&out.stderr)))
        }
    }

    /// A journal entry for an operator action (spec §7).
    // ponytail: a journal write that fails is not reported; the action's own
    // outcome is what the operator needs to see.
    fn journal(&self, what: &str) {
        let entry = format!("{} {what}", who());
        let _ = self.run(Logger, &["-t", "openvibes-admin", &entry]);
    }

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
        self.journal(&format!("{} {} {outcome}", action.verb(), unit.name()));
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
        let out = self.helper(&["logs", unit.name(), &count], None)?;
        Ok(out.stdout.lines().map(printable).collect())
    }

    fn read_config(&self, service: Service) -> Result<String, HostError> {
        self.helper(&["config-read", service.name()], None)
            .map(|out| out.stdout)
    }

    fn write_config(&self, service: Service, toml: &str) -> Result<(), HostError> {
        let result = self.helper(&["config-write", service.name()], Some(toml.as_bytes()));
        let outcome = if result.is_ok() { "ok" } else { "failed" };
        self.journal(&format!("config-write {} {outcome}", service.name()));
        result.map(drop)
    }
}
