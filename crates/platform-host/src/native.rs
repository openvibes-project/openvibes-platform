//! [`Host`] on a native (RPM, systemd) install. Operators act through the
//! polkit rule (start, stop, restart of the allow-listed units) and the root
//! helper (`openvibes-admin helper logs`) the RPM installs (admin TUI §3).

use zeroize::Zeroizing;

use crate::{
    CERTIFICATES, Database, DiskUse, Host, HostError, PackageUpdate, Privileged, SETUP_FILE,
    Secret, Service, ServiceAction, ServiceStatus, Unit,
    runner::{
        Program::{Curl, Df, Dnf, Ip, Logger, Rpm, Ss, Sudo, Systemctl},
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

/// `stderr` without sudo's first-use lecture, which comes before whatever
/// went wrong and so stood in for it (board #75): from its first line
/// through "#3)", and the "password … will not be visible" note after it.
fn without_lecture(stderr: &str) -> String {
    let Some(start) = stderr.find("We trust you have received the usual lecture") else {
        return stderr.to_owned();
    };
    let rest = &stderr[start..];
    let end = rest
        .find("#3)")
        .and_then(|at| rest[at..].find('\n').map(|nl| at + nl + 1))
        .unwrap_or(rest.len());
    let mut after = &rest[end..];
    let note = "For security reasons, the password you type will not be visible.";
    if let Some(stripped) = after.trim_start().strip_prefix(note) {
        after = stripped;
    }
    format!("{}{}", &stderr[..start], after).trim().to_owned()
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
        operator(out)
    }

    /// `sudo -n -u openvibes-admin openvibes-admin ARGS…`: the CLI with its
    /// peer login and audit log (sudoers entry for operators).
    fn as_admin(&self, args: &[&str]) -> Result<crate::runner::Output, HostError> {
        let mut argv = vec!["-n", "-u", "openvibes-admin", ADMIN];
        argv.extend_from_slice(args);
        operator(self.run(Sudo, &argv)?)
    }

    /// A journal line (spec §7).
    // ponytail: a journal write that fails is not reported; the action's own
    // outcome is what the operator needs to see.
    fn log(&self, what: &str) {
        let entry = format!("{} {what}", who());
        let _ = self.run(Logger, &["-t", "openvibes-admin", &entry]);
    }

    /// An operator action: journalled, and recorded in `audit_log` through
    /// `audit note` when the database is reachable (spec §7).
    // ponytail: the note is best effort (no database yet during Setup, no
    // operator group before the next login); the journal line is the record.
    fn journal(&self, action: &str, target: &str, outcome: &str) {
        self.log(&format!("{action} {target} {outcome}"));
        let _ = self.as_admin(&["audit", "note", action, target, outcome]);
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
        self.journal(action.verb(), unit.name(), outcome);
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
        self.journal("config-write", service.name(), outcome);
        result.map(drop)
    }

    fn is_set_up(&self) -> bool {
        std::path::Path::new(SETUP_FILE).exists()
    }

    fn needs_password(&self) -> bool {
        !effective_root()
    }

    fn privileged(&self, verb: Privileged<'_>, password: &Secret) -> Result<String, HostError> {
        let args = verb.args();
        // -S: password from stdin; -k: never a cached credential; -p '': no
        // prompt text mixed into the output.
        let mut argv = vec!["-S", "-k", "-p", "", ADMIN, "helper"];
        argv.extend(args.iter().map(String::as_str));
        let mut input = Zeroizing::new(password.expose().as_bytes().to_vec());
        input.push(b'\n');
        let out = self
            .runner
            .run_with_input(Sudo, &argv, &input)
            .map_err(|error| HostError::Io(format!("{}: {error}", Sudo.path())))?;
        // A step that ran but failed exits 0 with its state first.
        let outcome = match (out.status, out.stdout.split('\t').next()) {
            (0, Some(state @ ("failed" | "waiting" | "todo"))) => state,
            (0, _) => "ok",
            _ => "failed",
        };
        let journal = verb.journal();
        match journal.split_once(' ') {
            Some((action, target)) => self.journal(action, target, outcome),
            // One-word verbs: `setup-status` only reads, so it is journalled
            // but not noted (the console exports audit_log); `setup-plan`
            // is noted with the file it writes.
            None => {
                self.log(&format!("{journal} {outcome}"));
                if !matches!(verb, Privileged::SetupStatus) {
                    let _ = self.as_admin(&["audit", "note", &journal, SETUP_FILE, outcome]);
                }
            }
        }
        let stderr = without_lecture(&out.stderr);
        if out.status == 0 {
            Ok(out.stdout)
        } else if stderr.contains("incorrect password") || stderr.contains("Sorry, try again") {
            Err(HostError::WrongPassword)
        } else if stderr.contains("not in the sudoers file")
            || stderr.contains("may not run sudo")
            || stderr.contains("is not allowed to run sudo")
            || stderr.contains("is not allowed to execute")
        {
            Err(HostError::NotSudoer)
        } else {
            Err(HostError::Failed(printable(&stderr)))
        }
    }
    fn packages(&self) -> Result<Vec<PackageUpdate>, HostError> {
        let out = self.run(
            Rpm,
            &[
                "-qa",
                "--qf",
                "%{NAME} %{VERSION}-%{RELEASE}\n",
                "openvibes-*",
            ],
        )?;
        if out.status != 0 {
            return Err(HostError::Failed(printable(&out.stderr)));
        }
        let mut packages: Vec<PackageUpdate> = out
            .stdout
            .lines()
            .filter_map(|line| {
                let (name, version) = line.split_once(' ')?;
                (!name.ends_with("-debuginfo") && !name.ends_with("-debugsource")).then(|| {
                    PackageUpdate {
                        name: name.into(),
                        installed: version.into(),
                        available: None,
                    }
                })
            })
            .collect();
        packages.sort_by(|a, b| a.name.cmp(&b.name));
        // ponytail: dnf as the user reads its own metadata cache; offline or
        // failing, the list simply shows no newer versions.
        let upgrades = self.run(Dnf, &["-q", "list", "--upgrades", "openvibes-*"])?;
        if upgrades.status == 0 {
            for line in upgrades.stdout.lines() {
                let fields: Vec<&str> = line.split_whitespace().collect();
                let [full, version, _repo] = fields[..] else {
                    continue;
                };
                let name = full.rsplit_once('.').map_or(full, |(name, _arch)| name);
                if let Some(package) = packages.iter_mut().find(|p| p.name == name) {
                    package.available = Some(version.to_owned());
                }
            }
        }
        Ok(packages)
    }

    fn setup_plan(&self) -> Result<String, HostError> {
        std::fs::read_to_string(SETUP_FILE)
            .map_err(|error| HostError::Failed(format!("{SETUP_FILE}: {error}")))
    }

    fn database(&self, command: Database) -> Result<String, HostError> {
        let result = self.as_admin(command.args());
        // The CLI writes its own audit_log row; the journal gets the change.
        if matches!(command, Database::Migrate | Database::Maintenance) {
            let outcome = if result.is_ok() { "ok" } else { "failed" };
            self.log(&format!("{} {outcome}", command.args().join(" ")));
        }
        result.map(|out| out.stdout)
    }

    fn certificates(&self) -> Vec<(&'static str, Result<String, HostError>)> {
        CERTIFICATES
            .into_iter()
            .filter_map(|path| match std::fs::read_to_string(path) {
                Ok(pem) => Some((path, Ok(pem))),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => Some((path, Err(HostError::Failed(format!("{path}: {error}"))))),
            })
            .collect()
    }

    fn addresses(&self) -> Vec<String> {
        self.run(Ip, &crate::IP_ADDRESSES)
            .ok()
            .filter(|out| out.status == 0)
            .map(|out| crate::host_addresses(&out.stdout))
            .unwrap_or_default()
    }

    fn listeners(&self, port: u16) -> Result<String, HostError> {
        let filter = format!(":{port}");
        let out = self.run(Ss, &["-ltnpH", "sport", "=", &filter])?;
        if out.status != 0 {
            return Err(HostError::Failed(printable(&out.stderr)));
        }
        Ok(out.stdout)
    }

    fn disk(&self) -> Result<Vec<DiskUse>, HostError> {
        let mut paths = vec!["/var/lib/pgsql".to_owned()];
        if let Ok(entries) = std::fs::read_dir("/var/lib") {
            let mut ours: Vec<String> = entries
                .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
                .filter(|name| name.starts_with("openvibes-"))
                .map(|name| format!("/var/lib/{name}"))
                .collect();
            ours.sort();
            paths.extend(ours);
        }
        paths.retain(|path| std::path::Path::new(path).exists());
        self.df(&paths)
    }
}

impl<R: Runner> Native<R> {
    /// `df` for `paths` (the argument is the row's name, so no mount point
    /// needs reading).
    pub fn df(&self, paths: &[String]) -> Result<Vec<DiskUse>, HostError> {
        if paths.is_empty() {
            return Ok(Vec::new());
        }
        let mut args = vec!["--output=file,pcent,avail", "-h"];
        args.extend(paths.iter().map(String::as_str));
        let out = self.run(Df, &args)?;
        if out.status != 0 {
            return Err(HostError::Failed(printable(&out.stderr)));
        }
        Ok(out
            .stdout
            .lines()
            .skip(1)
            .filter_map(|line| {
                let mut fields = line.split_whitespace();
                Some(DiskUse {
                    path: fields.next()?.to_owned(),
                    used_percent: fields.next()?.trim_end_matches('%').parse().ok()?,
                    available: fields.next()?.to_owned(),
                })
            })
            .collect())
    }
}

/// sudo's outcome: refusal means the user is not an operator.
fn operator(out: crate::runner::Output) -> Result<crate::runner::Output, HostError> {
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

/// Whether this process runs as root: the effective uid, the second field
/// of `Uid:` in `/proc/self/status` (no `unsafe` libc call). Unreadable
/// means not root, so the prompt is shown.
fn effective_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("Uid:"))
                .and_then(|ids| ids.split_whitespace().nth(1))
                .map(|euid| euid == "0")
        })
        .unwrap_or(false)
}
