//! [`Host`] on a native (RPM, systemd) install. Operators act through the
//! polkit rule (start, stop, restart of the allow-listed units) and the root
//! helper (`openvibes-admin helper logs`) the RPM installs (admin TUI §3).

use crate::{
    CERTIFICATES, Database, DiskUse, Host, HostError, PackageUpdate, Privileged, SETUP_FILE,
    Secret, Service, ServiceAction, ServiceStatus, Unit,
    journal::step_suffix,
    runner::{
        Program::{Admin, Curl, Df, Dnf, Getent, Ip, Logger, Rpm, Ss, Sudo, Systemctl},
        Runner,
    },
    stderr::{printable, without_lecture},
};

const ADMIN: &str = "/usr/bin/openvibes-admin";
const PROPERTIES: &str = "--property=Id,LoadState,ActiveState,UnitFileState,ActiveEnterTimestamp";
/// The certificate timer's service: its last run failing is said on the
/// timer (`last_run_failed`), which keeps going either way.
const RENEWAL: &str = "openvibes-certificates.service";

/// The systemd backend.
pub struct Native<R: Runner> {
    /// Runs every command.
    pub runner: R,
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
        self.journal_detail(action, target, outcome, "");
    }
    /// `journal` with `suffix` on the journal line only (not `audit note`).
    fn journal_detail(&self, action: &str, target: &str, outcome: &str, suffix: &str) {
        self.log(&format!("{action} {target} {outcome}{suffix}"));
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
        args.push(RENEWAL);
        let out = self.run(Systemctl, &args)?;
        if out.status != 0 {
            return Err(HostError::Failed(printable(&out.stderr)));
        }
        let mut services: Vec<ServiceStatus> = Vec::new();
        for block in out.stdout.split("\n\n") {
            let field = |name: &str| {
                block
                    .lines()
                    .find_map(|line| line.strip_prefix(name)?.strip_prefix('='))
                    .unwrap_or("")
            };
            let Some(unit) = Unit::parse(field("Id")) else {
                if field("Id") == RENEWAL && field("ActiveState") == "failed" {
                    let timer = services.iter_mut().find(|s| s.unit == Unit::Certificates);
                    if let Some(timer) = timer {
                        timer.last_run_failed = true;
                    }
                }
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
                last_run_failed: false,
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
        let root = effective_root();
        // Already root (started with sudo, #92): run the helper directly,
        // with no password, keeping SUDO_USER, so Setup still names the
        // person who started it (operators group, root key owner).
        // Otherwise -S: password from stdin; -k: never a cached credential;
        // -p '': no prompt text mixed into the output.
        let (program, mut argv) = if root {
            (Admin, vec![])
        } else {
            (Sudo, vec!["-S", "-k", "-p", "", ADMIN])
        };
        argv.push("helper");
        argv.extend(args.iter().map(String::as_str));
        let out = match verb.stdin((!root).then_some(password)) {
            Some(input) => self.runner.run_with_input(program, &argv, &input),
            None => self.runner.run(program, &argv),
        }
        .map_err(|error| HostError::Io(format!("{}: {error}", program.path())))?;
        // A step that ran but failed exits 0 with its state first.
        let outcome = match (out.status, out.stdout.split('\t').next()) {
            (0, Some(state @ ("failed" | "waiting" | "todo"))) => state,
            (0, _) => "ok",
            _ => "failed",
        };
        let journal = verb.journal();
        match journal.split_once(' ') {
            Some((action, target)) => {
                let suffix = step_suffix(action, target, &out.stdout);
                self.journal_detail(action, target, outcome, &suffix);
            }
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
        // Offline or failing, the list simply shows no newer versions.
        let upgrades = self.run(Dnf, &upgrades_args(effective_root()))?;
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
        self.as_admin(command.args()).map(|out| out.stdout)
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

    fn root_and_chain(&self) -> Option<(String, bool)> {
        let root = std::fs::read_to_string(crate::ROOT_CERT).ok()?;
        Some((root, chain_in_place(crate::CHAIN)))
    }

    fn own_console_cert(&self) -> Option<String> {
        std::fs::read_to_string(crate::OWN_CONSOLE_CERT).ok()
    }

    fn signer(&self) -> Option<crate::SignerFiles> {
        let trust = std::fs::read_to_string(crate::SITE_TRUST).ok();
        let status = match std::fs::read_to_string(crate::SIGNER_STATUS) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && trust.is_none() => {
                return None;
            }
            read => read
                .map_err(|error| HostError::Failed(format!("{}: {error}", crate::SIGNER_STATUS))),
        };
        Some(crate::SignerFiles { status, trust })
    }

    fn addresses(&self) -> Vec<String> {
        self.run(Ip, &crate::IP_ADDRESSES)
            .ok()
            .filter(|out| out.status == 0)
            .map(|out| crate::host_addresses(&out.stdout))
            .unwrap_or_default()
    }

    fn user_home(&self, user: &str) -> Option<String> {
        // getent asks NSS, so SSSD, FreeIPA and LDAP users are found too;
        // /etc/passwd is the fallback when getent is missing or fails.
        self.run(Getent, &["passwd", "--", user])
            .ok()
            .filter(|out| out.status == 0)
            .and_then(|out| crate::passwd_home(&out.stdout, user))
            .or_else(|| crate::passwd_home(&std::fs::read_to_string("/etc/passwd").ok()?, user))
    }

    fn shell(&self) -> Result<(), HostError> {
        crate::shell::open(&self.runner)
    }

    fn listeners(&self, port: u16) -> Result<String, HostError> {
        let filter = format!(":{port}");
        let out = self.run(Ss, &["-ltnpH", "sport", "=", &filter])?;
        if out.status != 0 {
            return Err(HostError::Failed(printable(&out.stderr)));
        }
        Ok(out.stdout)
    }

    fn free_space(&self, path: &str) -> Option<String> {
        let out = self.run(Df, &["--output=avail", "-h", "--", path]).ok()?;
        (out.status == 0)
            .then(|| out.stdout.lines().nth(1).map(|l| l.trim().to_owned()))
            .flatten()
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
        let mut args = vec!["--output=file,size,pcent,avail", "-h"];
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
                    size: fields.next()?.to_owned(),
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

/// `dnf list --upgrades`; as root, our index refreshed first like Update, or
/// a release from today reads as "up to date" (dnf caches it up to 48 h).
// ponytail: a user reads the system's cache; refreshing would need the key.
fn upgrades_args(root: bool) -> Vec<&'static str> {
    let mut args = vec!["-q", "list", "--upgrades"];
    if root {
        args.push(crate::REFRESH_OURS);
    }
    args.push("openvibes-*");
    args
}

/// Whether this process runs as root: the effective uid, the second field
/// of `Uid:` in `/proc/self/status` (no `unsafe` libc call). Unreadable
/// means not root, so the prompt is shown.
fn effective_root() -> bool {
    crate::shell::euid() == Some(0)
}

/// Whether `chain` exists, or the new one a Replace cut short by a crash
/// left beside it (Repair finishes that; the chain is not lost).
fn chain_in_place(chain: &str) -> bool {
    [chain.to_owned(), format!("{chain}.new")]
        .iter()
        .any(|path| std::path::Path::new(path).exists())
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_new_chain_left_by_a_crash_counts_as_in_place() {
        let dir = std::env::temp_dir().join(format!("ov-chain-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let chain = dir.join("chain.crt").display().to_string();
        assert!(!super::chain_in_place(&chain));
        std::fs::write(format!("{chain}.new"), "").unwrap();
        assert!(super::chain_in_place(&chain));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_package_list_refreshes_our_index_only_as_root() {
        let refresh = super::upgrades_args(true);
        assert_eq!(refresh[3], crate::REFRESH_OURS);
        assert_eq!(refresh.len(), 5);
        assert!(!super::upgrades_args(false).contains(&crate::REFRESH_OURS));
    }
}
