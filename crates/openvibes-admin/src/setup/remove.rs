//! Removing components (keep data) and Remove everything (admin TUI spec
//! §6.5). `openvibes-admin` itself is removed by the last step, `admin`:
//! the running helper keeps its file open until it exits.

use std::{fs, path::PathBuf};

use platform_host::{
    RemoveStep, StepState,
    runner::{
        Program::{Dnf, FirewallCmd, Groupdel, Rpm, Systemctl, Userdel},
        Runner,
    },
};

use super::{
    Ctx, backup,
    plan::{Component, check_name},
    run::ports_for,
};

#[derive(clap::Args, Clone, Debug, Default)]
pub struct RemoveArgs {
    /// The components to remove.
    #[arg(long, value_delimiter = ',', value_enum)]
    pub components: Vec<Component>,
    /// Write a database backup here first (a new file).
    #[arg(long)]
    pub backup: Option<PathBuf>,
    /// This host's name, typed to confirm Remove everything.
    #[arg(long)]
    pub confirm: Option<String>,
    /// Record in backup.toml whether this run backs up first (the TUI's
    /// Back up first, remembered for next time).
    #[arg(long)]
    pub remember_choice: bool,
}

impl RemoveArgs {
    pub fn check(&self) -> Result<(), String> {
        if self.components.is_empty() {
            return Err("--components is required".into());
        }
        if let Some(path) = &self.backup {
            backup::check_path(path)?;
        }
        if let Some(name) = &self.confirm {
            check_name(name)?;
        }
        Ok(())
    }
}

/// Data directories Remove everything deletes (fixed; never from input).
const DATA: [&str; 10] = [
    "/etc/openvibes",
    "/etc/openvibes-agent",
    "/var/lib/openvibes-admin",
    "/var/lib/openvibes-ingest",
    "/var/lib/openvibes-distribution",
    "/var/lib/openvibes-vulns",
    "/var/lib/openvibes-console",
    "/var/lib/openvibes-llm",
    "/var/lib/openvibes-agent",
    // The site rule-signing key and version state (own rules).
    "/var/lib/openvibes-signer",
];
/// Service accounts (user and group of the same name) it deletes.
const ACCOUNTS: [&str; 10] = [
    "openvibes-ingest",
    "openvibes-netlog",
    "openvibes-distribution",
    "openvibes-vulns",
    "openvibes-console",
    "openvibes-llm",
    "openvibes-signer",
    "openvibes-fetch",
    "openvibes_agent",
    "openvibes-admin",
];

fn installed<R: Runner>(ctx: &Ctx<R>, package: &str) -> bool {
    ctx.succeeds(Rpm, &["-q", "--quiet", package])
}

fn packages<R: Runner>(ctx: &Ctx<R>, args: &RemoveArgs) -> Vec<&'static str> {
    args.components
        .iter()
        .flat_map(|c| c.packages())
        .copied()
        .filter(|package| *package != "openvibes-admin" && installed(ctx, package))
        .collect()
}

fn stop<R: Runner>(ctx: &Ctx<R>, args: &RemoveArgs) -> Result<StepState, String> {
    let mut units: Vec<&str> = Vec::new();
    for component in &args.components {
        if component
            .packages()
            .iter()
            .any(|package| installed(ctx, package))
        {
            units.extend(component.units().iter().map(|unit| unit.name()));
            if *component == Component::Agent {
                units.push("openvibes-agent.service");
            }
            if *component == Component::Console && installed(ctx, "openvibes-fetch") {
                units.push("openvibes-fetch.socket");
            }
            if *component == Component::Assistant {
                units.extend([
                    "openvibes-llm.socket",
                    "openvibes-llm-proxy.service",
                    "openvibes-llm.service",
                ]);
            }
        }
    }
    if units.is_empty() {
        return Ok(StepState::Skipped("nothing installed to stop".into()));
    }
    let mut argv = vec!["disable", "--now"];
    argv.extend(&units);
    ctx.ok(Systemctl, &argv)?;
    Ok(StepState::Done(format!(
        "stopped and disabled: {}",
        units.join(" ")
    )))
}

fn firewall<R: Runner>(ctx: &Ctx<R>, args: &RemoveArgs) -> Result<StepState, String> {
    if !ctx.succeeds(FirewallCmd, &["--state"]) {
        return Ok(StepState::Skipped("firewalld is not running".into()));
    }
    // The console's port is read from its config, which may be gone already.
    let ports = ports_for(ctx, &args.components).unwrap_or_default();
    let open: Vec<&String> = ports
        .iter()
        .filter(|port| ctx.succeeds(FirewallCmd, &["--permanent", "--query-port", port]))
        .collect();
    for port in &open {
        ctx.ok(FirewallCmd, &["--permanent", "--remove-port", port])?;
    }
    ctx.ok(FirewallCmd, &["--reload"])?;
    let closed: Vec<&str> = open.iter().map(|port| port.as_str()).collect();
    Ok(StepState::Done(format!("closed: {}", closed.join(" "))))
}

fn remove_packages<R: Runner>(ctx: &Ctx<R>, args: &RemoveArgs) -> Result<StepState, String> {
    let packages = packages(ctx, args);
    if !packages.is_empty() {
        let mut argv = vec!["remove", "-y"];
        argv.extend(&packages);
        ctx.ok(Dnf, &argv)?;
    }
    Ok(StepState::Done(format!("removed: {}", packages.join(" "))))
}

fn purge<R: Runner>(ctx: &Ctx<R>, args: &RemoveArgs) -> Result<StepState, String> {
    let Some(confirm) = &args.confirm else {
        return Ok(StepState::Skipped("data kept".into()));
    };
    if *confirm != ctx.plan.hostname {
        return Err(format!(
            "the typed name does not match this host's name ({}); nothing removed",
            ctx.plan.hostname
        ));
    }
    if !ctx
        .plan
        .components
        .iter()
        .all(|c| args.components.contains(c))
    {
        return Err("Remove everything applies to the whole platform: list every component".into());
    }
    let roles = ctx.as_postgres(&[
        "/usr/bin/psql",
        "-Atqc",
        "SELECT rolname FROM pg_roles WHERE rolname LIKE 'openvibes-%' ORDER BY oid",
    ])?;
    ctx.as_postgres(&["/usr/bin/dropdb", "--if-exists", "openvibes"])?;
    for role in roles.lines().map(str::trim).filter(|r| {
        r.starts_with("openvibes-") && r.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
    }) {
        ctx.as_postgres(&["/usr/bin/dropuser", "--if-exists", role])?;
    }
    // #82: the admin package is removed last (this tool is part of it), so
    // its configuration file stays for rpm: deleting it here made `dnf
    // remove` warn, and a reinstall in between left it missing. The last
    // step removes what rpm kept.
    let kept = if installed(ctx, "openvibes-admin") {
        ctx.stdout(Rpm, &["-qc", "openvibes-admin"])?
    } else {
        String::new()
    };
    let mut kept: Vec<&str> = kept.lines().map(str::trim).collect();
    // The plan stays until the last step: every step loads it, so a retry
    // after a failure (or the `admin` step) still finds it.
    kept.push("/etc/openvibes/setup.toml");
    let site_key = ctx.exists("/var/lib/openvibes-signer/site.key");
    for dir in DATA {
        let path = ctx.path(dir);
        if !path.exists() {
            continue;
        }
        let fail = |error: std::io::Error| format!("{dir}: {error}");
        // One level only: kept files sit directly in the directory (today
        // just /etc/openvibes/admin.toml); a subdirectory goes whole.
        if kept.iter().any(|file| file.starts_with(&format!("{dir}/"))) {
            for entry in fs::read_dir(&path).map_err(fail)? {
                let entry = entry.map_err(fail)?;
                let name = format!("{dir}/{}", entry.file_name().to_string_lossy());
                if kept.contains(&name.as_str()) {
                    continue;
                }
                if entry.file_type().map_err(fail)?.is_dir() {
                    fs::remove_dir_all(entry.path()).map_err(fail)?;
                } else {
                    fs::remove_file(entry.path()).map_err(fail)?;
                }
            }
        } else {
            fs::remove_dir_all(&path).map_err(fail)?;
        }
    }
    let passwd = ctx.read("/etc/passwd")?;
    for account in ACCOUNTS {
        if passwd
            .lines()
            .any(|line| line.starts_with(&format!("{account}:")))
        {
            ctx.ok(Userdel, &[account])?;
        }
    }
    let groups = ctx.read("/etc/group")?;
    for group in ACCOUNTS
        .iter()
        .chain(&["openvibes-operators", "openvibes-signer-clients"])
    {
        if groups
            .lines()
            .any(|line| line.starts_with(&format!("{group}:")))
        {
            // userdel already removed a user's own group on most hosts.
            let _ = ctx.ok(Groupdel, &[group]);
        }
    }
    // A reinstalled signer makes a new site key (lead, #2086).
    let site_key = if site_key {
        "; the site rule key is gone: after a reinstall, agents need the new key's lines from `agent command`"
    } else {
        ""
    };
    Ok(StepState::Done(format!(
        "database, roles, configuration, data and service accounts removed; PostgreSQL itself stays installed{site_key}"
    )))
}

/// The package repository install.sh writes, and the signing key file it
/// installs next to it (removed once no OpenVIBES package is left).
const REPO_DIR: &str = "/etc/yum.repos.d";
const KEY_FILE: &str = "/etc/pki/rpm-gpg/RPM-GPG-KEY-openvibes";
/// The OpenVIBES packages key in rpm's database (`gpg-pubkey-<id>-<time>`;
/// the id is the last eight hex digits of fingerprint 710AD8AF…7786DA36,
/// see packaging/rpm/openvibes-packages.gpg). Never another key.
const KEY_ID: &str = "gpg-pubkey-7786da36-";
/// dnf's per-repository caches (`<repo id>-<16 hex digits>`).
const CACHES: [&str; 2] = ["/var/cache/libdnf5", "/var/cache/dnf"];

fn remove_path(path: &std::path::Path) -> Result<(), String> {
    let result = if path.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    };
    match result {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            Err(format!("{}: {error}", path.display()))
        }
        _ => Ok(()),
    }
}

/// Removes every entry of `dir` whose name `ours` accepts; their names.
fn remove_matching<R: Runner>(
    ctx: &Ctx<R>,
    dir: &str,
    ours: impl Fn(&str) -> bool,
) -> Result<Vec<String>, String> {
    let Ok(entries) = fs::read_dir(ctx.path(dir)) else {
        return Ok(Vec::new());
    };
    let mut gone = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if ours(&name) {
            remove_path(&entry.path())?;
            gone.push(format!("{dir}/{name}"));
        }
    }
    Ok(gone)
}

/// `/etc/openvibes` last-file-last: `setup.toml` (the plan every step
/// loads) goes after everything else, so a failure half way leaves a host
/// the next run can still load.
fn remove_config_dir<R: Runner>(ctx: &Ctx<R>) -> Result<(), String> {
    let dir = ctx.path("/etc/openvibes");
    let Ok(entries) = fs::read_dir(&dir) else {
        return Ok(());
    };
    for entry in entries.flatten() {
        if entry.file_name() != "setup.toml" {
            remove_path(&entry.path())?;
        }
    }
    remove_path(&dir)
}

/// Last: the administration tool itself (this helper is part of it; the
/// running process keeps its file until it exits), what rpm kept of it,
/// its state, and the package repository, its signing key and caches once
/// no OpenVIBES package is left. Only for the whole platform: removing one
/// part leaves the tool. With `--everything` (a confirmation) nothing may
/// stay; without it the configuration and data are kept and listed.
/// Safe to repeat: every part first checks whether it is still there.
fn remove_admin<R: Runner>(ctx: &Ctx<R>, args: &RemoveArgs) -> Result<StepState, String> {
    if !ctx
        .plan
        .components
        .iter()
        .all(|c| args.components.contains(c))
    {
        return Ok(StepState::Skipped(
            "the administration tool stays: other parts remain".into(),
        ));
    }
    let mut done = Vec::new();
    if installed(ctx, "openvibes-admin") {
        ctx.ok(Dnf, &["remove", "-y", "openvibes-admin"])?;
        done.push("openvibes-admin".to_owned());
    }
    if ctx.ok(Rpm, &["-qa", "openvibes-*"])?.trim().is_empty() {
        done.extend(remove_matching(ctx, REPO_DIR, |n| {
            n.starts_with("openvibes") && n.ends_with(".repo")
        })?);
        if ctx.exists(KEY_FILE) {
            remove_path(&ctx.path(KEY_FILE))?;
            done.push(KEY_FILE.to_owned());
        }
        for cache in CACHES {
            done.extend(remove_matching(ctx, cache, |n| {
                n.strip_prefix("openvibes-")
                    .is_some_and(|id| id.len() == 16 && id.bytes().all(|b| b.is_ascii_hexdigit()))
            })?);
        }
        // Exit 1 when no key is installed: the output is what counts.
        let keys = ctx.stdout(
            Rpm,
            &[
                "-q",
                "gpg-pubkey",
                "--qf",
                "%{NAME}-%{VERSION}-%{RELEASE}\t%{SUMMARY}\n",
            ],
        )?;
        for key in keys
            .lines()
            .filter(|l| l.contains("OpenVIBES packages"))
            .filter_map(|l| l.split('\t').next())
            .filter(|name| name.starts_with(KEY_ID))
        {
            ctx.ok(Rpm, &["-e", key])?;
            done.push(key.to_owned());
        }
    }
    let kept = if args.confirm.is_some() {
        remove_path(&ctx.path("/var/lib/openvibes-admin"))?;
        done.extend(remove_matching(ctx, "/etc/sudoers.d", |n| {
            n.starts_with("openvibes-operators")
        })?);
        remove_config_dir(ctx)?;
        done.push("its configuration and data".into());
        String::new()
    } else {
        "; kept: /etc/openvibes and /var/lib/openvibes-* (reinstalling finds them)".into()
    };
    let text = if done.is_empty() {
        "nothing left to remove".to_owned()
    } else {
        format!("removed {}", done.join(", "))
    };
    Ok(StepState::Done(format!(
        "{text}{kept}; this program closes here: nothing of OpenVIBES remains to remove by hand"
    )))
}

/// The job is over: the mark, and the lock file this run holds (its
/// directory is tmpfs, but nothing of ours stays).
fn finish<R: Runner>(ctx: &Ctx<R>) {
    ctx.job_end();
    let _ = fs::remove_file(ctx.path("/run/openvibes-admin/setup.lock"));
    let _ = fs::remove_dir(ctx.path("/run/openvibes-admin"));
}

pub fn run<R: Runner>(ctx: &Ctx<R>, step: RemoveStep, args: &RemoveArgs) -> StepState {
    // A mistyped name stops the first step, not only the last: the user
    // asked for nothing to happen.
    if let Some(confirm) = &args.confirm
        && *confirm != ctx.plan.hostname
    {
        return StepState::Failed(format!(
            "the typed name does not match this host's name ({}); nothing removed",
            ctx.plan.hostname
        ));
    }
    if let Err(error) = super::system::job_guard(ctx.root, "uninstall") {
        return StepState::Failed(error);
    }
    let result = match step {
        RemoveStep::Backup => {
            if args.remember_choice {
                // ponytail: best effort; the choice only presets a checkbox.
                let _ = backup::remember(ctx, None, Some(args.backup.is_some()));
            }
            match &args.backup {
                None => Ok(StepState::Skipped("no backup chosen".into())),
                Some(path) => backup::dump(ctx, path).map(StepState::Done),
            }
        }
        RemoveStep::Stop => ctx.job_begin("uninstall").and_then(|()| stop(ctx, args)),
        RemoveStep::Firewall => firewall(ctx, args),
        RemoveStep::Packages => remove_packages(ctx, args),
        RemoveStep::Purge => purge(ctx, args),
        RemoveStep::Admin => remove_admin(ctx, args).inspect(|_| finish(ctx)),
    };
    result.unwrap_or_else(StepState::Failed)
}

#[cfg(test)]
#[path = "remove_tests.rs"]
mod tests;
