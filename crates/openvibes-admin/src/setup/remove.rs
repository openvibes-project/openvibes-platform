//! Removing components (keep data) and Remove everything (admin TUI spec
//! §6.5). `openvibes-admin` itself is removed by the last step, `admin`:
//! the running helper keeps its file open until it exits.

use std::{
    fs,
    path::{Path, PathBuf},
};

use platform_host::{
    RemoveStep, StepState,
    runner::{
        Program::{Dnf, FirewallCmd, Groupdel, Rpm, Systemctl, Userdel},
        Runner,
    },
};

use super::{
    Ctx, backup,
    base::{PG_MARK, PG_PACKAGES, PG_RECORD},
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
            if let Some(folder) = self.backup.as_deref().and_then(removed_by_everything) {
                return Err(format!(
                    "Remove everything removes {folder}, and the backup with it: choose another folder"
                ));
            }
        }
        Ok(())
    }
}

/// The folder of Remove everything's that holds `path`, if any: a backup
/// there would be deleted by the same run (review C1).
pub(crate) fn removed_by_everything(path: &Path) -> Option<&'static str> {
    DATA.into_iter()
        .chain([admin::BACKUPS])
        .find(|folder| path.starts_with(folder))
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

pub(super) fn installed<R: Runner>(ctx: &Ctx<R>, package: &str) -> bool {
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

fn remove_file_or_dir(path: &std::path::Path) -> Result<(), String> {
    match if path.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    } {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            Err(format!("{}: {error}", path.display()))
        }
        _ => Ok(()),
    }
}

/// PostgreSQL goes only when Setup installed it (the record), the package
/// is still installed and the cluster holds nothing but the system
/// databases and `openvibes`. Everything that can refuse runs before the
/// mark and before anything stops; after the mark, each part checks whether
/// it is still to do, so a retry finishes. `/var/lib/pgsql` goes only under
/// the mark, never on a record alone. The record goes last.
fn postgresql<R: Runner>(ctx: &Ctx<R>) -> Result<String, String> {
    let Ok(record) = ctx.read(PG_RECORD) else {
        return Ok("Setup has no record of installing PostgreSQL; it stays".into());
    };
    if !ctx.exists(PG_MARK) {
        if !installed(ctx, "postgresql-server") {
            remove_file_or_dir(&ctx.path(PG_RECORD))?;
            return Ok(
                "the record of Setup installing PostgreSQL was stale, so PostgreSQL is not removed"
                    .into(),
            );
        }
        let others = ctx.as_postgres(&[
            "/usr/bin/psql",
            "-Atqc",
            "SELECT datname FROM pg_database WHERE datname NOT IN ('postgres','template0','template1','openvibes')",
        ])?;
        let count = others.lines().filter(|l| !l.trim().is_empty()).count();
        if count > 0 {
            return Ok(format!(
                "PostgreSQL stays: it holds {count} other database{}",
                if count == 1 { "" } else { "s" }
            ));
        }
        let mut test = vec!["-e", "--test"];
        test.extend(packages_to_remove(ctx, &record));
        ctx.ok(Rpm, &test)?;
        ctx.put(PG_MARK, b"removing\n", None, 0o644)?;
    }
    if installed(ctx, "postgresql-server") {
        ctx.ok(Systemctl, &["disable", "--now", "postgresql"])?;
        let mut argv = vec!["-e"];
        argv.extend(packages_to_remove(ctx, &record));
        ctx.ok(Rpm, &argv)?;
    }
    remove_file_or_dir(&ctx.path("/var/lib/pgsql"))?;
    remove_file_or_dir(&ctx.path(PG_MARK))?;
    remove_file_or_dir(&ctx.path(PG_RECORD))?;
    Ok("PostgreSQL removed: Setup installed it and nothing else uses it".into())
}

fn packages_to_remove<'a, R: Runner>(ctx: &Ctx<R>, record: &'a str) -> Vec<&'a str> {
    record
        .lines()
        .filter(|p| PG_PACKAGES.contains(p) && installed(ctx, p))
        .collect()
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
    // Once PostgreSQL's own removal has begun the cluster may be gone: the
    // database work was done before the mark was written.
    let roles = if ctx.exists(PG_MARK) {
        String::new()
    } else {
        let roles = ctx.as_postgres(&[
            "/usr/bin/psql",
            "-Atqc",
            "SELECT rolname FROM pg_roles WHERE rolname LIKE 'openvibes-%' ORDER BY oid",
        ])?;
        ctx.as_postgres(&["/usr/bin/dropdb", "--if-exists", "openvibes"])?;
        roles
    };
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
    // So does the PostgreSQL record, until PostgreSQL is gone.
    kept.push(PG_RECORD);
    kept.push(PG_MARK);
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
    let postgresql = postgresql(ctx)?;
    // A reinstalled signer makes a new site key (lead, #2086).
    let site_key = if site_key {
        "; the site rule key is gone: after a reinstall, agents need the new key's lines from `agent command`"
    } else {
        ""
    };
    Ok(StepState::Done(format!(
        "database, roles, configuration, data and service accounts removed; {postgresql}{site_key}"
    )))
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
        RemoveStep::Admin => {
            admin::remove_admin(ctx, args).inspect(|state| admin::finish(ctx, state))
        }
    };
    result.unwrap_or_else(StepState::Failed)
}

#[path = "remove_admin.rs"]
mod admin;

#[cfg(test)]
#[path = "remove_tests.rs"]
mod tests;
