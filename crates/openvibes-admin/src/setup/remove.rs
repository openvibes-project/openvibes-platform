//! Removing components (keep data) and Remove everything (admin TUI spec
//! §6.5). `openvibes-admin` itself is never removed here: the TUI is
//! running; the last line says how to remove it.

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
}

impl RemoveArgs {
    pub fn check(&self) -> Result<(), String> {
        if self.components.is_empty() {
            return Err("--components is required".into());
        }
        if let Some(path) = &self.backup
            && !path.is_absolute()
        {
            return Err(format!("{} is not an absolute path", path.display()));
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
const ACCOUNTS: [&str; 9] = [
    "openvibes-ingest",
    "openvibes-netlog",
    "openvibes-distribution",
    "openvibes-vulns",
    "openvibes-console",
    "openvibes-llm",
    "openvibes-signer",
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
    let mut text = format!("removed: {}", packages.join(" "));
    if args.components.contains(&Component::Ingest) {
        text.push_str(
            "; last, remove the administration tool itself: sudo dnf remove openvibes-admin",
        );
    }
    Ok(StepState::Done(text))
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
    // #82: the admin package is removed last, by hand (this tool is part
    // of it), so its configuration file stays for rpm: deleting it here
    // made `dnf remove` warn, and a reinstall in between left it missing.
    let kept = if installed(ctx, "openvibes-admin") {
        ctx.stdout(Rpm, &["-qc", "openvibes-admin"])?
    } else {
        String::new()
    };
    let kept: Vec<&str> = kept.lines().map(str::trim).collect();
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
        RemoveStep::Backup => match &args.backup {
            None => Ok(StepState::Skipped("no backup chosen".into())),
            Some(path) => backup::dump(ctx, path).map(StepState::Done),
        },
        RemoveStep::Stop => ctx.job_begin("uninstall").and_then(|()| stop(ctx, args)),
        RemoveStep::Firewall => firewall(ctx, args),
        RemoveStep::Packages => remove_packages(ctx, args),
        RemoveStep::Purge => purge(ctx, args).inspect(|_| ctx.job_end()),
    };
    result.unwrap_or_else(StepState::Failed)
}

#[cfg(test)]
mod tests {
    use platform_host::{RemoveStep, StepState};

    use super::{RemoveArgs, run};
    use crate::setup::{
        fake::{Fake, plan},
        plan::Component::{self, *},
    };

    const PG: [&str; 4] = ["/usr/sbin/runuser", "-u", "postgres", "--"];

    fn args(components: &[Component], confirm: Option<&str>) -> RemoveArgs {
        RemoveArgs {
            components: components.to_vec(),
            backup: None,
            confirm: confirm.map(str::to_owned),
        }
    }

    #[test]
    fn removing_a_component_stops_it_closes_its_port_and_removes_its_packages() {
        let fake = Fake::new("remove-distribution");
        fake.answer(
            &["/usr/bin/rpm", "-q", "--quiet", "openvibes-distribution"],
            0,
            "",
        );
        fake.answer(&["/usr/bin/systemctl", "disable", "--now"], 0, "");
        fake.answer(&["/usr/bin/firewall-cmd", "--state"], 0, "running\n");
        fake.answer(
            &[
                "/usr/bin/firewall-cmd",
                "--permanent",
                "--query-port",
                "18424/tcp",
            ],
            0,
            "yes\n",
        );
        fake.answer(
            &["/usr/bin/firewall-cmd", "--permanent", "--remove-port"],
            0,
            "success\n",
        );
        fake.answer(&["/usr/bin/firewall-cmd", "--reload"], 0, "success\n");
        fake.answer(&["/usr/bin/dnf", "remove"], 0, "");
        let plan = plan(&[Ingest, Distribution]);
        let ctx = fake.ctx(&plan);
        let args = args(&[Distribution], None);
        for step in RemoveStep::ALL {
            let state = run(&ctx, step, &args);
            assert!(state.finished(), "{step:?}: {state:?}");
        }
        assert_eq!(
            fake.call(&["/usr/bin/systemctl", "disable"]),
            [
                "/usr/bin/systemctl",
                "disable",
                "--now",
                "openvibes-distribution.service"
            ]
        );
        assert_eq!(
            fake.call(&["/usr/bin/firewall-cmd", "--permanent", "--remove-port"])[3],
            "18424/tcp"
        );
        assert_eq!(
            fake.call(&["/usr/bin/dnf"]),
            ["/usr/bin/dnf", "remove", "-y", "openvibes-distribution"]
        );
        assert!(!fake.called(&PG), "keep data: the database is not touched");
    }

    #[test]
    fn the_admin_package_is_left_for_last() {
        let fake = Fake::new("remove-admin");
        fake.answer(&["/usr/bin/rpm", "-q", "--quiet"], 0, "");
        fake.answer(&["/usr/bin/dnf", "remove"], 0, "");
        let plan = plan(&[Ingest, Agent]);
        let state = run(
            &fake.ctx(&plan),
            RemoveStep::Packages,
            &args(&[Ingest, Agent], None),
        );
        assert_eq!(
            fake.call(&["/usr/bin/dnf"]),
            [
                "/usr/bin/dnf",
                "remove",
                "-y",
                "openvibes-ingest",
                "openvibes-agent"
            ]
        );
        assert!(
            state.detail().contains("sudo dnf remove openvibes-admin"),
            "{state:?}"
        );
    }

    #[test]
    fn purge_needs_the_hostname_and_the_whole_platform() {
        let fake = Fake::new("purge-refused");
        fake.file("/etc/openvibes/setup.toml", "kept");
        let plan = plan(&[Ingest, Vulns]);
        let ctx = fake.ctx(&plan);
        assert!(matches!(
            run(&ctx, RemoveStep::Purge, &args(&[Ingest, Vulns], None)),
            StepState::Skipped(_)
        ));
        let wrong = run(
            &ctx,
            RemoveStep::Purge,
            &args(&[Ingest, Vulns], Some("other.example.com")),
        );
        assert!(wrong.detail().contains("does not match"), "{wrong:?}");
        let partial = run(
            &ctx,
            RemoveStep::Purge,
            &args(&[Vulns], Some("platform.example.com")),
        );
        assert!(partial.detail().contains("whole platform"), "{partial:?}");
        assert!(fake.root.join("etc/openvibes/setup.toml").exists());
        assert!(!fake.called(&PG));
    }

    #[test]
    fn purge_drops_the_database_roles_files_and_accounts() {
        let fake = Fake::new("purge");
        fake.file("/etc/openvibes/setup.toml", "x");
        fake.file("/var/lib/openvibes-ingest/intermediate.key", "x");
        fake.file("/etc/openvibes-agent/agent.toml", "x");
        fake.answer(
            &[&PG[..], &["/usr/bin/psql"]].concat(),
            0,
            "openvibes-admin\nopenvibes-ingest\nopenvibes-console\n",
        );
        fake.answer(&[&PG[..], &["/usr/bin/dropdb"]].concat(), 0, "");
        fake.answer(&[&PG[..], &["/usr/bin/dropuser"]].concat(), 0, "");
        fake.answer(&["/usr/sbin/userdel"], 0, "");
        fake.answer(&["/usr/sbin/groupdel"], 0, "");
        let plan = plan(&[Ingest, Console]);
        let state = run(
            &fake.ctx(&plan),
            RemoveStep::Purge,
            &args(&[Ingest, Console], Some("platform.example.com")),
        );
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
        assert!(fake.called(&[&PG[..], &["/usr/bin/dropdb", "--if-exists", "openvibes"]].concat()));
        let dropped: Vec<String> = fake
            .calls
            .borrow()
            .iter()
            .filter(|c| c.get(4).is_some_and(|p| p == "/usr/bin/dropuser"))
            .map(|c| c[6].clone())
            .collect();
        assert_eq!(
            dropped,
            ["openvibes-admin", "openvibes-ingest", "openvibes-console"]
        );
        for gone in [
            "etc/openvibes",
            "var/lib/openvibes-ingest",
            "etc/openvibes-agent",
        ] {
            assert!(!fake.root.join(gone).exists(), "{gone}");
        }
        assert!(fake.called(&["/usr/sbin/userdel", "openvibes-ingest"]));
        assert!(fake.called(&["/usr/sbin/groupdel", "openvibes-operators"]));
        assert!(
            state.detail().contains("PostgreSQL itself stays"),
            "{state:?}"
        );
    }

    /// #82: while openvibes-admin is still installed, its packaged
    /// Review 2026-10-10 (user: nothing may be left behind): every account
    /// a platform package creates is one Uninstall deletes.
    #[test]
    fn every_packaged_service_account_is_deleted() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../packaging/rpm");
        let mut packaged = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|e| e == "sysusers") {
                for line in std::fs::read_to_string(&path).unwrap().lines() {
                    if let Some(rest) = line.strip_prefix("u ") {
                        packaged.push(rest.split_whitespace().next().unwrap().to_owned());
                    }
                }
            }
        }
        assert!(packaged.len() >= 7, "{packaged:?}");
        for account in &packaged {
            assert!(
                super::ACCOUNTS.contains(&account.as_str()),
                "{account} is left behind"
            );
        }
    }

    /// admin.toml stays for `dnf remove`; everything else goes.
    #[test]
    fn purge_leaves_the_admin_package_config_for_rpm() {
        let fake = Fake::new("purge-keep");
        fake.file("/etc/openvibes/admin.toml", "x");
        fake.file("/etc/openvibes/setup.toml", "x");
        fake.file("/etc/openvibes/tls/server.pem", "x");
        fake.answer(&["/usr/bin/rpm", "-q", "--quiet", "openvibes-admin"], 0, "");
        fake.answer(
            &["/usr/bin/rpm", "-qc", "openvibes-admin"],
            0,
            "/etc/openvibes/admin.toml\n",
        );
        fake.answer(&[&PG[..], &["/usr/bin/psql"]].concat(), 0, "");
        fake.answer(&[&PG[..], &["/usr/bin/dropdb"]].concat(), 0, "");
        fake.answer(&["/usr/sbin/userdel"], 0, "");
        fake.answer(&["/usr/sbin/groupdel"], 0, "");
        let plan = plan(&[Ingest]);
        let state = run(
            &fake.ctx(&plan),
            RemoveStep::Purge,
            &args(&[Ingest], Some("platform.example.com")),
        );
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
        assert!(fake.root.join("etc/openvibes/admin.toml").exists());
        assert!(!fake.root.join("etc/openvibes/setup.toml").exists());
        assert!(!fake.root.join("etc/openvibes/tls").exists());
    }

    #[test]
    fn a_wrong_confirmation_stops_every_step() {
        let fake = Fake::new("remove-wrong-name");
        let plan = plan(&[Ingest]);
        for step in RemoveStep::ALL {
            let state = run(
                &fake.ctx(&plan),
                step,
                &args(&[Ingest], Some("other.example.com")),
            );
            assert!(
                state.detail().contains("does not match"),
                "{step:?}: {state:?}"
            );
        }
        assert!(fake.calls.borrow().is_empty(), "nothing ran");
    }
}
