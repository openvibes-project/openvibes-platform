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
const DATA: [&str; 9] = [
    "/etc/openvibes",
    "/etc/openvibes-agent",
    "/var/lib/openvibes-admin",
    "/var/lib/openvibes-ingest",
    "/var/lib/openvibes-distribution",
    "/var/lib/openvibes-vulns",
    "/var/lib/openvibes-console",
    "/var/lib/openvibes-llm",
    "/var/lib/openvibes-agent",
];
/// Service accounts (user and group of the same name) it deletes.
const ACCOUNTS: [&str; 7] = [
    "openvibes-ingest",
    "openvibes-distribution",
    "openvibes-vulns",
    "openvibes-console",
    "openvibes-llm",
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
                units.push("openvibes-llm.service");
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
    for dir in DATA {
        let path = ctx.path(dir);
        if path.exists() {
            fs::remove_dir_all(&path).map_err(|error| format!("{dir}: {error}"))?;
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
    for group in ACCOUNTS.iter().chain(&["openvibes-operators"]) {
        if groups
            .lines()
            .any(|line| line.starts_with(&format!("{group}:")))
        {
            // userdel already removed a user's own group on most hosts.
            let _ = ctx.ok(Groupdel, &[group]);
        }
    }
    Ok(StepState::Done(
        "database, roles, configuration, data and service accounts removed; PostgreSQL itself stays installed".into(),
    ))
}

pub fn run<R: Runner>(ctx: &Ctx<R>, step: RemoveStep, args: &RemoveArgs) -> StepState {
    let result = match step {
        RemoveStep::Backup => match &args.backup {
            None => Ok(StepState::Skipped("no backup chosen".into())),
            Some(path) => backup::dump(ctx, path).map(StepState::Done),
        },
        RemoveStep::Stop => stop(ctx, args),
        RemoveStep::Firewall => firewall(ctx, args),
        RemoveStep::Packages => remove_packages(ctx, args),
        RemoveStep::Purge => purge(ctx, args),
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
}
