//! Update (admin TUI spec §6.5a): backup offered, the active OpenVIBES
//! units stopped (and remembered), exactly the installed OpenVIBES packages
//! upgraded, the database migrated, the remembered units started again.

use std::path::PathBuf;

use platform_host::{
    StepState, Unit, UpdateStep,
    runner::{
        Program::{Dnf, Rpm, Systemctl},
        Runner,
    },
};

use super::{Ctx, backup, base::local_rpm, run::ready};

const ACTIVE: &str = "/run/openvibes-admin/update-active";
const AGENT: &str = "openvibes-agent.service";

#[derive(clap::Args, Clone, Debug, Default)]
pub struct UpdateArgs {
    /// Write a database backup here first (a new file).
    #[arg(long)]
    pub backup: Option<PathBuf>,
    /// Upgrade from this folder of package files (test builds).
    #[arg(long)]
    pub repo_dir: Option<PathBuf>,
}

impl UpdateArgs {
    pub fn check(&self) -> Result<(), String> {
        for path in [&self.backup, &self.repo_dir].into_iter().flatten() {
            if !path.is_absolute() {
                return Err(format!("{} is not an absolute path", path.display()));
            }
        }
        Ok(())
    }
}

fn units() -> Vec<&'static str> {
    Unit::ALL
        .iter()
        .map(|unit| unit.name())
        .chain([AGENT])
        .collect()
}

fn stop<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let active: Vec<&str> = units()
        .into_iter()
        .filter(|unit| ctx.succeeds(Systemctl, &["is-active", "--quiet", unit]))
        .collect();
    ctx.put(
        ACTIVE,
        format!("{}\n", active.join("\n")).as_bytes(),
        None,
        0o600,
    )?;
    if !active.is_empty() {
        let mut args = vec!["stop"];
        args.extend(&active);
        ctx.ok(Systemctl, &args)?;
    }
    Ok(StepState::Done(format!("stopped: {}", active.join(" "))))
}

fn upgrade<R: Runner>(ctx: &Ctx<R>, args: &UpdateArgs) -> Result<StepState, String> {
    let installed = ctx.ok(Rpm, &["-qa", "--qf", "%{NAME}\n", "openvibes-*"])?;
    let mut names: Vec<&str> = installed
        .lines()
        .filter(|name| !name.ends_with("-debuginfo") && !name.ends_with("-debugsource"))
        .collect();
    names.sort_unstable();
    let mut argv = vec!["upgrade".to_owned(), "-y".to_owned()];
    match args.repo_dir.as_ref().or(ctx.plan.repo_dir.as_ref()) {
        None => argv.extend(names.iter().map(|name| (*name).to_owned())),
        Some(dir) => {
            let check = if ctx.plan.allow_unsigned_local {
                "0"
            } else {
                "1"
            };
            argv.push(format!("--setopt=localpkg_gpgcheck={check}"));
            // A package the folder does not have stays as it is.
            argv.extend(
                names
                    .iter()
                    .filter_map(|name| local_rpm(ctx, dir, name).ok()),
            );
        }
    }
    let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    ctx.ok(Dnf, &argv)?;
    Ok(StepState::Done(format!(
        "upgraded where newer: {}",
        names.join(" ")
    )))
}

fn migrate<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let migrated = ctx.as_admin(&["migrate"])?;
    let maintained = ctx.as_admin(&["maintenance"])?;
    Ok(StepState::Done(format!(
        "{}; {}",
        migrated.trim(),
        maintained.trim()
    )))
}

fn start<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let text = ctx
        .read(ACTIVE)
        .map_err(|_| "no record of the stopped services: run the Stop step first".to_owned())?;
    let active: Vec<&str> = text.lines().filter(|line| units().contains(line)).collect();
    if !active.is_empty() {
        let mut args = vec!["start"];
        args.extend(&active);
        ctx.ok(Systemctl, &args)?;
    }
    let _ = std::fs::remove_file(ctx.path(ACTIVE));
    Ok(StepState::Done(format!(
        "started again: {}",
        active.join(" ")
    )))
}

fn wait_ready<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let running: Vec<Unit> = Unit::ALL
        .into_iter()
        .filter(|unit| ctx.succeeds(Systemctl, &["is-active", "--quiet", unit.name()]))
        .collect();
    for unit in &running {
        let mut attempts = 0;
        while !ready(ctx, *unit) {
            attempts += 1;
            if attempts == 30 {
                return Err(format!(
                    "{} is not ready after 30 seconds; see journalctl -u {}",
                    unit.name(),
                    unit.name()
                ));
            }
            ctx.pause();
        }
    }
    let names: Vec<&str> = running.iter().map(|unit| unit.name()).collect();
    Ok(StepState::Done(format!("ready: {}", names.join(" "))))
}

pub fn run<R: Runner>(ctx: &Ctx<R>, step: UpdateStep, args: &UpdateArgs) -> StepState {
    let result = match step {
        UpdateStep::Backup => match &args.backup {
            None => Ok(StepState::Skipped("no backup chosen".into())),
            Some(path) => backup::dump(ctx, path).map(StepState::Done),
        },
        UpdateStep::Stop => stop(ctx),
        UpdateStep::Upgrade => upgrade(ctx, args),
        UpdateStep::Migrate => migrate(ctx),
        UpdateStep::Start => start(ctx),
        UpdateStep::Ready => wait_ready(ctx),
    };
    result.unwrap_or_else(StepState::Failed)
}

#[cfg(test)]
mod tests {
    use platform_host::{StepState, UpdateStep};

    use super::{UpdateArgs, run};
    use crate::setup::{
        fake::{Fake, plan},
        plan::Component::*,
    };

    const ADMIN: [&str; 5] = [
        "/usr/sbin/runuser",
        "-u",
        "openvibes-admin",
        "--",
        "/usr/bin/openvibes-admin",
    ];

    #[test]
    fn without_a_backup_path_the_backup_is_skipped() {
        let fake = Fake::new("update-no-backup");
        let plan = plan(&[Ingest]);
        assert!(matches!(
            run(&fake.ctx(&plan), UpdateStep::Backup, &UpdateArgs::default()),
            StepState::Skipped(_)
        ));
    }

    #[test]
    fn update_stops_nothing_when_the_backup_fails() {
        let fake = Fake::new("update-backup-exists");
        fake.file("/home/alice/b.dump", "old");
        let plan = plan(&[Ingest]);
        let args = UpdateArgs {
            backup: Some("/home/alice/b.dump".into()),
            repo_dir: None,
        };
        let state = run(&fake.ctx(&plan), UpdateStep::Backup, &args);
        assert!(matches!(state, StepState::Failed(_)), "{state:?}");
        assert!(!fake.called(&["/usr/bin/systemctl"]));
    }

    #[test]
    fn only_previously_active_units_are_started() {
        let fake = Fake::new("update-stop-start");
        fake.answer(
            &[
                "/usr/bin/systemctl",
                "is-active",
                "--quiet",
                "openvibes-ingest.service",
            ],
            0,
            "",
        );
        fake.answer(
            &[
                "/usr/bin/systemctl",
                "is-active",
                "--quiet",
                "openvibes-agent.service",
            ],
            0,
            "",
        );
        fake.answer(&["/usr/bin/systemctl", "is-active"], 3, "");
        fake.answer(&["/usr/bin/systemctl", "stop"], 0, "");
        fake.answer(&["/usr/bin/systemctl", "start"], 0, "");
        let plan = plan(&[Ingest, Distribution, Agent]);
        let ctx = fake.ctx(&plan);
        assert!(matches!(
            run(&ctx, UpdateStep::Stop, &UpdateArgs::default()),
            StepState::Done(_)
        ));
        assert_eq!(
            fake.call(&["/usr/bin/systemctl", "stop"]),
            [
                "/usr/bin/systemctl",
                "stop",
                "openvibes-ingest.service",
                "openvibes-agent.service"
            ]
        );
        assert!(matches!(
            run(&ctx, UpdateStep::Start, &UpdateArgs::default()),
            StepState::Done(_)
        ));
        assert_eq!(
            fake.call(&["/usr/bin/systemctl", "start"]),
            [
                "/usr/bin/systemctl",
                "start",
                "openvibes-ingest.service",
                "openvibes-agent.service"
            ],
            "distribution was stopped before and stays stopped"
        );
        assert!(!fake.root.join("run/openvibes-admin/update-active").exists());
    }

    #[test]
    fn exactly_the_installed_packages_are_upgraded() {
        let fake = Fake::new("update-upgrade");
        fake.answer(
            &["/usr/bin/rpm", "-qa"],
            0,
            "openvibes-ingest\nopenvibes-admin\nopenvibes-agent\nopenvibes-ingest-debuginfo\n",
        );
        fake.answer(&["/usr/bin/dnf", "upgrade"], 0, "");
        let plan = plan(&[Ingest, Agent]);
        assert!(matches!(
            run(
                &fake.ctx(&plan),
                UpdateStep::Upgrade,
                &UpdateArgs::default()
            ),
            StepState::Done(_)
        ));
        assert_eq!(
            fake.call(&["/usr/bin/dnf"]),
            [
                "/usr/bin/dnf",
                "upgrade",
                "-y",
                "openvibes-admin",
                "openvibes-agent",
                "openvibes-ingest"
            ]
        );
    }

    #[test]
    fn a_local_folder_upgrades_from_its_files() {
        let fake = Fake::new("update-local");
        fake.answer(
            &["/usr/bin/rpm", "-qa"],
            0,
            "openvibes-ingest\nopenvibes-admin\n",
        );
        fake.answer(&["/usr/bin/dnf", "upgrade"], 0, "");
        fake.file("/srv/new/openvibes-ingest-0.2.0-1.fc44.x86_64.rpm", "");
        fake.file("/srv/new/openvibes-admin-0.2.0-1.fc44.x86_64.rpm", "");
        let mut plan = plan(&[Ingest]);
        plan.allow_unsigned_local = true;
        let args = UpdateArgs {
            backup: None,
            repo_dir: Some("/srv/new".into()),
        };
        assert!(matches!(
            run(&fake.ctx(&plan), UpdateStep::Upgrade, &args),
            StepState::Done(_)
        ));
        assert_eq!(
            fake.call(&["/usr/bin/dnf"]),
            [
                "/usr/bin/dnf",
                "upgrade",
                "-y",
                "--setopt=localpkg_gpgcheck=0",
                "/srv/new/openvibes-admin-0.2.0-1.fc44.x86_64.rpm",
                "/srv/new/openvibes-ingest-0.2.0-1.fc44.x86_64.rpm"
            ]
        );
    }

    #[test]
    fn migrate_runs_migrate_and_maintenance() {
        let fake = Fake::new("update-migrate");
        fake.answer(
            &[&ADMIN[..], &["migrate"]].concat(),
            0,
            "schema version 25\n",
        );
        fake.answer(
            &[&ADMIN[..], &["maintenance"]].concat(),
            0,
            "created 0 partitions\n",
        );
        let plan = plan(&[Ingest]);
        let state = run(
            &fake.ctx(&plan),
            UpdateStep::Migrate,
            &UpdateArgs::default(),
        );
        assert_eq!(
            state,
            StepState::Done("schema version 25; created 0 partitions".into())
        );
    }
}
