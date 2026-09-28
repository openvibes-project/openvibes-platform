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

use super::{Ctx, backup, base::local_rpm, fleet, run::ready};

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
    let running: Vec<&str> = units()
        .into_iter()
        .filter(|unit| ctx.succeeds(Systemctl, &["is-active", "--quiet", unit]))
        .collect();
    // A re-run after a failure keeps what the first run stopped.
    let earlier = ctx.read(ACTIVE).unwrap_or_default();
    let remembered: Vec<&str> = units()
        .into_iter()
        .filter(|unit| running.contains(unit) || earlier.lines().any(|line| line == *unit))
        .collect();
    ctx.job_begin("update")?;
    ctx.put(
        ACTIVE,
        format!("{}\n", remembered.join("\n")).as_bytes(),
        None,
        0o600,
    )?;
    if !running.is_empty() {
        let mut args = vec!["stop"];
        args.extend(&running);
        ctx.ok(Systemctl, &args)?;
    }
    Ok(StepState::Done(format!(
        "stopped: {}; started again after the update: {}",
        running.join(" "),
        remembered.join(" ")
    )))
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
            let before = argv.len();
            for name in &names {
                match local_rpm(ctx, dir, name) {
                    Ok(file) => argv.push(file),
                    // A package the folder does not have stays as it is.
                    Err(error) if error.starts_with("no ") => {}
                    Err(error) => return Err(error),
                }
            }
            if argv.len() == before {
                // A bare `dnf upgrade` would upgrade the whole system.
                return Ok(StepState::Done(format!(
                    "nothing to upgrade: {} has none of the installed packages",
                    dir.display()
                )));
            }
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
    let mut detail = format!("{}; {}", migrated.trim(), maintained.trim());
    // A newer rules package arrived with the upgrade: publish it now, so
    // agents get it without a separate Repair.
    if fleet::rules_check(ctx)? == StepState::Todo {
        detail = format!("{detail}; {}", fleet::rules_apply(ctx)?.detail());
    }
    Ok(StepState::Done(detail))
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
    if let Err(error) = super::system::job_guard(ctx.root, "update") {
        return StepState::Failed(error);
    }
    let result = match step {
        UpdateStep::Backup => match &args.backup {
            None => Ok(StepState::Skipped("no backup chosen".into())),
            Some(path) => backup::dump(ctx, path).map(StepState::Done),
        },
        UpdateStep::Stop => stop(ctx),
        UpdateStep::Upgrade => upgrade(ctx, args),
        UpdateStep::Migrate => migrate(ctx),
        UpdateStep::Start => start(ctx),
        UpdateStep::Ready => wait_ready(ctx).inspect(|_| ctx.job_end()),
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

    #[test]
    fn migrate_publishes_a_newer_rules_package() {
        let fake = Fake::new("update-rules");
        fake.answer(
            &[&ADMIN[..], &["migrate"]].concat(),
            0,
            "schema version 26\n",
        );
        fake.answer(
            &[&ADMIN[..], &["maintenance"]].concat(),
            0,
            "created 0 partitions\n",
        );
        fake.answer(
            &[&ADMIN[..], &["rules", "list"]].concat(),
            0,
            "baseline v1 keys 1 expires 2028-09-27T00:00:00Z\n",
        );
        fake.answer(
            &["/usr/bin/rpm", "-q", "--quiet", "openvibes-rules-baseline"],
            0,
            "",
        );
        fake.answer(
            &[&ADMIN[..], &["rules", "trust", "add"]].concat(),
            0,
            "already trusted\n",
        );
        fake.answer(
            &[&ADMIN[..], &["rules", "publish"]].concat(),
            0,
            "published baseline v2\n",
        );
        fake.file(
            "/usr/share/openvibes/rules/baseline.key",
            "baseline openvibes-1 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
        );
        fake.file(
            "/usr/share/openvibes/rules/baseline.json",
            "{\"rule_set_version\":2}",
        );
        let plan = plan(&[Ingest, Distribution, Rules]);
        let state = run(
            &fake.ctx(&plan),
            UpdateStep::Migrate,
            &UpdateArgs::default(),
        );
        assert_eq!(
            state,
            StepState::Done(
                "schema version 26; created 0 partitions; rule set baseline published".into()
            )
        );
    }

    #[test]
    fn a_second_stop_keeps_the_services_the_first_one_stopped() {
        let fake = Fake::new("update-rerun");
        // An earlier run stopped ingest, then failed at Upgrade.
        fake.file(
            "/run/openvibes-admin/update-active",
            "openvibes-ingest.service\n",
        );
        fake.answer(&["/usr/bin/systemctl", "is-active"], 3, "");
        fake.answer(&["/usr/bin/systemctl", "start"], 0, "");
        let plan = plan(&[Ingest]);
        let ctx = fake.ctx(&plan);
        assert!(matches!(
            run(&ctx, UpdateStep::Stop, &UpdateArgs::default()),
            StepState::Done(_)
        ));
        assert!(matches!(
            run(&ctx, UpdateStep::Start, &UpdateArgs::default()),
            StepState::Done(_)
        ));
        assert_eq!(
            fake.call(&["/usr/bin/systemctl", "start"]),
            ["/usr/bin/systemctl", "start", "openvibes-ingest.service"]
        );
    }

    #[test]
    fn a_folder_without_the_packages_upgrades_nothing() {
        let fake = Fake::new("update-empty-folder");
        fake.answer(
            &["/usr/bin/rpm", "-qa"],
            0,
            "openvibes-ingest\nopenvibes-admin\n",
        );
        std::fs::create_dir_all(fake.root.join("srv/new")).unwrap();
        let plan = plan(&[Ingest]);
        let args = UpdateArgs {
            backup: None,
            repo_dir: Some("/srv/new".into()),
        };
        let state = run(&fake.ctx(&plan), UpdateStep::Upgrade, &args);
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
        assert!(
            !fake.called(&["/usr/bin/dnf"]),
            "a bare dnf upgrade would upgrade the whole system"
        );
        let missing = UpdateArgs {
            backup: None,
            repo_dir: Some("/srv/typo".into()),
        };
        assert!(matches!(
            run(&fake.ctx(&plan), UpdateStep::Upgrade, &missing),
            StepState::Failed(_)
        ));
        fake.file("/srv/new/openvibes-ingest-0.2.0-1.fc44.x86_64.rpm", "");
        fake.file("/srv/new/openvibes-ingest-0.3.0-1.fc44.x86_64.rpm", "");
        let state = run(&fake.ctx(&plan), UpdateStep::Upgrade, &args);
        assert!(
            state.detail().contains("several openvibes-ingest"),
            "{state:?}"
        );
        assert!(!fake.called(&["/usr/bin/dnf"]));
    }

    #[test]
    fn a_half_done_update_blocks_other_setup_runs() {
        let fake = Fake::new("update-marker");
        fake.answer(&["/usr/bin/systemctl", "is-active"], 3, "");
        let plan = plan(&[Ingest]);
        let ctx = fake.ctx(&plan);
        assert!(matches!(
            run(&ctx, UpdateStep::Stop, &UpdateArgs::default()),
            StepState::Done(_)
        ));
        let refused = crate::setup::system::job_guard(&fake.root, "setup").unwrap_err();
        assert!(refused.contains("update is half done"), "{refused}");
        assert!(crate::setup::system::job_guard(&fake.root, "update").is_ok());
        assert!(matches!(
            run(&ctx, UpdateStep::Ready, &UpdateArgs::default()),
            StepState::Done(_)
        ));
        assert!(crate::setup::system::job_guard(&fake.root, "setup").is_ok());
    }
}
