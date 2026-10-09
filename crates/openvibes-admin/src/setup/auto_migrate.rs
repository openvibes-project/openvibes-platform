//! `helper upgrade-migrate`: what `openvibes-migrate.service` runs after a
//! package upgrade. An additive migration is applied as before; a migration
//! that changes stored data (board #77) gets Update's path: a database
//! backup first, then the migration (`update::migrate`, which also
//! publishes a newer rules package). Services that want the unit start
//! after it, so none runs on a half-migrated schema. Every step is a
//! journal line; a failure leaves the schema as it was and the backup kept.

use std::{fs, os::unix::fs::DirBuilderExt, path::Path};

use platform_host::runner::{Program::Systemctl, Runner};

use super::{Ctx, backup, plan::Plan, system, update};

const BACKUPS: &str = "/var/backups/openvibes";

/// What the additive attempt means.
#[derive(Debug, PartialEq)]
pub enum Next {
    /// Applied, or already current.
    Done(String),
    /// A migration that changes stored data is pending: back up, then migrate.
    BackupThenMigrate,
    Fail(String),
}

/// The refusal's fixed start, from the store's own message (no separate
/// copy of the wording to drift).
fn needs_backup_text() -> String {
    let full = platform_store::StoreError::NeedsBackup(0).to_string();
    full.split_once("(migration")
        .map_or(full.clone(), |(head, _)| format!("{head}(migration"))
}

/// Decides from `openvibes-admin migrate --additive`'s result.
pub fn decide(additive: Result<String, String>) -> Next {
    match additive {
        Ok(out) => Next::Done(out.trim().to_owned()),
        Err(error) if error.contains(&needs_backup_text()) => Next::BackupThenMigrate,
        Err(error) => Next::Fail(error),
    }
}

/// The log lines and whether the unit succeeded. `stamp` names the backup.
pub fn run<R: Runner>(root: &Path, runner: &R, stamp: &str) -> (Vec<String>, bool) {
    let mut log = Vec::new();
    // Setup, or Update (which migrates itself), holds this lock.
    let _lock = match system::lock(root) {
        Ok(lock) => lock,
        Err(error) if error.contains("another Setup run") => {
            log.push("Setup or Update is running; if the services then refuse the schema, run Update in Setup".into());
            return (log, true);
        }
        Err(error) => return (vec![format!("upgrade migration failed: {error}")], false),
    };
    if let Err(error) = system::job_guard(root, "setup") {
        return (vec![format!("upgrade migration skipped: {error}")], true);
    }
    let Ok(plan) = Plan::load(root) else {
        return (
            vec!["Setup has not run on this host; nothing to migrate".into()],
            true,
        );
    };
    let ctx = Ctx {
        runner,
        plan: &plan,
        root,
        pause: std::time::Duration::from_secs(1),
        repair: false,
    };
    match decide(ctx.as_admin(&["migrate", "--additive"])) {
        Next::Done(out) => {
            log.push(format!("database is current: {out}"));
            (log, true)
        }
        Next::Fail(error) => {
            log.push(format!("upgrade migration failed: {error}"));
            (log, false)
        }
        Next::BackupThenMigrate => {
            let ok = data_migration(&ctx, stamp, &mut log);
            if !ok {
                // Later runs (the console's restarts, the maintenance
                // timer) skip with "an update is half done" instead of
                // dumping the database again each time; Update clears it.
                let _ = ctx.job_begin("update");
            }
            (log, ok)
        }
    }
}

/// Services that must not run while stored data changes (Update stops the
/// same ones, plus the agent, which stays up here).
const STOP: [&str; 7] = [
    "openvibes-ingest.service",
    "openvibes-distribution.service",
    "openvibes-vulns.service",
    "openvibes-signer.service",
    "openvibes-console.service",
    "openvibes-maintenance.timer",
    "openvibes-maintenance.service",
];

/// Stops what runs, backs up, migrates; whatever happens, queues the
/// stopped units to start again (they wait for this unit to finish).
fn data_migration<R: Runner>(ctx: &Ctx<R>, stamp: &str, log: &mut Vec<String>) -> bool {
    let running: Vec<&str> = STOP
        .into_iter()
        .filter(|unit| ctx.succeeds(Systemctl, &["is-active", "--quiet", unit]))
        .collect();
    log.push(format!(
        "this upgrade changes stored data: stopping {} and backing up first",
        if running.is_empty() {
            "nothing".to_owned()
        } else {
            running.join(" ")
        }
    ));
    let result = (|| {
        if !running.is_empty() {
            let mut args = vec!["stop"];
            args.extend(&running);
            ctx.ok(Systemctl, &args).map_err(|error| {
                format!("could not stop the services, nothing migrated: {error}")
            })?;
        }
        let file = format!("{BACKUPS}/upgrade-{stamp}.dump");
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(ctx.path(BACKUPS))
            .map_err(|error| format!("{BACKUPS}: {error}"))
            .and_then(|()| backup::dump(ctx, Path::new(&file)))
            .map(|done| log.push(done))
            .map_err(|error| format!("backup failed, nothing migrated: {error}"))?;
        update::migrate(ctx)
            .map(|state| log.push(format!("migrated: {}", state.detail())))
            .map_err(|error| {
                format!("{error}; the backup {file} is kept; run Update in openvibes-admin")
            })
    })();
    if !running.is_empty() {
        let mut args = vec!["start", "--no-block"];
        args.extend(&running);
        if let Err(error) = ctx.ok(Systemctl, &args) {
            log.push(format!("could not queue the services to start: {error}"));
        }
    }
    match result {
        Ok(()) => true,
        Err(error) => {
            log.push(format!("upgrade migration failed: {error}"));
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Next, decide, run};
    use crate::setup::{
        fake::{Fake, plan},
        plan::Component::*,
        system,
    };

    const ADMIN: [&str; 5] = [
        "/usr/sbin/runuser",
        "-u",
        "openvibes-admin",
        "--",
        "/usr/bin/openvibes-admin",
    ];

    fn needs() -> String {
        platform_store::StoreError::NeedsBackup(43).to_string()
    }

    const SYSTEMCTL: &str = "/usr/bin/systemctl";

    /// Only the console is running.
    fn console_only(fake: &Fake) {
        fake.answer(&[SYSTEMCTL, "stop"], 0, "");
        fake.answer(&[SYSTEMCTL, "start"], 0, "");
        fake.answer(
            &[
                SYSTEMCTL,
                "is-active",
                "--quiet",
                "openvibes-console.service",
            ],
            0,
            "",
        );
        fake.fail(&[SYSTEMCTL, "is-active"], "inactive");
    }

    fn position(fake: &Fake, matches: impl Fn(&[String]) -> bool) -> Option<usize> {
        fake.calls.borrow().iter().position(|call| matches(call))
    }

    fn admin(rest: &[&'static str]) -> Vec<&'static str> {
        ADMIN.iter().chain(rest).copied().collect()
    }

    /// A call that is exactly `argv`, not just starts with it.
    fn exact(fake: &Fake, argv: &[&str]) -> bool {
        fake.calls.borrow().iter().any(|call| call == argv)
    }

    fn host(test: &str) -> Fake {
        let fake = Fake::new(test);
        plan(&[Ingest]).save(&fake.root).unwrap();
        fake
    }

    #[test]
    fn decisions() {
        assert_eq!(
            decide(Ok("schema version 43\n".into())),
            Next::Done("schema version 43".into())
        );
        assert_eq!(decide(Err(needs())), Next::BackupThenMigrate);
        assert_eq!(
            decide(Err("database unavailable".into())),
            Next::Fail("database unavailable".into())
        );
    }

    #[test]
    fn additive_only_migrates_as_before() {
        let fake = host("mig-additive");
        fake.answer(&admin(&["migrate", "--additive"]), 0, "schema version 43\n");
        let (log, ok) = run(&fake.root, &fake, "t");
        assert!(ok, "{log:?}");
        assert!(!exact(&fake, &admin(&["migrate"])));
        assert!(!fake.called(&["/usr/sbin/runuser", "-u", "postgres"]));
    }

    /// The pg_dump effect: the dump lands in the staging directory.
    fn dumping(fake: &Fake) {
        fake.effect(
            &[
                "/usr/sbin/runuser",
                "-u",
                "postgres",
                "--",
                "/usr/bin/pg_dump",
            ],
            |root| {
                for entry in std::fs::read_dir(root.join("var/tmp")).unwrap().flatten() {
                    std::fs::write(entry.path().join("openvibes.dump"), "dump").unwrap();
                }
            },
        );
        fake.answer(&["/usr/sbin/runuser", "-u", "postgres"], 0, "-- roles\n");
    }

    fn is_dump(call: &[String]) -> bool {
        call.iter().any(|arg| arg == "/usr/bin/pg_dump")
    }

    fn is_stop(call: &[String]) -> bool {
        call.get(..2) == Some(&[SYSTEMCTL.to_owned(), "stop".to_owned()])
    }

    fn is_start(call: &[String]) -> bool {
        call.get(..3)
            == Some(&[
                SYSTEMCTL.to_owned(),
                "start".to_owned(),
                "--no-block".to_owned(),
            ])
    }

    #[test]
    fn a_data_changing_migration_stops_backs_up_then_migrates_and_restarts() {
        let fake = host("mig-backup");
        console_only(&fake);
        fake.fail(&admin(&["migrate", "--additive"]), &needs());
        fake.answer(&admin(&["migrate"]), 0, "schema version 43\n");
        fake.answer(&admin(&["maintenance"]), 0, "created 0 partitions\n");
        dumping(&fake);
        let (log, ok) = run(&fake.root, &fake, "t");
        assert!(ok, "{log:?}");
        let migrate = position(&fake, |c| c == admin(&["migrate"])).expect("no migrate");
        let stop = position(&fake, is_stop).expect("no stop");
        let dump = position(&fake, is_dump).expect("no backup");
        let start = position(&fake, is_start).expect("no start");
        assert!(
            stop < dump && dump < migrate && migrate < start,
            "{:?}",
            fake.calls
        );
        assert_eq!(
            fake.calls.borrow()[stop],
            [SYSTEMCTL, "stop", "openvibes-console.service"]
        );
        assert!(
            fake.root
                .join("var/backups/openvibes/upgrade-t.dump")
                .exists()
        );
        assert!(!fake.root.join("run/openvibes-admin/job").exists());
    }

    #[test]
    fn a_failed_backup_migrates_nothing_restarts_and_blocks_retries() {
        let fake = host("mig-nobackup");
        console_only(&fake);
        fake.fail(&admin(&["migrate", "--additive"]), &needs());
        fake.fail(
            &["/usr/sbin/runuser", "-u", "postgres"],
            "pg_dump: no space left",
        );
        let (log, ok) = run(&fake.root, &fake, "t");
        assert!(!ok, "{log:?}");
        assert!(log.join("\n").contains("nothing migrated"), "{log:?}");
        assert!(position(&fake, |c| c == admin(&["migrate"])).is_none());
        assert!(position(&fake, is_start).is_some(), "services left off");
        // The next run (a restarting console, the timer) does not dump again.
        let before = fake.calls.borrow().len();
        let (log, ok) = run(&fake.root, &fake, "u");
        assert!(ok && log[0].contains("half done"), "{log:?}");
        assert_eq!(fake.calls.borrow().len(), before);
    }

    #[test]
    fn a_failed_migration_keeps_the_backup_restarts_and_blocks_retries() {
        let fake = host("mig-migfail");
        console_only(&fake);
        fake.fail(&admin(&["migrate", "--additive"]), &needs());
        fake.fail(&admin(&["migrate"]), "database query failed");
        dumping(&fake);
        let (log, ok) = run(&fake.root, &fake, "t");
        assert!(!ok, "{log:?}");
        assert!(
            fake.root
                .join("var/backups/openvibes/upgrade-t.dump")
                .exists()
        );
        assert!(log.join("\n").contains("is kept"), "{log:?}");
        assert!(position(&fake, is_start).is_some(), "services left off");
        let (log, ok) = run(&fake.root, &fake, "u");
        assert!(ok && log[0].contains("half done"), "{log:?}");
    }

    #[test]
    fn nothing_is_stopped_when_nothing_runs() {
        let fake = host("mig-idle");
        fake.fail(&[SYSTEMCTL, "is-active"], "inactive");
        fake.fail(&admin(&["migrate", "--additive"]), &needs());
        fake.answer(&admin(&["migrate"]), 0, "schema version 43\n");
        fake.answer(&admin(&["maintenance"]), 0, "created 0 partitions\n");
        dumping(&fake);
        let (log, ok) = run(&fake.root, &fake, "t");
        assert!(ok, "{log:?}");
        assert!(position(&fake, is_stop).is_none() && position(&fake, is_start).is_none());
    }

    #[test]
    fn a_real_error_fails_the_unit() {
        let fake = host("mig-error");
        fake.fail(&admin(&["migrate", "--additive"]), "database unavailable");
        let (log, ok) = run(&fake.root, &fake, "t");
        assert!(!ok, "{log:?}");
        assert!(!fake.called(&["/usr/sbin/runuser", "-u", "postgres"]));
    }

    #[test]
    fn a_held_lock_skips() {
        let fake = host("mig-locked");
        let _held = system::lock(&fake.root).unwrap();
        let (log, ok) = run(&fake.root, &fake, "t");
        assert!(
            ok && log[0].contains("Setup or Update is running"),
            "{log:?}"
        );
        assert!(fake.calls.borrow().is_empty());
    }

    #[test]
    fn setup_never_ran_skips() {
        let fake = Fake::new("mig-nosetup");
        let (log, ok) = run(&fake.root, &fake, "t");
        assert!(ok && log[0].contains("Setup has not run"), "{log:?}");
        assert!(fake.calls.borrow().is_empty());
    }
}
