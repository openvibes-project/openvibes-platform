//! `helper upgrade-migrate`: what `openvibes-migrate.service` runs after a
//! package upgrade. An additive migration is applied as before; a migration
//! that changes stored data (board #77) gets Update's path: a database
//! backup first, then the migration (`update::migrate`, which also
//! publishes a newer rules package). Services that want the unit start
//! after it, so none runs on a half-migrated schema. Every step is a
//! journal line; a failure leaves the schema as it was and the backup kept.

use std::{fs, os::unix::fs::DirBuilderExt, path::Path};

use platform_host::runner::Runner;

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

/// Decides from `openvibes-admin migrate --additive`'s result.
pub fn decide(additive: Result<String, String>) -> Next {
    match additive {
        Ok(out) => Next::Done(out.trim().to_owned()),
        Err(error) if error.contains("changes stored data") => Next::BackupThenMigrate,
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
            log.push("Setup is running; it migrates the database itself".into());
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
            log.push("this upgrade changes stored data: backing up first".into());
            let file = format!("{BACKUPS}/upgrade-{stamp}.dump");
            let backed = fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(ctx.path(BACKUPS))
                .map_err(|error| format!("{BACKUPS}: {error}"))
                .and_then(|()| backup::dump(&ctx, Path::new(&file)));
            match backed {
                Err(error) => {
                    log.push(format!(
                        "upgrade migration failed: backup failed, nothing migrated: {error}"
                    ));
                    return (log, false);
                }
                Ok(done) => log.push(done),
            }
            match update::migrate(&ctx) {
                Ok(state) => {
                    log.push(format!("migrated: {}", state.detail()));
                    (log, true)
                }
                Err(error) => {
                    log.push(format!(
                        "upgrade migration failed: {error}; the backup {file} is kept; run Update in openvibes-admin"
                    ));
                    (log, false)
                }
            }
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
    const NEEDS: &str = "openvibes-admin: this upgrade changes stored data (migration 43): run `openvibes-admin` → Update";

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
        assert_eq!(decide(Err(NEEDS.into())), Next::BackupThenMigrate);
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

    #[test]
    fn a_data_changing_migration_backs_up_then_migrates() {
        let fake = host("mig-backup");
        fake.fail(&admin(&["migrate", "--additive"]), NEEDS);
        fake.answer(&admin(&["migrate"]), 0, "schema version 43\n");
        fake.answer(&admin(&["maintenance"]), 0, "created 0 partitions\n");
        fake.effect(
            &[
                "/usr/sbin/runuser",
                "-u",
                "postgres",
                "--",
                "/usr/bin/pg_dump",
            ],
            |root| {
                // The dump lands in the staging directory the helper made.
                for entry in std::fs::read_dir(root.join("var/tmp")).unwrap().flatten() {
                    std::fs::write(entry.path().join("openvibes.dump"), "dump").unwrap();
                }
            },
        );
        fake.answer(&["/usr/sbin/runuser", "-u", "postgres"], 0, "-- roles\n");
        let (log, ok) = run(&fake.root, &fake, "t");
        assert!(ok, "{log:?}");
        let calls = fake.calls.borrow();
        let at = |argv: &[&str]| calls.iter().position(|call| call == argv);
        let dump = calls
            .iter()
            .position(|call| call.iter().any(|arg| arg == "/usr/bin/pg_dump"))
            .expect("no backup");
        let migrate = at(&admin(&["migrate"])).expect("no migrate");
        assert!(dump < migrate, "{calls:?}");
        assert!(
            fake.root
                .join("var/backups/openvibes/upgrade-t.dump")
                .exists()
        );
    }

    #[test]
    fn a_failed_backup_migrates_nothing() {
        let fake = host("mig-nobackup");
        fake.fail(&admin(&["migrate", "--additive"]), NEEDS);
        fake.fail(
            &["/usr/sbin/runuser", "-u", "postgres"],
            "pg_dump: no space left",
        );
        let (log, ok) = run(&fake.root, &fake, "t");
        assert!(!ok, "{log:?}");
        assert!(log.join("\n").contains("nothing migrated"), "{log:?}");
        assert!(!exact(&fake, &admin(&["migrate"])));
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
        assert!(ok && log[0].contains("Setup is running"), "{log:?}");
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
