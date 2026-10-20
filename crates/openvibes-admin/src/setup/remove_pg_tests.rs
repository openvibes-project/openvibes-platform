//! Remove everything's PostgreSQL removal against the fake runner.
use platform_host::{RemoveStep, StepState};

use super::{PG, args, run};
use crate::setup::{
    fake::{Fake, plan},
    plan::Component::*,
};

const REC: &str = "/etc/openvibes/setup-installed-postgresql";
const OTHERS: [&str; 4] = ["/usr/sbin/runuser", "-u", "postgres", "--"];

fn others_query() -> Vec<&'static str> {
    [&OTHERS[..], &["/usr/bin/psql", "-Atqc", "SELECT datname FROM pg_database WHERE datname NOT IN ('postgres','template0','template1','openvibes')"]].concat()
}

/// A host where Remove everything's Purge runs; `others` is what the
/// cluster lists besides openvibes and the system databases.
fn purge_pg(name: &str, recorded: bool, others: &str, everything: bool) -> (Fake, StepState) {
    purge_pg_with(Fake::new(name), recorded, others, everything)
}

fn purge_pg_on(fake: Fake, others: &str) -> (Fake, StepState) {
    purge_pg_with(fake, true, others, true)
}

fn purge_pg_with(fake: Fake, recorded: bool, others: &str, everything: bool) -> (Fake, StepState) {
    fake.file("/etc/openvibes/setup.toml", "plan");
    if recorded {
        fake.file(
            REC,
            "postgresql-server\npostgresql\npostgresql-private-libs\n",
        );
    }
    fake.file("/var/lib/pgsql/data/PG_VERSION", "17\n");
    fake.answer(&others_query(), 0, others);
    fake.answer(&[&PG[..], &["/usr/bin/psql"]].concat(), 0, "");
    fake.answer(&[&PG[..], &["/usr/bin/dropdb"]].concat(), 0, "");
    fake.answer(&["/usr/sbin/userdel"], 0, "");
    fake.answer(&["/usr/sbin/groupdel"], 0, "");
    fake.answer(
        &["/usr/bin/rpm", "-q", "--quiet", "postgresql-server"],
        0,
        "",
    );
    fake.answer(&["/usr/bin/rpm", "-q", "--quiet", "postgresql"], 0, "");
    fake.answer(
        &["/usr/bin/rpm", "-q", "--quiet", "postgresql-private-libs"],
        0,
        "",
    );
    fake.answer(&["/usr/bin/rpm", "-e"], 0, "");
    fake.answer(&["/usr/bin/systemctl", "disable"], 0, "");
    let plan = plan(&[Ingest]);
    let confirm = everything.then_some("platform.example.com");
    let state = run(
        &fake.ctx(&plan),
        RemoveStep::Purge,
        &args(&[Ingest], confirm),
    );
    (fake, state)
}

#[test]
fn postgresql_setup_installed_goes_when_nothing_else_uses_it() {
    let (fake, state) = purge_pg("pg-gone", true, "", true);
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
    assert!(fake.called(&["/usr/bin/systemctl", "disable", "--now", "postgresql"]));
    assert!(fake.called(&["/usr/bin/rpm", "-e", "postgresql-server"]));
    let removed = fake.call(&["/usr/bin/rpm", "-e"]);
    assert!(
        removed.contains(&"postgresql-private-libs".to_owned()),
        "{removed:?}"
    );
    assert!(
        !fake.called(&["/usr/bin/dnf"]),
        "dependants are not removed silently"
    );
    assert!(
        !fake.root.join("var/lib/pgsql").exists(),
        "the data folder goes"
    );
    assert!(!fake.root.join(REC.trim_start_matches('/')).exists());
    assert!(state.detail().contains("PostgreSQL removed"), "{state:?}");
}

#[test]
fn postgresql_stays_when_another_database_exists() {
    let (fake, state) = purge_pg("pg-others", true, "wiki\nblog\n", true);
    assert!(!fake.called(&["/usr/bin/rpm", "-e"]));
    assert!(fake.root.join("var/lib/pgsql/data/PG_VERSION").exists());
    assert!(state.detail().contains("2 other databases"), "{state:?}");
}

#[test]
fn postgresql_stays_without_the_record() {
    let (fake, state) = purge_pg("pg-unrecorded", false, "", true);
    assert!(!fake.called(&["/usr/bin/rpm", "-e"]));
    assert!(fake.root.join("var/lib/pgsql").exists());
    assert!(
        state
            .detail()
            .contains("Setup has no record of installing PostgreSQL; it stays"),
        "{state:?}"
    );
}

#[test]
fn postgresql_stays_on_keep_data() {
    let (fake, state) = purge_pg("pg-keep", true, "", false);
    assert!(matches!(state, StepState::Skipped(_)), "{state:?}");
    assert!(!fake.called(&["/usr/bin/rpm", "-e"]));
    assert!(fake.root.join(REC.trim_start_matches('/')).exists());
}

/// Another package needs PostgreSQL (postgresql-upgrade, say): it stays and
/// Purge finishes, instead of failing at every retry (review I1).
#[test]
fn postgresql_stays_when_another_package_needs_it() {
    let fake = Fake::new("pg-needed");
    fake.file("/etc/openvibes/setup.toml", "plan");
    fake.file(REC, "postgresql-server\n");
    fake.answer(&others_query(), 0, "");
    fake.answer(&[&PG[..], &["/usr/bin/psql"]].concat(), 0, "");
    fake.answer(&[&PG[..], &["/usr/bin/dropdb"]].concat(), 0, "");
    fake.answer(&["/usr/sbin/userdel"], 0, "");
    fake.answer(&["/usr/sbin/groupdel"], 0, "");
    fake.answer(
        &["/usr/bin/rpm", "-q", "--quiet", "postgresql-server"],
        0,
        "",
    );
    fake.fail(
        &["/usr/bin/rpm", "-e", "--test"],
        "needed by postgresql-upgrade",
    );
    let plan = plan(&[Ingest]);
    let state = run(
        &fake.ctx(&plan),
        RemoveStep::Purge,
        &args(&[Ingest], Some("platform.example.com")),
    );
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
    assert!(state.detail().contains("PostgreSQL stays"), "{state:?}");
    assert!(state.detail().contains("postgresql-upgrade"), "{state:?}");
    assert!(!fake.called(&["/usr/bin/systemctl", "disable"]));
    assert!(!fake.root.join(MARK.trim_start_matches('/')).exists());
}

/// A mark left from an old removal, with PostgreSQL back in use (Setup
/// re-run): the cluster answers, so every check runs again (review I2).
#[test]
fn a_stale_mark_never_skips_the_other_databases_check() {
    let fake = Fake::new("pg-stale-mark");
    fake.file(MARK, "removing\n");
    let (fake, state) = purge_pg_on(fake, "wiki\n");
    assert!(
        fake.called(&[&PG[..], &["/usr/bin/dropdb"]].concat()),
        "openvibes is dropped"
    );
    assert!(!fake.called(&["/usr/bin/rpm", "-e"]));
    assert!(fake.root.join("var/lib/pgsql/data/PG_VERSION").exists());
    assert!(state.detail().contains("1 other database"), "{state:?}");
    assert!(
        !fake.root.join(MARK.trim_start_matches('/')).exists(),
        "the stale mark goes"
    );
}

const MARK: &str = "/etc/openvibes/postgresql-removing";

/// Purge with the cluster unreachable (as after a half-done removal): every
/// database query fails, and the retry must finish anyway.
fn resume(name: &str, server_installed: bool) -> (Fake, StepState) {
    let fake = Fake::new(name);
    fake.file("/etc/openvibes/setup.toml", "plan");
    fake.file(REC, "postgresql-server\npostgresql\n");
    fake.file(MARK, "removing\n");
    fake.file("/var/lib/pgsql/data/PG_VERSION", "17\n");
    let rpm_q = if server_installed { 0 } else { 1 };
    fake.answer(
        &["/usr/bin/rpm", "-q", "--quiet", "postgresql-server"],
        rpm_q,
        "",
    );
    fake.answer(&["/usr/bin/rpm", "-q", "--quiet", "postgresql"], rpm_q, "");
    fake.answer(&["/usr/bin/rpm", "-e"], 0, "");
    fake.answer(&["/usr/bin/systemctl", "disable"], 0, "");
    fake.answer(&["/usr/sbin/userdel"], 0, "");
    fake.answer(&["/usr/sbin/groupdel"], 0, "");
    // Everything else, the database tools included, fails.
    let plan = plan(&[Ingest]);
    let state = run(
        &fake.ctx(&plan),
        RemoveStep::Purge,
        &args(&[Ingest], Some("platform.example.com")),
    );
    (fake, state)
}

fn finished_pg(fake: &Fake, state: &StepState) {
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
    // The cluster is down: the probes fail and nothing is dropped.
    assert!(
        !fake.called(&[&PG[..], &["/usr/bin/dropdb"]].concat()),
        "nothing dropped on a retry"
    );
    for gone in [
        "var/lib/pgsql",
        "etc/openvibes/postgresql-removing",
        "etc/openvibes/setup-installed-postgresql",
    ] {
        assert!(!fake.root.join(gone).exists(), "{gone}");
    }
    assert!(fake.root.join("etc/openvibes/setup.toml").exists());
    assert!(state.detail().contains("PostgreSQL removed"), "{state:?}");
}

/// The service was disabled, then `rpm -e` failed.
#[test]
fn a_retry_after_the_service_stopped_but_the_package_stayed_finishes() {
    let (fake, state) = resume("pg-resume-1", true);
    finished_pg(&fake, &state);
    assert!(fake.called(&["/usr/bin/rpm", "-e", "postgresql-server", "postgresql"]));
}

/// The package went, then the data folder or the record could not.
#[test]
fn a_retry_after_the_package_went_finishes() {
    let (fake, state) = resume("pg-resume-2", false);
    finished_pg(&fake, &state);
    assert!(!fake.called(&["/usr/bin/rpm", "-e"]));
    assert!(!fake.called(&["/usr/bin/systemctl"]));
}

/// A first run that fails at the real removal leaves the mark for the retry.
#[test]
fn a_failed_package_removal_leaves_the_mark() {
    let fake = Fake::new("pg-mark");
    fake.file("/etc/openvibes/setup.toml", "plan");
    fake.file(REC, "postgresql-server\n");
    fake.answer(&[&PG[..], &["/usr/bin/psql", "-Atqc", "SELECT datname FROM pg_database WHERE datname NOT IN ('postgres','template0','template1','openvibes')"]].concat(), 0, "");
    fake.answer(&[&PG[..], &["/usr/bin/psql"]].concat(), 0, "");
    fake.answer(&[&PG[..], &["/usr/bin/dropdb"]].concat(), 0, "");
    fake.answer(&["/usr/sbin/userdel"], 0, "");
    fake.answer(&["/usr/sbin/groupdel"], 0, "");
    fake.answer(
        &["/usr/bin/rpm", "-q", "--quiet", "postgresql-server"],
        0,
        "",
    );
    fake.answer(&["/usr/bin/systemctl", "disable"], 0, "");
    fake.answer(&["/usr/bin/rpm", "-e", "--test"], 0, "");
    fake.fail(&["/usr/bin/rpm", "-e", "postgresql-server"], "locked");
    let plan = plan(&[Ingest]);
    let state = run(
        &fake.ctx(&plan),
        RemoveStep::Purge,
        &args(&[Ingest], Some("platform.example.com")),
    );
    assert!(matches!(state, StepState::Failed(_)), "{state:?}");
    assert!(fake.root.join(MARK.trim_start_matches('/')).exists());
    assert!(fake.root.join(REC.trim_start_matches('/')).exists());
}

/// A record without the Fedora server package (a PGDG cluster, say) never
/// deletes a data folder.
#[test]
fn a_stale_record_deletes_nothing() {
    let fake = Fake::new("pg-stale");
    fake.file("/etc/openvibes/setup.toml", "plan");
    fake.file(REC, "postgresql-server\n");
    fake.file("/var/lib/pgsql/16/data/PG_VERSION", "16\n");
    fake.answer(&["/usr/sbin/userdel"], 0, "");
    fake.answer(&["/usr/sbin/groupdel"], 0, "");
    let plan = plan(&[Ingest]);
    let state = run(
        &fake.ctx(&plan),
        RemoveStep::Purge,
        &args(&[Ingest], Some("platform.example.com")),
    );
    // No server and no mark: nothing to drop, the record goes, the data stays.
    assert!(state.detail().contains("no PostgreSQL server"), "{state:?}");
    assert!(fake.root.join("var/lib/pgsql/16/data/PG_VERSION").exists());
    assert!(!fake.root.join(REC.trim_start_matches('/')).exists());
    assert!(!fake.called(&["/usr/bin/rpm", "-e"]));
    assert!(!fake.called(&[&PG[..], &["/usr/bin/psql"]].concat()));
}

fn update_mark(fake: &Fake) {
    fake.file("/run/openvibes-admin/job", "update");
    fake.answer(
        &["/usr/bin/rpm", "-q", "--quiet", "openvibes-ingest"],
        0,
        "",
    );
    fake.answer(&["/usr/bin/systemctl", "disable", "--now"], 0, "");
}

#[test]
fn an_uninstall_runs_after_a_half_done_update() {
    let fake = Fake::new("remove-after-update");
    update_mark(&fake);
    let plan = plan(&[Ingest]);
    let keep = args(&[Ingest], None);
    let backup = run(&fake.ctx(&plan), RemoveStep::Backup, &keep);
    assert!(matches!(backup, StepState::Skipped(_)), "{backup:?}");
    let stop = run(&fake.ctx(&plan), RemoveStep::Stop, &keep);
    assert!(matches!(stop, StepState::Done(_)), "{stop:?}");
    assert_eq!(fake.text("/run/openvibes-admin/job"), "uninstall");
}

#[test]
fn uninstall_after_a_half_done_update_starts_the_agent_again() {
    let fake = Fake::new("remove-after-update-agent");
    update_mark(&fake);
    fake.file("/run/openvibes-admin/update-agent", "");
    fake.file(
        "/run/openvibes-admin/update-active",
        "openvibes-agent.service\n",
    );
    fake.answer(
        &["/usr/bin/systemctl", "start", "openvibes-agent.service"],
        0,
        "",
    );
    let plan = plan(&[Ingest]);
    let stop = run(&fake.ctx(&plan), RemoveStep::Stop, &args(&[Ingest], None));
    assert!(matches!(stop, StepState::Done(_)), "{stop:?}");
    assert!(fake.called(&["/usr/bin/systemctl", "start", "openvibes-agent.service"]));
    assert!(!fake.root.join("run/openvibes-admin/update-active").exists());
    assert!(!fake.root.join("run/openvibes-admin/update-agent").exists());
}

#[test]
fn backup_without_a_server_says_untick_it() {
    let fake = Fake::new("remove-backup-no-server");
    fake.answer(
        &["/usr/bin/rpm", "-q", "--quiet", "postgresql-server"],
        1,
        "",
    );
    let plan = plan(&[Ingest]);
    let mut with = args(&[Ingest], None);
    with.backup = Some("/var/backups/ov-new".into());
    let state = run(&fake.ctx(&plan), RemoveStep::Backup, &with);
    assert!(
        matches!(&state, StepState::Failed(why) if why.contains("PostgreSQL is not installed")
            && why.contains("untick Back up first")),
        "{state:?}"
    );
    assert!(!fake.called(&["/usr/bin/systemctl", "stop"]));
}

#[test]
fn remove_everything_without_a_server_keeps_the_data_folder() {
    let fake = Fake::new("remove-everything-no-server");
    fake.file("/etc/openvibes/setup.toml", "plan");
    fake.file(REC, "postgresql-server\n");
    fake.file("/var/lib/pgsql/data/PG_VERSION", "17\n");
    fake.answer(
        &["/usr/bin/rpm", "-q", "--quiet", "postgresql-server"],
        1,
        "",
    );
    fake.answer(&["/usr/sbin/userdel"], 0, "");
    fake.answer(&["/usr/sbin/groupdel"], 0, "");
    let plan = plan(&[Ingest]);
    let state = run(
        &fake.ctx(&plan),
        RemoveStep::Purge,
        &args(&[Ingest], Some("platform.example.com")),
    );
    assert!(
        matches!(&state, StepState::Done(text) if text.contains(
            "no PostgreSQL server: the database was not dropped and /var/lib/pgsql stays")),
        "{state:?}"
    );
    assert!(!state.detail().contains("database, roles"), "{state:?}");
    assert!(!fake.called(&[&PG[..], &["/usr/bin/psql"]].concat()));
    assert!(!fake.called(&[&PG[..], &["/usr/bin/dropdb"]].concat()));
    assert!(fake.root.join("var/lib/pgsql/data").exists());
    assert!(
        !fake
            .root
            .join("etc/openvibes/setup-installed-postgresql")
            .exists()
    );
}

#[test]
fn abandoning_an_update_between_stop_and_start_starts_only_the_agent() {
    let fake = Fake::new("remove-after-update-no-pending");
    update_mark(&fake);
    fake.file(
        "/run/openvibes-admin/update-active",
        "openvibes-agent.service\nopenvibes-ingest.service\n",
    );
    fake.answer(
        &["/usr/bin/systemctl", "start", "openvibes-agent.service"],
        0,
        "",
    );
    let plan = plan(&[Ingest]);
    let stop = run(&fake.ctx(&plan), RemoveStep::Stop, &args(&[Ingest], None));
    assert!(matches!(stop, StepState::Done(_)), "{stop:?}");
    assert!(fake.called(&["/usr/bin/systemctl", "start", "openvibes-agent.service"]));
    assert!(!fake.called(&["/usr/bin/systemctl", "start", "openvibes-ingest.service"]));
    assert!(!fake.root.join("run/openvibes-admin/update-active").exists());
}
