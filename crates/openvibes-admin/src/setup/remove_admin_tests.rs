//! The `admin` step and PostgreSQL removal against the fake runner.
use platform_host::{RemoveStep, StepState};

use super::{GPG, GPG6, PG, admin_answers, args, run};
use crate::setup::{
    fake::{Fake, plan},
    plan::Component::*,
};

#[test]
fn the_last_step_removes_the_tool_what_rpm_kept_and_the_repository() {
    let fake = Fake::new("remove-admin-last");
    fake.file("/etc/openvibes/setup.toml", "x");
    fake.file("/etc/openvibes/admin.toml.rpmsave", "x");
    fake.file("/etc/sudoers.d/openvibes-operators.rpmsave", "x");
    fake.file("/etc/sudoers.d/wheel", "not ours");
    fake.file("/var/lib/openvibes-admin/state", "x");
    fake.file("/etc/yum.repos.d/openvibes.repo", "[openvibes]\n");
    fake.file("/etc/yum.repos.d/fedora.repo", "[fedora]\n");
    fake.file("/etc/pki/rpm-gpg/RPM-GPG-KEY-openvibes", "k");
    fake.file("/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-44", "k");
    fake.file("/var/cache/libdnf5/openvibes-0123456789abcdef/x", "c");
    fake.file("/var/cache/libdnf5/fedora-cff72538bc9825a4/x", "c");
    fake.file("/var/backups/openvibes/db.dump", "x");
    fake.file("/var/cache/dnf/openvibes.solv", "c");
    fake.file("/var/cache/dnf/openvibes-filenames.solvx", "c");
    fake.file("/var/cache/dnf/fedora.solv", "c");
    fake.file("/run/openvibes-admin/job", "uninstall");
    fake.file("/run/openvibes-admin/setup.lock", "");
    fake.file(
        "/var/lib/systemd/timers/stamp-openvibes-maintenance.timer",
        "",
    );
    admin_answers(&fake, "openvibes-admin-0.2.8-1.fc44.x86_64\n");
    let plan = plan(&[Ingest, Agent]);
    let state = run(
        &fake.ctx(&plan),
        RemoveStep::Admin,
        &args(&[Ingest, Agent], Some("platform.example.com")),
    );
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
    for gone in [
        "etc/openvibes",
        "var/lib/openvibes-admin",
        "etc/yum.repos.d/openvibes.repo",
        "etc/sudoers.d/openvibes-operators.rpmsave",
        "etc/pki/rpm-gpg/RPM-GPG-KEY-openvibes",
        "var/cache/libdnf5/openvibes-0123456789abcdef",
        "run/openvibes-admin",
        "var/backups/openvibes",
        "var/cache/dnf/openvibes.solv",
        "var/cache/dnf/openvibes-filenames.solvx",
        "var/lib/systemd/timers/stamp-openvibes-maintenance.timer",
    ] {
        assert!(!fake.root.join(gone).exists(), "{gone} left behind");
    }
    for kept in [
        "etc/yum.repos.d/fedora.repo",
        "etc/sudoers.d/wheel",
        "etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-44",
        "var/cache/libdnf5/fedora-cff72538bc9825a4",
        "var/cache/dnf/fedora.solv",
    ] {
        assert!(fake.root.join(kept).exists(), "{kept} is not ours");
    }
    assert_eq!(
        fake.call(&["/usr/bin/rpm", "-e"]),
        ["/usr/bin/rpm", "-e", "gpg-pubkey-7786da36-6a0f1e07"]
    );
    assert!(!fake.called(&["/usr/bin/rpm", "-e", "gpg-pubkey-11111111-1"]));
    let last = fake.calls.borrow().last().cloned().unwrap();
    assert_eq!(
        last,
        ["/usr/bin/rpm", "-e", "openvibes-admin"],
        "the package goes last"
    );
    assert!(
        state.detail().contains("closes"),
        "says what the user sees: {state:?}"
    );
}

#[test]
fn keep_data_removes_the_tool_and_keeps_the_configuration() {
    let fake = Fake::new("remove-admin-keep");
    fake.file("/etc/openvibes/setup.toml", "kept");
    fake.file("/var/lib/openvibes-admin/state", "kept");
    fake.file("/var/backups/openvibes/db.dump", "kept");
    admin_answers(&fake, "");
    let plan = plan(&[Ingest]);
    let state = run(&fake.ctx(&plan), RemoveStep::Admin, &args(&[Ingest], None));
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
    assert!(fake.called(&["/usr/bin/rpm", "-e", "openvibes-admin"]));
    assert!(
        !fake.called(&["/usr/bin/dnf"]),
        "rpm -e refuses on dependants"
    );
    assert_eq!(fake.text("/etc/openvibes/setup.toml"), "kept");
    assert_eq!(fake.text("/var/lib/openvibes-admin/state"), "kept");
    assert!(
        state.detail().contains("kept: /etc/openvibes"),
        "listed: {state:?}"
    );
}

#[test]
fn removing_one_part_leaves_the_administration_tool() {
    let fake = Fake::new("remove-admin-part");
    let plan = plan(&[Ingest, Agent]);
    let state = run(&fake.ctx(&plan), RemoveStep::Admin, &args(&[Agent], None));
    assert!(matches!(state, StepState::Skipped(_)), "{state:?}");
    assert!(!fake.called(&["/usr/bin/dnf"]));
}

#[test]
fn the_repository_stays_while_another_openvibes_package_is_installed() {
    let fake = Fake::new("remove-admin-agent-left");
    fake.file("/etc/yum.repos.d/openvibes.repo", "[openvibes]\n");
    admin_answers(&fake, "openvibes-agent\n");
    let plan = plan(&[Ingest]);
    run(&fake.ctx(&plan), RemoveStep::Admin, &args(&[Ingest], None));
    assert!(fake.root.join("etc/yum.repos.d/openvibes.repo").exists());
    assert!(!fake.called(&["/usr/bin/rpm", "-e", "gpg-pubkey-7786da36-6a0f1e07"]));
}

#[test]
fn purge_keeps_the_plan_so_the_last_step_can_load_it() {
    let fake = Fake::new("purge-keeps-plan");
    fake.file("/etc/openvibes/setup.toml", "plan");
    fake.file("/etc/openvibes/tls/server.pem", "x");
    fake.answer(&[&PG[..], &["/usr/bin/psql"]].concat(), 0, "");
    fake.answer(&[&PG[..], &["/usr/bin/dropdb"]].concat(), 0, "");
    fake.answer(&["/usr/sbin/userdel"], 0, "");
    fake.answer(&["/usr/sbin/groupdel"], 0, "");
    let plan = plan(&[Ingest]);
    let ctx = fake.ctx(&plan);
    let a = args(&[Ingest], Some("platform.example.com"));
    // Running it twice is safe: the second run finds the work done.
    for _ in 0..2 {
        let state = run(&ctx, RemoveStep::Purge, &a);
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
    }
    assert_eq!(fake.text("/etc/openvibes/setup.toml"), "plan");
    assert!(!fake.root.join("etc/openvibes/tls").exists());
}

/// A failed key removal leaves the plan in place and the job marked, and
/// Try again on a host where the package is already gone finishes.
#[test]
fn a_failed_last_step_can_be_run_again() {
    let fake = Fake::new("remove-admin-retry");
    fake.file("/etc/openvibes/setup.toml", "plan");
    fake.file("/etc/yum.repos.d/openvibes.repo", "[openvibes]\n");
    fake.answer(&["/usr/bin/rpm", "-q", "--quiet", "openvibes-admin"], 0, "");
    fake.answer(&["/usr/bin/rpm", "-qa", "openvibes-*"], 0, "");
    fake.answer(&["/usr/bin/rpm", "-q", "gpg-pubkey"], 0, GPG);
    fake.fail(
        &["/usr/bin/rpm", "-e", "gpg-pubkey-7786da36-6a0f1e07"],
        "rpmdb locked",
    );
    fake.answer(&["/usr/bin/rpm", "-e"], 0, "");
    let plan = plan(&[Ingest]);
    let a = args(&[Ingest], Some("platform.example.com"));
    let state = run(&fake.ctx(&plan), RemoveStep::Admin, &a);
    assert!(matches!(state, StepState::Failed(_)), "{state:?}");
    assert!(
        fake.root.join("etc/openvibes/setup.toml").exists(),
        "the plan is needed to retry"
    );
    assert!(!fake.called(&["/usr/bin/rpm", "-e", "openvibes-admin"]));

    // Second run: the package and the key are already gone.
    let again = Fake::new("remove-admin-retry-2");
    again.file("/etc/openvibes/setup.toml", "plan");
    again.answer(&["/usr/bin/rpm", "-qa", "openvibes-*"], 0, "");
    again.answer(
        &["/usr/bin/rpm", "-q", "gpg-pubkey"],
        1,
        "package gpg-pubkey is not installed\n",
    );
    let state = run(&again.ctx(&plan), RemoveStep::Admin, &a);
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
    assert!(!again.called(&["/usr/bin/dnf"]));
    assert!(!again.root.join("etc/openvibes").exists());
}

#[test]
fn a_failed_last_step_keeps_the_job_marked() {
    let fake = Fake::new("remove-admin-mark");
    fake.file("/run/openvibes-admin/job", "uninstall");
    fake.file("/etc/openvibes/setup.toml", "plan");
    fake.answer(&["/usr/bin/rpm", "-q", "--quiet", "openvibes-admin"], 0, "");
    fake.answer(&["/usr/bin/rpm", "-qa", "openvibes-*"], 0, "");
    fake.answer(&["/usr/bin/rpm", "-q", "gpg-pubkey"], 1, "");
    fake.fail(
        &["/usr/bin/rpm", "-e", "openvibes-admin"],
        "needed by openvibes-x",
    );
    let plan = plan(&[Ingest]);
    let state = run(&fake.ctx(&plan), RemoveStep::Admin, &args(&[Ingest], None));
    assert!(matches!(state, StepState::Failed(_)), "{state:?}");
    assert!(
        state.detail().contains("needed by"),
        "refusal shown: {state:?}"
    );
    assert!(fake.root.join("run/openvibes-admin/job").exists());
}

#[test]
fn the_signing_key_is_found_in_the_rpm_6_form() {
    let fake = Fake::new("remove-admin-rpm6");
    fake.answer(&["/usr/bin/rpm", "-q", "gpg-pubkey"], 0, GPG6);
    admin_answers(&fake, "");
    let plan = plan(&[Ingest]);
    run(&fake.ctx(&plan), RemoveStep::Admin, &args(&[Ingest], None));
    let removed: Vec<Vec<String>> = fake
        .calls
        .borrow()
        .iter()
        .filter(|c| c[..2] == ["/usr/bin/rpm", "-e"] && c[2].starts_with("gpg-pubkey"))
        .cloned()
        .collect();
    assert_eq!(removed.len(), 1, "{removed:?}");
    assert_eq!(
        removed[0][2],
        "gpg-pubkey-710ad8afb7afe6e864c0cdc4e134baf37786da36-6a0f1e07"
    );
}

#[test]
fn another_package_keeps_the_repository_and_the_step_says_so() {
    let fake = Fake::new("remove-admin-says");
    admin_answers(&fake, "openvibes-agent-0.2.8-1.fc44.x86_64\n");
    let plan = plan(&[Ingest]);
    let state = run(&fake.ctx(&plan), RemoveStep::Admin, &args(&[Ingest], None));
    assert!(
        state
            .detail()
            .contains("the package repository stays: openvibes-agent"),
        "{state:?}"
    );
    assert!(
        !state.detail().contains("nothing of OpenVIBES remains"),
        "{state:?}"
    );
}

#[test]
fn a_skipped_last_step_keeps_the_lock_file() {
    let fake = Fake::new("remove-admin-skip-lock");
    fake.file("/run/openvibes-admin/setup.lock", "");
    let plan = plan(&[Ingest, Agent]);
    run(&fake.ctx(&plan), RemoveStep::Admin, &args(&[Agent], None));
    assert!(fake.root.join("run/openvibes-admin/setup.lock").exists());
}

const REC: &str = "/etc/openvibes/setup-installed-postgresql";
const OTHERS: [&str; 4] = ["/usr/sbin/runuser", "-u", "postgres", "--"];

fn others_query() -> Vec<&'static str> {
    [&OTHERS[..], &["/usr/bin/psql", "-Atqc", "SELECT datname FROM pg_database WHERE datname NOT IN ('postgres','template0','template1','openvibes')"]].concat()
}

/// A host where Remove everything's Purge runs; `others` is what the
/// cluster lists besides openvibes and the system databases.
fn purge_pg(name: &str, recorded: bool, others: &str, everything: bool) -> (Fake, StepState) {
    let fake = Fake::new(name);
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

/// The record stays until PostgreSQL is gone, so a retry still knows.
#[test]
fn a_refused_postgresql_removal_keeps_the_record_and_the_service() {
    let fake = Fake::new("pg-retry");
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
    fake.fail(&["/usr/bin/rpm", "-e", "--test"], "needed by foo");
    let plan = plan(&[Ingest]);
    let state = run(
        &fake.ctx(&plan),
        RemoveStep::Purge,
        &args(&[Ingest], Some("platform.example.com")),
    );
    assert!(matches!(state, StepState::Failed(_)), "{state:?}");
    assert!(fake.root.join(REC.trim_start_matches('/')).exists());
    assert!(!fake.called(&["/usr/bin/systemctl", "disable"]));
}

const MARK: &str = "/etc/openvibes/postgresql-removing";

/// Purge with the cluster unreachable (as after a half-done removal): any
/// database query would fail, so the retry must not make one.
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
    assert!(!fake.called(&PG), "no database query on a retry");
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
    assert!(state.detail().contains("stale"), "{state:?}");
    assert!(fake.root.join("var/lib/pgsql/16/data/PG_VERSION").exists());
    assert!(!fake.root.join(REC.trim_start_matches('/')).exists());
    assert!(!fake.called(&["/usr/bin/rpm", "-e"]));
}
