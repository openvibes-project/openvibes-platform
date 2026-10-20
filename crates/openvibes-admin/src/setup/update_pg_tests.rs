//! Tests for Update's PostgreSQL check and enabled units (#292).

use platform_host::{StepState, UpdateStep};

use super::{
    UpdateArgs, run,
    tests::{ADMIN, RPM_Q, at, server_removed},
};
use crate::setup::{
    fake::{Fake, plan},
    plan::Component::*,
};

#[test]
fn a_missing_postgresql_stops_the_update_before_anything_stops() {
    let fake = Fake::new("update-pg-gone");
    fake.answer(RPM_Q, 1, "");
    let plan = plan(&[Ingest]);
    let state = run(&fake.ctx(&plan), UpdateStep::Backup, &UpdateArgs::default());
    assert!(
        matches!(&state, StepState::Failed(text) if text.contains("data folder")),
        "{state:?}"
    );
    assert!(!fake.called(&["/usr/bin/systemctl", "stop"]));
    assert!(crate::setup::system::job_guard(&fake.root, "setup").is_ok());
}

#[test]
fn the_backup_step_puts_postgresql_back() {
    let fake = Fake::new("update-pg-backup");
    server_removed(&fake);
    let plan = plan(&[Ingest]);
    let state = run(&fake.ctx(&plan), UpdateStep::Backup, &UpdateArgs::default());
    assert!(
        matches!(&state, StepState::Skipped(text) if text.starts_with("PostgreSQL was missing or stopped") && text.ends_with("no backup chosen")),
        "{state:?}"
    );
    assert!(fake.called(&["/usr/bin/dnf", "install", "-y", "postgresql-server"]));
    assert!(!fake.called(&["/usr/bin/systemctl", "stop"]));
}

#[test]
fn migrate_puts_postgresql_back_first() {
    let fake = Fake::new("update-pg-migrate");
    server_removed(&fake);
    fake.file("run/openvibes-admin/job", "update\n");
    fake.answer(
        &[&ADMIN[..], &["migrate"]].concat(),
        0,
        "schema version 25\n",
    );
    fake.answer(&[&ADMIN[..], &["maintenance"]].concat(), 0, "ok\n");
    let plan = plan(&[Ingest]);
    let state = run(
        &fake.ctx(&plan),
        UpdateStep::Migrate,
        &UpdateArgs::default(),
    );
    assert!(
        matches!(&state, StepState::Done(text) if text.starts_with("PostgreSQL was missing or stopped")),
        "{state:?}"
    );
    assert!(at(&fake, &["/usr/bin/dnf", "install"]) < at(&fake, &ADMIN));
}

#[test]
fn an_enabled_unit_that_was_down_starts_again() {
    let fake = Fake::new("update-enabled-down");
    fake.answer(
        &[
            "/usr/bin/systemctl",
            "is-enabled",
            "--quiet",
            "openvibes-ingest.service",
        ],
        0,
        "",
    );
    fake.answer(&["/usr/bin/systemctl", "is-active"], 3, "");
    fake.answer(&["/usr/bin/systemctl", "is-enabled"], 1, "");
    fake.answer(&["/usr/bin/systemctl", "start"], 0, "");
    let plan = plan(&[Ingest, Distribution]);
    let ctx = fake.ctx(&plan);
    run(&ctx, UpdateStep::Stop, &UpdateArgs::default());
    run(&ctx, UpdateStep::Start, &UpdateArgs::default());
    assert_eq!(
        fake.call(&["/usr/bin/systemctl", "start"]),
        ["/usr/bin/systemctl", "start", "openvibes-ingest.service"]
    );
}
