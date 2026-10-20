//! Tests for Update's database step.

use platform_host::{StepState, UpdateStep};

use super::{
    UpdateArgs, run,
    tests::{ADMIN, healthy},
};
use crate::setup::{
    fake::{Fake, plan},
    plan::Component::*,
};

#[test]
fn migrate_runs_migrate_and_maintenance() {
    let fake = Fake::new("update-migrate");
    healthy(&fake);
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
fn migrate_flattens_multi_line_maintenance_output() {
    let fake = Fake::new("update-migrate-flat");
    healthy(&fake);
    fake.answer(
        &[&ADMIN[..], &["migrate"]].concat(),
        0,
        "schema version 25\n",
    );
    fake.answer(
        &[&ADMIN[..], &["maintenance"]].concat(),
        0,
        "created 0 partitions\nrecorded history for 2 hosts, deleted 0 old rows\n",
    );
    let plan = plan(&[Ingest]);
    let state = run(
        &fake.ctx(&plan),
        UpdateStep::Migrate,
        &UpdateArgs::default(),
    );
    assert_eq!(
        state,
        StepState::Done(
            "schema version 25; created 0 partitions; recorded history for 2 hosts, deleted 0 old rows"
                .into()
        )
    );
}

#[test]
fn migrate_publishes_a_newer_rules_package() {
    let fake = Fake::new("update-rules");
    healthy(&fake);
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
fn a_failing_rules_publish_never_stops_the_update() {
    let fake = Fake::new("update-rules-fail");
    healthy(&fake);
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
        1,
        "openvibes-admin: the envelope expired\n",
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
    // The services still start: Health and Repair show the rules problem.
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
    assert!(
        state.detail().contains("rules not published: "),
        "{state:?}"
    );
}
