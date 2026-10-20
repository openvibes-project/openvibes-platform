//! Tests for the Update steps.

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
        remember_choice: false,
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
        ["/usr/bin/systemctl", "start", "openvibes-ingest.service"],
        "distribution was stopped before and stays stopped; the agent waits"
    );
    assert!(!fake.root.join("run/openvibes-admin/update-active").exists());

    // Board #111: the agent starts only once the platform answers.
    fake.answer(&["/usr/bin/curl"], 0, "");
    let ready = run(&ctx, UpdateStep::Ready, &UpdateArgs::default());
    assert!(ready.detail().contains("agent started"), "{ready:?}");
    let starts: Vec<Vec<String>> = fake
        .calls
        .borrow()
        .iter()
        .filter(|call| call.get(1).is_some_and(|verb| verb == "start"))
        .cloned()
        .collect();
    assert_eq!(
        starts.last().unwrap(),
        &["/usr/bin/systemctl", "start", "openvibes-agent.service"]
    );
    assert!(!fake.root.join("run/openvibes-admin/update-agent").exists());
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
            "--setopt=openvibes.metadata_expire=0",
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
        remember_choice: false,
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
fn migrate_flattens_multi_line_maintenance_output() {
    let fake = Fake::new("update-migrate-flat");
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
        remember_choice: false,
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
        remember_choice: false,
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
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(fake.root.join("run/openvibes-admin/job"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(
        mode & 0o777,
        0o644,
        "the TUI reads the mark as the operator"
    );
    let dir_mode = std::fs::metadata(fake.root.join("run/openvibes-admin"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(dir_mode & 0o777, 0o755, "a umask cannot hide the mark");
    assert!(
        refused.contains("Maintenance › Update OpenVIBES"),
        "{refused}"
    );
    assert!(crate::setup::system::job_guard(&fake.root, "update").is_ok());
    assert!(matches!(
        run(&ctx, UpdateStep::Ready, &UpdateArgs::default()),
        StepState::Done(_)
    ));
    assert!(crate::setup::system::job_guard(&fake.root, "setup").is_ok());
}

/// Review of Task 6: after a failed Upgrade the TUI runs Start, then
/// Ready; the agent is running again and the half-done mark is gone.
#[test]
fn a_rescue_of_start_then_ready_leaves_nothing_stopped_or_half_done() {
    let fake = Fake::new("update-rescue-ready");
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
    fake.answer(&["/usr/bin/curl"], 0, "");
    let plan = plan(&[Ingest, Agent]);
    let ctx = fake.ctx(&plan);
    let args = UpdateArgs::default();
    assert!(matches!(
        run(&ctx, UpdateStep::Stop, &args),
        StepState::Done(_)
    ));
    let typo = UpdateArgs {
        repo_dir: Some("/srv/typo".into()),
        ..UpdateArgs::default()
    };
    assert!(matches!(
        run(&ctx, UpdateStep::Upgrade, &typo),
        StepState::Failed(_)
    ));
    assert!(matches!(
        run(&ctx, UpdateStep::Start, &args),
        StepState::Done(_)
    ));
    assert!(!fake.called(&["/usr/bin/systemctl", "start", "openvibes-agent.service"]));
    assert!(matches!(
        run(&ctx, UpdateStep::Ready, &args),
        StepState::Done(_)
    ));
    assert!(fake.called(&["/usr/bin/systemctl", "start", "openvibes-agent.service"]));
    assert!(crate::setup::system::job_guard(&fake.root, "setup").is_ok());
}

/// Reviewer on #157: a failed Start must not leave the agent stopped,
/// and an Update quit before Ready is made good by the next run.
#[test]
fn the_agent_is_never_left_stopped() {
    let fake = Fake::new("update-agent-left");
    fake.file(
        "/run/openvibes-admin/update-active",
        "openvibes-ingest.service\nopenvibes-agent.service\n",
    );
    fake.answer(
        &["/usr/bin/systemctl", "start", "openvibes-agent.service"],
        0,
        "",
    );
    fake.answer(&["/usr/bin/systemctl", "start"], 1, "");
    let plan = plan(&[Ingest, Agent]);
    let ctx = fake.ctx(&plan);
    let state = run(&ctx, UpdateStep::Start, &UpdateArgs::default());
    assert!(matches!(state, StepState::Failed(_)), "{state:?}");
    assert!(
        fake.called(&["/usr/bin/systemctl", "start", "openvibes-agent.service"]),
        "the agent is started even though ingest failed"
    );

    // Quit between Start and Ready: the next run starts the agent first.
    let later = Fake::new("update-agent-resumed");
    later.file("/run/openvibes-admin/update-agent", "\n");
    later.answer(
        &["/usr/bin/systemctl", "start", "openvibes-agent.service"],
        0,
        "",
    );
    later.answer(&["/usr/bin/systemctl", "is-active"], 3, "");
    let ctx = later.ctx(&plan);
    let _ = run(&ctx, UpdateStep::Stop, &UpdateArgs::default());
    assert!(later.called(&["/usr/bin/systemctl", "start", "openvibes-agent.service"]));
    assert!(!later.root.join("run/openvibes-admin/update-agent").exists());
}
