//! Drives the real binary against a fresh database.
// The test starts the CLI binary it verifies; this is not shipped code.
#![allow(clippy::disallowed_types)]

mod common;

use std::process::Command;

use chrono::Utc;
use common::{Fixture, row, stdout};
use platform_store::console_auth::{NewLocalUser, create_local_user, credential_by_username};

#[tokio::test]
async fn migrate_status_and_maintenance_are_audited() {
    let fixture = Fixture::create().await;
    assert!(stdout(&fixture.run(&["migrate"])).contains(&format!(
        "schema version {}",
        platform_store::SCHEMA_VERSION
    )));
    let status = stdout(&fixture.run(&["status"]));
    for line in [
        "agents active 0",
        "agents offline 0",
        "agents revoked 0",
        "tokens usable 0",
        "partitions none",
    ] {
        assert!(
            status.lines().any(|l| l == line),
            "missing {line:?} in {status}"
        );
    }
    // The whole retention window gets partitions, so any finding an agent may
    // still deliver has a home: 90 days back to 7 days ahead.
    assert!(stdout(&fixture.run(&["maintenance"])).contains("created 98 partitions, dropped 0"));
    let today = chrono::Utc::now().date_naive();
    let window = format!(
        "partitions {}..{}",
        today - chrono::Duration::days(90),
        today + chrono::Duration::days(7)
    );
    let status = stdout(&fixture.run(&["status"]));
    assert!(
        status.lines().any(|l| l == window),
        "missing {window:?} in {status}"
    );
    assert_eq!(
        fixture.audit().await,
        [
            row("migrate", "ok"),
            row("status", "ok"),
            row("maintenance", "ok"),
            row("status", "ok"),
        ]
    );
    fixture.drop().await;
}

#[tokio::test]
async fn a_failing_command_is_still_audited() {
    let fixture = Fixture::create().await;
    stdout(&fixture.run(&["migrate"]));
    let pool = platform_store::connect(&fixture.url).await.unwrap();
    pool.get()
        .await
        .unwrap()
        .batch_execute("UPDATE schema_version SET version = 99")
        .await
        .unwrap();
    let output = fixture.run(&["status"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("newer"));
    assert_eq!(
        fixture.audit().await,
        [row("migrate", "ok"), row("status", "error")]
    );
    fixture.drop().await;
}

#[tokio::test]
async fn an_out_of_range_retention_is_refused_before_any_change() {
    let fixture = Fixture::create().await;
    stdout(&fixture.run(&["migrate"]));
    for bad in ["0", "36501", "4294967295"] {
        let output = fixture.run(&["maintenance", "--retention-days", bad]);
        assert_eq!(output.status.code(), Some(2), "{bad}");
    }
    assert!(
        stdout(&fixture.run(&["status"]))
            .lines()
            .any(|l| l == "partitions none")
    );
    fixture.drop().await;
}

#[tokio::test]
async fn the_audit_actor_is_the_real_uid_even_without_user() {
    use std::os::unix::fs::MetadataExt;
    let fixture = Fixture::create().await;
    let output = Command::new(env!("CARGO_BIN_EXE_openvibes-admin"))
        .arg("--config")
        .arg(&fixture.config)
        .arg("migrate")
        .env_remove("USER")
        .output()
        .unwrap();
    assert!(output.status.success());
    let uid = std::fs::metadata("/proc/self").unwrap().uid();
    assert_eq!(fixture.audit().await[0].0, format!("uid {uid}"));
    fixture.drop().await;
}

#[tokio::test]
async fn status_and_maintenance_on_an_unmigrated_database_say_to_migrate() {
    let fixture = Fixture::create().await;
    for command in [&["status"][..], &["maintenance"][..]] {
        let output = fixture.run(command);
        assert!(!output.status.success(), "{command:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("run openvibes-admin migrate"),
            "{command:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    fixture.drop().await;
}

#[tokio::test]
async fn a_command_run_through_sudo_names_the_person_in_the_audit() {
    let fixture = Fixture::create().await;
    stdout(&fixture.run_with(&["migrate"], &[("SUDO_USER", "alice")]));
    let audit = fixture.audit().await;
    assert!(
        audit[0].0.starts_with("ov-test (uid ") && audit[0].0.ends_with(" via sudo by alice"),
        "{}",
        audit[0].0
    );
    fixture.drop().await;
}

#[tokio::test]
async fn local_user_list_and_disable_use_the_real_cli_and_audit() {
    let fixture = Fixture::create().await;
    stdout(&fixture.run(&["migrate"]));
    let mut client = platform_store::connect(&fixture.url)
        .await
        .unwrap()
        .get()
        .await
        .unwrap();
    create_local_user(
        &mut client,
        &NewLocalUser {
            user_id: "11111111-1111-4111-8111-111111111111",
            binding_id: "22222222-2222-4222-8222-222222222222",
            username: "alice",
            display_name: "Alice Example",
            password_phc: "$argon2id$v=19$m=19456,t=2,p=1$opaque-salt$opaque-hash",
            role_id: "admin",
            actor_id: "test-bootstrap",
            now: Utc::now(),
        },
    )
    .await
    .unwrap();
    drop(client);

    let listing = stdout(&fixture.run(&["user", "list"]));
    assert!(
        listing
            .lines()
            .any(|line| { line == "alice\tenabled\tadmin\tAlice Example\tnever" })
    );
    assert!(!listing.contains("opaque-hash"));
    assert!(
        stdout(&fixture.run(&["user", "disable", "ALICE"])).contains("disabled local user alice")
    );
    let disabled = credential_by_username(
        &platform_store::connect(&fixture.url)
            .await
            .unwrap()
            .get()
            .await
            .unwrap(),
        "alice",
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!disabled.enabled);
    assert_eq!(
        fixture.audit_targets().await,
        [
            ("migrate".into(), None, "ok".into()),
            (
                "user.created".into(),
                Some("alice".into()),
                "success".into()
            ),
            ("user.list".into(), None, "ok".into()),
            (
                "user.disabled".into(),
                Some("11111111-1111-4111-8111-111111111111".into()),
                "success".into()
            ),
            ("user.disable".into(), Some("alice".into()), "ok".into()),
        ]
    );
    fixture.drop().await;
}
