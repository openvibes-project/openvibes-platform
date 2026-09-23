//! Drives the real binary against a fresh database.
// The test starts the CLI binary it verifies; this is not shipped code.
#![allow(clippy::disallowed_types)]

mod common;

use std::process::Command;

use common::{Fixture, row, stdout};

#[tokio::test]
async fn migrate_status_and_maintenance_are_audited() {
    let fixture = Fixture::create().await;
    assert!(stdout(&fixture.run(&["migrate"])).contains("schema version 2"));
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
