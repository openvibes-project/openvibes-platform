//! `openvibes-admin agent`: list, show, revoke, all audited.
// The test starts the CLI binary it verifies; this is not shipped code.
#![allow(clippy::disallowed_types)]

mod common;

use chrono::{Duration, Utc};
use common::{Fixture, stdout};

const RECENT: &str = "agent.00000000-0000-4000-8000-000000000001";
const SILENT: &str = "agent.00000000-0000-4000-8000-000000000002";
const REVOKED: &str = "agent.00000000-0000-4000-8000-000000000003";
const UNKNOWN: &str = "agent.00000000-0000-4000-8000-000000000009";

async fn seeded() -> Fixture {
    let fixture = Fixture::create().await;
    stdout(&fixture.run(&["migrate"]));
    let pool = platform_store::connect(&fixture.url).await.unwrap();
    let client = pool.get().await.unwrap();
    let now = Utc::now();
    for (id, status, seen) in [
        (RECENT, "active", now - Duration::minutes(1)),
        (SILENT, "active", now - Duration::minutes(16)),
        (REVOKED, "revoked", now - Duration::days(2)),
    ] {
        client
            .execute(
                "INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at, scanner_version)
                 VALUES ($1, $2, $3, $4, '0.1.0')",
                &[&id, &status, &(now - Duration::days(3)), &seen],
            )
            .await
            .unwrap();
    }
    fixture
}

fn ids(output: &str) -> Vec<&str> {
    output
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .collect()
}

#[tokio::test]
async fn agents_are_listed_and_shown() {
    let fixture = seeded().await;
    assert_eq!(
        ids(&stdout(&fixture.run(&["agent", "list"]))),
        [RECENT, SILENT, REVOKED]
    );
    assert_eq!(
        ids(&stdout(&fixture.run(&["agent", "list", "--offline"]))),
        [SILENT]
    );
    assert_eq!(
        ids(&stdout(&fixture.run(&["agent", "list", "--revoked"]))),
        [REVOKED]
    );
    let shown = stdout(&fixture.run(&["agent", "show", RECENT]));
    for line in [
        format!("agent {RECENT}"),
        "status active".into(),
        "version 0.1.0".into(),
        "certificates 0".into(),
    ] {
        assert!(
            shown.lines().any(|l| l == line),
            "missing {line:?} in {shown}"
        );
    }
    let unknown = fixture.run(&["agent", "show", UNKNOWN]);
    assert!(!unknown.status.success());
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("unknown agent"));
    fixture.drop().await;
}

#[tokio::test]
async fn revocation_outcomes_are_distinct_and_audited() {
    let fixture = seeded().await;
    assert!(
        stdout(&fixture.run(&["agent", "revoke", RECENT])).contains(&format!("revoked {RECENT}"))
    );
    let again = fixture.run(&["agent", "revoke", RECENT]);
    assert!(!again.status.success());
    assert!(String::from_utf8_lossy(&again.stderr).contains("already revoked"));
    let unknown = fixture.run(&["agent", "revoke", UNKNOWN]);
    assert!(!unknown.status.success());
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("unknown agent"));
    let revokes: Vec<(Option<String>, String)> = fixture
        .audit_targets()
        .await
        .into_iter()
        .filter(|row| row.0 == "agent revoke")
        .map(|row| (row.1, row.2))
        .collect();
    assert_eq!(
        revokes,
        [
            (Some(RECENT.to_owned()), "ok".to_owned()),
            (Some(RECENT.to_owned()), "error".to_owned()),
            (Some(UNKNOWN.to_owned()), "error".to_owned()),
        ]
    );
    fixture.drop().await;
}
