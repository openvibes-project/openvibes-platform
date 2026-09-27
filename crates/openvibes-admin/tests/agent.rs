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
const IMPORTED: &str = "import.inst-1";

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
    client
        .execute(
            "INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at, scanner_version,
                 claimed_agent_id)
             VALUES ($1, 'imported', $2, $2, '0.1.0', $3)",
            &[&IMPORTED, &(now - Duration::days(30)), &RECENT],
        )
        .await
        .unwrap();
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
        [RECENT, SILENT, REVOKED, IMPORTED]
    );
    assert_eq!(
        ids(&stdout(&fixture.run(&["agent", "list", "--imported"]))),
        [IMPORTED]
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

#[tokio::test]
async fn imported_hosts_are_shown_and_cannot_be_revoked() {
    let fixture = seeded().await;
    let listed = stdout(&fixture.run(&["agent", "list", "--imported"]));
    assert!(
        listed.starts_with(&format!("{IMPORTED}  imported  ")),
        "{listed}"
    );
    assert!(listed.contains(&format!("claims {RECENT}")), "{listed}");
    let shown = stdout(&fixture.run(&["agent", "show", IMPORTED]));
    for line in ["status imported".to_owned(), format!("claims {RECENT}")] {
        assert!(
            shown.lines().any(|l| l == line),
            "missing {line:?} in {shown}"
        );
    }
    let revoke = fixture.run(&["agent", "revoke", IMPORTED]);
    assert!(!revoke.status.success());
    assert!(
        String::from_utf8_lossy(&revoke.stderr)
            .contains("imported hosts have no identity to revoke")
    );
    assert_eq!(
        fixture
            .count("SELECT count(*) FROM agents WHERE status = 'imported'")
            .await,
        1
    );
    let status = stdout(&fixture.run(&["status"]));
    assert!(status.lines().any(|l| l == "imported hosts 1"), "{status}");
    fixture.drop().await;
}

const DEGRADED: &str = "agent.00000000-0000-4000-8000-000000000004";

/// P12: adds an active agent whose report says a collector is failing.
async fn with_degraded(fixture: &Fixture) {
    let pool = platform_store::connect(&fixture.url).await.unwrap();
    let client = pool.get().await.unwrap();
    let now = Utc::now();
    let health = serde_json::json!({
        "queue": {"pending": 12, "oldest_pending_age_s": 340, "bytes": 1000,
                  "max_bytes": 268435456, "dropped_total": 0,
                  "rejected_total": {"retention_expired": 2}},
        "last_scan": {"finished_at_unix_ms": now.timestamp_millis() - 60_000, "interval_s": 3600,
                      "rules_evaluated": 42, "rules_unavailable": 1, "rules_failed": 0,
                      "collectors": {"packages": "permission_denied", "ports": "ok"}},
        "rule_sets": [{"id": "baseline", "version": 7,
                       "expires_at_unix_ms": now.timestamp_millis() + 30 * 86_400_000_i64,
                       "refused": null}],
        "storage_errors": 0
    });
    client
        .execute(
            "INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at, scanner_version,
                 health, health_at)
             VALUES ($1, 'active', $2, $3, '0.2.0', $4, $3)",
            &[&DEGRADED, &(now - Duration::days(1)), &now, &health],
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn agent_list_shows_health() {
    let fixture = seeded().await;
    with_degraded(&fixture).await;
    let listed = stdout(&fixture.run(&["agent", "list"]));
    let line = |id: &str| {
        listed
            .lines()
            .find(|l| l.starts_with(id))
            .unwrap()
            .to_owned()
    };
    assert!(line(SILENT).contains("health offline"), "{listed}");
    assert!(line(RECENT).contains("health unknown"), "{listed}");
    assert!(
        line(DEGRADED).contains("health degraded (collector_failing)"),
        "{listed}"
    );
    assert!(
        !line(REVOKED).contains("health"),
        "revoked agents have no health"
    );
    assert_eq!(
        ids(&stdout(
            &fixture.run(&["agent", "list", "--health", "degraded"])
        )),
        [DEGRADED]
    );
}

#[tokio::test]
async fn agent_show_prints_the_report() {
    let fixture = seeded().await;
    with_degraded(&fixture).await;
    let shown = stdout(&fixture.run(&["agent", "show", DEGRADED]));
    for want in [
        "health degraded",
        "reasons collector_failing",
        "queue 12 pending, oldest 340 s, 0 dropped, rejected retention_expired=2",
        "last scan",
        "42 rules (1 unavailable, 0 failed)",
        "collectors packages=permission_denied ports=ok",
        "rule set baseline version 7 expires",
        "storage errors 0",
    ] {
        assert!(shown.contains(want), "missing {want:?} in\n{shown}");
    }
}
