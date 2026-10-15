//! A match's end is recorded on the platform's clock (`end_recorded_at`),
//! so the P20 note window never depends on the agent's clock (fix round 2,
//! task 6). Run as the `openvibes-ingest` role.

mod common;

use chrono::{DateTime, Duration, Utc};
use common::TestDb;
use openvibes_core::{
    Confidence, EndedMatch, Finding, FindingChanges, Identifier, SchemaVersion, Severity, hex,
    match_digest,
};
use platform_store::{
    Client,
    finding_changes::{self, NOT_ASSIGNED_NOTE, Outcome, Rows, end_unassigned},
    wire,
};

const A: &str = "agent.00000000-0000-4000-8000-000000000001";
const L1: &str = "hardening-linux-l1";

fn id(value: &str) -> Identifier {
    Identifier::new(value).unwrap()
}

async fn setup() -> (TestDb, Client, Client) {
    let db = TestDb::create().await;
    let mut admin = db.pool.get().await.unwrap();
    platform_store::migrate(&mut admin).await.unwrap();
    platform_store::ensure_partitions(&admin, Utc::now().date_naive() - Duration::days(2), 9)
        .await
        .unwrap();
    admin
        .execute(
            "INSERT INTO agents (agent_id, status, enrolled_at) VALUES ($1, 'active', now())",
            &[&A],
        )
        .await
        .unwrap();
    let ingest = db.pool.get().await.unwrap();
    ingest
        .batch_execute("SET ROLE \"openvibes-ingest\"")
        .await
        .unwrap();
    (db, admin, ingest)
}

fn finding(rule: &str, at: DateTime<Utc>) -> Finding {
    Finding {
        detection: None,
        schema_version: SchemaVersion::V1,
        finding_id: id(&format!("finding.{rule}.{}", at.timestamp_millis())),
        scan_id: id("scan.1"),
        rule_set_id: Some(id(L1)),
        rule_id: id(rule),
        rule_version: 1,
        observed_at_unix_ms: at.timestamp_millis(),
        severity: Severity::High,
        confidence: Confidence::new(100).unwrap(),
        message: format!("{rule} matched"),
        evidence: vec![id("port.tcp.exposed")],
    }
}

/// Applies a P13 change set from `open` to `next` (by rule), the agent's
/// clock at `agent_now`: `next` starts as a replace, the rest end.
async fn change(ingest: &mut Client, open: &[&str], next: &[&str], agent_now: DateTime<Utc>) {
    let make = |rules: &[&str]| -> Vec<Finding> {
        rules
            .iter()
            .map(|rule| finding(rule, agent_now - Duration::hours(3)))
            .collect()
    };
    let (before, after) = (make(open), make(next));
    let started: Vec<Finding> = after
        .iter()
        .filter(|f| !before.contains(f))
        .cloned()
        .collect();
    let changes = FindingChanges {
        schema_version: SchemaVersion::V1,
        agent_id: id(A),
        base_sha256: hex(&match_digest(&before)),
        sha256: hex(&match_digest(&after)),
        replace: false,
        scanned_at_unix_ms: agent_now.timestamp_millis(),
        started: started.clone(),
        changed: Vec::new(),
        ended: before
            .iter()
            .filter(|f| !after.contains(f))
            .map(|f| EndedMatch {
                rule_set_id: id(L1),
                rule_id: f.rule_id.clone(),
                ended_at_unix_ms: agent_now.timestamp_millis(),
            })
            .collect(),
        transient: Vec::new(),
        transient_dropped: 0,
    };
    let days = platform_store::partition_days(ingest).await.unwrap();
    let now = Utc::now();
    let row = |f: &Finding| {
        wire::finding(f, now - Duration::days(90), now + Duration::hours(1), &days).unwrap()
    };
    let rows = Rows {
        started: started.iter().map(row).collect(),
        changed: Vec::new(),
        transient: Vec::new(),
    };
    let outcome = finding_changes::apply(ingest, A, &changes, &rows, now)
        .await
        .unwrap();
    assert_eq!(outcome, Outcome::Stored);
}

/// Ingest stores a report not listing L1 as not assigned, now.
async fn reported(admin: &Client) {
    let health = serde_json::json!({"rule_sets": [{"id": L1, "version": 4}]});
    admin
        .execute(
            "UPDATE agents SET health = $2, health_at = now() WHERE agent_id = $1",
            &[&A, &health],
        )
        .await
        .unwrap();
}

/// The rules that have the not-assigned note, in order.
async fn noted(admin: &Client) -> Vec<String> {
    admin
        .query(
            "SELECT rule_id FROM console_finding_triage_history WHERE note = $1 ORDER BY 1",
            &[&NOT_ASSIGNED_NOTE],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect()
}

/// The lab sequence with the agent's clock `skew` off the platform's: the
/// host fixed `fixed` before the last report; the scan that got the 410
/// ended `x` and `y`. Only those two get the note, once.
async fn sequence(skew: Duration) {
    let (db, admin, mut ingest) = setup().await;
    let agent_now = || Utc::now() + skew;
    change(&mut ingest, &[], &["fixed", "x", "y"], agent_now()).await;
    change(&mut ingest, &["fixed", "x", "y"], &["x", "y"], agent_now()).await;
    reported(&admin).await;
    change(&mut ingest, &["x", "y"], &[], agent_now()).await;
    let sets = [L1.to_owned()];
    assert_eq!(
        end_unassigned(&mut ingest, A, &sets, Utc::now())
            .await
            .unwrap(),
        2
    );
    assert_eq!(noted(&admin).await, ["x", "y"]);
    assert_eq!(
        end_unassigned(&mut ingest, A, &sets, Utc::now())
            .await
            .unwrap(),
        0
    );
    assert_eq!(noted(&admin).await, ["x", "y"]);
    drop((admin, ingest));
    db.drop().await;
}

#[tokio::test]
async fn an_agent_clock_ten_minutes_behind_still_gets_its_notes() {
    sequence(-Duration::minutes(10)).await;
}

#[tokio::test]
async fn an_agent_clock_ten_minutes_ahead_notes_no_earlier_fix() {
    sequence(Duration::minutes(10)).await;
}

async fn recorded(admin: &Client) -> bool {
    admin
        .query_one(
            "SELECT end_recorded_at IS NOT NULL FROM current_findings",
            &[],
        )
        .await
        .unwrap()
        .get(0)
}

#[tokio::test]
async fn a_match_that_starts_again_clears_its_recorded_end() {
    let (db, admin, mut ingest) = setup().await;
    change(&mut ingest, &[], &["x"], Utc::now()).await;
    change(&mut ingest, &["x"], &[], Utc::now()).await;
    assert!(recorded(&admin).await);
    change(&mut ingest, &[], &["x"], Utc::now()).await;
    assert!(!recorded(&admin).await);
    drop((admin, ingest));
    db.drop().await;
}
