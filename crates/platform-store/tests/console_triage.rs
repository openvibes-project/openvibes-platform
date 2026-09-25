//! Latest-finding triage writes remain versioned and automatically reopen.

mod common;

use chrono::{Duration, Utc};
use common::TestDb;
use platform_store::{
    console_triage::{self, TriageUpdate},
    ingest::{self, StoredFinding},
};

const AGENT: &str = "agent.00000000-0000-4000-8000-000000000099";

fn observation(id: &str, observed_at: chrono::DateTime<Utc>) -> StoredFinding {
    StoredFinding {
        finding_id: id.into(),
        scan_id: format!("scan-{id}"),
        rule_set_id: "base".into(),
        rule_id: "rule-1".into(),
        rule_version: 1,
        observed_at,
        severity: "high".into(),
        confidence: 90,
        message: "observed".into(),
        evidence: vec!["fact=value".into()],
    }
}

#[tokio::test]
async fn stale_writes_are_rejected_and_new_observation_reopens_mitigation() {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    let now = Utc::now();
    client
        .execute(
            "INSERT INTO agents(agent_id,status,enrolled_at) VALUES($1,'active',$2)",
            &[&AGENT, &now],
        )
        .await
        .unwrap();
    platform_store::ensure_partitions(&client, now.date_naive(), 2)
        .await
        .unwrap();
    ingest::store_findings(
        &mut client,
        AGENT,
        &[observation("finding-1", now - Duration::minutes(1))],
        now,
    )
    .await
    .unwrap();
    let default = console_triage::get(&client, AGENT, "base", "rule-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(default.state, "open");
    assert_eq!(default.version, 0);
    let changed = console_triage::update(
        &mut client,
        AGENT,
        "base",
        "rule-1",
        0,
        "investigating",
        None,
        None,
        None,
        "analyst",
        now,
    )
    .await
    .unwrap();
    assert!(matches!(changed, TriageUpdate::Updated(_)));
    assert!(matches!(
        console_triage::update(
            &mut client,
            AGENT,
            "base",
            "rule-1",
            0,
            "mitigated",
            None,
            Some("fixed"),
            None,
            "analyst",
            now
        )
        .await
        .unwrap(),
        TriageUpdate::Stale(_)
    ));
    assert!(matches!(
        console_triage::update(
            &mut client,
            AGENT,
            "base",
            "rule-1",
            1,
            "mitigated",
            None,
            Some("fixed"),
            None,
            "analyst",
            now
        )
        .await
        .unwrap(),
        TriageUpdate::Updated(_)
    ));
    ingest::store_findings(
        &mut client,
        AGENT,
        &[observation("finding-2", now + Duration::minutes(1))],
        now + Duration::minutes(2),
    )
    .await
    .unwrap();
    let reopened = console_triage::get(&client, AGENT, "base", "rule-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reopened.state, "open");
    assert_eq!(reopened.version, 3);
    let history:i64=client.query_one("SELECT count(*) FROM console_finding_triage_history WHERE agent_id=$1 AND rule_set_id='base' AND rule_id='rule-1'",&[&AGENT]).await.unwrap().get(0);
    let audit:i64=client.query_one("SELECT count(*) FROM audit_log WHERE action IN ('finding.triage.changed','finding.triage.reopened') AND target_id=$1",&[&format!("{AGENT}:base:rule-1")]).await.unwrap().get(0);
    assert_eq!(history, 3);
    assert_eq!(audit, 3);
    db.drop().await;
}
