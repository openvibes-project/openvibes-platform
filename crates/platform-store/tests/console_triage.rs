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
        detection: None,
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
        ingest::Origin::Online,
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
        "open",
        None,
        Some("looking into it"),
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
    assert!(matches!(
        console_triage::update(
            &mut client,
            AGENT,
            "base",
            "rule-1",
            2,
            "mitigated",
            None,
            Some("mitigation reviewed"),
            None,
            "analyst",
            now + Duration::minutes(1),
        )
        .await
        .unwrap(),
        TriageUpdate::Updated(_)
    ));
    // A result can arrive after mitigation while carrying an observation time
    // from before the analyst's decision. It must not reopen or erase triage.
    ingest::store_findings(
        &mut client,
        AGENT,
        &[observation("finding-queued", now - Duration::seconds(30))],
        ingest::Origin::Online,
        now + Duration::minutes(2),
    )
    .await
    .unwrap();
    let still_mitigated = console_triage::get(&client, AGENT, "base", "rule-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(still_mitigated.state, "mitigated");
    assert_eq!(still_mitigated.version, 3);
    assert_eq!(still_mitigated.note.as_deref(), Some("mitigation reviewed"));

    ingest::store_findings(
        &mut client,
        AGENT,
        &[observation("finding-2", now + Duration::seconds(30))],
        ingest::Origin::Online,
        now + Duration::minutes(3),
    )
    .await
    .unwrap();
    let reopened = console_triage::get(&client, AGENT, "base", "rule-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reopened.state, "open");
    assert_eq!(reopened.version, 4);
    let bulk = console_triage::update_many_with_request_id(
        &mut client,
        "base",
        "rule-1",
        &[(AGENT.to_owned(), reopened.version)],
        &platform_store::console_read::AgentScope::Global,
        "mitigated",
        None,
        Some("patched across the fleet"),
        None,
        "analyst",
        Some("bulk-triage-request-1"),
        now + Duration::minutes(4),
    )
    .await
    .unwrap();
    assert!(matches!(bulk, console_triage::BulkTriageUpdate::Updated(_)));
    // Triage v2: open goes straight to mitigated, and investigating is gone.
    assert!(matches!(
        console_triage::update(
            &mut client,
            AGENT,
            "base",
            "rule-1",
            5,
            "investigating",
            None,
            None,
            None,
            "analyst",
            now + Duration::minutes(5)
        )
        .await
        .unwrap(),
        TriageUpdate::InvalidFields
    ));
    let request_ids: Vec<String> = client
        .query(
            "SELECT request_id FROM audit_log WHERE action = 'finding.triage.changed' AND request_id = 'bulk-triage-request-1'",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(request_ids, vec!["bulk-triage-request-1"]);
    let history:i64=client.query_one("SELECT count(*) FROM console_finding_triage_history WHERE agent_id=$1 AND rule_set_id='base' AND rule_id='rule-1'",&[&AGENT]).await.unwrap().get(0);
    let audit:i64=client.query_one("SELECT count(*) FROM audit_log WHERE action IN ('finding.triage.changed','finding.triage.reopened') AND target_id=$1",&[&format!("{AGENT}:base:rule-1")]).await.unwrap().get(0);
    assert_eq!(history, 5);
    assert_eq!(audit, 5);
    db.drop().await;
}
