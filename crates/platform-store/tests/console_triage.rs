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

/// A triage assignee holds the area's `*.triage` permission through a role
/// that reaches some host (all hosts or a group); reach none does not count.
#[tokio::test]
async fn assignees_need_the_triage_permission_on_some_host() {
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
    client
        .batch_execute(
            "INSERT INTO console_asset_groups (asset_group_id, name, created_at, created_by)
                VALUES ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'lab', now(), 't');
             INSERT INTO console_roles (role_id, display_name, all_hosts) VALUES
                ('nowhere', 'Nowhere', false), ('lab', 'Lab', false), ('reader', 'Reader', true);
             INSERT INTO console_role_groups (role_id, asset_group_id)
                VALUES ('lab', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa');
             INSERT INTO console_role_permissions (role_id, permission_id) VALUES
                ('nowhere', 'compliance.read'), ('nowhere', 'compliance.triage'),
                ('lab', 'compliance.read'), ('lab', 'compliance.triage'),
                ('reader', 'compliance.read');",
        )
        .await
        .unwrap();
    for (n, (name, role)) in [("nora", "nowhere"), ("gail", "lab"), ("rita", "reader")]
        .into_iter()
        .enumerate()
    {
        platform_store::console_auth::create_local_user(
            &mut client,
            &platform_store::console_auth::NewLocalUser {
                user_id: &format!("11111111-1111-4111-8111-11111111111{n}"),
                binding_id: &format!("22222222-2222-4222-8222-22222222222{n}"),
                username: name,
                display_name: name,
                password_phc: "$argon2id$v=19$m=19456,t=2,p=1$opaque-salt$opaque-hash",
                role_id: role,
                actor_id: "test",
                actor_kind: "local_admin",
                password_must_change: false,
                now,
            },
        )
        .await
        .unwrap();
    }
    let assign = |who: &'static str, version: i64| {
        let pool = db.pool.clone();
        async move {
            console_triage::update(
                &mut pool.get().await.unwrap(),
                AGENT,
                "base",
                "rule-1",
                version,
                "open",
                Some(who),
                None,
                None,
                "test",
                Utc::now(),
            )
            .await
            .unwrap()
        }
    };
    for who in ["nora", "rita"] {
        assert!(
            matches!(assign(who, 0).await, TriageUpdate::AssigneeUnavailable),
            "{who}"
        );
    }
    assert!(matches!(assign("gail", 0).await, TriageUpdate::Updated(_)));
    drop(client);
    db.drop().await;
}
