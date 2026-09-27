//! Console store writes must work with the least-privilege database role.

mod common;

use chrono::{Duration, Utc};
use common::TestDb;
use platform_store::{
    console_auth::{
        AgentTag, NewConsoleEnrollmentToken, NewServiceToken, apply_agent_tags,
        create_enrollment_token, create_service_account, create_service_token, preview_agent_tags,
        revoke_agent_in_scope, save_asset_group,
    },
    console_read::AgentScope,
    console_triage::{self, TriageUpdate},
    ingest::{self, StoredFinding},
    rules::{self, NewBundle, Published, TrustAdded},
};
use sha2::{Digest, Sha256};

const AGENT: &str = "agent.00000000-0000-4000-8000-000000000091";
const REVOKE_AGENT: &str = "agent.00000000-0000-4000-8000-000000000092";

#[tokio::test]
async fn console_store_writes_work_as_openvibes_console() {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    let now = Utc::now();
    for agent_id in [AGENT, REVOKE_AGENT] {
        client
            .execute(
                "INSERT INTO agents(agent_id,status,enrolled_at) VALUES($1,'active',$2)",
                &[&agent_id, &now],
            )
            .await
            .unwrap();
    }
    platform_store::ensure_partitions(&client, now.date_naive(), 2)
        .await
        .unwrap();
    ingest::store_findings(
        &mut client,
        AGENT,
        &[StoredFinding {
            finding_id: "console-role-finding".into(),
            scan_id: "console-role-scan".into(),
            rule_set_id: "baseline".into(),
            rule_id: "ssh.exposed".into(),
            rule_version: 1,
            observed_at: now - Duration::minutes(1),
            severity: "high".into(),
            confidence: 90,
            message: "SSH is exposed".into(),
            evidence: vec!["port=22".into()],
        }],
        ingest::Origin::Online,
        now,
    )
    .await
    .unwrap();
    assert_eq!(
        rules::add_trust_key(&mut client, "baseline", "org.rules", [1; 32])
            .await
            .unwrap(),
        TrustAdded::Added
    );
    client
        .batch_execute("SET ROLE openvibes_console")
        .await
        .unwrap();

    let group = save_asset_group(
        &mut client,
        None,
        "Production",
        &[AgentTag {
            key: "env".into(),
            value: "prod".into(),
        }],
        "operator",
        now,
    )
    .await
    .unwrap()
    .unwrap();
    save_asset_group(
        &mut client,
        Some(&group.asset_group_id),
        "Production",
        &[AgentTag {
            key: "env".into(),
            value: "production".into(),
        }],
        "operator",
        now,
    )
    .await
    .unwrap()
    .unwrap();

    let enrollment = create_enrollment_token(
        &mut client,
        &NewConsoleEnrollmentToken {
            secret_sha256: &[3; 32],
            label: Some("console-role-test"),
            actor_id: "operator",
            now,
            expires_at: now + Duration::days(1),
            max_uses: 1,
            idempotency_key_sha256: &[4; 32],
            request_sha256: &[5; 32],
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        enrollment,
        platform_store::console_auth::EnrollmentTokenCreation::Created { .. }
    ));

    let service_account = create_service_account(
        &mut client,
        "console-role-test",
        "operator",
        "operator",
        now,
    )
    .await
    .unwrap()
    .unwrap();
    let token = create_service_token(
        &mut client,
        &NewServiceToken {
            service_account_id: &service_account,
            secret_sha256: &[6; 32],
            label: "console-role-test",
            actor_id: "operator",
            now,
            expires_at: now + Duration::days(1),
            idempotency_key_sha256: &[7; 32],
            request_sha256: &[8; 32],
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        token,
        platform_store::console_auth::ServiceTokenCreation::Created { .. }
    ));

    let tags = [AgentTag {
        key: "env".into(),
        value: "prod".into(),
    }];
    let preview = preview_agent_tags(&client, AGENT, &tags)
        .await
        .unwrap()
        .unwrap();
    apply_agent_tags(&mut client, AGENT, &tags, &preview.token, "operator", now)
        .await
        .unwrap();
    assert_eq!(
        revoke_agent_in_scope(
            &mut client,
            REVOKE_AGENT,
            &AgentScope::Global,
            "operator",
            "test",
            now,
        )
        .await
        .unwrap(),
        platform_store::agents::Revoke::Revoked
    );
    assert!(matches!(
        console_triage::update(
            &mut client,
            AGENT,
            "baseline",
            "ssh.exposed",
            0,
            "investigating",
            None,
            None,
            None,
            "operator",
            now,
        )
        .await
        .unwrap(),
        TriageUpdate::Updated(_)
    ));

    let envelope = b"verified-by-console-handler";
    assert_eq!(
        rules::publish(
            &mut client,
            &NewBundle {
                rule_set_id: "baseline",
                version: 1,
                envelope,
                envelope_sha256: Sha256::digest(envelope).into(),
                issuer_key_id: "org.rules",
                created_at_ms: 1,
                expires_at_ms: i64::MAX,
                published_by: "operator",
            },
        )
        .await
        .unwrap(),
        Published::Stored
    );

    drop(client);
    db.drop().await;
}
