//! Agent listing, inspection, and revocation.

mod common;

use chrono::{Duration, Utc};
use common::TestDb;
use platform_store::agents::{self, Filter, Revoke};

const RECENT: &str = "agent.00000000-0000-4000-8000-000000000001";
const SILENT: &str = "agent.00000000-0000-4000-8000-000000000002";
const REVOKED: &str = "agent.00000000-0000-4000-8000-000000000003";

#[tokio::test]
async fn agents_are_listed_shown_and_revoked() {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
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
    let ids =
        |list: Vec<agents::AgentInfo>| list.into_iter().map(|a| a.agent_id).collect::<Vec<_>>();
    assert_eq!(
        agents::list(&client, Filter::All, now).await.unwrap().len(),
        3
    );
    assert_eq!(
        ids(agents::list(&client, Filter::Offline, now).await.unwrap()),
        [SILENT]
    );
    assert_eq!(
        ids(agents::list(&client, Filter::Revoked, now).await.unwrap()),
        [REVOKED]
    );

    let shown = agents::show(&client, RECENT).await.unwrap().unwrap();
    assert_eq!((shown.status.as_str(), shown.certificates), ("active", 0));
    assert_eq!(shown.scanner_version.as_deref(), Some("0.1.0"));
    assert!(
        agents::show(&client, "agent.unknown")
            .await
            .unwrap()
            .is_none()
    );

    assert_eq!(
        agents::revoke(&client, RECENT, now).await.unwrap(),
        Revoke::Revoked
    );
    assert!(
        agents::show(&client, RECENT)
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_some()
    );
    assert_eq!(
        agents::revoke(&client, RECENT, now).await.unwrap(),
        Revoke::AlreadyRevoked
    );
    assert_eq!(
        agents::revoke(&client, "agent.unknown", now).await.unwrap(),
        Revoke::Unknown
    );
    drop(client);
    db.drop().await;
}

#[tokio::test]
async fn ca_certificates_are_recorded_once() {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    let not_after = Utc::now() + Duration::days(730);
    platform_store::ca::record(&client, "intermediate", [7; 32], "PEM", not_after)
        .await
        .unwrap();
    platform_store::ca::record(&client, "intermediate", [7; 32], "PEM", not_after)
        .await
        .unwrap();
    let listed = platform_store::ca::list(&client).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(
        (listed[0].role.as_str(), listed[0].fingerprint_sha256),
        ("intermediate", [7; 32])
    );
    drop(client);
    db.drop().await;
}
