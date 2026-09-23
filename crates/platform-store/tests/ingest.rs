//! Ingest queries, run as the least-privilege `openvibes_ingest` role.

mod common;

use chrono::{DateTime, Duration, Utc};
use common::TestDb;
use platform_store::{
    Client, StoreError,
    ingest::{self, Authenticated, Enrolled, IssuedCert, StoredFinding},
    tokens::{self, NewToken},
};

async fn setup() -> (TestDb, String, String) {
    let db = TestDb::create().await;
    let mut admin = db.pool.get().await.unwrap();
    platform_store::migrate(&mut admin).await.unwrap();
    platform_store::ensure_partitions(&admin, Utc::now().date_naive() - Duration::days(2), 9)
        .await
        .unwrap();
    let token = |byte: u8, uses: i32| NewToken {
        token_sha256: [byte; 32],
        label: None,
        created_by: "test".into(),
        expires_at: Utc::now() + Duration::days(1),
        max_uses: uses,
    };
    let single = tokens::create(&admin, &token(1, 1)).await.unwrap();
    let multi = tokens::create(&admin, &token(2, 5)).await.unwrap();
    (db, single, multi)
}

async fn as_ingest(db: &TestDb) -> Client {
    let client = db.pool.get().await.unwrap();
    client
        .batch_execute("SET ROLE openvibes_ingest")
        .await
        .unwrap();
    client
}

fn cert(serial: u8, spki: u8) -> IssuedCert {
    let now = Utc::now();
    IssuedCert {
        serial: [serial | 0x40; 16],
        spki_sha256: [spki; 32],
        not_before: now,
        not_after: now + Duration::days(30),
        chain_pem: vec![format!("LEAF {serial}"), "INTERMEDIATE".into()],
    }
}

fn issued(serial: u8, spki: u8) -> impl FnOnce(&str) -> Result<IssuedCert, StoreError> {
    move |agent_id: &str| {
        assert!(agent_id.starts_with("agent.") && agent_id.len() == 42);
        Ok(cert(serial, spki))
    }
}

#[tokio::test]
async fn enrollment_is_new_then_existing_then_exhausted() {
    let (db, single, _) = setup().await;
    let mut client = as_ingest(&db).await;
    let now = Utc::now();
    let Enrolled::New(first) = ingest::enroll(&mut client, &single, [9; 32], now, issued(1, 9))
        .await
        .unwrap()
    else {
        panic!("expected a new identity");
    };
    assert_eq!(first.chain_pem, ["LEAF 1", "INTERMEDIATE"]);
    let Enrolled::Existing(again) =
        ingest::enroll(&mut client, &single, [9; 32], now, issued(2, 9))
            .await
            .unwrap()
    else {
        panic!("a retry with the same key must return the same identity");
    };
    assert_eq!(
        (again.agent_id.as_str(), again.chain_pem.clone()),
        (first.agent_id.as_str(), first.chain_pem.clone())
    );
    assert!(matches!(
        ingest::enroll(&mut client, &single, [8; 32], now, issued(3, 8))
            .await
            .unwrap(),
        Enrolled::Exhausted
    ));
    let audit: i64 = db
        .pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT count(*) FROM audit_log WHERE action = 'enroll'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(audit, 1);
    drop(client);
    db.drop().await;
}

#[tokio::test]
async fn concurrent_enrollments_with_a_single_use_token_yield_one_identity() {
    let (db, single, _) = setup().await;
    let (mut a, mut b) = (as_ingest(&db).await, as_ingest(&db).await);
    let now = Utc::now();
    let (x, y) = tokio::join!(
        ingest::enroll(&mut a, &single, [5; 32], now, issued(5, 5)),
        ingest::enroll(&mut b, &single, [6; 32], now, issued(6, 6)),
    );
    let outcomes = [x.unwrap(), y.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| matches!(o, Enrolled::New(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| matches!(o, Enrolled::Exhausted))
            .count(),
        1
    );
    drop((a, b));
    db.drop().await;
}

#[tokio::test]
async fn authentication_needs_serial_and_key_and_an_active_agent() {
    let (db, _, multi) = setup().await;
    let mut client = as_ingest(&db).await;
    let now = Utc::now();
    let Enrolled::New(identity) = ingest::enroll(&mut client, &multi, [7; 32], now, issued(7, 7))
        .await
        .unwrap()
    else {
        panic!();
    };
    let serial = cert(7, 7).serial;
    assert_eq!(
        ingest::authenticate(&client, &serial, [7; 32])
            .await
            .unwrap(),
        Authenticated::Active(identity.agent_id.clone())
    );
    assert_eq!(
        ingest::authenticate(&client, &serial, [8; 32])
            .await
            .unwrap(),
        Authenticated::Unknown
    );
    assert_eq!(
        ingest::authenticate(&client, &[0x41; 16], [7; 32])
            .await
            .unwrap(),
        Authenticated::Unknown
    );
    let renewed = cert(17, 17);
    ingest::add_certificate(&client, &identity.agent_id, &renewed, now)
        .await
        .unwrap();
    assert_eq!(
        ingest::authenticate(&client, &renewed.serial, [17; 32])
            .await
            .unwrap(),
        Authenticated::Active(identity.agent_id.clone())
    );
    let admin = db.pool.get().await.unwrap();
    platform_store::agents::revoke(&admin, &identity.agent_id, now)
        .await
        .unwrap();
    assert_eq!(
        ingest::authenticate(&client, &serial, [7; 32])
            .await
            .unwrap(),
        Authenticated::Revoked
    );
    drop((client, admin));
    db.drop().await;
}

fn finding(id: &str, rule: &str, observed: DateTime<Utc>) -> StoredFinding {
    StoredFinding {
        finding_id: id.into(),
        scan_id: "scan.1".into(),
        rule_id: rule.into(),
        rule_version: 1,
        observed_at: observed,
        severity: "medium".into(),
        confidence: 90,
        message: "m".into(),
        evidence: vec!["process.names".into()],
    }
}

#[tokio::test]
async fn heartbeats_are_throttled_and_findings_stored_once() {
    let (db, _, multi) = setup().await;
    let mut client = as_ingest(&db).await;
    let now = Utc::now();
    let Enrolled::New(identity) = ingest::enroll(&mut client, &multi, [3; 32], now, issued(3, 3))
        .await
        .unwrap()
    else {
        panic!();
    };
    let id = identity.agent_id.as_str();
    assert!(
        ingest::heartbeat(&client, id, "0.1.0", &["scan".into()], now)
            .await
            .unwrap()
    );
    assert!(
        !ingest::heartbeat(&client, id, "0.1.1", &[], now + Duration::minutes(1))
            .await
            .unwrap()
    );
    assert!(
        ingest::heartbeat(&client, id, "0.1.2", &[], now + Duration::minutes(6))
            .await
            .unwrap()
    );

    let batch = [
        finding("f.1", "r.a", now - Duration::hours(2)),
        finding("f.2", "r.a", now - Duration::hours(1)),
        finding("f.3", "r.b", now - Duration::days(1)),
    ];
    assert_eq!(
        ingest::store_findings(&mut client, id, &batch, now)
            .await
            .unwrap(),
        3
    );
    assert_eq!(
        ingest::store_findings(&mut client, id, &batch, now)
            .await
            .unwrap(),
        0
    );
    let admin = db.pool.get().await.unwrap();
    let count: i64 = admin
        .query_one("SELECT count(*) FROM findings", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 3);
    let latest: String = admin
        .query_one(
            "SELECT last_finding_id FROM current_findings WHERE rule_id = 'r.a'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(latest, "f.2");
    let version: String = admin
        .query_one("SELECT scanner_version FROM agents", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(version, "0.1.2");
    drop((client, admin));
    db.drop().await;
}
