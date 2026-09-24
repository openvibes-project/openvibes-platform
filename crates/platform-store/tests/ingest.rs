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
async fn a_token_revoked_or_expired_before_the_transaction_enrolls_nothing() {
    let (db, single, multi) = setup().await;
    let admin = db.pool.get().await.unwrap();
    let mut client = as_ingest(&db).await;
    let now = Utc::now();
    // The handler checked the token a moment earlier; then it was revoked.
    tokens::revoke(&admin, &single, now).await.unwrap();
    assert!(matches!(
        ingest::enroll(&mut client, &single, [4; 32], now, issued(4, 4))
            .await
            .unwrap(),
        Enrolled::TokenInvalid
    ));
    // Or it expired in between: `multi` expires in a day.
    let later = now + Duration::days(2);
    assert!(matches!(
        ingest::enroll(&mut client, &multi, [5; 32], later, issued(5, 5))
            .await
            .unwrap(),
        Enrolled::TokenInvalid
    ));
    let agents: i64 = admin
        .query_one("SELECT count(*) FROM agents", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(agents, 0);
    drop((client, admin));
    db.drop().await;
}

#[tokio::test]
async fn a_same_key_retry_never_returns_a_revoked_identity() {
    let (db, _, multi) = setup().await;
    let admin = db.pool.get().await.unwrap();
    let mut client = as_ingest(&db).await;
    let now = Utc::now();
    let Enrolled::New(identity) = ingest::enroll(&mut client, &multi, [6; 32], now, issued(6, 6))
        .await
        .unwrap()
    else {
        panic!();
    };
    platform_store::agents::revoke(&admin, &identity.agent_id, now)
        .await
        .unwrap();
    assert!(matches!(
        ingest::enroll(&mut client, &multi, [6; 32], now, issued(7, 6))
            .await
            .unwrap(),
        Enrolled::AgentRevoked
    ));
    drop((client, admin));
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
        rule_set_id: "baseline".into(),
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
    let beat = |version: &'static str, hostname: Option<&'static str>, minutes: i64| {
        let client = &client;
        async move {
            ingest::heartbeat(
                client,
                id,
                version,
                hostname,
                &[],
                now + Duration::minutes(minutes),
            )
            .await
            .unwrap()
        }
    };
    assert!(beat("0.1.0", Some("host-a"), 0).await);
    assert!(!beat("0.1.1", None, 1).await, "throttled");
    assert!(
        beat("0.1.1", Some("host-b"), 2).await,
        "a new hostname is written at once"
    );
    assert!(
        !beat("0.1.1", Some("host-b"), 3).await,
        "the same hostname stays throttled"
    );
    assert!(beat("0.1.2", None, 8).await);

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
    let row = admin
        .query_one("SELECT scanner_version, hostname FROM agents", &[])
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "0.1.2");
    assert_eq!(
        row.get::<_, Option<String>>(1).as_deref(),
        Some("host-b"),
        "an absent hostname keeps the stored one"
    );
    let indexed: bool = admin
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM pg_indexes
             WHERE tablename = 'agents' AND indexdef LIKE '%hostname%')",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(indexed);
    drop((client, admin));
    db.drop().await;
}

#[tokio::test]
async fn waits_and_statements_are_bounded() {
    let db = TestDb::create().await;
    let pool = platform_store::connect_sized(&db.url(), 1).await.unwrap();
    let held = pool.get().await.unwrap();
    let timeout: String = held
        .query_one("SHOW statement_timeout", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(timeout, "10s");
    let started = std::time::Instant::now();
    assert!(pool.get().await.is_err(), "no connection is free");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(7),
        "the wait is bounded"
    );
    drop(held);
    db.drop().await;
}

#[tokio::test]
async fn the_ingest_role_has_only_the_rights_it_uses() {
    let (db, _, _) = setup().await;
    let client = as_ingest(&db).await;
    for statement in [
        "UPDATE findings SET message = 'x'",
        "UPDATE certificates SET chain_pem = 'x'",
        "UPDATE token_uses SET used_at = now()",
        "UPDATE enrollment_tokens SET revoked_at = now()",
        "SELECT count(*) FROM audit_log",
        "DELETE FROM agents",
        "CREATE TABLE intruder (x int)",
    ] {
        let error = client.batch_execute(statement).await.expect_err(statement);
        assert_eq!(
            error.code(),
            Some(&tokio_postgres::error::SqlState::INSUFFICIENT_PRIVILEGE),
            "{statement}"
        );
    }
    drop(client);
    db.drop().await;
}

#[tokio::test]
async fn current_state_is_kept_per_rule_set() {
    let (db, _, multi) = setup().await;
    let mut client = as_ingest(&db).await;
    let now = Utc::now();
    let Enrolled::New(identity) = ingest::enroll(&mut client, &multi, [8; 32], now, issued(8, 8))
        .await
        .unwrap()
    else {
        panic!();
    };
    // Two rule sets from different issuers both define ssh.root_login.
    let mut other = finding("f.b", "ssh.root_login", now - Duration::minutes(1));
    other.rule_set_id = "vendor".into();
    let batch = [
        finding("f.a", "ssh.root_login", now - Duration::minutes(2)),
        other,
    ];
    ingest::store_findings(&mut client, &identity.agent_id, &batch, now)
        .await
        .unwrap();
    let admin = db.pool.get().await.unwrap();
    let rows: Vec<(String, String)> = admin
        .query(
            "SELECT rule_set_id, last_finding_id FROM current_findings ORDER BY 1",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect();
    assert_eq!(
        rows,
        [
            ("baseline".into(), "f.a".into()),
            ("vendor".into(), "f.b".into())
        ],
        "one current state per rule set, not one shared per rule id"
    );
    let stored: i64 = admin
        .query_one(
            "SELECT count(*) FROM findings WHERE rule_set_id = 'vendor'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(stored, 1);
    drop((client, admin));
    db.drop().await;
}
