//! Rule distribution queries: admin writes as the owner, `serve` as the
//! least-privilege `openvibes_distribution` role.

mod common;

use common::TestDb;
use platform_store::{
    Client,
    rules::{self, NewBundle, Published, Served, TrustAdded},
};
use tokio_postgres::error::SqlState;

async fn setup() -> (TestDb, Client) {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    (db, client)
}

async fn as_role(db: &TestDb, role: &str) -> Client {
    let client = db.pool.get().await.unwrap();
    client
        .batch_execute(&format!("SET ROLE {role}"))
        .await
        .unwrap();
    client
}

fn bundle(version: i64, envelope: &[u8]) -> NewBundle<'_> {
    NewBundle {
        rule_set_id: "baseline",
        version,
        envelope,
        envelope_sha256: [u8::try_from(version).unwrap(); 32],
        issuer_key_id: "org.rules",
        created_at_ms: 1,
        expires_at_ms: i64::MAX,
        published_by: "test",
    }
}

async fn trusted(client: &Client) {
    let added = rules::add_trust_key(client, "baseline", "org.rules", [1; 32]).await;
    assert_eq!(added.unwrap(), TrustAdded::Added);
}

#[tokio::test]
async fn trust_keys_are_added_once_and_conflicts_refused() {
    let (db, client) = setup().await;
    trusted(&client).await;
    let add = |key| rules::add_trust_key(&client, "baseline", "org.rules", key);
    assert_eq!(add([1; 32]).await.unwrap(), TrustAdded::AlreadyTrusted);
    assert_eq!(add([2; 32]).await.unwrap(), TrustAdded::Conflict);
    assert!(
        rules::remove_trust_key(&client, "baseline", "org.rules")
            .await
            .unwrap()
    );
    assert!(
        !rules::remove_trust_key(&client, "baseline", "org.rules")
            .await
            .unwrap()
    );
    assert!(
        rules::active_trust_keys(&client, "baseline")
            .await
            .unwrap()
            .is_empty()
    );
    let listed = rules::trust_keys(&client, Some("baseline")).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert!(listed[0].removed_at.is_some());
    // A removed id is never re-used, not even for the same key.
    assert_eq!(add([1; 32]).await.unwrap(), TrustAdded::Conflict);
    db.drop().await;
}

#[tokio::test]
async fn publish_stores_exact_bytes_and_serves_by_version() {
    let (db, mut client) = setup().await;
    trusted(&client).await;
    let v1 = br#"{"exact":"bytes",  "v":1}"#;
    let stored = rules::publish(&mut client, &bundle(1, v1)).await.unwrap();
    assert_eq!(stored, Published::Stored);
    let dist = as_role(&db, "openvibes_distribution").await;
    let serve = |set, current| rules::serve(&dist, set, current);
    assert_eq!(
        serve("baseline", None).await.unwrap(),
        Served::Envelope(v1.to_vec())
    );
    assert_eq!(serve("baseline", Some(1)).await.unwrap(), Served::UpToDate);
    assert_eq!(serve("baseline", Some(9)).await.unwrap(), Served::UpToDate);
    assert_eq!(serve("unknown", None).await.unwrap(), Served::Unknown);
    db.drop().await;
}

#[tokio::test]
async fn a_set_without_bundles_is_unknown() {
    let (db, client) = setup().await;
    trusted(&client).await;
    let dist = as_role(&db, "openvibes_distribution").await;
    assert_eq!(
        rules::serve(&dist, "baseline", None).await.unwrap(),
        Served::Unknown
    );
    db.drop().await;
}

#[tokio::test]
async fn publish_is_idempotent_and_refuses_conflicts_and_old_versions() {
    let (db, mut client) = setup().await;
    trusted(&client).await;
    rules::publish(&mut client, &bundle(2, b"two"))
        .await
        .unwrap();
    let mut publish = async |b: NewBundle<'_>| rules::publish(&mut client, &b).await.unwrap();
    assert_eq!(publish(bundle(2, b"two")).await, Published::Unchanged);
    assert_eq!(publish(bundle(2, b"TWO")).await, Published::VersionConflict);
    assert_eq!(
        publish(bundle(1, b"one")).await,
        Published::NotAboveCurrent(2)
    );
    let mut unknown = bundle(1, b"x");
    unknown.rule_set_id = "nobody";
    assert_eq!(publish(unknown).await, Published::UnknownSet);
    db.drop().await;
}

#[tokio::test]
async fn concurrent_identical_publishes_store_one_row() {
    let (db, client) = setup().await;
    trusted(&client).await;
    let (mut a, mut b) = (db.pool.get().await.unwrap(), db.pool.get().await.unwrap());
    let (first, second) = (bundle(1, b"same"), bundle(1, b"same"));
    let (ra, rb) = tokio::join!(
        rules::publish(&mut a, &first),
        rules::publish(&mut b, &second)
    );
    let mut outcomes = [ra.unwrap(), rb.unwrap()];
    outcomes.sort_by_key(|outcome| format!("{outcome:?}"));
    assert_eq!(outcomes, [Published::Stored, Published::Unchanged]);
    assert_eq!(rules::bundles(&client, "baseline").await.unwrap().len(), 1);
    db.drop().await;
}

#[tokio::test]
async fn a_retired_set_is_unknown_and_refuses_publishing() {
    let (db, mut client) = setup().await;
    trusted(&client).await;
    rules::publish(&mut client, &bundle(1, b"one"))
        .await
        .unwrap();
    assert!(rules::retire(&client, "baseline").await.unwrap());
    assert!(!rules::retire(&client, "baseline").await.unwrap());
    let dist = as_role(&db, "openvibes_distribution").await;
    assert_eq!(
        rules::serve(&dist, "baseline", None).await.unwrap(),
        Served::Unknown
    );
    let published = rules::publish(&mut client, &bundle(2, b"two"))
        .await
        .unwrap();
    assert_eq!(published, Published::Retired);
    let added = rules::add_trust_key(&client, "baseline", "k2", [3; 32]).await;
    assert_eq!(added.unwrap(), TrustAdded::Retired);
    assert_eq!(
        rules::bundles(&client, "baseline").await.unwrap().len(),
        1,
        "kept for audit"
    );
    db.drop().await;
}

#[tokio::test]
async fn list_and_bundles_describe_sets() {
    let (db, mut client) = setup().await;
    trusted(&client).await;
    rules::publish(&mut client, &bundle(1, b"one"))
        .await
        .unwrap();
    rules::publish(&mut client, &bundle(3, b"three"))
        .await
        .unwrap();
    let sets = rules::list(&client).await.unwrap();
    assert_eq!(sets.len(), 1);
    assert_eq!(
        (
            sets[0].rule_set_id.as_str(),
            sets[0].current_version,
            sets[0].trusted_keys
        ),
        ("baseline", Some(3), 1)
    );
    assert!(sets[0].retired_at.is_none());
    let bundles = rules::bundles(&client, "baseline").await.unwrap();
    let versions: Vec<_> = bundles.iter().map(|b| (b.version, b.bytes)).collect();
    assert_eq!(versions, [(3, 5), (1, 3)]);
    assert_eq!(bundles[0].envelope_sha256, [3; 32]);
    db.drop().await;
}

#[tokio::test]
async fn the_distribution_role_has_only_the_rights_it_uses() {
    let (db, _client) = setup().await;
    let dist = as_role(&db, "openvibes_distribution").await;
    for allowed in [
        "SELECT count(*) FROM agents",
        "SELECT count(*) FROM certificates",
        "SELECT count(*) FROM rule_sets",
        "SELECT count(*) FROM rule_bundles",
        "SELECT version FROM schema_version",
    ] {
        dist.batch_execute(allowed).await.expect(allowed);
    }
    for denied in [
        "SELECT count(*) FROM rule_trust_keys",
        "SELECT count(*) FROM findings",
        "SELECT count(*) FROM enrollment_tokens",
        "INSERT INTO rule_sets (rule_set_id) VALUES ('x')",
        "UPDATE agents SET status = 'revoked'",
        "DELETE FROM rule_bundles",
    ] {
        let error = dist.batch_execute(denied).await.expect_err(denied);
        assert_eq!(
            error.code(),
            Some(&SqlState::INSUFFICIENT_PRIVILEGE),
            "{denied}"
        );
    }
    let ingest = as_role(&db, "openvibes_ingest").await;
    for denied in [
        "SELECT count(*) FROM rule_sets",
        "SELECT count(*) FROM rule_bundles",
        "SELECT count(*) FROM rule_trust_keys",
    ] {
        let error = ingest.batch_execute(denied).await.expect_err(denied);
        assert_eq!(
            error.code(),
            Some(&SqlState::INSUFFICIENT_PRIVILEGE),
            "{denied}"
        );
    }
    db.drop().await;
}
