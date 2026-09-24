//! Migrations apply once, are idempotent, and refuse a newer schema.

mod common;

use common::TestDb;

#[tokio::test]
async fn migration_applies_once_and_is_idempotent() {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    assert_eq!(platform_store::schema_version(&client).await.unwrap(), None);
    assert_eq!(
        platform_store::migrate(&mut client).await.unwrap(),
        platform_store::SCHEMA_VERSION
    );
    assert_eq!(
        platform_store::migrate(&mut client).await.unwrap(),
        platform_store::SCHEMA_VERSION
    );
    assert_eq!(
        platform_store::schema_version(&client).await.unwrap(),
        Some(platform_store::SCHEMA_VERSION)
    );
    drop(client);
    db.drop().await;
}

#[tokio::test]
async fn a_newer_schema_is_refused() {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    client
        .execute("UPDATE schema_version SET version = 99", &[])
        .await
        .unwrap();
    assert!(matches!(
        platform_store::migrate(&mut client).await,
        Err(platform_store::StoreError::NewerSchema(99))
    ));
    drop(client);
    db.drop().await;
}

#[tokio::test]
async fn the_ingest_role_can_read_the_schema_version() {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    let allowed: bool = client
        .query_one(
            "SELECT has_table_privilege('openvibes_ingest', 'schema_version', 'SELECT')",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(allowed, "ingest's /ready check reads schema_version");
    drop(client);
    db.drop().await;
}

/// Two operators (or a timer and an operator) running `migrate` or
/// `maintenance` at once: both succeed, one after the other.
#[tokio::test]
async fn concurrent_migrate_and_maintenance_both_succeed() {
    for _ in 0..3 {
        let db = TestDb::create().await;
        let (mut a, mut b) = (db.pool.get().await.unwrap(), db.pool.get().await.unwrap());
        let (x, y) = tokio::join!(
            platform_store::migrate(&mut a),
            platform_store::migrate(&mut b)
        );
        assert_eq!(
            (x.unwrap(), y.unwrap()),
            (
                platform_store::SCHEMA_VERSION,
                platform_store::SCHEMA_VERSION
            )
        );
        let today = chrono::Utc::now().date_naive();
        let (x, y) = tokio::join!(
            platform_store::ensure_partitions(&a, today, 7),
            platform_store::ensure_partitions(&b, today, 7)
        );
        assert_eq!(x.unwrap() + y.unwrap(), 8, "each partition created once");
        drop((a, b));
        db.drop().await;
    }
}

#[tokio::test]
async fn an_invalid_database_url_is_a_configuration_error() {
    let error = platform_store::connect("postgresql://[not-a-url")
        .await
        .map(drop)
        .unwrap_err();
    assert_eq!(error, platform_store::StoreError::InvalidUrl);
    assert_eq!(error.to_string(), "invalid database_url");
}
