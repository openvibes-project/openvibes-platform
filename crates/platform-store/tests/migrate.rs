//! Migrations apply once, are idempotent, and refuse a newer schema.

mod common;

use common::TestDb;

#[tokio::test]
async fn migration_applies_once_and_is_idempotent() {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    assert_eq!(platform_store::schema_version(&client).await.unwrap(), None);
    assert_eq!(platform_store::migrate(&mut client).await.unwrap(), 3);
    assert_eq!(platform_store::migrate(&mut client).await.unwrap(), 3);
    assert_eq!(
        platform_store::schema_version(&client).await.unwrap(),
        Some(3)
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
