//! Migrations apply once, are idempotent, and refuse a newer schema.

mod common;

use common::TestDb;

#[tokio::test]
async fn migration_applies_once_and_is_idempotent() {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    assert_eq!(platform_store::schema_version(&client).await.unwrap(), None);
    assert_eq!(platform_store::migrate(&mut client).await.unwrap(), 1);
    assert_eq!(platform_store::migrate(&mut client).await.unwrap(), 1);
    assert_eq!(
        platform_store::schema_version(&client).await.unwrap(),
        Some(1)
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
