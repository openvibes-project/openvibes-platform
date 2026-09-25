//! Migrations apply once, are idempotent, and refuse a newer schema.

mod common;

use common::TestDb;

#[tokio::test]
async fn migration_applies_once_and_is_idempotent() {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    assert_eq!(platform_store::schema_version(&client).await.unwrap(), None);
    assert!(
        !platform_store::console_read::schema_is_current(&client)
            .await
            .unwrap()
    );
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
    assert!(
        platform_store::console_read::schema_is_current(&client)
            .await
            .unwrap()
    );
    client
        .execute("UPDATE schema_version SET version = 6", &[])
        .await
        .unwrap();
    assert!(
        !platform_store::console_read::schema_is_current(&client)
            .await
            .unwrap()
    );
    drop(client);
    db.drop().await;
}

#[tokio::test]
async fn schema_seven_upgrades_to_eight() {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    client
        .batch_execute("CREATE TABLE schema_version (version integer NOT NULL)")
        .await
        .unwrap();
    for migration in [
        include_str!("../../../migrations/0001_initial.sql"),
        include_str!("../../../migrations/0002_ca_tokens_agents.sql"),
        include_str!("../../../migrations/0003_agent_hostname.sql"),
        include_str!("../../../migrations/0004_ingest_least_privilege.sql"),
        include_str!("../../../migrations/0005_finding_rule_set.sql"),
        include_str!("../../../migrations/0006_rule_distribution.sql"),
        include_str!("../../../migrations/0007_console_read_models.sql"),
    ] {
        client.batch_execute(migration).await.unwrap();
    }
    client
        .execute("INSERT INTO schema_version VALUES (7)", &[])
        .await
        .unwrap();
    assert_eq!(
        platform_store::migrate(&mut client).await.unwrap(),
        platform_store::SCHEMA_VERSION
    );
    let retention_days: i32 = client
        .query_one(
            "SELECT retention_days FROM console_audit_retention WHERE singleton",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(retention_days, 365);
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
    assert!(
        !platform_store::console_read::schema_is_current(&client)
            .await
            .unwrap()
    );
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

#[tokio::test]
async fn the_console_role_has_only_its_declared_schema_rights() {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    let row = client
        .query_one(
            "SELECT has_table_privilege('openvibes_console', 'console_sessions', 'SELECT'),
                    has_table_privilege('openvibes_console', 'console_sessions', 'UPDATE'),
                    has_table_privilege('openvibes_console', 'agents', 'UPDATE'),
                    has_table_privilege('openvibes_console', 'certificates', 'SELECT'),
                    has_table_privilege('openvibes_console', 'rule_trust_keys', 'SELECT'),
                    has_table_privilege('openvibes_console', 'rule_trust_keys', 'INSERT'),
                    has_table_privilege('openvibes_console', 'rule_trust_keys', 'UPDATE'),
                    has_table_privilege('openvibes_console', 'audit_log', 'INSERT'),
                    has_table_privilege('openvibes_console', 'audit_log', 'UPDATE')",
            &[],
        )
        .await
        .unwrap();
    let rights = (
        row.get::<_, bool>(0),
        row.get::<_, bool>(1),
        row.get::<_, bool>(2),
        row.get::<_, bool>(3),
        row.get::<_, bool>(4),
        row.get::<_, bool>(5),
        row.get::<_, bool>(6),
        row.get::<_, bool>(7),
        row.get::<_, bool>(8),
    );
    assert_eq!(
        rights,
        (true, true, false, true, true, false, false, true, false)
    );
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
