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
async fn schema_eleven_upgrades_to_current() {
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
        include_str!("../../../migrations/0007_inventory.sql"),
        include_str!("../../../migrations/0008_vulnerabilities.sql"),
        include_str!("../../../migrations/0009_running_kernel.sql"),
        include_str!("../../../migrations/0010_cve_enrichment.sql"),
        include_str!("../../../migrations/0011_nvd_euvd.sql"),
    ] {
        client.batch_execute(migration).await.unwrap();
    }
    client
        .execute("INSERT INTO schema_version VALUES (11)", &[])
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
            "SELECT has_table_privilege('openvibes-ingest', 'schema_version', 'SELECT')",
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
            "SELECT has_table_privilege('openvibes-console', 'console_sessions', 'SELECT'),
                    has_table_privilege('openvibes-console', 'console_sessions', 'UPDATE'),
                    has_table_privilege('openvibes-console', 'agents', 'UPDATE'),
                    has_table_privilege('openvibes-console', 'certificates', 'SELECT'),
                    has_table_privilege('openvibes-console', 'rule_trust_keys', 'SELECT'),
                    has_table_privilege('openvibes-console', 'rule_trust_keys', 'INSERT'),
                    has_table_privilege('openvibes-console', 'rule_trust_keys', 'UPDATE'),
                    has_table_privilege('openvibes-console', 'audit_log', 'INSERT'),
                    has_table_privilege('openvibes-console', 'audit_log', 'UPDATE')",
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
    let write_rights = client
        .query_one(
            "SELECT has_table_privilege('openvibes-console', 'console_idempotency', 'DELETE'),
                    has_table_privilege('openvibes-console', 'console_asset_group_selectors', 'DELETE'),
                    has_table_privilege('openvibes-console', 'console_agent_tags', 'DELETE'),
                    has_table_privilege('openvibes-console', 'current_findings', 'UPDATE'),
                    has_table_privilege('openvibes-console', 'rule_sets', 'UPDATE'),
                    has_table_privilege('openvibes-console', 'rule_bundles', 'INSERT')",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        (
            write_rights.get::<_, bool>(0),
            write_rights.get::<_, bool>(1),
            write_rights.get::<_, bool>(2),
            write_rights.get::<_, bool>(3),
            write_rights.get::<_, bool>(4),
            write_rights.get::<_, bool>(5),
        ),
        (true, true, true, false, false, true)
    );
    let column_rights = client
        .query_one(
            "SELECT has_column_privilege('openvibes-console', 'agents', 'status', 'UPDATE'),
                    has_column_privilege('openvibes-console', 'agents', 'revoked_at', 'UPDATE'),
                    has_column_privilege('openvibes-console', 'agents', 'enrolled_at', 'UPDATE'),
                    has_column_privilege('openvibes-console', 'current_findings', 'received_at', 'UPDATE'),
                    has_column_privilege('openvibes-console', 'current_findings', 'message', 'UPDATE'),
                    has_column_privilege('openvibes-console', 'rule_sets', 'created_at', 'UPDATE'),
                    has_column_privilege('openvibes-console', 'rule_sets', 'retired_at', 'UPDATE'),
                    has_column_privilege('openvibes-console', 'rule_trust_keys', 'added_at', 'UPDATE'),
                    has_column_privilege('openvibes-console', 'rule_trust_keys', 'public_key', 'UPDATE'),
                    has_column_privilege('openvibes-console', 'rule_trust_keys', 'removed_at', 'UPDATE')",
            &[],
        )
        .await
        .unwrap();
    let column_rights = (0..10)
        .map(|index| column_rights.get::<_, bool>(index))
        .collect::<Vec<_>>();
    assert_eq!(
        column_rights,
        [
            true, true, false, true, false, true, false, true, false, false
        ]
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
        assert_eq!(x.unwrap() + y.unwrap(), 24, "each partition created once");
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

// Fresh databases create the hyphenated roles (admin TUI spec §2), with the
// grants the services need, even in a cluster that still holds old-named
// roles from earlier runs.
#[tokio::test]
async fn roles_are_hyphenated() {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    for (role, table, privilege) in [
        ("openvibes-ingest", "findings", "INSERT"),
        ("openvibes-distribution", "rule_bundles", "SELECT"),
        ("openvibes-vulns", "vulnerabilities", "INSERT"),
    ] {
        let granted: bool = client
            .query_one(
                "SELECT has_table_privilege($1, $2, $3)",
                &[&role, &table, &privilege],
            )
            .await
            .unwrap()
            .get(0);
        assert!(granted, "{role} {privilege} {table}");
    }
    db.drop().await;
}

/// A database with migrations 1..=VERSION applied from the files.
async fn at_version(db: &TestDb, version: i32) -> deadpool_postgres::Client {
    let client = db.pool.get().await.unwrap();
    client
        .batch_execute("CREATE TABLE schema_version (version integer NOT NULL)")
        .await
        .unwrap();
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../migrations");
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    files.sort();
    for file in files.iter().take(version as usize) {
        client
            .batch_execute(&std::fs::read_to_string(file).unwrap())
            .await
            .unwrap();
    }
    client
        .execute("INSERT INTO schema_version VALUES ($1)", &[&version])
        .await
        .unwrap();
    client
}

/// Board #77: after a plain `dnf upgrade` the services' migrate unit
/// applies only additive migrations; one that changes stored data waits for
/// Update, which backs up first.
#[tokio::test]
async fn automatic_migration_stops_before_a_data_changing_one() {
    let db = TestDb::create().await;
    let mut client = at_version(&db, 11).await;
    assert!(matches!(
        platform_store::migrate_additive(&mut client).await,
        Err(platform_store::StoreError::NeedsBackup(13))
    ));
    assert_eq!(
        platform_store::schema_version(&client).await.unwrap(),
        Some(11),
        "nothing applied"
    );
    drop(client);
    db.drop().await;
}

#[tokio::test]
async fn automatic_migration_applies_additive_ones() {
    let db = TestDb::create().await;
    let mut client = at_version(&db, 24).await;
    assert_eq!(
        platform_store::migrate_additive(&mut client).await.unwrap(),
        platform_store::SCHEMA_VERSION
    );
    drop(client);
    db.drop().await;
}
