//! Imported hosts (protocol P3b): agent export files stored as `import.`
//! rows, run as the admin (database owner) like `openvibes-admin import`.

mod common;

use chrono::{DateTime, Duration, DurationRound, Utc};
use common::TestDb;
use platform_store::{
    Client,
    imports::{self, ImportedHost, InventoryImport},
    ingest::{self, Origin, StoredFinding},
    inventory::PackageRow,
};

const ENROLLED: &str = "agent.00000000-0000-4000-8000-000000000001";

async fn setup() -> (TestDb, Client) {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    // From yesterday, so a finding observed an hour ago always has a day.
    platform_store::ensure_partitions(&client, Utc::now().date_naive() - Duration::days(1), 8)
        .await
        .unwrap();
    (db, client)
}

fn host<'a>(
    seen_at: DateTime<Utc>,
    hostname: &'a str,
    claimed: Option<&'a str>,
) -> ImportedHost<'a> {
    ImportedHost {
        install_id: "inst-1",
        claimed_agent_id: claimed,
        hostname: Some(hostname),
        scanner_version: "0.1.0",
        seen_at,
    }
}

fn finding(id: &str) -> StoredFinding {
    StoredFinding {
        finding_id: id.into(),
        scan_id: "scan.1".into(),
        rule_set_id: "baseline".into(),
        rule_id: "process.ssh.running".into(),
        rule_version: 1,
        observed_at: Utc::now() - Duration::hours(1),
        severity: "medium".into(),
        confidence: 100,
        message: "An SSH server process was observed".into(),
        evidence: vec!["process.names".into()],
    }
}

fn packages(release: &str) -> Vec<PackageRow> {
    vec![PackageRow {
        manager: "rpm".into(),
        name: "bash".into(),
        epoch: 0,
        version: "5.2".into(),
        release: release.into(),
        arch: "x86_64".into(),
        source: None,
        source_version: None,
    }]
}

async fn count(client: &Client, sql: &str) -> i64 {
    client.query_one(sql, &[]).await.unwrap().get(0)
}

#[tokio::test]
async fn reimport_stores_nothing_new() {
    let (db, mut client) = setup().await;
    let now = Utc::now();
    let id = imports::upsert_host(&client, &host(now, "h", None), now)
        .await
        .unwrap();
    assert_eq!(id, "import.inst-1");
    let batch = [finding("finding.a")];
    let first = ingest::store_findings(&mut client, &id, &batch, Origin::Import, now).await;
    let second = ingest::store_findings(&mut client, &id, &batch, Origin::Import, now).await;
    assert_eq!((first.unwrap(), second.unwrap()), (1, 0));
    let row = client
        .query_one("SELECT origin, authenticated FROM findings", &[])
        .await
        .unwrap();
    assert_eq!(
        (row.get::<_, String>(0), row.get::<_, bool>(1)),
        ("import".to_owned(), false)
    );
    let current = client
        .query_one(
            "SELECT origin, authenticated FROM current_findings WHERE agent_id=$1",
            &[&id],
        )
        .await
        .unwrap();
    assert_eq!(
        (current.get::<_, String>(0), current.get::<_, bool>(1)),
        ("import".to_owned(), false)
    );
    db.drop().await;
}

#[tokio::test]
async fn newest_inventory_wins() {
    let (db, mut client) = setup().await;
    let base = Utc::now().duration_trunc(Duration::seconds(1)).unwrap();
    let t = |hours| base - Duration::hours(hours);
    let id = imports::upsert_host(&client, &host(t(2), "h", None), Utc::now())
        .await
        .unwrap();
    let mut replace = async |release: &str, digest: u8, at| {
        imports::replace_inventory(
            &mut client,
            &id,
            "fedora",
            "44",
            None,
            &packages(release),
            [digest; 32],
            at,
        )
        .await
        .unwrap()
    };
    assert_eq!(replace("1", 1, t(2)).await, InventoryImport::Stored);
    assert_eq!(replace("0", 0, t(3)).await, InventoryImport::Older);
    assert_eq!(replace("1", 1, t(2)).await, InventoryImport::Unchanged);
    assert_eq!(replace("2", 2, t(1)).await, InventoryImport::Stored);
    let row = client
        .query_one(
            "SELECT inventory_at, os_id FROM agents WHERE agent_id = $1",
            &[&id],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, DateTime<Utc>>(0), t(1));
    assert_eq!(row.get::<_, String>(1), "fedora");
    let release: String = client
        .query_one(
            "SELECT v.release FROM host_packages h JOIN package_versions v ON v.id = h.package_version_id
             WHERE h.agent_id = $1",
            &[&id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(release, "2");
    db.drop().await;
}

#[tokio::test]
async fn claimed_enrolled_agent_is_untouched() {
    let (db, mut client) = setup().await;
    let now = Utc::now();
    client
        .execute(
            "INSERT INTO agents (agent_id, status, enrolled_at, hostname) VALUES ($1, 'active', $2, 'real')",
            &[&ENROLLED, &now],
        )
        .await
        .unwrap();
    let id = imports::upsert_host(&client, &host(now, "fake", Some(ENROLLED)), now)
        .await
        .unwrap();
    ingest::store_findings(
        &mut client,
        &id,
        &[finding("finding.b")],
        Origin::Import,
        now,
    )
    .await
    .unwrap();
    imports::replace_inventory(
        &mut client,
        &id,
        "fedora",
        "44",
        None,
        &packages("1"),
        [1; 32],
        now,
    )
    .await
    .unwrap();
    let enrolled = client
        .query_one(
            "SELECT hostname, status FROM agents WHERE agent_id = $1",
            &[&ENROLLED],
        )
        .await
        .unwrap();
    assert_eq!(
        (enrolled.get::<_, String>(0), enrolled.get::<_, String>(1)),
        ("real".to_owned(), "active".to_owned())
    );
    for table in ["findings", "current_findings", "host_packages"] {
        let sql = format!("SELECT count(*) FROM {table} WHERE agent_id = '{ENROLLED}'");
        assert_eq!(count(&client, &sql).await, 0, "{table}");
    }
    let claimed: Option<String> = client
        .query_one(
            "SELECT claimed_agent_id FROM agents WHERE agent_id = $1",
            &[&id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(claimed.as_deref(), Some(ENROLLED));
    db.drop().await;
}

#[tokio::test]
async fn import_ids_cannot_be_active_and_agent_ids_cannot_be_imported() {
    let (db, client) = setup().await;
    let insert = "INSERT INTO agents (agent_id, status, enrolled_at) VALUES ($1, $2, now())";
    assert!(
        client
            .execute(insert, &[&"import.x", &"active"])
            .await
            .is_err()
    );
    assert!(
        client
            .execute(insert, &[&ENROLLED, &"imported"])
            .await
            .is_err()
    );
    assert!(
        client
            .execute(insert, &[&"import.x", &"imported"])
            .await
            .is_ok()
    );
    db.drop().await;
}

#[tokio::test]
async fn upsert_keeps_first_import_time_and_newest_labels() {
    let (db, client) = setup().await;
    let base = Utc::now().duration_trunc(Duration::seconds(1)).unwrap();
    let t = |hours| base - Duration::hours(hours);
    let first_import = t(0);
    imports::upsert_host(&client, &host(t(1), "newer", None), first_import)
        .await
        .unwrap();
    imports::upsert_host(
        &client,
        &host(t(2), "older", None),
        first_import + Duration::minutes(5),
    )
    .await
    .unwrap();
    let row = client
        .query_one(
            "SELECT enrolled_at, last_seen_at, hostname, status FROM agents WHERE agent_id = 'import.inst-1'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, DateTime<Utc>>(0), first_import);
    assert_eq!(row.get::<_, DateTime<Utc>>(1), t(1));
    assert_eq!(row.get::<_, String>(2), "newer");
    assert_eq!(row.get::<_, String>(3), "imported");
    db.drop().await;
}

// A(t1, X), B(t2, Y), C(t3, X): the newest wins whatever the order, also when
// its content equals an older file's (a package rolled back).
#[tokio::test]
async fn newest_wins_when_content_repeats() {
    let (db, mut client) = setup().await;
    let base = Utc::now().duration_trunc(Duration::seconds(1)).unwrap();
    let t = |hours| base - Duration::hours(hours);
    let id = imports::upsert_host(&client, &host(t(3), "h", None), base)
        .await
        .unwrap();
    for (release, digest, at) in [("x", 1, t(3)), ("x", 1, t(1)), ("y", 2, t(2))] {
        imports::replace_inventory(
            &mut client,
            &id,
            "fedora",
            "44",
            None,
            &packages(release),
            [digest; 32],
            at,
        )
        .await
        .unwrap();
    }
    let release: String = client
        .query_one(
            "SELECT v.release FROM host_packages h JOIN package_versions v ON v.id = h.package_version_id
             WHERE h.agent_id = $1",
            &[&id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(release, "x", "the file from t1 (newest) wins");
    db.drop().await;
}
