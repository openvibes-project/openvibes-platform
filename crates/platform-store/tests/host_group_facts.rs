//! Agent facts that feed host groups: the peer address a heartbeat records,
//! and the automatic groups ingest makes for new OS families and distributions.
mod common;

use std::net::IpAddr;

use chrono::{Duration, Utc};
use common::TestDb;
use platform_store::{
    Client,
    host_group_facts::{distribution_name, ensure_automatic_groups, os_family_name},
    ingest,
};

const AGENT: &str = "agent.00000000-0000-4000-8000-000000000001";

async fn setup() -> (TestDb, Client, Client) {
    let db = TestDb::create().await;
    let mut admin = db.pool.get().await.unwrap();
    platform_store::migrate(&mut admin).await.unwrap();
    admin
        .execute(
            "INSERT INTO agents (agent_id, status, enrolled_at) VALUES ($1, 'active', now())",
            &[&AGENT],
        )
        .await
        .unwrap();
    let ingest = db.pool.get().await.unwrap();
    ingest
        .batch_execute("SET ROLE \"openvibes-ingest\"")
        .await
        .unwrap();
    (db, admin, ingest)
}

async fn groups(admin: &Client) -> Vec<(String, String, String, String)> {
    admin
        .query(
            "SELECT g.auto_key, g.name, g.description, c.field || '=' || c.vals[1]
             FROM console_asset_groups g JOIN console_host_group_conditions c USING (asset_group_id)
             WHERE g.kind = 'automatic' ORDER BY 1",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3)))
        .collect()
}

#[tokio::test]
async fn a_new_distribution_creates_its_group_once() {
    let (db, admin, ingest) = setup().await;
    let now = Utc::now();
    for _ in 0..2 {
        ensure_automatic_groups(&ingest, "linux", "debian 12", now)
            .await
            .unwrap();
    }
    assert_eq!(
        groups(&admin).await,
        [
            (
                "distribution:debian 12".into(),
                "Debian 12".into(),
                "Hosts running Debian 12.".into(),
                "distribution=debian 12".into()
            ),
            (
                "os_family:linux".into(),
                "Linux".into(),
                "Every host that reports Linux. Kept up to date by OpenVIBES.".into(),
                "os_family=linux".into()
            ),
        ]
    );
    let audited: i64 = admin
        .query_one(
            "SELECT count(*) FROM audit_log WHERE action = 'host_group.created_automatically'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(audited, 2);
    drop((ingest, admin));
    db.drop().await;
}

#[tokio::test]
async fn a_dismissed_key_is_not_created_again() {
    let (db, admin, ingest) = setup().await;
    admin
        .execute(
            "INSERT INTO console_host_group_dismissed VALUES ('distribution:debian 12', now(), 'u')",
            &[],
        )
        .await
        .unwrap();
    ensure_automatic_groups(&ingest, "linux", "debian 12", Utc::now())
        .await
        .unwrap();
    let keys: Vec<String> = groups(&admin).await.into_iter().map(|g| g.0).collect();
    assert_eq!(keys, ["os_family:linux"]);
    drop((ingest, admin));
    db.drop().await;
}

#[tokio::test]
async fn a_name_taken_by_a_user_group_gets_automatic_appended() {
    let (db, admin, ingest) = setup().await;
    admin
        .execute(
            "INSERT INTO console_asset_groups (asset_group_id, name, created_at, created_by)
             VALUES (gen_random_uuid(), 'debian 12', now(), 'u')",
            &[],
        )
        .await
        .unwrap();
    ensure_automatic_groups(&ingest, "linux", "debian 12", Utc::now())
        .await
        .unwrap();
    let names: Vec<String> = groups(&admin).await.into_iter().map(|g| g.1).collect();
    assert_eq!(names, ["Debian 12 (automatic)", "Linux"]);
    drop((ingest, admin));
    db.drop().await;
}

#[tokio::test]
async fn display_names_match_the_migration() {
    let (db, admin, _ingest) = setup().await;
    for family in ["linux", "windows", "freebsd", "x"] {
        let sql: String = admin
            .query_one("SELECT console_os_family_name($1)", &[&family])
            .await
            .unwrap()
            .get(0);
        assert_eq!(os_family_name(family), sql, "{family}");
    }
    for d in [
        "debian 12",
        "ubuntu 24.04",
        "fedora 44",
        "rocky 9",
        "almalinux 10",
        "arch rolling",
        "opensuse-leap 15.6",
        "windows 11",
        "x 1",
        "alpine 3.20.1",
        "pop 22.04",
    ] {
        let sql: String = admin
            .query_one("SELECT console_distribution_name($1)", &[&d])
            .await
            .unwrap()
            .get(0);
        assert_eq!(distribution_name(d), sql, "{d}");
    }
    drop((_ingest, admin));
    db.drop().await;
}

async fn last_address(admin: &Client) -> Option<IpAddr> {
    admin
        .query_one(
            "SELECT last_address FROM agents WHERE agent_id = $1",
            &[&AGENT],
        )
        .await
        .unwrap()
        .get(0)
}

async fn beat(ingest: &Client, address: &str, minutes: i64, now: chrono::DateTime<Utc>) -> bool {
    let address: IpAddr = address.parse().unwrap();
    ingest::heartbeat(
        ingest,
        AGENT,
        "0.1.0",
        None,
        &[],
        None,
        Some(address),
        now + Duration::minutes(minutes),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn a_new_address_is_written_even_inside_the_throttle() {
    let (db, admin, ingest) = setup().await;
    let now = Utc::now();
    assert!(beat(&ingest, "192.0.2.1", 0, now).await);
    assert!(beat(&ingest, "192.0.2.2", 1, now).await);
    assert_eq!(
        last_address(&admin).await,
        Some("192.0.2.2".parse().unwrap())
    );
    drop((ingest, admin));
    db.drop().await;
}

#[tokio::test]
async fn an_unchanged_address_inside_the_throttle_writes_nothing() {
    let (db, admin, ingest) = setup().await;
    let now = Utc::now();
    assert!(beat(&ingest, "192.0.2.1", 0, now).await);
    assert!(!beat(&ingest, "192.0.2.1", 1, now).await);
    assert_eq!(
        last_address(&admin).await,
        Some("192.0.2.1".parse().unwrap())
    );
    drop((ingest, admin));
    db.drop().await;
}
