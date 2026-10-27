//! The change log written by ingest (step 5e, rulings 2 to 6), run as the
//! `openvibes-ingest` role.

mod common;

use chrono::{Duration, Utc};
use common::TestDb;
use openvibes_core::{Identifier, OsRelease, inventory_fingerprint};
use platform_store::{
    Client, change_log,
    host_services::{self, Listener, Report, Service},
    inventory::{self, ChangesOutcome, InventoryOutcome, PackageRow},
};

const HOST: &str = "agent.00000000-0000-4000-8000-000000000601";

fn listener(port: i32, exposed: bool, address: &str) -> Listener {
    Listener {
        protocol: "tcp".into(),
        address: address.parse().unwrap(),
        port,
        exposed,
        service: None,
        program: None,
    }
}

fn report(sha: char, listeners: Vec<Listener>, units: &[(&str, i32)]) -> Report {
    Report {
        sha256: sha.to_string().repeat(64),
        owners: "complete".into(),
        truncated: false,
        listeners,
        services: units
            .iter()
            .map(|(unit, processes)| Service {
                unit: (*unit).into(),
                programs: vec![],
                processes: *processes,
                run_as: None,
            })
            .collect(),
    }
}

fn package(name: &str, version: &str) -> PackageRow {
    PackageRow {
        manager: "rpm".into(),
        name: name.into(),
        epoch: 0,
        version: version.into(),
        release: "1".into(),
        arch: "x86_64".into(),
        source: None,
        source_version: None,
    }
}

async fn setup() -> (TestDb, Client, Client) {
    let (db, admin) = common::migrated().await;
    common::seed_agent(&admin, HOST).await;
    let ingest = db.pool.get().await.unwrap();
    ingest
        .batch_execute("SET ROLE \"openvibes-ingest\"")
        .await
        .unwrap();
    (db, admin, ingest)
}

async fn log(admin: &Client) -> Vec<(String, String, String)> {
    admin
        .query(
            "SELECT kind, key, change FROM change_log ORDER BY at, kind, key, change",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .collect()
}

async fn services(ingest: &mut Client, r: &Report) {
    host_services::replace(ingest, HOST, r, Utc::now())
        .await
        .unwrap();
}

async fn inventory(ingest: &mut Client, packages: &[PackageRow], sha: u8) -> InventoryOutcome {
    inventory::replace(
        ingest,
        HOST,
        "fedora",
        "44",
        None,
        packages,
        [sha; 32],
        Utc::now(),
    )
    .await
    .unwrap()
}

fn entry(kind: &str, key: &str, change: &str) -> (String, String, String) {
    (kind.into(), key.into(), change.into())
}

#[tokio::test]
async fn first_report_is_the_baseline() {
    let (db, admin, mut ingest) = setup().await;
    services(
        &mut ingest,
        &report(
            'a',
            vec![listener(22, true, "0.0.0.0")],
            &[("sshd.service", 1)],
        ),
    )
    .await;
    inventory(&mut ingest, &[package("bash", "5.2")], 1).await;
    assert!(log(&admin).await.is_empty());
    db.drop().await;
}

#[tokio::test]
async fn a_report_with_no_changes_writes_nothing() {
    let (db, admin, mut ingest) = setup().await;
    let base = report(
        'a',
        vec![listener(22, true, "0.0.0.0")],
        &[("sshd.service", 1)],
    );
    services(&mut ingest, &base).await;
    services(&mut ingest, &base).await;
    // A new digest with the same keys: only a process count changed.
    services(
        &mut ingest,
        &report(
            'b',
            vec![listener(22, true, "0.0.0.0")],
            &[("sshd.service", 9)],
        ),
    )
    .await;
    inventory(&mut ingest, &[package("bash", "5.2")], 1).await;
    assert_eq!(
        inventory(&mut ingest, &[package("bash", "5.2")], 1).await,
        InventoryOutcome::Unchanged
    );
    assert!(log(&admin).await.is_empty());
    db.drop().await;
}

#[tokio::test]
async fn upgrade_writes_no_flood() {
    // Hosts that reported before the upgrade have rows and a digest; the
    // next report (any digest, same keys) diffs against those rows.
    let (db, admin, mut ingest) = setup().await;
    services(
        &mut ingest,
        &report(
            'a',
            vec![listener(22, true, "0.0.0.0"), listener(80, true, "::")],
            &[("sshd.service", 1), ("nginx.service", 2)],
        ),
    )
    .await;
    inventory(
        &mut ingest,
        &[package("bash", "5.2"), package("zsh", "5.9")],
        1,
    )
    .await;
    services(
        &mut ingest,
        &report(
            'b',
            vec![listener(80, true, "0.0.0.0"), listener(22, true, "::")],
            &[("nginx.service", 3), ("sshd.service", 1)],
        ),
    )
    .await;
    inventory(
        &mut ingest,
        &[package("zsh", "5.9"), package("bash", "5.2")],
        2,
    )
    .await;
    assert!(log(&admin).await.is_empty());
    db.drop().await;
}

#[tokio::test]
async fn ports_and_units_are_logged() {
    let (db, admin, mut ingest) = setup().await;
    services(
        &mut ingest,
        &report(
            'a',
            vec![
                listener(22, true, "0.0.0.0"),
                listener(5432, true, "0.0.0.0"),
            ],
            &[("sshd.service", 1), ("old.service", 1)],
        ),
    )
    .await;
    services(
        &mut ingest,
        &report(
            'b',
            vec![
                listener(22, true, "0.0.0.0"),
                listener(5432, false, "127.0.0.1"),
                listener(8080, true, "0.0.0.0"),
            ],
            &[("sshd.service", 1), ("new.service", 1)],
        ),
    )
    .await;
    let mut got = log(&admin).await;
    got.sort();
    assert_eq!(
        got,
        [
            entry("listener", "tcp/5432", "local"),
            entry("listener", "tcp/8080", "appeared"),
            entry("service", "new.service", "appeared"),
            entry("service", "old.service", "went_away"),
        ]
    );
    services(
        &mut ingest,
        &report(
            'c',
            vec![listener(22, true, "0.0.0.0")],
            &[("sshd.service", 1)],
        ),
    )
    .await;
    let gone = log(&admin).await;
    assert!(gone.contains(&entry("listener", "tcp/8080", "went_away")));
    assert!(gone.contains(&entry("listener", "tcp/5432", "went_away")));
    db.drop().await;
}

#[tokio::test]
async fn a_package_upgrade_writes_the_pair_at_one_time() {
    let (db, admin, mut ingest) = setup().await;
    inventory(
        &mut ingest,
        &[package("openssl", "3.0.1"), package("bash", "5.2")],
        1,
    )
    .await;
    inventory(
        &mut ingest,
        &[package("openssl", "3.0.2"), package("bash", "5.2")],
        2,
    )
    .await;
    let rows = admin
        .query(
            "SELECT change, detail->>'version', (SELECT count(DISTINCT at) FROM change_log WHERE key = 'openssl') FROM change_log
             WHERE kind = 'package' AND key = 'openssl' ORDER BY change",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].get::<_, String>(0), "appeared");
    assert_eq!(rows[0].get::<_, String>(1), "0:3.0.2-1");
    assert_eq!(rows[1].get::<_, String>(0), "went_away");
    assert_eq!(rows[1].get::<_, String>(1), "0:3.0.1-1");
    assert_eq!(rows[0].get::<_, i64>(2), 1, "the pair shares one time");
    assert_eq!(log(&admin).await.len(), 2);
    db.drop().await;
}

#[tokio::test]
async fn a_change_set_writes_exactly_its_rows() {
    let (db, admin, mut ingest) = setup().await;
    let os = OsRelease {
        id: Identifier::new("fedora").unwrap(),
        version_id: Identifier::new("44").unwrap(),
    };
    let before = [package("bash", "5.2"), package("curl", "8.0")];
    let after = [package("bash", "5.2"), package("git", "2.50")];
    let fingerprint = |rows: &[PackageRow]| {
        inventory_fingerprint(&os, None, rows.iter().map(PackageRow::normalized))
    };
    inventory::replace(
        &mut ingest,
        HOST,
        "fedora",
        "44",
        None,
        &before,
        fingerprint(&before),
        Utc::now(),
    )
    .await
    .unwrap();
    let outcome = inventory::apply_changes(
        &mut ingest,
        HOST,
        &os,
        None,
        &[package("git", "2.50")],
        &[package("curl", "8.0")],
        fingerprint(&before),
        fingerprint(&after),
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(outcome, ChangesOutcome::Stored);
    assert_eq!(
        log(&admin).await,
        [
            entry("package", "curl", "went_away"),
            entry("package", "git", "appeared"),
        ]
    );
    // A change set that does not fit writes nothing.
    let outcome = inventory::apply_changes(
        &mut ingest,
        HOST,
        &os,
        None,
        &[package("git", "2.50")],
        &[],
        fingerprint(&after),
        fingerprint(&after),
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(outcome, ChangesOutcome::Resync);
    assert_eq!(log(&admin).await.len(), 2);
    db.drop().await;
}

#[tokio::test]
async fn a_resync_diffs_against_the_stored_rows() {
    let (db, admin, mut ingest) = setup().await;
    inventory(&mut ingest, &[package("bash", "5.2")], 1).await;
    inventory(
        &mut ingest,
        &[package("bash", "5.2"), package("vim", "9")],
        2,
    )
    .await;
    assert_eq!(log(&admin).await, [entry("package", "vim", "appeared")]);
    db.drop().await;
}

#[tokio::test]
async fn prune_removes_rows_older_than_90_days_only() {
    let (db, admin, _ingest) = setup().await;
    let now = Utc::now();
    for (age, key) in [(91, "tcp/1"), (89, "tcp/2")] {
        admin
            .execute(
                "INSERT INTO change_log (at, agent_id, kind, key, change)
                 VALUES ($1, $2, 'listener', $3, 'appeared')",
                &[&(now - Duration::days(age)), &HOST, &key],
            )
            .await
            .unwrap();
    }
    assert_eq!(change_log::prune(&admin, now).await.unwrap(), 1);
    assert_eq!(log(&admin).await, [entry("listener", "tcp/2", "appeared")]);
    db.drop().await;
}

#[tokio::test]
async fn the_log_begins_when_the_migration_ran() {
    let (db, admin, _ingest) = setup().await;
    let start: chrono::DateTime<Utc> = admin
        .query_one("SELECT at FROM change_log_start", &[])
        .await
        .unwrap()
        .get(0);
    assert!(Utc::now() - start < Duration::minutes(5));
    db.drop().await;
}
