//! Matching stored inventories against advisories, and the vulnerability
//! lifecycle, as the least-privilege `openvibes_vulns` role.

mod common;

use chrono::{Duration, Utc};
use common::TestDb;
use openvibes_vulns::matching;
use platform_store::{
    Client,
    inventory::{self, PackageRow},
    vulns::{self, FixedRow, NewAdvisory},
};
use tokio_postgres::error::SqlState;

const A: &str = "agent.00000000-0000-4000-8000-00000000000a";
const B: &str = "agent.00000000-0000-4000-8000-00000000000b";

async fn setup() -> (TestDb, Client, Client) {
    let db = TestDb::create().await;
    let mut admin = db.pool.get().await.unwrap();
    platform_store::migrate(&mut admin).await.unwrap();
    for agent in [A, B] {
        admin
            .execute(
                "INSERT INTO agents (agent_id, status, enrolled_at) VALUES ($1, 'active', now())",
                &[&agent],
            )
            .await
            .unwrap();
    }
    let vulns = db.pool.get().await.unwrap();
    vulns
        .batch_execute("SET ROLE openvibes_vulns")
        .await
        .unwrap();
    (db, admin, vulns)
}

fn pkg(name: &str, epoch: i32, version: &str, arch: &str) -> PackageRow {
    PackageRow {
        manager: "rpm".into(),
        name: name.into(),
        epoch,
        version: version.into(),
        release: "1.fc44".into(),
        arch: arch.into(),
    }
}

async fn host(admin: &mut Client, agent: &str, release: &str, packages: &[PackageRow], digest: u8) {
    inventory::replace(
        admin,
        agent,
        "fedora",
        release,
        packages,
        [digest; 32],
        Utc::now(),
    )
    .await
    .unwrap();
}

fn advisory(id: &str, name: &str, epoch: i32, version: &str, arch: &str) -> NewAdvisory {
    NewAdvisory {
        advisory_id: id.into(),
        severity: "important".into(),
        title: format!("{name} security update"),
        issued_at: Some(Utc::now() - Duration::days(1)),
        updated_at: Some(Utc::now() - Duration::days(1)),
        url: format!("https://bodhi.fedoraproject.org/updates/{id}"),
        cves: vec!["CVE-2026-0001".into()],
        packages: vec![FixedRow {
            name: name.into(),
            arch: arch.into(),
            epoch,
            version: version.into(),
            release: "1.fc44".into(),
        }],
    }
}

async fn open(client: &Client, agent: &str) -> Vec<String> {
    client
        .query(
            "SELECT advisory_id FROM vulnerabilities WHERE agent_id = $1 AND fixed_at IS NULL ORDER BY 1",
            &[&agent],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect()
}

async fn load(vulns: &mut Client, advisories: &[NewAdvisory], release: &str) {
    vulns::replace_advisories(
        vulns,
        "fedora-44-x86_64",
        "fedora",
        release,
        advisories,
        Utc::now(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn an_older_installed_version_is_vulnerable_a_newer_one_is_not() {
    let (db, mut admin, mut vulns) = setup().await;
    host(
        &mut admin,
        A,
        "44",
        &[pkg("bash", 0, "5.2.36", "x86_64")],
        1,
    )
    .await;
    host(
        &mut admin,
        B,
        "44",
        &[pkg("bash", 0, "5.2.38", "x86_64")],
        2,
    )
    .await;
    load(
        &mut vulns,
        &[advisory("FEDORA-1", "bash", 0, "5.2.37", "x86_64")],
        "44",
    )
    .await;
    matching::match_release(&mut vulns, "fedora", "44", Utc::now())
        .await
        .unwrap();
    assert_eq!(open(&vulns, A).await, ["FEDORA-1"]);
    assert!(open(&vulns, B).await.is_empty());
    let packages: serde_json::Value = vulns
        .query_one(
            "SELECT packages FROM vulnerabilities WHERE agent_id = $1",
            &[&A],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(packages[0]["name"], "bash");
    assert_eq!(packages[0]["installed"], "0:5.2.36-1.fc44");
    assert_eq!(packages[0]["fixed"], "0:5.2.37-1.fc44");
    db.drop().await;
}

#[tokio::test]
async fn arch_noarch_epoch_and_release_rules() {
    let (db, mut admin, mut vulns) = setup().await;
    host(
        &mut admin,
        A,
        "44",
        &[
            pkg("wordpress", 0, "6.9.6", "noarch"),
            pkg("tool", 1, "1.0", "x86_64"),
            pkg("lib", 0, "1.0", "aarch64"),
        ],
        1,
    )
    .await;
    host(
        &mut admin,
        B,
        "43",
        &[pkg("wordpress", 0, "6.9.6", "noarch")],
        2,
    )
    .await;
    load(
        &mut vulns,
        &[
            advisory("FEDORA-W", "wordpress", 0, "6.9.7", "noarch"),
            advisory("FEDORA-T", "tool", 0, "2.0", "x86_64"), // epoch 1 beats 0:2.0
            advisory("FEDORA-L", "lib", 0, "2.0", "x86_64"),  // other architecture
        ],
        "44",
    )
    .await;
    matching::match_release(&mut vulns, "fedora", "44", Utc::now())
        .await
        .unwrap();
    assert_eq!(open(&vulns, A).await, ["FEDORA-W"]);
    assert!(
        open(&vulns, B).await.is_empty(),
        "Fedora 43 hosts are not matched against 44"
    );
    db.drop().await;
}

#[tokio::test]
async fn several_installed_versions_count_by_the_newest() {
    let (db, mut admin, mut vulns) = setup().await;
    // Kernels: an old one kept beside a fixed one is not open.
    host(
        &mut admin,
        A,
        "44",
        &[
            pkg("kernel-core", 0, "6.17.4", "x86_64"),
            pkg("kernel-core", 0, "6.17.7", "x86_64"),
        ],
        1,
    )
    .await;
    host(
        &mut admin,
        B,
        "44",
        &[
            pkg("kernel-core", 0, "6.17.4", "x86_64"),
            pkg("kernel-core", 0, "6.17.5", "x86_64"),
        ],
        2,
    )
    .await;
    load(
        &mut vulns,
        &[advisory("FEDORA-K", "kernel-core", 0, "6.17.6", "x86_64")],
        "44",
    )
    .await;
    matching::match_release(&mut vulns, "fedora", "44", Utc::now())
        .await
        .unwrap();
    assert!(open(&vulns, A).await.is_empty());
    assert_eq!(open(&vulns, B).await, ["FEDORA-K"]);
    let packages: serde_json::Value = vulns
        .query_one(
            "SELECT packages FROM vulnerabilities WHERE agent_id = $1",
            &[&B],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        packages[0]["installed"], "0:6.17.5-1.fc44",
        "the newest installed"
    );
    db.drop().await;
}

#[tokio::test]
async fn upgrade_fixes_and_downgrade_reopens() {
    let (db, mut admin, mut vulns) = setup().await;
    host(
        &mut admin,
        A,
        "44",
        &[pkg("bash", 0, "5.2.36", "x86_64")],
        1,
    )
    .await;
    load(
        &mut vulns,
        &[advisory("FEDORA-1", "bash", 0, "5.2.37", "x86_64")],
        "44",
    )
    .await;
    let t0 = Utc::now();
    matching::match_release(&mut vulns, "fedora", "44", t0)
        .await
        .unwrap();
    // Upgrade: the host's next inventory has the fixed version.
    host(
        &mut admin,
        A,
        "44",
        &[pkg("bash", 0, "5.2.37", "x86_64")],
        2,
    )
    .await;
    let t1 = t0 + Duration::hours(1);
    matching::match_host(&mut vulns, A, t1).await.unwrap();
    assert!(open(&vulns, A).await.is_empty());
    let row = vulns
        .query_one(
            "SELECT first_seen_at, fixed_at FROM vulnerabilities WHERE agent_id = $1",
            &[&A],
        )
        .await
        .unwrap();
    let (first, fixed): (chrono::DateTime<Utc>, Option<chrono::DateTime<Utc>>) =
        (row.get(0), row.get(1));
    assert_eq!(fixed.map(|f| f.timestamp()), Some(t1.timestamp()));
    // Downgrade: open again, first seen unchanged.
    host(
        &mut admin,
        A,
        "44",
        &[pkg("bash", 0, "5.2.36", "x86_64")],
        3,
    )
    .await;
    matching::match_host(&mut vulns, A, t1 + Duration::hours(1))
        .await
        .unwrap();
    assert_eq!(open(&vulns, A).await, ["FEDORA-1"]);
    let again: chrono::DateTime<Utc> = vulns
        .query_one(
            "SELECT first_seen_at FROM vulnerabilities WHERE agent_id = $1",
            &[&A],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(again.timestamp(), first.timestamp());
    db.drop().await;
}

#[tokio::test]
async fn a_reloaded_feed_keeps_history_and_the_role_is_limited() {
    let (db, mut admin, mut vulns) = setup().await;
    host(
        &mut admin,
        A,
        "44",
        &[pkg("bash", 0, "5.2.36", "x86_64")],
        1,
    )
    .await;
    load(
        &mut vulns,
        &[advisory("FEDORA-1", "bash", 0, "5.2.37", "x86_64")],
        "44",
    )
    .await;
    matching::match_release(&mut vulns, "fedora", "44", Utc::now())
        .await
        .unwrap();
    // The same feed again (or one without the advisory) never deletes records.
    load(&mut vulns, &[], "44").await;
    assert_eq!(open(&vulns, A).await, ["FEDORA-1"]);
    for denied in [
        "DELETE FROM host_packages",
        "INSERT INTO package_versions (manager, name, version) VALUES ('rpm', 'x', '1')",
        "UPDATE agents SET status = 'revoked'",
        "SELECT count(*) FROM findings",
    ] {
        let error = vulns.batch_execute(denied).await.expect_err(denied);
        assert_eq!(
            error.code(),
            Some(&SqlState::INSUFFICIENT_PRIVILEGE),
            "{denied}"
        );
    }
    db.drop().await;
}
