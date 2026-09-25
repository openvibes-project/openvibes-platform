//! Matching stored inventories against advisories, and the vulnerability
//! lifecycle, as the least-privilege `openvibes_vulns` role.

mod common;

use chrono::{Duration, Utc};
use common::TestDb;
use openvibes_vulns::{
    enrich::{self, Source},
    matching,
};
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
        source: None,
        source_version: None,
    }
}

async fn host(admin: &mut Client, agent: &str, release: &str, packages: &[PackageRow], digest: u8) {
    booted(admin, agent, release, packages, None, digest).await;
}

async fn booted(
    admin: &mut Client,
    agent: &str,
    release: &str,
    packages: &[PackageRow],
    kernel: Option<&str>,
    digest: u8,
) {
    inventory::replace(
        admin,
        agent,
        "fedora",
        release,
        kernel,
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
        packages: vec![FixedRow::rpm(
            name,
            arch,
            &format!("{epoch}:{version}-1.fc44"),
        )],
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
async fn an_installed_kernel_fix_counts_once_it_runs() {
    let (db, mut admin, mut vulns) = setup().await;
    let kernels = [
        pkg("kernel-core", 0, "6.17.4", "x86_64"),
        pkg("kernel-core", 0, "6.17.7", "x86_64"),
    ];
    // A: fix installed, old kernel running. B: fix running. Neither host
    // reported a kernel before P9: B's twin without one counts as fixed.
    booted(
        &mut admin,
        A,
        "44",
        &kernels,
        Some("6.17.4-1.fc44.x86_64"),
        1,
    )
    .await;
    booted(
        &mut admin,
        B,
        "44",
        &kernels,
        Some("6.17.7-1.fc44.x86_64"),
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
    assert_eq!(open(&vulns, A).await, ["FEDORA-K"]);
    assert!(open(&vulns, B).await.is_empty());
    let row = vulns
        .query_one(
            "SELECT packages, reboot_needed FROM vulnerabilities WHERE agent_id = $1",
            &[&A],
        )
        .await
        .unwrap();
    let packages: serde_json::Value = row.get(0);
    assert_eq!(packages[0]["installed"], "0:6.17.7-1.fc44");
    assert_eq!(packages[0]["running"], "0:6.17.4-1.fc44");
    assert!(row.get::<_, bool>(1), "fix installed, reboot needed");

    // A reboots into the fix: its next inventory closes it.
    booted(
        &mut admin,
        A,
        "44",
        &kernels,
        Some("6.17.7-1.fc44.x86_64"),
        3,
    )
    .await;
    matching::match_host(&mut vulns, A, Utc::now())
        .await
        .unwrap();
    assert!(open(&vulns, A).await.is_empty());

    // Other packages ignore the running kernel; a kernel still to install
    // is open without the reboot flag.
    booted(
        &mut admin,
        B,
        "44",
        &[pkg("kernel-core", 0, "6.17.4", "x86_64")],
        Some("6.17.4-1.fc44.x86_64"),
        4,
    )
    .await;
    matching::match_host(&mut vulns, B, Utc::now())
        .await
        .unwrap();
    let reboot: bool = vulns
        .query_one(
            "SELECT reboot_needed FROM vulnerabilities WHERE agent_id = $1 AND fixed_at IS NULL",
            &[&B],
        )
        .await
        .unwrap()
        .get(0);
    assert!(!reboot, "an update is needed first");
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

#[tokio::test]
async fn exploited_first_then_likely_exploited_then_severity() {
    let (db, mut admin, mut vulns) = setup().await;
    let names = ["a", "b", "c", "d"];
    let packages: Vec<PackageRow> = names.iter().map(|n| pkg(n, 0, "1.0", "x86_64")).collect();
    host(&mut admin, A, "44", &packages, 1).await;
    let make = |id: &str, name: &str, severity: &str, cves: &[&str]| {
        let mut a = advisory(id, name, 0, "2.0", "x86_64");
        a.severity = severity.into();
        a.cves = cves.iter().map(|c| (*c).to_owned()).collect();
        a
    };
    load(
        &mut vulns,
        &[
            make("FEDORA-CRIT", "a", "critical", &[]),
            make(
                "FEDORA-KEV",
                "b",
                "low",
                &["CVE-2026-1111", "CVE-2026-2222"],
            ),
            make("FEDORA-LIKELY", "c", "important", &["CVE-2026-3333"]),
            make("FEDORA-UNLIKELY", "d", "important", &["CVE-2026-4444"]),
        ],
        "44",
    )
    .await;
    matching::match_release(&mut vulns, "fedora", "44", Utc::now())
        .await
        .unwrap();
    let kev = br#"{"vulnerabilities":[{"cveID":"CVE-2026-2222","dateAdded":"2026-09-01",
        "dueDate":"2026-09-22","knownRansomwareCampaignUse":"Known"}]}"#;
    enrich::import(&mut vulns, Source::Kev, kev, Utc::now())
        .await
        .unwrap();
    let epss = b"cve,epss,percentile\nCVE-2026-1111,0.001,0.1\nCVE-2026-3333,0.9,0.995\nCVE-2026-4444,0.1,0.9\n";
    enrich::import(&mut vulns, Source::Epss, epss, Utc::now())
        .await
        .unwrap();

    let rows = vulns::list(&vulns, &vulns::ListFilter::default())
        .await
        .unwrap();
    let order: Vec<&str> = rows.iter().map(|r| r.advisory_id.as_str()).collect();
    assert_eq!(
        order,
        [
            "FEDORA-KEV",
            "FEDORA-LIKELY",
            "FEDORA-UNLIKELY",
            "FEDORA-CRIT"
        ]
    );
    let exploited = &rows[0];
    assert!(exploited.exploited && exploited.ransomware);
    assert_eq!(exploited.kev_due, "2026-09-22".parse().ok());
    assert_eq!(
        exploited.epss_percentile,
        Some(0.1),
        "the advisory's other CVE"
    );
    assert_eq!(rows[1].epss, Some(0.9));
    assert!(!rows[1].exploited);
    assert_eq!(rows[3].epss, None);

    let summary = vulns::summary(&vulns).await.unwrap();
    assert_eq!(summary.exploited, 1);
    db.drop().await;
}

#[tokio::test]
async fn euvd_counts_as_exploited_and_cvss_breaks_ties() {
    let (db, mut admin, mut vulns) = setup().await;
    let packages: Vec<PackageRow> = ["a", "b", "c"]
        .iter()
        .map(|n| pkg(n, 0, "1.0", "x86_64"))
        .collect();
    host(&mut admin, A, "44", &packages, 1).await;
    let make = |id: &str, name: &str, cve: &str| {
        let mut a = advisory(id, name, 0, "2.0", "x86_64");
        a.cves = vec![cve.to_owned()];
        a
    };
    load(
        &mut vulns,
        &[
            make("FEDORA-LOW-CVSS", "a", "CVE-2026-1111"),
            make("FEDORA-HIGH-CVSS", "b", "CVE-2026-2222"),
            make("FEDORA-EUVD", "c", "CVE-2026-3333"),
        ],
        "44",
    )
    .await;
    matching::match_release(&mut vulns, "fedora", "44", Utc::now())
        .await
        .unwrap();
    let cvss = |id: &str, score: f32| {
        format!(
            r#"{{"cve":{{"id":"{id}","metrics":{{"cvssMetricV31":[{{"type":"Primary",
            "cvssData":{{"baseScore":{score},"vectorString":"CVSS:3.1/AV:N"}}}}]}}}}}}"#
        )
    };
    let nvd = format!(
        r#"{{"totalResults":2,"startIndex":0,"vulnerabilities":[{},{}]}}"#,
        cvss("CVE-2026-1111", 5.3),
        cvss("CVE-2026-2222", 9.8)
    );
    enrich::import(&mut vulns, Source::Nvd, nvd.as_bytes(), Utc::now())
        .await
        .unwrap();
    let euvd = br#"{"total":1,"items":[{"id":"EUVD-2026-1","aliases":"CVE-2026-3333"}]}"#;
    enrich::import(&mut vulns, Source::Euvd, euvd, Utc::now())
        .await
        .unwrap();

    let rows = vulns::list(&vulns, &vulns::ListFilter::default())
        .await
        .unwrap();
    let order: Vec<&str> = rows.iter().map(|r| r.advisory_id.as_str()).collect();
    assert_eq!(
        order,
        ["FEDORA-EUVD", "FEDORA-HIGH-CVSS", "FEDORA-LOW-CVSS"]
    );
    assert!(rows[0].exploited && rows[0].euvd && !rows[0].kev);
    assert_eq!(rows[1].cvss, Some(9.8));
    assert_eq!(vulns::summary(&vulns).await.unwrap().exploited, 1);
    db.drop().await;
}

#[tokio::test]
async fn a_release_is_matched_in_batches_of_hosts() {
    let (db, mut admin, mut vulns) = setup().await;
    let c = "agent.00000000-0000-4000-8000-00000000000c";
    admin
        .execute(
            "INSERT INTO agents (agent_id, status, enrolled_at) VALUES ($1, 'active', now())",
            &[&c],
        )
        .await
        .unwrap();
    for (i, agent) in [A, B, c].into_iter().enumerate() {
        host(
            &mut admin,
            agent,
            "44",
            &[pkg("bash", 0, "5.0", "x86_64")],
            u8::try_from(i).unwrap() + 1,
        )
        .await;
    }
    load(
        &mut vulns,
        &[advisory("FEDORA-B", "bash", 0, "5.1", "x86_64")],
        "44",
    )
    .await;
    let opened = matching::match_release_in_batches(&mut vulns, "fedora", "44", 2, Utc::now())
        .await
        .unwrap();
    assert_eq!(opened, 3, "both batches matched");
    for agent in [A, B, c] {
        assert_eq!(open(&vulns, agent).await, ["FEDORA-B"]);
    }
    // The host in the second batch is fixed by a later run.
    host(&mut admin, c, "44", &[pkg("bash", 0, "5.1", "x86_64")], 9).await;
    matching::match_release_in_batches(&mut vulns, "fedora", "44", 2, Utc::now())
        .await
        .unwrap();
    assert!(open(&vulns, c).await.is_empty());
    assert_eq!(
        open(&vulns, A).await,
        ["FEDORA-B"],
        "the first batch keeps its own"
    );
    db.drop().await;
}

#[tokio::test]
async fn a_feed_is_recorded_current_only_after_its_match_succeeds() {
    let (db, mut admin, mut vulns) = setup().await;
    host(&mut admin, A, "44", &[pkg("bash", 0, "5.0", "x86_64")], 1).await;
    let content = std::fs::read(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/updateinfo-f44.xml.zst"),
    )
    .unwrap();
    let source: openvibes_vulns::feed::SourceId = "fedora-44-x86_64".parse().unwrap();
    // Matching fails (as it did on timeouts at scale): nothing is recorded
    // as current, so the next check downloads and imports it again.
    admin
        .batch_execute("REVOKE SELECT ON host_packages FROM openvibes_vulns")
        .await
        .unwrap();
    let failed = openvibes_vulns::feed::import(&mut vulns, &source, &content, Utc::now()).await;
    assert!(failed.is_err());
    assert_eq!(
        vulns::feed_digest(&vulns, "fedora-44-x86_64")
            .await
            .unwrap(),
        None
    );
    let feed = vulns::feeds(&vulns).await.unwrap().remove(0);
    assert!(feed.last_error.is_some());
    admin
        .batch_execute("GRANT SELECT ON host_packages TO openvibes_vulns")
        .await
        .unwrap();
    openvibes_vulns::feed::import(&mut vulns, &source, &content, Utc::now())
        .await
        .unwrap();
    assert!(
        vulns::feed_digest(&vulns, "fedora-44-x86_64")
            .await
            .unwrap()
            .is_some()
    );
    db.drop().await;
}
