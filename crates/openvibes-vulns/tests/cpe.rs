//! CPE matching: NVD applicability read from real records, stored, and
//! turned into lower-confidence findings, as the least-privilege
//! `openvibes-vulns` role.

mod common;

use chrono::Utc;
use common::TestDb;
use openvibes_vulns::{cpe, enrich};
use platform_store::{
    Client, cpe as store,
    inventory::{self, PackageRow},
    vulns::{FixedRow, NewAdvisory, replace_advisories},
};

const A: &str = "agent.00000000-0000-4000-8000-00000000000a";
const B: &str = "agent.00000000-0000-4000-8000-00000000000b";
const NVD: &[u8] = include_bytes!("fixtures/nvd-cpe.json");

fn pkg(name: &str, version: &str, source: Option<&str>) -> PackageRow {
    PackageRow {
        manager: "rpm".into(),
        name: name.into(),
        epoch: 0,
        version: version.into(),
        release: "1.fc44".into(),
        arch: "x86_64".into(),
        source: source.map(Into::into),
        source_version: None,
    }
}

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
    // A runs libcurl 8.3.0 (in NVD's range), B 8.5.0 (past it).
    for (agent, version, digest) in [(A, "8.3.0", 1u8), (B, "8.5.0", 2)] {
        inventory::replace(
            &mut admin,
            agent,
            "fedora",
            "44",
            None,
            &[
                pkg("libcurl", version, Some("curl")),
                pkg("xz", "5.4.0", None),
            ],
            [digest; 32],
            Utc::now(),
        )
        .await
        .unwrap();
    }
    let vulns = db.pool.get().await.unwrap();
    vulns
        .batch_execute("SET ROLE \"openvibes-vulns\"")
        .await
        .unwrap();
    (db, admin, vulns)
}

#[test]
fn real_nvd_records_give_application_ranges_only() {
    let page = enrich::parse_nvd(NVD).unwrap();
    let ranges = |cve: &str| -> Vec<_> {
        page.applicability
            .iter()
            .filter(|r| r.cve_id == cve)
            .collect()
    };
    let curl = ranges("CVE-2023-38545");
    assert_eq!(curl.len(), 1);
    assert_eq!(
        (
            curl[0].product.as_str(),
            curl[0].introduced.as_deref(),
            curl[0].fixed.as_deref()
        ),
        ("libcurl", Some("7.69.0"), Some("8.4.0"))
    );
    // NVD itself lists Fedora 37 as affected.
    assert_eq!(curl[0].fedora, ["37"]);
    // xz: two exact versions.
    let xz = ranges("CVE-2024-3094");
    assert_eq!(xz.len(), 2);
    assert!(
        xz.iter()
            .all(|r| r.introduced == r.last_affected && r.product == "xz")
    );
    // OpenSSH: ranges and exact versions; the `AND` firmware pairs are skipped.
    let ssh = ranges("CVE-2024-6387");
    assert!(ssh.iter().all(|r| r.product == "openssh"));
    assert!(ssh.iter().any(
        |r| r.introduced.as_deref() == Some("8.6") && r.last_affected.as_deref() == Some("9.8")
    ));
}

#[tokio::test]
async fn findings_follow_ranges_and_yield_to_advisories() {
    let (db, mut admin, mut vulns) = setup().await;
    let installed = store::installed_names(&vulns, "fedora").await.unwrap();
    let products = cpe::wanted_products(&installed);
    assert!(products.contains(&"libcurl".to_owned()) && products.contains(&"curl".to_owned()));
    assert_eq!(
        store::add_products(&vulns, &products).await.unwrap(),
        products.len() as u64
    );
    // Nothing new the second time: NVD need not be read again.
    assert!(!cpe::ensure_products(&vulns, "fedora").await.unwrap());

    let page = enrich::parse_nvd(NVD).unwrap();
    let ids: Vec<String> = page.entries.iter().map(|e| e.cve_id.clone()).collect();
    // Only ranges of kept products are stored (libcurl, xz; not openssh).
    let stored = store::replace_applicability(&mut vulns, &ids, &page.applicability)
        .await
        .unwrap();
    assert_eq!(stored, 3);

    let now = Utc::now();
    assert_eq!(
        cpe::refresh(&mut vulns, "fedora", "44", now).await.unwrap(),
        1
    );
    let found = store::list(&vulns, 0, None, None, None, 100).await.unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].agent_id, A);
    assert_eq!(
        (found[0].cve_id.as_str(), found[0].product.as_str()),
        ("CVE-2023-38545", "libcurl")
    );
    // An exact name match and a range: 60. NVD lists Fedora 37, not 44.
    assert_eq!(found[0].confidence, 60);
    assert!(found[0].basis.contains("7.69.0") && found[0].basis.contains("before 8.4.0"));
    assert!(
        store::list(&vulns, 61, None, None, None, 100)
            .await
            .unwrap()
            .is_empty()
    );
    // Scope: only the visible hosts.
    let only_b = vec![B.to_owned()];
    assert!(
        store::list(&vulns, 0, None, None, Some(&only_b), 100)
            .await
            .unwrap()
            .is_empty()
    );

    // A Fedora advisory naming the CVE takes over: no CPE finding remains.
    replace_advisories(
        &mut vulns,
        "fedora-44-x86_64",
        "fedora",
        "44",
        &[NewAdvisory {
            advisory_id: "FEDORA-2026-1".into(),
            severity: "important".into(),
            title: "curl security update".into(),
            issued_at: None,
            updated_at: None,
            url: "https://example.test".into(),
            cves: vec!["CVE-2023-38545".into()],
            packages: vec![FixedRow::rpm("libcurl", "x86_64", "0:8.4.0-1.fc44")],
        }],
        now,
    )
    .await
    .unwrap();
    assert_eq!(
        cpe::refresh(&mut vulns, "fedora", "44", now).await.unwrap(),
        0
    );
    assert!(
        store::list(&vulns, 0, None, None, None, 100)
            .await
            .unwrap()
            .is_empty()
    );
    let _ = &mut admin;
    drop(vulns);
    db.drop().await;
}
