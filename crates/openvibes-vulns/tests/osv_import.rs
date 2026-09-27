//! Importing an OSV `all.zip` per release and matching hosts: Rocky by
//! source RPM, AlmaLinux by binary, Debian and Ubuntu by dpkg source
//! package (OSV spec D2, D3).

mod common;

use std::{io::Write, path::PathBuf};

use chrono::Utc;
use common::TestDb;
use openvibes_vulns::{matching, osv};
use platform_store::{
    Client,
    inventory::{self, PackageRow},
    vulns,
};
use serde_json::{Value, json};

const R9: &str = "agent.00000000-0000-4000-8000-000000000091";
const R8: &str = "agent.00000000-0000-4000-8000-000000000081";
const A10: &str = "agent.00000000-0000-4000-8000-0000000000a0";
const F44: &str = "agent.00000000-0000-4000-8000-0000000000f4";
const D12: &str = "agent.00000000-0000-4000-8000-0000000000d1";
const U24: &str = "agent.00000000-0000-4000-8000-0000000000e1";

/// Records beyond the trimmed real ones: a Rocky 9 fix named by its source
/// RPM, and a Debian 12 openssl fix.
const EXTRA: [(&str, &str); 2] = [
    (
        "RLSA-TEST-1.json",
        r#"{"id":"RLSA-TEST-1","summary":"Moderate: systemd update","upstream":["CVE-2026-1111"],
        "affected":[{"package":{"name":"systemd","ecosystem":"Rocky Linux:9"},
        "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"0:252-67.el9_8.2"}]}]}]}"#,
    ),
    (
        "DEBIAN-CVE-2026-2222.json",
        r#"{"id":"DEBIAN-CVE-2026-2222","upstream":["CVE-2026-2222"],"affected":[{"package":{"name":"openssl","ecosystem":"Debian:12"},
        "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.13-1~deb12u1"}]}],
        "ecosystem_specific":{"urgency":"high"}}]}"#,
    ),
];

/// The trimmed real records and `EXTRA` as one zip, plus a non-JSON file
/// and a broken record, as OSV's `all.zip` might carry.
fn all_zip() -> Vec<u8> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/osv");
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let mut paths: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    paths.sort();
    for path in paths {
        zip.start_file(path.file_name().unwrap().to_string_lossy(), options)
            .unwrap();
        zip.write_all(&std::fs::read(&path).unwrap()).unwrap();
    }
    for (name, record) in EXTRA {
        zip.start_file(name, options).unwrap();
        zip.write_all(record.as_bytes()).unwrap();
    }
    zip.start_file("README.txt", options).unwrap();
    zip.write_all(b"not a record").unwrap();
    zip.start_file("BROKEN-1.json", options).unwrap();
    zip.write_all(b"{\"id\": ").unwrap();
    zip.finish().unwrap().into_inner()
}

fn rpm(name: &str, epoch: i32, version: &str, release: &str) -> PackageRow {
    PackageRow {
        manager: "rpm".into(),
        name: name.into(),
        epoch,
        version: version.into(),
        release: release.into(),
        arch: "x86_64".into(),
        source: None,
        source_version: None,
    }
}

fn deb(name: &str, version: &str, release: &str) -> PackageRow {
    PackageRow {
        manager: "dpkg".into(),
        arch: "amd64".into(),
        ..rpm(name, 0, version, release)
    }
}

fn from(mut package: PackageRow, source: &str) -> PackageRow {
    package.source = Some(source.into());
    package
}

async fn setup() -> (TestDb, Client, Client) {
    let db = TestDb::create().await;
    let mut admin = db.pool.get().await.unwrap();
    platform_store::migrate(&mut admin).await.unwrap();
    let hosts: [(&str, &str, &str, Vec<PackageRow>); 6] = [
        (
            R9,
            "rocky",
            "9.4",
            vec![
                rpm("gzip", 0, "1.10", "8.el9"),
                from(rpm("systemd-libs", 0, "252", "60.el9"), "systemd"),
            ],
        ),
        (
            R8,
            "rocky",
            "8.10",
            vec![rpm("oci-umount", 2, "2.3.4", "1.el8")],
        ),
        (
            A10,
            "almalinux",
            "10.0",
            vec![rpm("unbound-libs", 0, "1.24.2", "7.el10_2.5")],
        ),
        (F44, "fedora", "44", vec![rpm("gzip", 0, "1.10", "8.el9")]),
        (
            D12,
            "debian",
            "12",
            vec![
                from(deb("libssl3", "3.0.11", "1~deb12u2"), "openssl"),
                deb("net-tools", "2.10", "0.1"),
                deb("binutils", "2.40", "2"),
                from(deb("libpam0g", "1.5.2", "6+deb12u1"), "pam"),
            ],
        ),
        (
            U24,
            "ubuntu",
            "24.04",
            vec![from(deb("libpcre2-8-0", "10.42", "4ubuntu2"), "pcre2")],
        ),
    ];
    for (i, (agent, os, version, packages)) in hosts.iter().enumerate() {
        admin
            .execute(
                "INSERT INTO agents (agent_id, status, enrolled_at) VALUES ($1, 'active', now())",
                &[agent],
            )
            .await
            .unwrap();
        let digest = [u8::try_from(i).unwrap() + 1; 32];
        inventory::replace(
            &mut admin,
            agent,
            os,
            version,
            None,
            packages,
            digest,
            Utc::now(),
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

/// A host's open vulnerabilities, with a fix or without (kept per package
/// version), as its list shows them.
async fn open(client: &Client, agent: &str) -> Vec<String> {
    let mut ids: Vec<String> = host_rows(client, agent)
        .await
        .into_iter()
        .map(|r| r.advisory_id)
        .collect();
    ids.sort();
    ids
}

async fn host_rows(client: &Client, agent: &str) -> Vec<vulns::VulnRow> {
    let filter = vulns::ListFilter {
        host: Some(agent),
        ..vulns::ListFilter::default()
    };
    vulns::list(client, &filter).await.unwrap()
}

#[tokio::test]
async fn each_release_matches_by_its_own_package_names() {
    let (db, mut admin, mut vulns) = setup().await;
    let zip = all_zip();
    for (release, opened, no_fix) in [
        ("rocky-9", 2, 0),
        ("rocky-8", 1, 0),
        ("almalinux-10", 1, 0),
        ("debian-12", 1, 1),
        ("ubuntu-24.04", 0, 1),
    ] {
        let release: osv::Release = release.parse().unwrap();
        let (report, skipped) = osv::import(&mut vulns, &release, zip.clone(), Utc::now())
            .await
            .unwrap();
        assert_eq!(skipped, 1, "the broken record");
        assert_eq!((report.open, report.no_fix), (opened, no_fix), "{release}");
    }
    assert_eq!(
        open(&vulns, R9).await,
        ["RLSA-2022:4582/rocky-9", "RLSA-TEST-1/rocky-9"],
        "9.4 is release 9; systemd-libs by its source RPM"
    );
    assert_eq!(open(&vulns, R8).await, ["RLSA-2019:0975/rocky-8"]);
    assert_eq!(open(&vulns, A10).await, ["ALSA-2026:71419/almalinux-10"]);
    assert!(open(&vulns, F44).await.is_empty(), "Fedora is not Rocky");
    assert_eq!(
        open(&vulns, D12).await,
        [
            "DEBIAN-CVE-2024-10041/debian-12",
            "DEBIAN-CVE-2026-2222/debian-12"
        ],
        "pam without a fix; libssl3 by its source; binutils already fixed; \
         net-tools' issue is unimportant"
    );
    assert_eq!(
        open(&vulns, U24).await,
        ["UBUNTU-CVE-2026-86145/ubuntu-24.04"]
    );

    let rocky = host_rows(&vulns, R9).await;
    let gzip = rocky
        .iter()
        .find(|r| r.advisory_id == "RLSA-2022:4582/rocky-9")
        .unwrap();
    assert_eq!(gzip.severity, "important");
    assert_eq!(gzip.cves, ["CVE-2022-1271"]);
    assert_eq!(gzip.packages[0]["installed"], "0:1.10-8.el9");
    assert_eq!(gzip.packages[0]["fixed"], "0:1.10-9.el9_0");
    let debian: Vec<(String, String, Value)> = host_rows(&vulns, D12)
        .await
        .iter()
        .map(|r| {
            let p = &r.packages[0];
            (
                p["name"].as_str().unwrap().to_owned(),
                p["installed"].as_str().unwrap().to_owned(),
                p["fixed"].clone(),
            )
        })
        .collect();
    assert_eq!(
        debian,
        [
            (
                "openssl".to_owned(),
                "0:3.0.11-1~deb12u2".to_owned(),
                json!("3.0.13-1~deb12u1")
            ),
            (
                "pam".to_owned(),
                "0:1.5.2-6+deb12u1".to_owned(),
                Value::Null
            ),
        ],
        "high urgency first; no fix known for pam"
    );
    let feeds: Vec<String> = vulns::feeds(&vulns)
        .await
        .unwrap()
        .into_iter()
        .map(|f| f.source)
        .collect();
    assert_eq!(
        feeds,
        [
            "almalinux-10",
            "debian-12",
            "rocky-8",
            "rocky-9",
            "ubuntu-24.04"
        ]
    );

    // Updated: fixed at the host's next inventory.
    inventory::replace(
        &mut admin,
        R9,
        "rocky",
        "9.4",
        None,
        &[
            rpm("gzip", 0, "1.10", "9.el9_0"),
            from(rpm("systemd-libs", 0, "252", "67.el9_8.2"), "systemd"),
        ],
        [9; 32],
        Utc::now(),
    )
    .await
    .unwrap();
    matching::match_host(&mut vulns, R9, Utc::now())
        .await
        .unwrap();
    assert!(open(&vulns, R9).await.is_empty());
    db.drop().await;
}

#[tokio::test]
async fn a_file_that_is_not_a_zip_is_refused_and_recorded() {
    let (db, _admin, mut vulns) = setup().await;
    let release: osv::Release = "rocky-9".parse().unwrap();
    let error = osv::import(&mut vulns, &release, b"<html>".to_vec(), Utc::now())
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "not a readable feed file");
    let feed = vulns::feeds(&vulns).await.unwrap().remove(0);
    assert!(feed.last_error.is_some());
    db.drop().await;
}
