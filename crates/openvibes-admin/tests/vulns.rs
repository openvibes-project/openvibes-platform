//! `openvibes-admin feeds` and `vulns`: import a real (trimmed) Fedora 44
//! feed and read the vulnerabilities it opens on a stored inventory.
// The test starts the CLI binary it verifies; this is not shipped code.
#![allow(clippy::disallowed_types)]

mod common;

use std::path::PathBuf;

use chrono::Utc;
use common::{Fixture, scratch_dir, stdout};
use platform_store::inventory::{self, PackageRow};

const HOST: &str = "agent.00000000-0000-4000-8000-0000000000a1";

fn feed() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../openvibes-vulns/tests/fixtures/updateinfo-f44.xml.zst")
        .to_string_lossy()
        .into_owned()
}

async fn ready() -> Fixture {
    let fixture = Fixture::create().await;
    stdout(&fixture.run(&["migrate"]));
    let pool = platform_store::connect(&fixture.url).await.unwrap();
    let mut client = pool.get().await.unwrap();
    client
        .execute(
            "INSERT INTO agents (agent_id, status, enrolled_at, hostname) VALUES ($1, 'active', now(), 'web-01')",
            &[&HOST],
        )
        .await
        .unwrap();
    let packages = [
        PackageRow {
            manager: "rpm".into(),
            name: "wordpress".into(),
            epoch: 0,
            version: "6.9.6".into(),
            release: "1.fc44".into(),
            arch: "noarch".into(),
            source: None,
            source_version: None,
        },
        PackageRow {
            manager: "rpm".into(),
            name: "perl-Data-Entropy".into(),
            epoch: 0,
            version: "0.010".into(),
            release: "1.fc44".into(),
            arch: "noarch".into(),
            source: None,
            source_version: None,
        },
    ];
    inventory::replace(
        &mut client,
        HOST,
        "fedora",
        "44",
        None,
        &packages,
        [1; 32],
        Utc::now(),
    )
    .await
    .unwrap();
    fixture
}

fn failed(fixture: &Fixture, args: &[&str], message: &str) {
    let output = fixture.run(args);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "unexpected success: {args:?}");
    assert!(stderr.contains(message), "want {message:?}, got {stderr}");
}

#[tokio::test]
async fn an_imported_feed_opens_vulnerabilities_operators_can_read() {
    let fixture = ready().await;
    let out = stdout(&fixture.run(&["feeds", "import", &feed(), "--source", "fedora-44-x86_64"]));
    assert_eq!(
        out,
        "imported 3 advisories into fedora-44-x86_64; 1 open on fedora 44\n"
    );

    let status = stdout(&fixture.run(&["feeds", "status"]));
    assert!(
        status.starts_with("fedora-44-x86_64 advisories 3 checked "),
        "{status}"
    );

    let list = stdout(&fixture.run(&["vulns", "list"]));
    assert!(
        list.contains("important FEDORA-2026-dc0ff85b8b web-01"),
        "{list}"
    );
    assert!(
        list.contains("wordpress 0:6.9.6-1.fc44 -> 0:6.9.7-1.fc44"),
        "{list}"
    );
    assert!(list.contains("CVE-2026-64638"), "{list}");
    assert!(
        !list.contains("perl-Data-Entropy"),
        "already at the fixed version"
    );

    let summary = stdout(&fixture.run(&["vulns", "summary"]));
    assert!(
        summary.starts_with("open 1 on 1 hosts: important 1\n"),
        "{summary}"
    );
    assert!(summary.contains("web-01"), "{summary}");

    let advisory = stdout(&fixture.run(&["vulns", "show", "FEDORA-2026-dc0ff85b8b"]));
    assert!(advisory.contains("https://bodhi.fedoraproject.org/updates/FEDORA-2026-dc0ff85b8b"));
    assert!(advisory.contains("web-01"), "{advisory}");
    let host = stdout(&fixture.run(&["vulns", "show", "web-01"]));
    assert!(host.contains("FEDORA-2026-dc0ff85b8b"), "{host}");

    let actions: Vec<String> = fixture
        .audit_targets()
        .await
        .into_iter()
        .map(|(action, _, _)| action)
        .collect();
    assert!(actions.contains(&"feeds import".to_owned()), "{actions:?}");
    fixture.drop().await;
}

#[tokio::test]
async fn exploited_and_likely_exploited_are_shown_with_the_reason() {
    let fixture = ready().await;
    stdout(&fixture.run(&["feeds", "import", &feed(), "--source", "fedora-44-x86_64"]));
    let dir = scratch_dir("enrich");
    let kev = dir.join("kev.json");
    std::fs::write(
        &kev,
        r#"{"vulnerabilities":[{"cveID":"CVE-2026-64638","dateAdded":"2026-09-01",
            "dueDate":"2026-09-22","knownRansomwareCampaignUse":"Known"}]}"#,
    )
    .unwrap();
    let epss = dir.join("epss.csv");
    std::fs::write(&epss, "cve,epss,percentile\nCVE-2026-64638,0.94,0.995\n").unwrap();
    let out = stdout(&fixture.run(&["feeds", "import", kev.to_str().unwrap(), "--source", "kev"]));
    assert_eq!(out, "imported 1 CVEs from kev\n");
    stdout(&fixture.run(&[
        "feeds",
        "import",
        epss.to_str().unwrap(),
        "--source",
        "epss",
    ]));

    let list = stdout(&fixture.run(&["vulns", "list"]));
    assert!(
        list.contains("exploited (KEV, due 2026-09-22, ransomware) EPSS 94.0% (top 1%)"),
        "{list}"
    );
    let summary = stdout(&fixture.run(&["vulns", "summary"]));
    assert!(
        summary.contains("exploited in the wild (CISA KEV): 1\n"),
        "{summary}"
    );
    let status = stdout(&fixture.run(&["feeds", "status"]));
    assert!(status.contains("kev cves 1 checked "), "{status}");
    assert!(status.contains("epss cves 1 checked "), "{status}");
    failed(
        &fixture,
        &["feeds", "import", kev.to_str().unwrap(), "--source", "osv"],
        "use fedora-<release>-<arch>, rocky-N, almalinux-N, debian-N, ubuntu-YY.MM, kev, epss, nvd, or euvd",
    );

    // NVD and EUVD (VM5): CVSS, weakness and description; EUVD's mark.
    let nvd = dir.join("nvd.json");
    std::fs::write(
        &nvd,
        r#"{"totalResults":1,"startIndex":0,"vulnerabilities":[{"cve":{"id":"CVE-2026-64638",
            "lastModified":"2026-09-20T10:00:00.000","descriptions":[{"lang":"en",
            "value":"Stored XSS in the block editor."}],"weaknesses":[{"description":
            [{"lang":"en","value":"CWE-79"}]}],"metrics":{"cvssMetricV31":[{"type":"Primary",
            "cvssData":{"baseScore":6.1,"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}}]}}}]}"#,
    )
    .unwrap();
    let euvd = dir.join("euvd.json");
    std::fs::write(
        &euvd,
        r#"{"total":1,"items":[{"id":"EUVD-2026-64000","aliases":"CVE-2026-64638"}]}"#,
    )
    .unwrap();
    let out = stdout(&fixture.run(&["feeds", "import", nvd.to_str().unwrap(), "--source", "nvd"]));
    assert_eq!(out, "imported 1 CVEs from nvd\n");
    stdout(&fixture.run(&[
        "feeds",
        "import",
        euvd.to_str().unwrap(),
        "--source",
        "euvd",
    ]));
    let list = stdout(&fixture.run(&["vulns", "list"]));
    assert!(
        list.contains(
            "exploited (KEV, due 2026-09-22, ransomware; EUVD) EPSS 94.0% (top 1%) CVSS 6.1"
        ),
        "{list}"
    );
    let advisory = stdout(&fixture.run(&["vulns", "show", "FEDORA-2026-dc0ff85b8b"]));
    assert!(
        advisory.contains(
            "  CVE-2026-64638 CVSS 6.1 (3.1) CWE-79 KEV EUVD-2026-64000 EPSS 94.0%: Stored XSS in the block editor.\n"
        ),
        "{advisory}"
    );
    fixture.drop().await;
}

#[tokio::test]
async fn a_kernel_awaiting_reboot_is_shown_as_such() {
    let fixture = ready().await;
    stdout(&fixture.run(&["feeds", "import", &feed(), "--source", "fedora-44-x86_64"]));
    // As matching records it (protocol P9); the fixture feed has no kernel.
    let pool = platform_store::connect(&fixture.url).await.unwrap();
    pool.get()
        .await
        .unwrap()
        .execute(
            r#"UPDATE vulnerabilities SET reboot_needed = true, packages =
                 '[{"name":"kernel-core","installed":"0:6.17.7-1.fc44","fixed":"0:6.17.6-1.fc44","running":"0:6.17.4-1.fc44"}]'"#,
            &[],
        )
        .await
        .unwrap();
    let list = stdout(&fixture.run(&["vulns", "list"]));
    assert!(
        list.contains("kernel-core 0:6.17.7-1.fc44 -> 0:6.17.6-1.fc44 (running 0:6.17.4-1.fc44)"),
        "{list}"
    );
    assert!(list.contains("fix installed, reboot needed"), "{list}");
    // A separate state: not counted as open (the user's decision).
    let summary = stdout(&fixture.run(&["vulns", "summary"]));
    assert!(
        summary.starts_with("open 0 on 0 hosts: none\nfix installed, reboot needed on 1 hosts\n"),
        "{summary}"
    );
    fixture.drop().await;
}

#[tokio::test]
async fn bad_feeds_and_sources_are_refused_and_recorded() {
    let fixture = ready().await;
    let dir = scratch_dir("bad-feed");
    let junk = dir.join("junk.xml");
    std::fs::write(&junk, "<updates><update type=\"security\">").unwrap();
    failed(
        &fixture,
        &[
            "feeds",
            "import",
            junk.to_str().unwrap(),
            "--source",
            "fedora-44-x86_64",
        ],
        "not a readable feed file",
    );
    let status = stdout(&fixture.run(&["feeds", "status"]));
    assert!(
        status.contains("error: not a readable feed file"),
        "{status}"
    );
    failed(
        &fixture,
        &["feeds", "import", &feed(), "--source", "slackware-15"],
        "fedora-<release>-<arch>",
    );
    failed(
        &fixture,
        &["vulns", "show", "nothing-here"],
        "no advisory or host",
    );
    fixture.drop().await;
}

#[tokio::test]
async fn a_debian_vulnerability_without_a_fix_is_labelled_and_counted() {
    use std::io::Write;
    let fixture = Fixture::create().await;
    stdout(&fixture.run(&["migrate"]));
    let pool = platform_store::connect(&fixture.url).await.unwrap();
    let mut client = pool.get().await.unwrap();
    let debian = "agent.00000000-0000-4000-8000-0000000000d2";
    client
        .execute(
            "INSERT INTO agents (agent_id, status, enrolled_at, hostname) VALUES ($1, 'active', now(), 'deb-01')",
            &[&debian],
        )
        .await
        .unwrap();
    let pam = PackageRow {
        manager: "dpkg".into(),
        name: "libpam0g".into(),
        epoch: 0,
        version: "1.5.2".into(),
        release: "6+deb12u1".into(),
        arch: "amd64".into(),
        source: Some("pam".into()),
        source_version: None,
    };
    inventory::replace(
        &mut client,
        debian,
        "debian",
        "12",
        None,
        &[pam],
        [7; 32],
        Utc::now(),
    )
    .await
    .unwrap();
    let record = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../openvibes-vulns/tests/fixtures/osv/DEBIAN-CVE-2024-10041.json");
    let dir = scratch_dir("osv-debian");
    let zip_path = dir.join("all.zip");
    let mut zip = zip::ZipWriter::new(std::fs::File::create(&zip_path).unwrap());
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("DEBIAN-CVE-2024-10041.json", options)
        .unwrap();
    zip.write_all(&std::fs::read(record).unwrap()).unwrap();
    zip.finish().unwrap();

    let out = stdout(&fixture.run(&[
        "feeds",
        "import",
        zip_path.to_str().unwrap(),
        "--source",
        "debian-12",
    ]));
    assert_eq!(out, "imported 1 advisories into debian-12; 1 open\n");
    let list = stdout(&fixture.run(&["vulns", "list"]));
    assert!(
        list.contains("DEBIAN-CVE-2024-10041/debian-12 deb-01"),
        "{list}"
    );
    assert!(
        list.contains("pam 0:1.5.2-6+deb12u1 (no fix available)"),
        "{list}"
    );
    let summary = stdout(&fixture.run(&["vulns", "summary"]));
    assert!(summary.contains("no fix available yet: 1\n"), "{summary}");
    let show = stdout(&fixture.run(&["vulns", "show", "DEBIAN-CVE-2024-10041/debian-12"]));
    assert!(
        show.contains("https://osv.dev/vulnerability/DEBIAN-CVE-2024-10041"),
        "{show}"
    );
    fixture.drop().await;
}
