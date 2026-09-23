//! `openvibes-admin ca`: the offline chain, import on the host, server certs.
// The test starts the CLI binary it verifies; this is not shipped code.
#![allow(clippy::disallowed_types)]

mod common;

use std::{os::unix::fs::PermissionsExt, path::Path};

use common::{Fixture, offline, scratch_dir, stdout};

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn s(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// Root, intermediate request, and signature, all without a database.
fn offline_chain(dir: &Path) {
    let root = dir.join("root");
    let host = dir.join("host");
    stdout(&offline(&["ca", "init-root", "--out", s(&root)]));
    stdout(&offline(&["ca", "intermediate-request", "--out", s(&host)]));
    stdout(&offline(&[
        "ca",
        "sign-intermediate",
        "--root",
        s(&root),
        "--csr",
        s(&host.join("intermediate.csr")),
        "--out",
        s(&host.join("intermediate.crt")),
    ]));
}

#[tokio::test]
async fn the_offline_chain_imports_and_issues_server_certificates() {
    let dir = scratch_dir("chain");
    offline_chain(&dir);
    assert_eq!(mode(&dir.join("root/root.key")), 0o600);
    assert_eq!(mode(&dir.join("root/root.crt")), 0o644);
    assert_eq!(mode(&dir.join("host/intermediate.key")), 0o600);
    assert_eq!(mode(&dir.join("host/intermediate.crt")), 0o644);

    let fixture = Fixture::create().await;
    stdout(&fixture.run(&["migrate"]));
    stdout(&fixture.run(&[
        "ca",
        "import-intermediate",
        "--cert",
        s(&dir.join("host/intermediate.crt")),
        "--key",
        s(&dir.join("host/intermediate.key")),
        "--root-cert",
        s(&dir.join("root/root.crt")),
    ]));
    assert_eq!(
        fixture.count("SELECT count(*) FROM ca_certificates").await,
        2
    );
    stdout(&fixture.run(&[
        "ca",
        "issue-server",
        "ingest.example",
        "--san",
        "10.0.0.5",
        "--issuer-cert",
        s(&dir.join("host/intermediate.crt")),
        "--issuer-key",
        s(&dir.join("host/intermediate.key")),
        "--out",
        s(&dir.join("tls")),
    ]));
    assert_eq!(mode(&dir.join("tls/ingest.example.key")), 0o600);
    let chain = std::fs::read_to_string(dir.join("tls/ingest.example.crt")).unwrap();
    assert_eq!(
        chain.matches("BEGIN CERTIFICATE").count(),
        2,
        "leaf + intermediate"
    );
    let audit = fixture.audit_targets().await;
    assert_eq!(audit[1].0, "ca import-intermediate");
    assert_eq!(
        audit[1].1.as_ref().map(String::len),
        Some(64),
        "target: fingerprint hex"
    );
    assert_eq!(
        (audit[2].0.as_str(), audit[2].1.as_deref()),
        ("ca issue-server", Some("ingest.example"))
    );
    fixture.drop().await;
}

#[test]
fn an_existing_certificate_leaves_no_orphan_key() {
    let dir = scratch_dir("orphan");
    let root = dir.join("root");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("root.crt"), "operator's file").unwrap();
    let again = offline(&["ca", "init-root", "--out", s(&root)]);
    assert!(!again.status.success());
    assert!(
        !root.join("root.key").exists(),
        "no key without its certificate"
    );
    assert_eq!(
        std::fs::read_to_string(root.join("root.crt")).unwrap(),
        "operator's file"
    );

    let host = dir.join("host");
    std::fs::create_dir_all(&host).unwrap();
    std::fs::write(host.join("intermediate.csr"), "old").unwrap();
    assert!(
        !offline(&["ca", "intermediate-request", "--out", s(&host)])
            .status
            .success()
    );
    assert!(!host.join("intermediate.key").exists());
}

#[test]
fn keys_are_never_overwritten() {
    let dir = scratch_dir("overwrite");
    let root = dir.join("root");
    stdout(&offline(&["ca", "init-root", "--out", s(&root)]));
    let before = std::fs::read(root.join("root.key")).unwrap();
    let again = offline(&["ca", "init-root", "--out", s(&root)]);
    assert!(!again.status.success());
    assert!(String::from_utf8_lossy(&again.stderr).contains("already exists"));
    assert_eq!(std::fs::read(root.join("root.key")).unwrap(), before);
    let bad_name = offline(&["ca", "init-root", "--out", s(&dir.join("x"))]);
    assert!(bad_name.status.success(), "a fresh directory is fine");
}

#[tokio::test]
async fn a_bad_import_records_nothing_and_is_audited() {
    let dir = scratch_dir("bad-import");
    offline_chain(&dir);
    let other = dir.join("other");
    stdout(&offline(&["ca", "init-root", "--out", s(&other)]));
    stdout(&offline(&[
        "ca",
        "intermediate-request",
        "--out",
        s(&dir.join("other-host")),
    ]));

    let fixture = Fixture::create().await;
    stdout(&fixture.run(&["migrate"]));
    let wrong_key = fixture.run(&[
        "ca",
        "import-intermediate",
        "--cert",
        s(&dir.join("host/intermediate.crt")),
        "--key",
        s(&dir.join("other-host/intermediate.key")),
        "--root-cert",
        s(&dir.join("root/root.crt")),
    ]);
    assert!(!wrong_key.status.success());
    let wrong_root = fixture.run(&[
        "ca",
        "import-intermediate",
        "--cert",
        s(&dir.join("host/intermediate.crt")),
        "--key",
        s(&dir.join("host/intermediate.key")),
        "--root-cert",
        s(&other.join("root.crt")),
    ]);
    assert!(!wrong_root.status.success());
    assert_eq!(
        fixture.count("SELECT count(*) FROM ca_certificates").await,
        0
    );
    let results: Vec<String> = fixture
        .audit_targets()
        .await
        .into_iter()
        .map(|row| row.2)
        .collect();
    assert_eq!(results, ["ok", "error", "error"]);
    fixture.drop().await;
}
