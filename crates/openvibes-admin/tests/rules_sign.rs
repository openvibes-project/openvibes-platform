//! `openvibes-admin rules keygen|sign`: offline signing, no config or database.
// The test starts the CLI binary it verifies; this is not shipped code.
#![allow(clippy::disallowed_types)]

mod common;

use std::os::unix::fs::PermissionsExt;

use common::{offline, scratch_dir, stdout};

fn keygen(key: &std::path::Path, rule_set: &str) -> std::process::Output {
    offline(&[
        "rules",
        "keygen",
        key.to_str().unwrap(),
        "--rule-set",
        rule_set,
        "--issuer",
        "openvibes-1",
    ])
}

#[test]
fn keygen_writes_owner_only_key_and_prints_trust_line() {
    let dir = scratch_dir("keygen");
    let key = dir.join("rules.key");
    let line = stdout(&keygen(&key, "baseline"));
    let parts: Vec<&str> = line.trim_end().split(' ').collect();
    assert_eq!(parts[..2], ["baseline", "openvibes-1"], "{line}");
    assert_eq!(
        parts[2].len(),
        43,
        "32 bytes base64url without padding: {line}"
    );
    let meta = std::fs::metadata(&key).unwrap();
    assert_eq!(meta.len(), 32);
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
}

#[test]
fn keygen_refuses_existing_file() {
    let dir = scratch_dir("keygen-exists");
    let key = dir.join("rules.key");
    std::fs::write(&key, b"keep me").unwrap();
    assert!(!keygen(&key, "baseline").status.success());
    assert_eq!(std::fs::read(&key).unwrap(), b"keep me");
}

#[test]
fn keygen_refuses_bad_identifier() {
    let dir = scratch_dir("keygen-id");
    let key = dir.join("rules.key");
    assert!(!keygen(&key, "../x").status.success());
    assert!(!key.exists(), "no key written for a refused id");
}
