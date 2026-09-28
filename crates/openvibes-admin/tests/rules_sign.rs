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

const RULES: &str = r#"{"schema_version":1,"rules":[{"id":"port.redis.exposed","version":1,"title":"Redis is exposed","severity":"high","confidence":90,"expression":"'6379' in facts['port.tcp.exposed']","finding_message":"Redis listens on a non-loopback address (tcp 6379)"}]}"#;

/// A fresh key and rules file in `dir`; returns (key, rules) paths.
fn setup(dir: &std::path::Path) -> (String, String) {
    let key = dir.join("rules.key");
    let rules = dir.join("rules.json");
    std::fs::write(&rules, RULES).unwrap();
    stdout(&keygen(&key, "baseline"));
    (
        key.to_str().unwrap().to_owned(),
        rules.to_str().unwrap().to_owned(),
    )
}

fn sign_args<'a>(key: &'a str, rules: &'a str, out: &'a str) -> Vec<&'a str> {
    vec![
        "rules",
        "sign",
        key,
        rules,
        "--rule-set",
        "baseline",
        "--version",
        "3",
        "--issuer",
        "openvibes-1",
        "-o",
        out,
    ]
}

#[test]
fn sign_writes_an_envelope_over_the_exact_rules_bytes() {
    let dir = scratch_dir("sign");
    let (key, rules) = setup(&dir);
    let out = dir.join("baseline.json");
    let printed = stdout(&offline(&sign_args(&key, &rules, out.to_str().unwrap())));
    assert!(
        printed.starts_with("signed baseline v3, expires "),
        "{printed}"
    );
    let envelope: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
    assert_eq!(envelope["payload"], RULES);
    assert_eq!(envelope["rule_set_version"], 3);
    assert_eq!(envelope["issuer_key_id"], "openvibes-1");
    let lifetime = envelope["expires_at_unix_ms"].as_i64().unwrap()
        - envelope["created_at_unix_ms"].as_i64().unwrap();
    assert_eq!(lifetime, 730 * 86_400_000);
    // Created 0644, then narrowed by the umask: never writable by others.
    let mode = std::fs::metadata(&out).unwrap().permissions().mode();
    assert_eq!(mode & 0o022, 0, "mode {mode:o}");
    assert_ne!(mode & 0o400, 0, "mode {mode:o}");
}

#[test]
fn sign_refuses_group_readable_key() {
    for mode in [0o640, 0o604] {
        let dir = scratch_dir(&format!("sign-mode-{mode:o}"));
        let (key, rules) = setup(&dir);
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(mode)).unwrap();
        let out = dir.join("baseline.json");
        let output = offline(&sign_args(&key, &rules, out.to_str().unwrap()));
        assert!(!output.status.success(), "mode {mode:o} accepted");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("chmod 600"), "{stderr}");
        assert!(stderr.contains("FAT/exFAT"), "{stderr}");
        assert!(!out.exists());
    }
}

#[test]
fn sign_refuses_short_key() {
    let dir = scratch_dir("sign-short");
    let (key, rules) = setup(&dir);
    std::fs::write(&key, [7u8; 31]).unwrap();
    let out = dir.join("baseline.json");
    let output = offline(&sign_args(&key, &rules, out.to_str().unwrap()));
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("exactly 32 bytes"));
    assert!(!out.exists());
}

#[test]
fn sign_refuses_invalid_rules() {
    let dir = scratch_dir("sign-invalid");
    let (key, rules) = setup(&dir);
    std::fs::write(&rules, r#"{"schema_version":1,"rules":[]}"#).unwrap();
    let out = dir.join("baseline.json");
    let output = offline(&sign_args(&key, &rules, out.to_str().unwrap()));
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid rule set"));
    assert!(!out.exists());
}

#[test]
fn sign_refuses_existing_output() {
    let dir = scratch_dir("sign-exists");
    let (key, rules) = setup(&dir);
    let out = dir.join("baseline.json");
    std::fs::write(&out, b"previous release").unwrap();
    let output = offline(&sign_args(&key, &rules, out.to_str().unwrap()));
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("File exists"));
    assert_eq!(std::fs::read(&out).unwrap(), b"previous release");
}

#[test]
fn sign_refuses_zero_days() {
    let dir = scratch_dir("sign-days");
    let (key, rules) = setup(&dir);
    let out = dir.join("baseline.json");
    let mut args = sign_args(&key, &rules, out.to_str().unwrap());
    args.extend(["--days", "0"]);
    assert!(!offline(&args).status.success());
    assert!(!out.exists());
}

#[test]
fn keygen_accepts_a_bare_file_name() {
    // The directory to flush is "." when the path has no parent part.
    let dir = scratch_dir("keygen-bare");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_openvibes-admin"))
        .current_dir(&dir)
        .args(["--config", "/nonexistent/openvibes-admin.toml"])
        .args([
            "rules",
            "keygen",
            "rules.key",
            "--rule-set",
            "baseline",
            "--issuer",
            "openvibes-1",
        ])
        .output()
        .unwrap();
    stdout(&output);
    assert_eq!(std::fs::metadata(dir.join("rules.key")).unwrap().len(), 32);
}
