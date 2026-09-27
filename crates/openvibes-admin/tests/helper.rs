//! `openvibes-admin helper`: root-only verbs with closed arguments, checked
//! before anything else (admin TUI spec §3). Runs as the (non-root) test user.
// The test starts the CLI binary it verifies; this is not shipped code.
#![allow(clippy::disallowed_types)]

use std::process::{Command, Output};

fn helper(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_openvibes-admin"))
        .arg("helper")
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn refuses_without_root() {
    let out = helper(&["logs", "openvibes-ingest.service", "10"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("helper must run as root"));
}

#[test]
fn refuses_units_outside_the_allow_list_and_bad_counts_before_anything_else() {
    for args in [
        ["logs", "sshd.service", "10"],
        ["logs", "openvibes-ingest.service", "0"],
        ["logs", "openvibes-ingest.service", "100000"],
        ["logs", "openvibes-ingest.service", "x"],
    ] {
        let out = helper(&args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("not allowed"),
            "{args:?}"
        );
    }
}

#[test]
fn unknown_verbs_are_refused() {
    assert_eq!(helper(&["shell"]).status.code(), Some(2));
}

#[test]
fn config_verbs_refuse_other_services_before_anything_else() {
    for args in [
        ["config-read", "llm"],
        ["config-read", "../../etc/shadow"],
        ["config-write", "ingest.toml"],
        ["config-write", ""],
    ] {
        let out = helper(&args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("not allowed"),
            "{args:?}"
        );
    }
}

#[test]
fn config_verbs_need_root() {
    for verb in ["config-read", "config-write"] {
        let out = helper(&[verb, "ingest"]);
        assert_eq!(out.status.code(), Some(1), "{verb}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("helper must run as root"));
    }
}
