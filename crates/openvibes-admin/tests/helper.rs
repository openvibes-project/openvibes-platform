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

#[test]
fn setup_verbs_check_their_arguments_before_the_root_check() {
    for args in [
        vec!["setup-step", "everything"],
        vec!["setup-step", "../ca"],
        vec!["unit-enable", "sshd.service"],
        vec!["unit-disable", "openvibes-ingest"],
        vec![
            "setup-plan",
            "--components",
            "console",
            "--hostname",
            "platform.example.com",
        ],
        vec![
            "setup-plan",
            "--components",
            "ingest",
            "--hostname",
            "Bad Name",
        ],
    ] {
        let out = helper(&args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("not allowed"),
            "{args:?}"
        );
    }
    let out = helper(&["setup-step", "packages"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("helper must run as root"));
}

#[test]
fn setup_quick_needs_root_and_checks_its_plan() {
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_openvibes-admin"))
            .args(args)
            .output()
            .unwrap()
    };
    let out = run(&[
        "setup",
        "--quick",
        "--components",
        "ingest",
        "--hostname",
        "platform.example.com",
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("must run as root"));
    let out = run(&[
        "setup",
        "--quick",
        "--components",
        "vulns",
        "--hostname",
        "platform.example.com",
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("must include ingest"));
    let out = run(&[
        "setup",
        "--components",
        "ingest",
        "--hostname",
        "platform.example.com",
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--quick"));
}

#[test]
fn maintenance_verbs_check_their_arguments_before_the_root_check() {
    for (args, reason) in [
        (vec!["update-step", "everything"], "not an update step"),
        (
            vec!["update-step", "backup", "--backup", "relative.dump"],
            "absolute",
        ),
        (vec!["remove-step", "purge"], "--components is required"),
        (
            vec![
                "remove-step",
                "purge",
                "--components",
                "ingest",
                "--confirm",
                "Bad Name",
            ],
            "lowercase DNS name",
        ),
        (
            vec![
                "setup-plan",
                "--components",
                "ingest",
                "--hostname",
                "platform.example.com",
                "--allow-unsigned-local",
            ],
            "needs --repo-dir",
        ),
    ] {
        let out = helper(&args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("not allowed") && stderr.contains(reason),
            "{args:?}: {stderr}"
        );
    }
    for args in [
        vec!["setup-step", "ca", "--repair"],
        vec!["update-step", "stop"],
        vec!["remove-step", "stop", "--components", "vulns"],
    ] {
        let out = helper(&args);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
    }
}

#[test]
fn setup_actions_need_root_and_exactly_one_action() {
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_openvibes-admin"))
            .args(args)
            .output()
            .unwrap()
    };
    for args in [
        ["setup", "--repair"].as_slice(),
        &["setup", "--update"],
        &["setup", "--uninstall", "--keep-data"],
    ] {
        let out = run(args);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("must run as root"),
            "{args:?}"
        );
    }
    let out = run(&["setup", "--repair", "--update"]);
    assert_eq!(out.status.code(), Some(2));
    let out = run(&["setup", "--uninstall"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--keep-data or --everything"));
    let out = run(&["setup", "--uninstall", "--everything"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--confirm"));
}
