//! The OS update verbs against a scripted dnf.
use platform_host::os_updates::OsUpdates;

use super::{check, run_check, run_restart, run_update};
use crate::setup::fake::Fake;

const WAITING: &str = "\nkernel.x86_64  5.14.0-570  baseos\nvim-minimal.x86_64  2:8.2  baseos\n";
const ADVISORIES: &str = "RLSA-1 Important/Sec. kernel-5.14.0-570.x86_64\n";
const CHECK: [&str; 4] = ["/usr/bin/dnf", "-q", "--refresh", "check-update"];

fn scripted(test: &str) -> Fake {
    let fake = Fake::new(test);
    fake.answer(&CHECK, 100, WAITING);
    fake.answer(&["/usr/bin/dnf", "-q", "updateinfo"], 0, ADVISORIES);
    fake.answer(
        &["/usr/bin/dnf", "-q", "needs-restarting"],
        1,
        "Reboot is required",
    );
    fake
}

fn saved(fake: &Fake) -> OsUpdates {
    OsUpdates::from_file(&fake.text("/etc/openvibes/os-updates")).unwrap()
}

#[test]
fn check_counts_and_writes_the_state() {
    let fake = scripted("os-check");
    std::fs::create_dir_all(fake.root.join("etc/openvibes")).unwrap();
    let found = check(&fake, &fake.root, 7).unwrap();
    assert_eq!((found.total, found.security), (2, 1));
    assert!(found.kernel && found.restart);
    assert_eq!(saved(&fake), found);
}

#[test]
fn exit_100_is_updates_and_0_is_none() {
    let fake = Fake::new("os-none");
    std::fs::create_dir_all(fake.root.join("etc/openvibes")).unwrap();
    fake.answer(&CHECK, 0, "");
    fake.answer(&["/usr/bin/dnf", "-q", "updateinfo"], 0, "");
    fake.answer(
        &["/usr/bin/dnf", "-q", "needs-restarting"],
        0,
        "No core libraries",
    );
    let line = run_check(&fake, &fake.root).unwrap();
    assert_eq!(line, "done\t0\t0\tfalse");
}

#[test]
fn a_repository_error_is_reported_and_the_state_kept() {
    let fake = Fake::new("os-error");
    std::fs::create_dir_all(fake.root.join("etc/openvibes")).unwrap();
    fake.file(
        "/etc/openvibes/os-updates",
        &OsUpdates {
            checked_at: 1,
            ..Default::default()
        }
        .to_file(),
    );
    fake.fail(&CHECK, "Error: Failed to download metadata");
    let error = check(&fake, &fake.root, 9).unwrap_err();
    assert!(error.contains("Failed to download metadata"), "{error}");
    assert_eq!(saved(&fake).checked_at, 1);
}

#[test]
fn update_runs_the_upgrade_then_checks_again() {
    let fake = scripted("os-update");
    std::fs::create_dir_all(fake.root.join("etc/openvibes")).unwrap();
    fake.answer(&["/usr/bin/dnf", "-y", "--refresh", "upgrade"], 0, "");
    run_update(&fake, &fake.root).unwrap();
    let calls = fake.calls.borrow();
    assert_eq!(calls[0][1..], ["-y", "--refresh", "upgrade"]);
    assert_eq!(calls[1][1..], ["-q", "--refresh", "check-update"]);
}

#[test]
fn a_failed_upgrade_stops_before_the_check() {
    let fake = scripted("os-update-fail");
    fake.fail(&["/usr/bin/dnf", "-y"], "Error: transaction failed");
    let error = run_update(&fake, &fake.root).unwrap_err();
    assert!(error.contains("transaction failed"), "{error}");
    assert!(!fake.called(&CHECK));
}

#[test]
fn restart_asks_systemd_to_reboot() {
    let fake = Fake::new("os-restart");
    fake.answer(&["/usr/bin/systemctl", "reboot"], 0, "");
    assert_eq!(run_restart(&fake).unwrap(), "done\trestarting");
}
