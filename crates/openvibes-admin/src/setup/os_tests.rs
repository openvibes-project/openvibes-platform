//! The OS update verbs against a scripted dnf.
use platform_host::os_updates::OsUpdates;

use super::{check, run_check, run_restart, run_update};
use crate::setup::fake::Fake;

const WAITING: &str = "\nkernel.x86_64  5.14.0-570  baseos\nvim-minimal.x86_64  2:8.2  baseos\n";
const SECURITY: &str = "\nkernel.x86_64  5.14.0-570  baseos\n";
const CHECK: [&str; 4] = ["/usr/bin/dnf", "-q", "--refresh", "check-update"];
const SEC: [&str; 4] = ["/usr/bin/dnf", "-q", "check-update", "--security"];
const UPGRADE: [&str; 3] = [
    "/usr/bin/systemd-run",
    "--unit=openvibes-os-update",
    "--collect",
];

const NEEDS: [&str; 3] = ["/usr/bin/dnf", "-q", "needs-restarting"];

/// `after` is what the plain `check-update` prints once the upgrade ran.
fn scripted_after(test: &str, after: &str, needs: &str) -> Fake {
    let fake = Fake::new(test);
    std::fs::create_dir_all(fake.root.join("etc/openvibes")).unwrap();
    fake.answer(&CHECK, 100, WAITING);
    fake.answer(&SEC, 100, SECURITY);
    fake.answer(&["/usr/bin/dnf", "-q", "check-update"], 100, after);
    fake.answer(&NEEDS, 1, needs);
    fake
}

fn scripted(test: &str) -> Fake {
    scripted_after(
        test,
        WAITING,
        "Reboot is required to fully utilize these updates.",
    )
}

fn saved(fake: &Fake) -> OsUpdates {
    OsUpdates::from_file(&fake.text("/etc/openvibes/os-updates")).unwrap()
}

#[test]
fn check_counts_and_writes_the_state() {
    let fake = scripted("os-check");
    let found = check(&fake, &fake.root, 7, false).unwrap();
    assert_eq!((found.total, found.security), (2, 1));
    assert!(found.kernel && found.restart);
    assert_eq!(saved(&fake), found);
}

#[test]
fn exit_100_is_updates_and_0_is_none() {
    let fake = Fake::new("os-none");
    std::fs::create_dir_all(fake.root.join("etc/openvibes")).unwrap();
    fake.answer(&CHECK, 0, "");
    fake.answer(&SEC, 0, "");
    fake.answer(
        &["/usr/bin/dnf", "-q", "needs-restarting"],
        0,
        "No core libraries or services have been updated.\nReboot should not be necessary.",
    );
    let line = run_check(&fake, &fake.root).unwrap();
    assert_eq!(line, "done\t0\t0\tfalse\t0");
}

#[test]
fn a_missing_needs_restarting_plugin_is_not_a_restart() {
    let fake = scripted_after(
        "os-no-plugin",
        WAITING,
        "No such command: needs-restarting.",
    );
    assert!(!check(&fake, &fake.root, 1, false).unwrap().restart);
    // After an update that brought a kernel it is assumed.
    assert!(check(&fake, &fake.root, 1, true).unwrap().restart);
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
    let error = check(&fake, &fake.root, 9, false).unwrap_err();
    assert!(error.contains("Failed to download metadata"), "{error}");
    assert_eq!(saved(&fake).checked_at, 1);
}

#[test]
fn update_runs_in_its_own_unit_then_checks_again() {
    let fake = scripted("os-update");
    fake.answer(&UPGRADE, 0, "");
    run_update(&fake, &fake.root).unwrap();
    let calls = fake.calls.borrow();
    assert_eq!(calls[0][1..], ["-q", "--refresh", "check-update"]);
    assert_eq!(
        calls[1][1..],
        [
            "--unit=openvibes-os-update",
            "--collect",
            "--wait",
            "--quiet",
            "/usr/bin/dnf",
            "-y",
            "--refresh",
            "upgrade"
        ]
    );
    assert_eq!(calls[2][1..], ["-q", "--refresh", "check-update"]);
}

#[test]
fn update_reports_how_many_packages_it_upgraded() {
    // The same listing before and after: nothing was upgraded.
    let fake = scripted("os-update-none");
    fake.answer(&UPGRADE, 0, "");
    assert!(run_update(&fake, &fake.root).unwrap().ends_with("\t0"));
    let fake = scripted_after("os-update-count", "", "Reboot is required");
    fake.answer(&UPGRADE, 0, "");
    assert_eq!(
        run_update(&fake, &fake.root).unwrap(),
        "done\t2\t1\ttrue\t2"
    );
}

#[test]
fn a_failed_upgrade_still_checks_and_returns_the_upgrade_error() {
    let fake = scripted("os-update-fail");
    fake.fail(&UPGRADE, "Job failed. See journalctl.");
    fake.answer(
        &["/usr/bin/journalctl", "-u", "openvibes-os-update"],
        0,
        "Error: transaction failed\n",
    );
    let error = run_update(&fake, &fake.root).unwrap_err();
    assert!(error.contains("transaction failed"), "{error}");
    assert!(fake.called(&CHECK));
    assert_eq!(saved(&fake).total, 2);
}

#[test]
fn a_second_update_says_one_is_running() {
    let fake = scripted("os-update-twice");
    fake.fail(
        &UPGRADE,
        "Failed to start transient service unit: Unit openvibes-os-update.service already exists.",
    );
    let error = run_update(&fake, &fake.root).unwrap_err();
    assert_eq!(error, "An update is already running");
}

#[test]
fn restart_asks_systemd_to_reboot() {
    let fake = Fake::new("os-restart");
    fake.answer(&["/usr/bin/systemctl", "is-active"], 3, "");
    fake.answer(&["/usr/bin/systemctl", "reboot"], 0, "");
    assert_eq!(run_restart(&fake, &fake.root).unwrap(), "done\trestarting");
}

#[test]
fn restart_waits_for_a_running_update() {
    let fake = Fake::new("os-restart-busy");
    fake.answer(&["/usr/bin/systemctl", "is-active"], 0, "");
    assert!(run_restart(&fake, &fake.root).is_err());
    assert!(!fake.called(&["/usr/bin/systemctl", "reboot"]));
}

#[test]
fn restart_waits_for_a_setup_run() {
    let fake = Fake::new("os-restart-setup");
    fake.answer(&["/usr/bin/systemctl", "is-active"], 3, "");
    let _held = crate::setup::system::lock(&fake.root).unwrap();
    let error = run_restart(&fake, &fake.root).unwrap_err();
    assert!(error.contains("Setup run"), "{error}");
    assert!(!fake.called(&["/usr/bin/systemctl", "reboot"]));
}

#[test]
fn the_os_verbs_take_no_arguments() {
    use clap::Parser;

    #[derive(Parser)]
    struct Wrapper {
        #[command(subcommand)]
        command: crate::helper::HelperCommand,
    }
    for verb in ["os-check", "os-update", "os-restart"] {
        assert!(Wrapper::try_parse_from(["helper", verb]).is_ok(), "{verb}");
        assert!(
            Wrapper::try_parse_from(["helper", verb, "extra"]).is_err(),
            "{verb} extra"
        );
        assert!(
            Wrapper::try_parse_from(["helper", verb, "--root", "/x"]).is_err(),
            "{verb} --root"
        );
    }
}
