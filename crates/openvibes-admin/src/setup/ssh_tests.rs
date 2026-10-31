//! `ssh-set` against a scripted sshd and a temp root.

use super::{SetArgs, run_set};
use crate::setup::fake::Fake;

const SSHD: &str = "/usr/sbin/sshd";
const DROP_IN: &str = "/etc/ssh/sshd_config.d/00-openvibes.conf";

fn args(keys: &str, passwords: &str) -> SetArgs {
    SetArgs {
        keys: keys.into(),
        passwords: passwords.into(),
    }
}

fn host(test: &str) -> Fake {
    let fake = Fake::new(test);
    fake.answer(&[SSHD, "-t"], 0, "");
    fake.answer(
        &[SSHD, "-T"],
        0,
        "pubkeyauthentication yes\npasswordauthentication no\n",
    );
    fake.answer(&["/usr/bin/systemctl", "reload"], 0, "");
    fake
}

/// A host with a previous drop-in whose `sshd -t` passes and whose `sshd -T`
/// reports `in_force`.
fn with_previous(test: &str, in_force: &str) -> Fake {
    let fake = Fake::new(test);
    fake.file(DROP_IN, "previous\n");
    fake.answer(&[SSHD, "-t"], 0, "");
    fake.answer(&[SSHD, "-T"], 0, in_force);
    fake
}

#[test]
fn keys_only_is_written_checked_and_reloaded() {
    let fake = host("ssh-set");
    assert_eq!(
        run_set(&fake, &fake.root, &args("yes", "no")).unwrap(),
        "done\tset"
    );
    assert_eq!(
        fake.text(DROP_IN),
        "# Written by OpenVIBES (System > SSH). Do not edit.\nPubkeyAuthentication yes\nPasswordAuthentication no\n"
    );
    let calls = fake.calls.borrow();
    let sshd = calls.iter().position(|c| c[0] == SSHD).unwrap();
    let reload = calls
        .iter()
        .position(|c| c[0] == "/usr/bin/systemctl")
        .unwrap();
    assert!(sshd < reload, "{calls:?}");
    assert_eq!(calls[reload][1..], ["reload", "sshd.service"]);
}

#[test]
fn both_off_and_bad_words_change_nothing() {
    let fake = host("ssh-bad");
    for (keys, passwords) in [("no", "no"), ("maybe", "yes"), ("yes", "")] {
        assert!(run_set(&fake, &fake.root, &args(keys, passwords)).is_err());
    }
    assert!(
        !fake
            .root
            .join("etc/ssh/sshd_config.d/00-openvibes.conf")
            .exists()
    );
    assert!(!fake.called(&[SSHD]));
}

#[test]
fn a_config_sshd_refuses_is_taken_back() {
    let fake = Fake::new("ssh-refused");
    fake.file(DROP_IN, "previous\n");
    fake.fail(&[SSHD, "-t"], "bad option");
    let error = run_set(&fake, &fake.root, &args("yes", "no")).unwrap_err();
    assert!(error.contains("nothing changed"), "{error}");
    assert_eq!(fake.text(DROP_IN), "previous\n");
    assert!(!fake.called(&["/usr/bin/systemctl"]));

    let fresh = Fake::new("ssh-refused-fresh");
    fresh.fail(&[SSHD, "-t"], "bad option");
    assert!(run_set(&fresh, &fresh.root, &args("no", "yes")).is_err());
    assert!(
        !fresh
            .root
            .join("etc/ssh/sshd_config.d/00-openvibes.conf")
            .exists()
    );
}

#[test]
fn another_file_that_overrides_the_choice_is_refused_and_taken_back() {
    // cloud-init's file sorts first and says no to passwords.
    let fake = with_previous(
        "ssh-overridden",
        "pubkeyauthentication no\npasswordauthentication no\n",
    );
    let error = run_set(&fake, &fake.root, &args("no", "yes")).unwrap_err();
    assert!(error.contains("overrides"), "{error}");
    assert_eq!(fake.text(DROP_IN), "previous\n");
    assert!(!fake.called(&["/usr/bin/systemctl"]));

    let blind = Fake::new("ssh-blind");
    blind.answer(&[SSHD, "-t"], 0, "");
    blind.fail(&[SSHD, "-T"], "no host key");
    assert!(run_set(&blind, &blind.root, &args("yes", "no")).is_err());
    assert!(
        !blind
            .root
            .join("etc/ssh/sshd_config.d/00-openvibes.conf")
            .exists()
    );
}

#[test]
fn a_failed_reload_takes_the_file_back() {
    let fake = with_previous(
        "ssh-noreload",
        "pubkeyauthentication yes\npasswordauthentication no\n",
    );
    fake.fail(&["/usr/bin/systemctl", "reload"], "not running");
    assert!(run_set(&fake, &fake.root, &args("yes", "no")).is_err());
    assert_eq!(fake.text(DROP_IN), "previous\n");
}

#[test]
fn the_verb_takes_both_choices() {
    use clap::Parser;
    #[derive(Parser)]
    struct Wrapper {
        #[command(subcommand)]
        command: crate::helper::HelperCommand,
    }
    assert!(
        Wrapper::try_parse_from(["helper", "ssh-set", "--keys", "yes", "--passwords", "no"])
            .is_ok()
    );
    assert!(Wrapper::try_parse_from(["helper", "ssh-set", "--keys", "yes"]).is_err());
}
