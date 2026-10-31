//! `ssh-set` against a scripted sshd and a temp root.

use super::{SetArgs, run_set};
use crate::setup::fake::Fake;

const SSHD: &str = "/usr/sbin/sshd";
const DROP_IN: &str = "/etc/ssh/sshd_config.d/50-openvibes.conf";

fn args(keys: &str, passwords: &str) -> SetArgs {
    SetArgs {
        keys: keys.into(),
        passwords: passwords.into(),
    }
}

fn host(test: &str) -> Fake {
    let fake = Fake::new(test);
    fake.answer(&[SSHD, "-t"], 0, "");
    fake.answer(&["/usr/bin/systemctl", "reload"], 0, "");
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
            .join("etc/ssh/sshd_config.d/50-openvibes.conf")
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
            .join("etc/ssh/sshd_config.d/50-openvibes.conf")
            .exists()
    );
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
