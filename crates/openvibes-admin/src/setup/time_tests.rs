//! `time-set` against a scripted timedatectl and a temp root.

use super::{SetArgs, run_set};
use crate::setup::fake::Fake;

const CONF: &str = "# chrony\npool 2.fedora.pool.ntp.org iburst\nserver 10.9.9.9\ndriftfile /var/lib/chrony/drift\nconfdir /etc/chrony.d\n";
const TIMEDATECTL: &str = "/usr/bin/timedatectl";

fn args(servers: &str, zone: &str) -> SetArgs {
    SetArgs {
        servers: servers.into(),
        zone: zone.into(),
    }
}

fn host(test: &str, conf: &str) -> Fake {
    let fake = Fake::new(test);
    fake.file("/etc/chrony.conf", conf);
    fake.answer(
        &[TIMEDATECTL, "list-timezones"],
        0,
        "UTC\nEurope/Stockholm\n",
    );
    fake.answer(&[TIMEDATECTL, "set-timezone"], 0, "");
    fake.answer(&["/usr/bin/systemctl", "restart"], 0, "");
    fake
}

#[test]
fn chosen_servers_replace_the_distributions_own() {
    let fake = host("time-set", CONF);
    let done = run_set(
        &fake,
        &fake.root,
        &args("ntp.lime.lab, 10.0.0.1", "Europe/Stockholm"),
    );
    assert_eq!(done.unwrap(), "done\tset");
    assert_eq!(
        fake.text("/etc/chrony.d/50-openvibes.conf"),
        "# Written by OpenVIBES (System > Time). Do not edit.\nserver ntp.lime.lab iburst\nserver 10.0.0.1 iburst\n"
    );
    let conf = fake.text("/etc/chrony.conf");
    assert!(
        conf.contains("#openvibes# pool 2.fedora.pool.ntp.org iburst\n"),
        "{conf}"
    );
    assert!(conf.contains("#openvibes# server 10.9.9.9\n"), "{conf}");
    assert!(conf.contains("\ndriftfile /var/lib/chrony/drift\n"));
    assert!(fake.called(&[TIMEDATECTL, "set-timezone", "Europe/Stockholm"]));
    assert!(fake.called(&["/usr/bin/systemctl", "restart", "chronyd.service"]));
}

#[test]
fn clearing_the_list_puts_the_distributions_back() {
    let fake = host("time-clear", CONF);
    run_set(&fake, &fake.root, &args("ntp.lime.lab", "UTC")).unwrap();
    run_set(&fake, &fake.root, &args("", "UTC")).unwrap();
    assert_eq!(fake.text("/etc/chrony.conf"), CONF);
    assert!(!fake.root.join("etc/chrony.d/50-openvibes.conf").exists());
}

#[test]
fn setting_twice_does_not_stack_marks() {
    let fake = host("time-twice", CONF);
    run_set(&fake, &fake.root, &args("a.lab", "UTC")).unwrap();
    let once = fake.text("/etc/chrony.conf");
    run_set(&fake, &fake.root, &args("b.lab", "UTC")).unwrap();
    assert_eq!(fake.text("/etc/chrony.conf"), once);
    assert!(
        fake.text("/etc/chrony.d/50-openvibes.conf")
            .contains("server b.lab iburst")
    );
}

#[test]
fn a_conf_without_confdir_gets_one() {
    let fake = host("time-confdir", "pool x.pool iburst\n");
    run_set(&fake, &fake.root, &args("a.lab", "UTC")).unwrap();
    assert!(
        fake.text("/etc/chrony.conf")
            .contains("\nconfdir /etc/chrony.d\n")
    );
}

#[test]
fn bad_values_change_nothing() {
    let fake = host("time-bad", CONF);
    for (servers, zone) in [
        ("a b", "UTC"),
        ("a.lab;reboot", "UTC"),
        ("a.lab", "../etc"),
        ("a.lab", "Mars/Base"),
        ("a.lab,a.lab", "UTC"),
    ] {
        assert!(
            run_set(&fake, &fake.root, &args(servers, zone)).is_err(),
            "{servers} {zone}"
        );
    }
    assert_eq!(fake.text("/etc/chrony.conf"), CONF);
    assert!(!fake.called(&[TIMEDATECTL, "set-timezone"]));
    assert!(!fake.called(&["/usr/bin/systemctl"]));
}

#[test]
fn a_host_without_chrony_conf_says_so() {
    let fake = host("time-noconf", CONF);
    fake.remove("/etc/chrony.conf");
    let error = run_set(&fake, &fake.root, &args("a.lab", "UTC")).unwrap_err();
    assert!(error.contains("chrony.conf"), "{error}");
}

#[test]
fn the_verb_takes_servers_and_a_zone() {
    use clap::Parser;
    #[derive(Parser)]
    struct Wrapper {
        #[command(subcommand)]
        command: crate::helper::HelperCommand,
    }
    assert!(
        Wrapper::try_parse_from(["helper", "time-set", "--servers", "a.lab", "--zone", "UTC"])
            .is_ok()
    );
    assert!(Wrapper::try_parse_from(["helper", "time-set"]).is_err());
}
