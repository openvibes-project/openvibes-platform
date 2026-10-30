//! The network verbs against a scripted nmcli.

use super::{ApplyArgs, run_apply, run_hostname, run_keep, run_revert};
use crate::setup::fake::Fake;

const NMCLI: &str = "/usr/bin/nmcli";
const ACTIVE: &str = "Wired connection 1:802-3-ethernet:eth0\nlo:loopback:lo\n";
const CONFIG: &str =
    "ipv4.method,ipv4.addresses,ipv4.gateway,ipv4.dns,ipv4.dns-search,ipv4.ignore-auto-dns";
const DHCP: &str = "ipv4.method:auto\nipv4.addresses:\nipv4.gateway:\nipv4.dns:\nipv4.dns-search:\nipv4.ignore-auto-dns:no\n";
const FIXED: &str = "ipv4.method:manual\nipv4.addresses:192.168.1.50/24\nipv4.gateway:192.168.1.1\nipv4.dns:9.9.9.9\nipv4.dns-search:lime.lab\nipv4.ignore-auto-dns:yes\n";

fn fixed() -> ApplyArgs {
    ApplyArgs {
        mode: "fixed".into(),
        address: "192.168.1.50/24".into(),
        gateway: "192.168.1.1".into(),
        dns: "9.9.9.9".into(),
        search: "lime.lab".into(),
    }
}

fn host(test: &str, config: &str) -> Fake {
    let fake = Fake::new(test);
    fake.answer(&[NMCLI, "-t", "-f", "NAME,TYPE,DEVICE"], 0, ACTIVE);
    fake.answer(&[NMCLI, "-t", "-f", CONFIG], 0, config);
    fake.answer(&[NMCLI, "connection"], 0, "");
    fake.answer(&["/usr/bin/systemd-run"], 0, "");
    fake.answer(&["/usr/bin/systemctl"], 0, "");
    fake
}

fn pending(fake: &Fake) -> std::path::PathBuf {
    fake.root.join("run/openvibes-admin/net-previous")
}

#[test]
fn apply_changes_the_connection_saves_the_old_settings_and_starts_the_timer() {
    let fake = host("net-apply", DHCP);
    assert_eq!(
        run_apply(&fake, &fake.root, &fixed()).unwrap(),
        "done\tpending\t60"
    );
    assert!(fake.called(&[
        NMCLI,
        "connection",
        "modify",
        "Wired connection 1",
        "ipv4.method",
        "manual",
        "ipv4.addresses",
        "192.168.1.50/24",
        "ipv4.gateway",
        "192.168.1.1",
        "ipv4.dns",
        "9.9.9.9",
        "ipv4.dns-search",
        "lime.lab",
        "ipv4.ignore-auto-dns",
        "yes",
    ]));
    assert!(fake.called(&[NMCLI, "connection", "up", "Wired connection 1"]));
    assert!(fake.called(&[
        "/usr/bin/systemd-run",
        "--unit",
        "openvibes-net-revert",
        "--on-active",
        "60",
        "--collect",
        "--quiet",
        "/usr/bin/openvibes-admin",
        "helper",
        "net-revert",
    ]));
    let saved = std::fs::read_to_string(pending(&fake)).unwrap();
    assert!(
        saved.contains("connection=Wired connection 1\nmethod=auto\n"),
        "{saved}"
    );
    assert!(saved.contains("ignore_auto_dns=no"), "{saved}");
}

#[test]
fn apply_to_dhcp_clears_the_fixed_values() {
    let fake = host("net-apply-dhcp", FIXED);
    let args = ApplyArgs {
        mode: "dhcp".into(),
        address: String::new(),
        gateway: String::new(),
        dns: String::new(),
        search: String::new(),
    };
    run_apply(&fake, &fake.root, &args).unwrap();
    assert!(fake.called(&[
        NMCLI,
        "connection",
        "modify",
        "Wired connection 1",
        "ipv4.method",
        "auto",
        "ipv4.addresses",
        "",
        "ipv4.gateway",
        "",
        "ipv4.dns",
        "",
        "ipv4.dns-search",
        "",
        "ipv4.ignore-auto-dns",
        "no",
    ]));
}

#[test]
fn the_same_settings_change_nothing() {
    let fake = host("net-apply-same", FIXED);
    assert_eq!(
        run_apply(&fake, &fake.root, &fixed()).unwrap(),
        "done\tunchanged"
    );
    assert!(!fake.called(&[NMCLI, "connection", "modify"]));
    assert!(!pending(&fake).exists());
}

#[test]
fn a_second_change_waits_for_the_first_to_be_kept_or_put_back() {
    let fake = host("net-apply-twice", DHCP);
    run_apply(&fake, &fake.root, &fixed()).unwrap();
    let error = run_apply(&fake, &fake.root, &fixed()).unwrap_err();
    assert!(error.contains("waiting"), "{error}");
}

#[test]
fn values_that_are_not_addresses_never_reach_nmcli() {
    let fake = host("net-apply-bad", DHCP);
    for address in [
        "192.168.1.50/24; reboot",
        "x",
        "192.168.1.50/24 ipv4.method auto",
    ] {
        let args = ApplyArgs {
            address: address.into(),
            ..fixed()
        };
        assert!(run_apply(&fake, &fake.root, &args).is_err(), "{address}");
    }
    assert!(!fake.called(&[NMCLI]));
}

#[test]
fn a_failed_change_puts_the_old_settings_back_at_once() {
    let fake = Fake::new("net-apply-fails");
    fake.answer(&[NMCLI, "-t", "-f", "NAME,TYPE,DEVICE"], 0, ACTIVE);
    fake.answer(&[NMCLI, "-t", "-f", CONFIG], 0, DHCP);
    // The new settings fail to come up; the old ones are accepted.
    fake.answer(&[NMCLI, "connection", "up"], 0, "");
    fake.answer(
        &[
            NMCLI,
            "connection",
            "modify",
            "Wired connection 1",
            "ipv4.method",
            "manual",
        ],
        4,
        "",
    );
    fake.answer(&[NMCLI, "connection", "modify"], 0, "");
    let error = run_apply(&fake, &fake.root, &fixed()).unwrap_err();
    assert!(error.contains("nmcli"), "{error}");
    assert!(!pending(&fake).exists());
    assert!(fake.called(&[
        NMCLI,
        "connection",
        "modify",
        "Wired connection 1",
        "ipv4.method",
        "auto"
    ]));
}

#[test]
fn without_a_timer_the_change_is_not_left_in_place() {
    let fake = Fake::new("net-apply-no-timer");
    fake.answer(&[NMCLI, "-t", "-f", "NAME,TYPE,DEVICE"], 0, ACTIVE);
    fake.answer(&[NMCLI, "-t", "-f", CONFIG], 0, DHCP);
    fake.answer(&[NMCLI, "connection"], 0, "");
    fake.answer(&["/usr/bin/systemd-run"], 1, "");
    fake.answer(&["/usr/bin/systemctl"], 0, "");
    let error = run_apply(&fake, &fake.root, &fixed()).unwrap_err();
    assert!(error.contains("rollback timer"), "{error}");
    assert!(!pending(&fake).exists());
    assert!(fake.called(&[
        NMCLI,
        "connection",
        "modify",
        "Wired connection 1",
        "ipv4.method",
        "auto"
    ]));
}

#[test]
fn keep_stops_the_timer_and_forgets_the_old_settings() {
    let fake = host("net-keep", DHCP);
    run_apply(&fake, &fake.root, &fixed()).unwrap();
    assert_eq!(run_keep(&fake, &fake.root).unwrap(), "done\tkept");
    assert!(fake.called(&["/usr/bin/systemctl", "stop", "openvibes-net-revert.timer"]));
    assert!(!pending(&fake).exists());
    assert_eq!(
        run_keep(&fake, &fake.root).unwrap(),
        "done\tnothing pending"
    );
}

#[test]
fn keep_says_so_when_the_timer_cannot_be_stopped() {
    let fake = host("net-keep-fails", DHCP);
    run_apply(&fake, &fake.root, &fixed()).unwrap();
    let stop = Fake::new("net-keep-fails-2");
    std::fs::create_dir_all(pending(&stop).parent().unwrap()).unwrap();
    std::fs::copy(pending(&fake), pending(&stop)).unwrap();
    stop.answer(&["/usr/bin/systemctl"], 1, "");
    let error = run_keep(&stop, &stop.root).unwrap_err();
    assert!(error.contains("come back"), "{error}");
    assert!(pending(&stop).exists());
}

#[test]
fn revert_restores_the_saved_settings() {
    let fake = host("net-revert", FIXED);
    let args = ApplyArgs {
        mode: "dhcp".into(),
        address: String::new(),
        gateway: String::new(),
        dns: String::new(),
        search: String::new(),
    };
    run_apply(&fake, &fake.root, &args).unwrap();
    assert_eq!(run_revert(&fake, &fake.root).unwrap(), "done\treverted");
    assert!(fake.called(&[
        NMCLI,
        "connection",
        "modify",
        "Wired connection 1",
        "ipv4.method",
        "manual",
        "ipv4.addresses",
        "192.168.1.50/24",
        "ipv4.gateway",
        "192.168.1.1",
        "ipv4.dns",
        "9.9.9.9",
        "ipv4.dns-search",
        "lime.lab",
        "ipv4.ignore-auto-dns",
        "yes",
    ]));
    assert!(!pending(&fake).exists());
    assert_eq!(
        run_revert(&fake, &fake.root).unwrap(),
        "done\tnothing pending"
    );
}

#[test]
fn an_unreadable_saved_file_is_refused_not_applied() {
    let fake = host("net-revert-garbage", DHCP);
    std::fs::create_dir_all(pending(&fake).parent().unwrap()).unwrap();
    std::fs::write(pending(&fake), "connection=x\nrm -rf /\n").unwrap();
    assert!(run_revert(&fake, &fake.root).is_err());
    assert!(!fake.called(&[NMCLI]));
}

#[test]
fn the_host_name_is_checked_and_set() {
    let fake = Fake::new("hostname");
    fake.answer(&["/usr/bin/hostnamectl"], 0, "");
    assert_eq!(
        run_hostname(&fake, "va.lime.lab").unwrap(),
        "done\tva.lime.lab"
    );
    assert!(fake.called(&["/usr/bin/hostnamectl", "set-hostname", "--", "va.lime.lab"]));
    for bad in ["", "-x", "a b", "a;b", "localhost", "va."] {
        assert!(run_hostname(&fake, bad).is_err(), "{bad:?}");
    }
}

#[test]
fn the_keep_and_revert_verbs_take_no_arguments() {
    use clap::Parser;
    #[derive(Parser)]
    struct Wrapper {
        #[command(subcommand)]
        command: crate::helper::HelperCommand,
    }
    for verb in ["net-keep", "net-revert"] {
        assert!(Wrapper::try_parse_from(["helper", verb]).is_ok(), "{verb}");
        assert!(
            Wrapper::try_parse_from(["helper", verb, "extra"]).is_err(),
            "{verb}"
        );
    }
    assert!(Wrapper::try_parse_from(["helper", "net-apply", "--mode", "dhcp"]).is_ok());
    assert!(Wrapper::try_parse_from(["helper", "net-apply"]).is_err());
    assert!(Wrapper::try_parse_from(["helper", "hostname-set", "va"]).is_ok());
}
