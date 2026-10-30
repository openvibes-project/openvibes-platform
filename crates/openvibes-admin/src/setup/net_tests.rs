//! The network verbs against a scripted nmcli.

use super::{ApplyArgs, run_apply, run_hostname, run_keep, run_revert};
use crate::setup::fake::Fake;

const NMCLI: &str = "/usr/bin/nmcli";
const UUID: &str = "5d1f3a7c-1111-4222-8333-944455556666";
const ACTIVE: &str = "Wired connection 1:5d1f3a7c-1111-4222-8333-944455556666:802-3-ethernet:eth0\nlo:00000000-0000-4000-8000-000000000000:loopback:lo\n";
const CONFIG: &str =
    "ipv4.method,ipv4.addresses,ipv4.gateway,ipv4.dns,ipv4.dns-search,ipv4.ignore-auto-dns";
const DHCP: &str = "ipv4.method:auto\nipv4.addresses:\nipv4.gateway:\nipv4.dns:\nipv4.dns-search:\nipv4.ignore-auto-dns:no\n";
const FIXED: &str = "ipv4.method:manual\nipv4.addresses:192.168.1.50/24\nipv4.gateway:192.168.1.1\nipv4.dns:9.9.9.9\nipv4.dns-search:lime.lab\nipv4.ignore-auto-dns:yes\n";
const TWO: &str = "ipv4.method:manual\nipv4.addresses:192.168.1.50/24, 10.0.0.2/8\nipv4.gateway:192.168.1.1\nipv4.dns:9.9.9.9,1.1.1.1\nipv4.dns-search:lime.lab,lab2.lab\nipv4.ignore-auto-dns:yes\n";

fn fixed() -> ApplyArgs {
    ApplyArgs {
        mode: "fixed".into(),
        address: "192.168.1.50/24".into(),
        gateway: "192.168.1.1".into(),
        dns: "9.9.9.9".into(),
        search: "lime.lab".into(),
    }
}

fn dhcp() -> ApplyArgs {
    ApplyArgs {
        mode: "dhcp".into(),
        address: String::new(),
        gateway: String::new(),
        dns: String::new(),
        search: String::new(),
    }
}

fn host(test: &str, config: &str) -> Fake {
    let fake = Fake::new(test);
    fake.answer(&[NMCLI, "-t", "-f", "NAME,UUID,TYPE,DEVICE"], 0, ACTIVE);
    fake.answer(&[NMCLI, "-t", "-f", CONFIG], 0, config);
    fake.answer(&[NMCLI, "connection"], 0, "");
    fake.answer(&["/usr/bin/systemd-run"], 0, "");
    fake.answer(&["/usr/bin/systemctl"], 0, "");
    fake
}

fn pending(fake: &Fake) -> std::path::PathBuf {
    fake.root.join("run/openvibes-admin/net-previous")
}

/// Index of the first call starting with `prefix`.
fn at(fake: &Fake, prefix: &[&str]) -> usize {
    fake.calls
        .borrow()
        .iter()
        .position(|call| call.len() >= prefix.len() && call.iter().zip(prefix).all(|(a, b)| a == b))
        .unwrap_or_else(|| panic!("no call {prefix:?}"))
}

fn modify_call<'a>(
    method: &'a str,
    address: &'a str,
    gateway: &'a str,
    dns: &'a str,
    search: &'a str,
    ignore: &'a str,
) -> Vec<&'a str> {
    vec![
        NMCLI,
        "connection",
        "modify",
        "uuid",
        UUID,
        "ipv4.method",
        method,
        "ipv4.addresses",
        address,
        "ipv4.gateway",
        gateway,
        "ipv4.dns",
        dns,
        "ipv4.dns-search",
        search,
        "ipv4.ignore-auto-dns",
        ignore,
    ]
}

#[test]
fn apply_arms_the_timer_before_it_changes_anything_and_rearms_when_up() {
    let fake = host("net-apply", DHCP);
    assert_eq!(
        run_apply(&fake, &fake.root, &fixed()).unwrap(),
        "done\tpending\t60"
    );
    let first_timer = at(
        &fake,
        &[
            "/usr/bin/systemd-run",
            "--unit",
            "openvibes-net-revert",
            "--on-active",
            "150",
        ],
    );
    let modify = at(
        &fake,
        &modify_call(
            "manual",
            "192.168.1.50/24",
            "192.168.1.1",
            "9.9.9.9",
            "lime.lab",
            "yes",
        ),
    );
    let up = at(&fake, &[NMCLI, "connection", "up", "uuid", UUID]);
    let last_timer = at(
        &fake,
        &[
            "/usr/bin/systemd-run",
            "--unit",
            "openvibes-net-revert",
            "--on-active",
            "60",
        ],
    );
    assert!(first_timer < modify && modify < up && up < last_timer);
    let saved = std::fs::read_to_string(pending(&fake)).unwrap();
    assert!(
        saved.starts_with(&format!("uuid={UUID}\nmethod=auto\n")),
        "{saved}"
    );
    assert!(saved.contains("ignore_auto_dns=no"), "{saved}");
}

#[test]
fn apply_to_dhcp_clears_the_fixed_values() {
    let fake = host("net-apply-dhcp", FIXED);
    run_apply(&fake, &fake.root, &dhcp()).unwrap();
    at(&fake, &modify_call("auto", "", "", "", "", "no"));
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
fn values_that_are_not_addresses_never_reach_nmcli_and_checked_ones_are_rebuilt() {
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
    // "/+024" parses as 24 and goes on as the rebuilt "/24".
    let args = ApplyArgs {
        address: "192.168.1.50/+024".into(),
        dns: " 9.9.9.9 ,".into(),
        ..fixed()
    };
    run_apply(&fake, &fake.root, &args).unwrap();
    at(
        &fake,
        &modify_call(
            "manual",
            "192.168.1.50/24",
            "192.168.1.1",
            "9.9.9.9",
            "lime.lab",
            "yes",
        ),
    );
}

#[test]
fn a_failed_change_puts_the_old_settings_back_and_stops_the_timer() {
    let fake = Fake::new("net-apply-fails");
    fake.answer(&[NMCLI, "-t", "-f", "NAME,UUID,TYPE,DEVICE"], 0, ACTIVE);
    fake.answer(&[NMCLI, "-t", "-f", CONFIG], 0, DHCP);
    fake.answer(&[NMCLI, "connection", "up"], 0, "");
    fake.answer(
        &[
            NMCLI,
            "connection",
            "modify",
            "uuid",
            UUID,
            "ipv4.method",
            "manual",
        ],
        4,
        "",
    );
    fake.answer(&[NMCLI, "connection", "modify"], 0, "");
    fake.answer(&["/usr/bin/systemd-run"], 0, "");
    fake.answer(&["/usr/bin/systemctl"], 0, "");
    let error = run_apply(&fake, &fake.root, &fixed()).unwrap_err();
    assert!(error.contains("nmcli"), "{error}");
    assert!(!pending(&fake).exists());
    at(&fake, &modify_call("auto", "", "", "", "", "no"));
    assert!(fake.called(&["/usr/bin/systemctl", "stop", "openvibes-net-revert.timer"]));
}

#[test]
fn without_a_timer_nothing_is_changed() {
    let fake = Fake::new("net-apply-no-timer");
    fake.answer(&[NMCLI, "-t", "-f", "NAME,UUID,TYPE,DEVICE"], 0, ACTIVE);
    fake.answer(&[NMCLI, "-t", "-f", CONFIG], 0, DHCP);
    fake.answer(&[NMCLI, "connection"], 0, "");
    fake.answer(&["/usr/bin/systemd-run"], 1, "");
    fake.answer(&["/usr/bin/systemctl"], 0, "");
    let error = run_apply(&fake, &fake.root, &fixed()).unwrap_err();
    assert!(error.contains("rollback timer"), "{error}");
    assert!(!pending(&fake).exists());
    assert!(!fake.called(&[NMCLI, "connection", "modify"]));
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
fn keep_works_when_the_timer_is_already_gone_but_not_when_it_will_not_stop() {
    let gone = Fake::new("net-keep-gone");
    std::fs::create_dir_all(pending(&gone).parent().unwrap()).unwrap();
    std::fs::write(pending(&gone), saved("manual")).unwrap();
    gone.answer(&["/usr/bin/systemctl", "stop"], 5, "");
    gone.answer(&["/usr/bin/systemctl", "is-active"], 3, "");
    assert_eq!(run_keep(&gone, &gone.root).unwrap(), "done\tkept");
    assert!(!pending(&gone).exists());

    let stuck = Fake::new("net-keep-stuck");
    std::fs::create_dir_all(pending(&stuck).parent().unwrap()).unwrap();
    std::fs::write(pending(&stuck), saved("manual")).unwrap();
    stuck.answer(&["/usr/bin/systemctl", "stop"], 1, "");
    stuck.answer(&["/usr/bin/systemctl", "is-active"], 0, "");
    let error = run_keep(&stuck, &stuck.root).unwrap_err();
    assert!(error.contains("come back"), "{error}");
    assert!(pending(&stuck).exists());
}

fn saved(method: &str) -> String {
    format!(
        "uuid={UUID}\nmethod={method}\naddresses=192.168.1.50/24\ngateway=192.168.1.1\ndns=9.9.9.9\nsearch=lime.lab\nignore_auto_dns=yes\n"
    )
}

#[test]
fn revert_restores_everything_nmcli_held_not_just_the_first_value() {
    let fake = host("net-revert", TWO);
    run_apply(&fake, &fake.root, &dhcp()).unwrap();
    assert_eq!(run_revert(&fake, &fake.root).unwrap(), "done\treverted");
    // The last modify is the restore, with both addresses, servers and domains.
    assert!(fake.called(&modify_call(
        "manual",
        "192.168.1.50/24, 10.0.0.2/8",
        "192.168.1.1",
        "9.9.9.9,1.1.1.1",
        "lime.lab,lab2.lab",
        "yes"
    )));
    assert!(!pending(&fake).exists());
    assert_eq!(
        run_revert(&fake, &fake.root).unwrap(),
        "done\tnothing pending"
    );
}

#[test]
fn an_unreadable_saved_file_is_moved_aside_and_nothing_runs() {
    let fake = host("net-revert-garbage", DHCP);
    std::fs::create_dir_all(pending(&fake).parent().unwrap()).unwrap();
    std::fs::write(pending(&fake), "uuid=x\nrm -rf /\n").unwrap();
    let error = run_revert(&fake, &fake.root).unwrap_err();
    assert!(error.contains("could not be read"), "{error}");
    assert!(!fake.called(&[NMCLI]));
    assert!(!pending(&fake).exists());
    assert!(
        fake.root
            .join("run/openvibes-admin/net-previous.bad")
            .exists()
    );
    // and it blocks nothing: a new change goes through
    assert_eq!(
        run_apply(&fake, &fake.root, &fixed()).unwrap(),
        "done\tpending\t60"
    );
}

#[test]
fn a_revert_that_nmcli_refuses_keeps_the_file_so_keep_can_clear_it() {
    let fake = Fake::new("net-revert-refused");
    std::fs::create_dir_all(pending(&fake).parent().unwrap()).unwrap();
    std::fs::write(pending(&fake), saved("manual")).unwrap();
    fake.answer(&[NMCLI], 10, "");
    fake.answer(&["/usr/bin/systemctl", "stop"], 5, "");
    fake.answer(&["/usr/bin/systemctl", "is-active"], 3, "");
    assert!(run_revert(&fake, &fake.root).is_err());
    assert!(pending(&fake).exists());
    assert_eq!(run_keep(&fake, &fake.root).unwrap(), "done\tkept");
    assert!(!pending(&fake).exists());
}

#[test]
fn keep_after_the_timer_has_put_the_settings_back_says_so() {
    let fake = host("net-keep-late", DHCP);
    run_apply(&fake, &fake.root, &fixed()).unwrap();
    run_revert(&fake, &fake.root).unwrap();
    assert_eq!(
        run_keep(&fake, &fake.root).unwrap(),
        "done\tnothing pending"
    );
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
    let long = format!("{}.lab", "a".repeat(62));
    for bad in ["", "-x", "a b", "a;b", "localhost", "va.", long.as_str()] {
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
