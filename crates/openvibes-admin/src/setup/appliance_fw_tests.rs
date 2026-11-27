//! The appliance's Firewall step (#561) against the fake runner.

use super::super::{
    Step, StepState,
    fake::{Fake, plan},
    plan::Component::{Distribution, Ingest},
    run_step,
};
use super::SSH_PORT;

const FW: &str = "/usr/bin/firewall-cmd";

/// An appliance whose firewalld runs with AlmaLinux's default zone plus a
/// stray port, and whose sshd listens on `ssh`.
fn appliance(name: &str, ssh: u16) -> Fake {
    let fake = Fake::new(name);
    fake.file(platform_host::setup::APPLIANCE_FILE, "");
    fake.answer(&[FW, "--state"], 0, "running\n");
    fake.answer(
        &[FW, "--permanent", "--list-services"],
        0,
        "cockpit dhcpv6-client ssh\n",
    );
    fake.answer(
        &[FW, "--permanent", "--list-ports"],
        0,
        "8080/tcp 18423/tcp\n",
    );
    fake.answer(&[FW], 0, "success\n");
    fake.answer(&["/usr/sbin/sshd", "-T"], 0, &format!("port {ssh}\n"));
    fake
}

fn calls(fake: &Fake, verb: &str) -> Vec<String> {
    fake.calls
        .borrow()
        .iter()
        .filter(|c| c.get(2).is_some_and(|a| a == verb))
        .map(|c| c[3].clone())
        .collect()
}

#[test]
fn the_appliance_opens_exactly_its_ports_and_ssh() {
    let fake = appliance("afw-exact", 22);
    let plan = plan(&[Ingest, Distribution]);
    let state = run_step(&fake.ctx(&plan), Step::Firewall);
    assert_eq!(
        state,
        StepState::Done("open: 18423/tcp 18424/tcp 514/udp 22/tcp; nothing else".into())
    );
    assert_eq!(
        calls(&fake, "--remove-service"),
        ["cockpit", "ssh"],
        "dhcpv6-client stays"
    );
    assert_eq!(calls(&fake, "--remove-port"), ["8080/tcp"]);
    assert_eq!(
        calls(&fake, "--add-port"),
        ["18424/tcp", "514/udp", "22/tcp"]
    );
    assert!(fake.called(&[FW, "--reload"]));
    assert!(!fake.called(&["/usr/sbin/semanage"]), "sshd already on 22");
}

#[test]
fn an_exact_appliance_firewall_is_done() {
    let fake = Fake::new("afw-done");
    fake.file(platform_host::setup::APPLIANCE_FILE, "");
    fake.answer(&[FW, "--state"], 0, "running\n");
    fake.answer(
        &[FW, "--permanent", "--list-services"],
        0,
        "dhcpv6-client\n",
    );
    fake.answer(
        &[FW, "--permanent", "--list-ports"],
        0,
        "22/tcp 514/udp 18423/tcp\n",
    );
    fake.answer(&["/usr/sbin/sshd", "-T"], 0, "port 22\n");
    let plan = plan(&[Ingest]);
    let state = super::check(&fake.ctx(&plan)).unwrap();
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
}

#[test]
fn a_new_ssh_port_moves_sshd_and_the_firewall_together() {
    let fake = appliance("afw-move", 22);
    fake.answer(&["/usr/sbin/semanage"], 0, "");
    fake.answer(&["/usr/sbin/sshd", "-t"], 0, "");
    fake.answer(&["/usr/bin/systemctl", "reload", "sshd.service"], 0, "");
    let mut plan = plan(&[Ingest]);
    plan.ssh_port = 2222;
    let state = run_step(&fake.ctx(&plan), Step::Firewall);
    assert!(state.detail().contains("2222/tcp"), "{state:?}");
    assert_eq!(fake.text(SSH_PORT), "Port 2222\n");
    assert_eq!(
        fake.call(&["/usr/sbin/semanage"])[1..],
        ["port", "-a", "-t", "ssh_port_t", "-p", "tcp", "2222"]
    );
    assert!(fake.called(&["/usr/bin/systemctl", "reload", "sshd.service"]));
    assert!(!calls(&fake, "--add-port").contains(&"22/tcp".to_owned()));
}

#[test]
fn a_refused_ssh_port_changes_nothing() {
    let fake = appliance("afw-refused", 22);
    fake.answer(&["/usr/sbin/semanage"], 0, "");
    fake.fail(&["/usr/sbin/sshd", "-t"], "Bad port");
    let mut plan = plan(&[Ingest]);
    plan.ssh_port = 2222;
    let state = run_step(&fake.ctx(&plan), Step::Firewall);
    assert!(matches!(state, StepState::Failed(_)), "{state:?}");
    assert!(!fake.root.join(SSH_PORT.trim_start_matches('/')).exists());
    assert!(
        calls(&fake, "--remove-service").is_empty(),
        "the firewall is untouched"
    );
}

#[test]
fn back_to_22_removes_the_drop_in() {
    let fake = appliance("afw-back", 2222);
    fake.file(SSH_PORT, "Port 2222\n");
    fake.answer(&["/usr/sbin/sshd", "-t"], 0, "");
    fake.answer(&["/usr/bin/systemctl", "reload", "sshd.service"], 0, "");
    let plan = plan(&[Ingest]);
    run_step(&fake.ctx(&plan), Step::Firewall);
    assert!(!fake.root.join(SSH_PORT.trim_start_matches('/')).exists());
    assert!(!fake.called(&["/usr/sbin/semanage"]));
}
