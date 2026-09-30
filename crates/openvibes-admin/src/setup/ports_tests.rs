//! Setup's port handling against the fake runner (boards #45, #48, #61).

use platform_host::{Step, StepState};

use crate::setup::{
    fake::{Fake, plan},
    plan::Component::*,
    ports::*,
    run_step,
};

const SS: &str = "/usr/sbin/ss";

fn listens(fake: &Fake, port: u16, line: &str) {
    fake.answer(&[SS, "-ltnpH", "sport", "=", &format!(":{port}")], 0, line);
}

fn free(fake: &Fake) {
    fake.answer(&[SS], 0, "");
}

/// `unit` runs with main process `pid`.
fn running(fake: &Fake, unit: &str, pid: u32) {
    fake.answer(
        &[
            "/usr/bin/systemctl",
            "show",
            "--property=MainPID",
            "--value",
            unit,
        ],
        0,
        &format!("{pid}\n"),
    );
}

#[test]
fn a_listener_is_named_when_ss_can_see_it() {
    assert_eq!(parse(""), None);
    assert_eq!(parse("\n"), None);
    // The user's host (2026-09-29), unprivileged: no process shown.
    assert_eq!(
        parse("LISTEN 0      4096   *:443 *:*\n"),
        Some(("another process".into(), None))
    );
    assert_eq!(
        parse(
            "LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:((\"nginx\",pid=4242,fd=6),(\"nginx\",pid=4243,fd=6))\n"
        ),
        Some(("nginx (pid 4242)".into(), Some(4242)))
    );
    // IPv6 only, or one address only: still taken.
    assert!(parse("LISTEN 0 128 [::]:443 [::]:*\n").is_some());
    assert!(parse("LISTEN 0 128 127.0.0.1:443 0.0.0.0:*\n").is_some());
}

#[test]
fn chosen_ports_are_real_ours_to_take_and_different() {
    check_ports(443, 18423, 18424).unwrap();
    check_ports(8443, 18500, 18501).unwrap();
    assert_eq!(
        check_ports(0, 18423, 18424).unwrap_err(),
        "console port 0 is not a port"
    );
    for (c, i, d) in [
        (18430, 18423, 18424),
        (443, 18480, 18424),
        (443, 18423, 18483),
    ] {
        assert!(
            check_ports(c, i, d)
                .unwrap_err()
                .contains("18430 and 18480-18483"),
            "{c} {i} {d}"
        );
    }
    for (c, i, d) in [
        (18423, 18423, 18424),
        (443, 18424, 18424),
        (443, 443, 18424),
    ] {
        assert!(
            check_ports(c, i, d).unwrap_err().contains("must differ"),
            "{c} {i} {d}"
        );
    }
}

#[test]
fn a_taken_console_port_names_the_holder_and_a_free_one() {
    let fake = Fake::new("ports-console");
    listens(
        &fake,
        443,
        "LISTEN 0 511 *:443 *:* users:((\"nginx\",pid=7,fd=6))\n",
    );
    listens(&fake, 8443, "LISTEN 0 511 *:8443 *:*\n");
    free(&fake);
    let plan = plan(&[Ingest, Console]);
    assert_eq!(
        check(&fake.ctx(&plan)).unwrap_err(),
        "port 443 is taken by nginx (pid 7); the console needs it: stop that process or choose another port, e.g. 8444 (free)"
    );
}

#[test]
fn a_taken_ingest_port_names_a_free_one_too() {
    let fake = Fake::new("ports-ingest");
    listens(&fake, 18423, "LISTEN 0 5 0.0.0.0:18423 0.0.0.0:*\n");
    free(&fake);
    let plan = plan(&[Ingest, Distribution]);
    // 18424 is distribution's own, so it is not offered.
    assert_eq!(
        check(&fake.ctx(&plan)).unwrap_err(),
        "port 18423 is taken by another process; ingest needs it: stop that process or choose another port, e.g. 18425 (free)"
    );
}

#[test]
fn our_own_units_on_their_ports_pass() {
    let fake = Fake::new("ports-own");
    running(&fake, "openvibes-ingest", 11);
    listens(
        &fake,
        18423,
        "LISTEN 0 5 0.0.0.0:18423 0.0.0.0:* users:((\"openvibes-inges\",pid=11,fd=9))\n",
    );
    free(&fake);
    let mut plan = plan(&[Ingest, Distribution, Console]);
    plan.console_port = 8443;
    assert_eq!(check(&fake.ctx(&plan)).unwrap(), Vec::<&str>::new());
    assert!(fake.called(&[SS, "-ltnpH", "sport", "=", ":8443"]));
    assert!(!fake.called(&[SS, "-ltnpH", "sport", "=", ":443"]));
}

#[test]
fn a_running_unit_off_its_planned_port_is_restarted() {
    let fake = Fake::new("ports-moved");
    // Repair after a move: the console still listens on 8444, the plan
    // says 8445, which is free.
    running(&fake, "openvibes-console", 21);
    free(&fake);
    let mut plan = plan(&[Ingest, Console]);
    plan.console_port = 8445;
    assert_eq!(check(&fake.ctx(&plan)).unwrap(), ["openvibes-console"]);
}

#[test]
fn a_foreign_holder_is_refused_even_when_our_unit_runs() {
    let fake = Fake::new("ports-foreign");
    // console.toml already says 8445 (the Console step ran), the console
    // runs as pid 21 on its old port, and someone else holds 8445.
    running(&fake, "openvibes-console", 21);
    listens(
        &fake,
        8445,
        "LISTEN 0 511 *:8445 *:* users:((\"python3\",pid=99,fd=3))\n",
    );
    free(&fake);
    let mut plan = plan(&[Ingest, Console]);
    plan.console_port = 8445;
    assert!(
        check(&fake.ctx(&plan))
            .unwrap_err()
            .starts_with("port 8445 is taken by python3 (pid 99)")
    );
}

#[test]
fn a_failing_ss_is_an_error_not_a_free_port() {
    let fake = Fake::new("ports-ss-fails");
    assert!(
        check(&fake.ctx(&plan(&[Ingest])))
            .unwrap_err()
            .contains("could not list")
    );
}

#[test]
fn chosen_ingest_and_distribution_ports_are_configured() {
    let fake = Fake::new("ports-configure");
    let ingest = include_str!("../../../../packaging/rpm/ingest.toml");
    let distribution = include_str!("../../../../packaging/rpm/distribution.toml");
    fake.file("/etc/openvibes/ingest.toml", &format!("# kept\n{ingest}"));
    fake.file("/etc/openvibes/distribution.toml", distribution);
    let mut plan = plan(&[Ingest, Distribution]);
    plan.ingest_port = 18500;
    configure(&fake.ctx(&plan)).unwrap();
    let ingest = fake.text("/etc/openvibes/ingest.toml");
    assert!(
        ingest.contains("listen = \"0.0.0.0:18500\"") && ingest.contains("# kept"),
        "{ingest}"
    );
    assert_eq!(fake.text("/etc/openvibes/distribution.toml"), distribution);
}

#[test]
fn services_do_not_start_on_a_taken_port() {
    let fake = Fake::new("ports-services");
    listens(&fake, 443, "LISTEN 0 511 *:443 *:*\n");
    free(&fake);
    fake.answer(&["/usr/bin/systemctl", "is-enabled"], 1, "");
    fake.answer(&["/usr/bin/systemctl", "enable", "--now"], 0, "");
    let state = run_step(&fake.ctx(&plan(&[Ingest, Console])), Step::Services);
    assert!(
        matches!(&state, StepState::Failed(e) if e.starts_with("port 443 is taken by another process")),
        "{state:?}"
    );
    assert!(!fake.called(&["/usr/bin/systemctl", "enable"]));
}

#[test]
fn repair_restarts_a_running_unit_whose_port_moved() {
    let fake = Fake::new("ports-repair-restart");
    // Everything enabled and running, but the console on its old port.
    fake.answer(&["/usr/bin/systemctl", "is-enabled"], 0, "");
    fake.answer(&["/usr/bin/systemctl", "is-active"], 0, "");
    running(&fake, "openvibes-console", 21);
    running(&fake, "openvibes-ingest", 11);
    listens(
        &fake,
        18423,
        "LISTEN 0 5 0.0.0.0:18423 0.0.0.0:* users:((\"openvibes-inges\",pid=11,fd=9))\n",
    );
    free(&fake);
    fake.answer(&["/usr/bin/systemctl", "enable", "--now"], 0, "");
    fake.answer(&["/usr/bin/systemctl", "try-restart"], 0, "");
    let mut plan = plan(&[Ingest, Console]);
    plan.console_port = 8445;
    let state = run_step(&fake.ctx(&plan), Step::Services);
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
    assert_eq!(
        fake.call(&["/usr/bin/systemctl", "try-restart"]),
        ["/usr/bin/systemctl", "try-restart", "openvibes-console"]
    );
}

#[test]
fn readiness_quotes_why_a_service_is_down() {
    let fake = Fake::new("ports-ready");
    fake.answer(&["/usr/bin/curl"], 7, "");
    // The service's own messages, not systemd's "Failed with result".
    fake.answer(
        &[
            "/usr/bin/journalctl",
            "_SYSTEMD_UNIT=openvibes-ingest.service",
            "-n",
            "1",
            "-o",
            "cat",
            "--no-pager",
        ],
        0,
        "console listener failed: Address already in use (os error 98)\n",
    );
    fake.answer(
        &["/usr/bin/journalctl"],
        0,
        "openvibes-ingest.service: Failed with result 'exit-code'.\n",
    );
    let state = run_step(&fake.ctx(&plan(&[Ingest, Console])), Step::Ready);
    assert_eq!(
        state,
        StepState::Failed(
            "openvibes-ingest.service is not ready after 30 seconds: \
             console listener failed: Address already in use (os error 98)"
                .into()
        )
    );
}

#[test]
fn readiness_needs_the_listen_port_not_only_health() {
    let fake = Fake::new("ports-ready-listen");
    // Health answers, but nothing listens on the console's planned port
    // (reviewer's 8444 → 8445 Repair, #61).
    fake.answer(
        &[
            "/usr/bin/curl",
            "--silent",
            "--insecure",
            "--max-time",
            "2",
            "--output",
            "/dev/null",
            "https://127.0.0.1:8445/",
        ],
        7,
        "",
    );
    fake.answer(&["/usr/bin/curl"], 0, "");
    fake.answer(&["/usr/bin/journalctl"], 0, "");
    let mut plan = plan(&[Ingest, Console]);
    plan.console_port = 8445;
    let state = run_step(&fake.ctx(&plan), Step::Ready);
    assert!(
        matches!(&state, StepState::Failed(e) if e.starts_with("openvibes-console.service is not ready")),
        "{state:?}"
    );
}

#[test]
fn behind_a_proxy_the_console_port_is_the_proxy_s() {
    let fake = Fake::new("ports-proxy");
    // Switched to reverse_proxy in the config editor: nginx holding 443 is
    // the point, not a clash (reviewer on #92).
    fake.file(
        "/etc/openvibes/console.toml",
        "development_listen = \"127.0.0.1:8080\"\ntransport_mode = \"reverse_proxy\"\n",
    );
    listens(
        &fake,
        443,
        "LISTEN 0 511 *:443 *:* users:((\"nginx\",pid=7,fd=6))\n",
    );
    free(&fake);
    let plan = plan(&[Ingest, Console]);
    assert_eq!(check(&fake.ctx(&plan)).unwrap(), Vec::<&str>::new());
    assert!(!fake.called(&[SS, "-ltnpH", "sport", "=", ":443"]));
    assert_eq!(
        listen_port(&fake.ctx(&plan), "openvibes-console.service"),
        None
    );
}

#[test]
fn a_repair_names_the_agent_ports_it_moves() {
    let old = plan(&[Ingest, Distribution, Console]);
    let moved = old.with_ports(Some(8444), Some(18600), None).unwrap();
    // The console is not an agent port: only ingest counts here.
    assert_eq!(moved_agent_ports(&old, &moved), [("ingest", 18423, 18600)]);
    assert!(moved_agent_ports(&old, &old).is_empty());
}

#[test]
fn a_repair_closes_the_ports_it_moved_away_from() {
    let fake = Fake::new("ports-close");
    fake.answer(&["/usr/bin/firewall-cmd", "--state"], 0, "running\n");
    fake.answer(
        &[
            "/usr/bin/firewall-cmd",
            "--permanent",
            "--query-port",
            "18423/tcp",
        ],
        0,
        "yes\n",
    );
    fake.answer(
        &["/usr/bin/firewall-cmd", "--permanent", "--query-port"],
        1,
        "no\n",
    );
    fake.answer(
        &["/usr/bin/firewall-cmd", "--permanent", "--remove-port"],
        0,
        "success\n",
    );
    fake.answer(&["/usr/bin/firewall-cmd", "--reload"], 0, "success\n");
    let old = plan(&[Ingest, Distribution, Console]);
    let new = old.with_ports(Some(8444), Some(18600), None).unwrap();
    // 18423 was open and is closed; 443 was not open, so nothing to remove.
    assert_eq!(close_old(&fake.ctx(&new), &old).unwrap(), ["18423/tcp"]);
    assert_eq!(
        fake.call(&["/usr/bin/firewall-cmd", "--permanent", "--remove-port"]),
        [
            "/usr/bin/firewall-cmd",
            "--permanent",
            "--remove-port",
            "18423/tcp"
        ]
    );
    // The running firewall too, not only after a reboot.
    assert!(fake.called(&["/usr/bin/firewall-cmd", "--reload"]));
    // Without firewalld there is nothing to close.
    let fake = Fake::new("ports-close-off");
    assert!(close_old(&fake.ctx(&new), &old).unwrap().is_empty());
}

#[test]
fn a_port_another_service_moved_onto_stays_open() {
    let fake = Fake::new("ports-swap");
    fake.answer(&["/usr/bin/firewall-cmd", "--state"], 0, "running\n");
    fake.answer(
        &["/usr/bin/firewall-cmd", "--permanent", "--query-port"],
        0,
        "yes\n",
    );
    fake.answer(
        &["/usr/bin/firewall-cmd", "--permanent", "--remove-port"],
        0,
        "success\n",
    );
    fake.answer(&["/usr/bin/firewall-cmd", "--reload"], 0, "success\n");
    let old = plan(&[Ingest, Distribution, Console]);
    // The console leaves 443 and ingest takes it: 443 must stay open.
    let new = old.with_ports(Some(8443), Some(443), None).unwrap();
    assert_eq!(close_old(&fake.ctx(&new), &old).unwrap(), ["18423/tcp"]);
}

/// Board #72: a name that resolves to IPv6 only (the user's hostname) or an
/// IPv6 client reaches the services when the kernel binds `[::]` for both.
#[test]
fn services_listen_on_both_ip_versions_where_the_kernel_allows_it() {
    let fake = Fake::new("ports-dual-stack");
    let ingest = include_str!("../../../../packaging/rpm/ingest.toml");
    fake.file("/etc/openvibes/ingest.toml", ingest);
    fake.file("/proc/sys/net/ipv6/bindv6only", "0\n");
    configure(&fake.ctx(&plan(&[Ingest]))).unwrap();
    let ingest = fake.text("/etc/openvibes/ingest.toml");
    assert!(ingest.contains("listen = \"[::]:18423\""), "{ingest}");
}

#[test]
fn without_dual_stack_ipv6_services_stay_on_ipv4() {
    // IPv6 off (no such file), or a `[::]` socket that would be IPv6 only.
    for bindv6only in [None, Some("1\n")] {
        let fake = Fake::new("ports-v4-only");
        let ingest = include_str!("../../../../packaging/rpm/ingest.toml");
        fake.file("/etc/openvibes/ingest.toml", ingest);
        if let Some(value) = bindv6only {
            fake.file("/proc/sys/net/ipv6/bindv6only", value);
        }
        let mut plan = plan(&[Ingest]);
        plan.ingest_port = 18500;
        configure(&fake.ctx(&plan)).unwrap();
        let ingest = fake.text("/etc/openvibes/ingest.toml");
        assert!(ingest.contains("listen = \"0.0.0.0:18500\""), "{ingest}");
    }
}

/// Reviewer on #102: Repair on a running host rewrites `0.0.0.0` to `[::]`
/// and must restart the unit, though its own process holds its port.
#[test]
fn repair_restarts_a_unit_whose_listen_address_changed() {
    let fake = Fake::new("ports-dual-stack-restart");
    let ingest = include_str!("../../../../packaging/rpm/ingest.toml");
    fake.file("/etc/openvibes/ingest.toml", ingest);
    fake.file("/proc/sys/net/ipv6/bindv6only", "0\n");
    fake.answer(&["/usr/bin/systemctl", "is-enabled"], 0, "");
    fake.answer(&["/usr/bin/systemctl", "is-active"], 0, "");
    running(&fake, "openvibes-ingest", 11);
    listens(
        &fake,
        18423,
        "LISTEN 0 5 0.0.0.0:18423 0.0.0.0:* users:((\"openvibes-inges\",pid=11,fd=9))\n",
    );
    free(&fake);
    fake.answer(&["/usr/bin/systemctl", "enable", "--now"], 0, "");
    fake.answer(&["/usr/bin/systemctl", "try-restart"], 0, "");
    let state = run_step(&fake.ctx(&plan(&[Ingest])), Step::Services);
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
    assert!(
        fake.text("/etc/openvibes/ingest.toml")
            .contains("listen = \"[::]:18423\"")
    );
    assert_eq!(
        fake.call(&["/usr/bin/systemctl", "try-restart"]),
        ["/usr/bin/systemctl", "try-restart", "openvibes-ingest"]
    );

/// Reviewer on #106: the TUI saves a moved plan, then runs; the old ports
/// close only once every service is ready, as the CLI's Repair does.
#[test]
fn a_tui_move_closes_the_old_port_after_the_run() {
    let fake = Fake::new("ports-moved-from");
    let mut old = plan(&[Ingest, Console]);
    old.console_port = 443;
    let mut new = old.clone();
    remember_moved(&fake.root, &old, &new).unwrap();
    assert!(
        !fake.root.join("etc/openvibes/setup-moved-from").exists(),
        "nothing moved"
    );
    new.console_port = 8443;
    std::fs::create_dir_all(fake.root.join("etc/openvibes")).unwrap();
    remember_moved(&fake.root, &old, &new).unwrap();
    // A second move before a run finished keeps the first ports.
    let mut newer = new.clone();
    newer.console_port = 9443;
    remember_moved(&fake.root, &new, &newer).unwrap();
    assert_eq!(fake.text(MOVED_FROM), "443 18423 18424\n");

    fake.answer(&["/usr/bin/firewall-cmd", "--state"], 0, "running");
    fake.answer(
        &[
            "/usr/bin/firewall-cmd",
            "--permanent",
            "--query-port",
            "443/tcp",
        ],
        0,
        "yes",
    );
    fake.answer(
        &[
            "/usr/bin/firewall-cmd",
            "--permanent",
            "--remove-port",
            "443/tcp",
        ],
        0,
        "",
    );
    fake.answer(&["/usr/bin/firewall-cmd", "--reload"], 0, "");
    assert_eq!(close_moved(&fake.ctx(&newer)).unwrap(), ["443/tcp"]);
    assert!(
        !fake.root.join("etc/openvibes/setup-moved-from").exists(),
        "forgotten"
    );
    assert!(close_moved(&fake.ctx(&newer)).unwrap().is_empty());
}
