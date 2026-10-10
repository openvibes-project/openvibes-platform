//! Services, firewall and readiness against the fake runner.
use platform_host::{Step, StepState};

use crate::setup::{
    fake::{Fake, plan},
    plan::Component::*,
    run_step,
};

const TOKEN: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";

#[test]
fn chosen_services_are_enabled_and_started() {
    let fake = Fake::new("services");
    fake.answer(&["/usr/sbin/ss"], 0, "");
    fake.answer(&["/usr/bin/systemctl", "is-enabled"], 1, "");
    fake.answer(&["/usr/bin/systemctl", "enable", "--now"], 0, "");
    let state = run_step(
        &fake.ctx(&plan(&[Ingest, Vulns, Assistant])),
        Step::Services,
    );
    assert!(
        !state.detail().contains('`'),
        "no command for users: {state:?}"
    );
    assert_eq!(
        fake.call(&["/usr/bin/systemctl", "enable"]),
        [
            "/usr/bin/systemctl",
            "enable",
            "--now",
            "openvibes-ingest.service",
            "openvibes-maintenance.timer",
            "openvibes-vulns.service"
        ]
    );
}

#[test]
fn the_console_brings_the_fetch_socket_when_its_package_is_installed() {
    for (installed, listed) in [(0, true), (1, false)] {
        let fake = Fake::new(&format!("fetch-socket-{installed}"));
        fake.answer(&["/usr/sbin/ss"], 0, "");
        fake.answer(
            &["/usr/bin/rpm", "-q", "--quiet", "openvibes-fetch"],
            installed,
            "",
        );
        fake.answer(&["/usr/bin/systemctl", "is-enabled"], 1, "");
        fake.answer(&["/usr/bin/systemctl", "enable", "--now"], 0, "");
        let state = run_step(&fake.ctx(&plan(&[Ingest, Console])), Step::Services);
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
        let call = fake.call(&["/usr/bin/systemctl", "enable"]);
        assert_eq!(
            call.contains(&"openvibes-fetch.socket".to_owned()),
            listed,
            "{call:?}"
        );
    }
}

#[test]
fn firewall_ports_are_opened_or_the_step_skipped() {
    let fake = Fake::new("firewall");
    fake.file(
        "/etc/openvibes/console.toml",
        "development_listen = \"0.0.0.0:8443\"\ntransport_mode = \"direct_tls\"\n",
    );
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
        &["/usr/bin/firewall-cmd", "--permanent", "--add-port"],
        0,
        "success\n",
    );
    fake.answer(&["/usr/bin/firewall-cmd", "--reload"], 0, "success\n");
    let state = run_step(
        &fake.ctx(&plan(&[Ingest, Console, Distribution])),
        Step::Firewall,
    );
    assert_eq!(
        state,
        StepState::Done("open: 18423/tcp 18424/tcp 8443/tcp".into())
    );
    let added: Vec<String> = fake
        .calls
        .borrow()
        .iter()
        .filter(|c| c.get(2).is_some_and(|a| a == "--add-port"))
        .map(|c| c[3].clone())
        .collect();
    assert_eq!(added, ["18424/tcp", "8443/tcp"], "18423 was already open");
    assert!(fake.called(&["/usr/bin/firewall-cmd", "--reload"]));

    let fake = Fake::new("firewall-off");
    assert!(matches!(
        run_step(&fake.ctx(&plan(&[Ingest])), Step::Firewall),
        StepState::Skipped(_)
    ));
}

#[test]
fn readiness_waits_then_creates_an_endpoint_token() {
    let fake = Fake::new("ready");
    fake.answer(&["/usr/bin/curl"], 0, "");
    fake.answer(
        &[
            "/usr/sbin/runuser",
            "-u",
            "openvibes-admin",
            "--",
            "/usr/bin/openvibes-admin",
            "token",
            "fleet",
        ],
        0,
        &format!("token id 7\ntoken {TOKEN}\n"),
    );
    let root = platform_pki::generate_root(chrono::Utc::now()).unwrap();
    fake.file("/etc/openvibes/pki/root.crt", &root.cert_pem);
    // Everything is already ready (the usual case on a first install): the
    // run makes sure the standing token exists (the console's install
    // package and command need it), but shows neither it nor an agent
    // line: hosts are added from the console (install walkthrough,
    // 2026-10-08). The line's own logic is in command_tests.rs.
    let state = run_step(&fake.ctx(&plan(&[Ingest])), Step::Ready);
    assert!(fake.called(&[
        "/usr/sbin/runuser",
        "-u",
        "openvibes-admin",
        "--",
        "/usr/bin/openvibes-admin",
        "token",
        "fleet"
    ]));
    assert!(
        state
            .detail()
            .starts_with("ready: openvibes-ingest.service"),
        "{state:?}"
    );
    assert!(
        state
            .detail()
            .contains("add hosts in the console under Enrollment"),
        "{state:?}"
    );
    assert!(
        !state.detail().contains("curl") && !state.detail().contains(TOKEN),
        "{state:?}"
    );
    // Only a status check leaves the token alone.
    fake.calls.borrow_mut().clear();
    assert!(matches!(
        crate::setup::check(&fake.ctx(&plan(&[Ingest])), Step::Ready),
        StepState::Done(_)
    ));
    assert!(!fake.called(&["/usr/sbin/runuser"]));

    let fake = Fake::new("not-ready");
    fake.answer(&["/usr/bin/curl"], 7, "");
    let state = run_step(&fake.ctx(&plan(&[Ingest])), Step::Ready);
    assert!(
        state
            .detail()
            .contains("openvibes-ingest.service is not ready"),
        "{state:?}"
    );
}

#[test]
fn tokens_are_read_from_token_create() {
    // `token create`'s real output (token.rs): the id line also starts
    // with "token ".
    assert_eq!(
        super::token_from(&format!(
            "token id 7\ntoken {TOKEN}\nThe token is shown only now; store it safely.\n"
        ))
        .unwrap(),
        TOKEN
    );
    assert!(super::token_from("token short\n").is_err());
    assert!(super::token_from("nothing\n").is_err());
}

#[test]
fn a_repair_mints_no_enrollment_token() {
    // Board #64: every Repair used to leave another 10-use token behind.
    let fake = Fake::new("ready-repair");
    fake.answer(&["/usr/bin/curl"], 0, "");
    let plan = plan(&[Ingest]);
    let mut ctx = fake.ctx(&plan);
    ctx.repair = true;
    let state = run_step(&ctx, Step::Ready);
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
    assert!(
        state.detail().contains("openvibes-admin agent command"),
        "{state:?}"
    );
    assert!(!fake.called(&[
        "/usr/sbin/runuser",
        "-u",
        "openvibes-admin",
        "--",
        "/usr/bin/openvibes-admin",
        "token"
    ]));
}

#[test]
fn an_update_quotes_why_a_service_is_not_ready() {
    // Board #67: Update's readiness said only "see journalctl".
    let fake = Fake::new("update-ready-why");
    fake.answer(
        &[
            "/usr/bin/systemctl",
            "is-active",
            "--quiet",
            "openvibes-ingest.service",
        ],
        0,
        "",
    );
    fake.answer(&["/usr/bin/systemctl", "is-active"], 3, "");
    fake.answer(&["/usr/bin/curl"], 7, "");
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
        "ingest listener failed: Address already in use (os error 98)\n",
    );
    let plan = plan(&[Ingest]);
    let state = crate::setup::update::run(
        &fake.ctx(&plan),
        platform_host::UpdateStep::Ready,
        &crate::setup::update::UpdateArgs::default(),
    );
    assert_eq!(
        state,
        StepState::Failed(
            "openvibes-ingest.service is not ready after 30 seconds: \
             ingest listener failed: Address already in use (os error 98)"
                .into()
        )
    );
}
