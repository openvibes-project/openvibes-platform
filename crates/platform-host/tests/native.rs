//! The systemd backend against a fake runner: exact commands, parsing, and
//! how refusals are reported.

use std::cell::RefCell;

use platform_host::{
    Host, HostError, ServiceAction, Unit,
    native::Native,
    runner::{Output, Runner},
};

/// Answers calls whose argv starts with a scripted prefix; records every call.
struct FakeRunner {
    calls: RefCell<Vec<Vec<String>>>,
    answers: Vec<(Vec<&'static str>, Output)>,
}

impl Runner for FakeRunner {
    fn run(&self, program: &str, args: &[&str]) -> std::io::Result<Output> {
        let mut call = vec![program.to_owned()];
        call.extend(args.iter().map(|a| (*a).to_owned()));
        self.calls.borrow_mut().push(call.clone());
        for (prefix, out) in &self.answers {
            if call.len() >= prefix.len() && call.iter().zip(prefix).all(|(a, b)| a == b) {
                return Ok(out.clone());
            }
        }
        Ok(out(1, "", "unexpected call"))
    }
}

fn out(status: i32, stdout: &str, stderr: &str) -> Output {
    Output {
        status,
        stdout: stdout.into(),
        stderr: stderr.into(),
    }
}

fn fake(answers: Vec<(Vec<&'static str>, Output)>) -> Native<FakeRunner> {
    Native {
        runner: FakeRunner {
            calls: RefCell::new(Vec::new()),
            answers,
        },
    }
}

#[test]
fn services_parse_systemctl_show() {
    // systemctl show prints one block per unit, blank-line separated, in argument order.
    let show = "Id=openvibes-ingest.service\nLoadState=loaded\nActiveState=active\nUnitFileState=enabled\nActiveEnterTimestamp=Sun 2026-09-27 10:00:00 UTC\n\n\
                Id=openvibes-distribution.service\nLoadState=not-found\nActiveState=inactive\nUnitFileState=\nActiveEnterTimestamp=\n\n\
                Id=openvibes-vulns.service\nLoadState=loaded\nActiveState=failed\nUnitFileState=enabled\nActiveEnterTimestamp=\n\n\
                Id=openvibes-llm.service\nLoadState=loaded\nActiveState=inactive\nUnitFileState=disabled\nActiveEnterTimestamp=\n\n\
                Id=openvibes-maintenance.timer\nLoadState=loaded\nActiveState=active\nUnitFileState=enabled\nActiveEnterTimestamp=Sun 2026-09-27 09:00:00 UTC\n";
    let host = fake(vec![
        (vec!["/usr/bin/systemctl", "show"], out(0, show, "")),
        (
            vec![
                "/usr/bin/curl",
                "--silent",
                "--fail",
                "--max-time",
                "1",
                "--output",
                "/dev/null",
                "http://127.0.0.1:18480/ready",
            ],
            out(0, "", ""),
        ),
    ]);
    let services = host.services().unwrap();
    assert_eq!(services.len(), 5);
    let ingest = &services[0];
    assert_eq!(
        (
            ingest.unit,
            ingest.installed,
            ingest.enabled,
            ingest.active.as_str()
        ),
        (Unit::Ingest, true, true, "active")
    );
    assert_eq!(ingest.ready, Some(true));
    assert!(!services[1].installed, "not-found means not installed");
    assert_eq!(services[2].active, "failed");
    assert_eq!(services[2].ready, None, "not active: not probed");
    assert_eq!(services[4].ready, None, "the timer has no endpoint");
    assert_eq!(
        services[4].since.as_deref(),
        Some("Sun 2026-09-27 09:00:00 UTC")
    );
    let calls = host.runner.calls.borrow();
    assert_eq!(
        calls[0][..3],
        [
            "/usr/bin/systemctl",
            "show",
            "--property=Id,LoadState,ActiveState,UnitFileState,ActiveEnterTimestamp"
        ]
    );
    assert_eq!(calls[0][3..], Unit::ALL.map(|u| u.name().to_owned()));
}

#[test]
fn actions_are_exact_argument_vectors_and_journalled() {
    let host = fake(vec![
        (vec!["/usr/bin/systemctl"], out(0, "", "")),
        (vec!["/usr/bin/logger"], out(0, "", "")),
    ]);
    host.service_action(Unit::Vulns, ServiceAction::Restart)
        .unwrap();
    let calls = host.runner.calls.borrow();
    assert_eq!(
        calls[0],
        [
            "/usr/bin/systemctl",
            "--no-ask-password",
            "restart",
            "openvibes-vulns.service"
        ]
    );
    assert_eq!(calls[1][..3], ["/usr/bin/logger", "-t", "openvibes-admin"]);
    assert!(
        calls[1][3].contains("restart openvibes-vulns.service ok"),
        "{:?}",
        calls[1]
    );
}

#[test]
fn polkit_refusal_names_the_group() {
    let host = fake(vec![
        (
            vec!["/usr/bin/systemctl"],
            out(
                1,
                "",
                "Failed to restart openvibes-vulns.service: Access denied\n",
            ),
        ),
        (vec!["/usr/bin/logger"], out(0, "", "")),
    ]);
    let refused = host.service_action(Unit::Vulns, ServiceAction::Restart);
    assert_eq!(refused, Err(HostError::NotOperator));
    assert!(
        refused
            .unwrap_err()
            .to_string()
            .contains("openvibes-operators")
    );
    let journal = host.runner.calls.borrow();
    assert!(journal[1][3].contains("restart openvibes-vulns.service failed"));
}

#[test]
fn other_failures_keep_the_error_text_without_control_characters() {
    let host = fake(vec![
        (
            vec!["/usr/bin/systemctl"],
            out(1, "", "Job failed.\u{1b}[31m See journalctl.\n"),
        ),
        (vec!["/usr/bin/logger"], out(0, "", "")),
    ]);
    let Err(HostError::Failed(text)) = host.service_action(Unit::Ingest, ServiceAction::Start)
    else {
        panic!("want Failed");
    };
    assert!(text.starts_with("Job failed."), "{text}");
    assert!(!text.contains('\u{1b}'), "{text:?}");
}

#[test]
fn logs_go_through_the_helper() {
    let host = fake(vec![(
        vec!["/usr/bin/sudo"],
        out(0, "line one\nline two\n", ""),
    )]);
    assert_eq!(
        host.logs(Unit::Ingest, 50).unwrap(),
        ["line one", "line two"]
    );
    assert_eq!(
        host.runner.calls.borrow()[0],
        [
            "/usr/bin/sudo",
            "-n",
            "/usr/bin/openvibes-admin",
            "helper",
            "logs",
            "openvibes-ingest.service",
            "50"
        ]
    );
    let denied = fake(vec![(
        vec!["/usr/bin/sudo"],
        out(1, "", "sudo: a password is required\n"),
    )]);
    assert_eq!(denied.logs(Unit::Ingest, 50), Err(HostError::NotOperator));
}

#[test]
fn unit_names_round_trip_and_nothing_else_parses() {
    for unit in Unit::ALL {
        assert_eq!(Unit::parse(unit.name()), Some(unit));
    }
    for bad in [
        "sshd.service",
        "openvibes-ingest",
        "openvibes-ingest.service ",
        "../openvibes-ingest.service",
    ] {
        assert_eq!(Unit::parse(bad), None, "{bad}");
    }
}
