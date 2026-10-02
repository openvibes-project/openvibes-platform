//! The systemd backend against a fake runner: exact commands, parsing, and
//! how refusals are reported.

use std::cell::RefCell;

use platform_host::{
    Database, DiskUse, Host, HostError, PackageUpdate, Privileged, RemoveStep, Secret, Service,
    ServiceAction, Step, StepState, Unit, UpdateStep,
    native::Native,
    runner::{Output, Program, Runner},
};

/// Answers calls whose argv starts with a scripted prefix; records every call.
struct FakeRunner {
    calls: RefCell<Vec<Vec<String>>>,
    inputs: RefCell<Vec<String>>,
    answers: Vec<(Vec<&'static str>, Output)>,
}

impl Runner for FakeRunner {
    fn run(&self, program: Program, args: &[&str]) -> std::io::Result<Output> {
        let mut call = vec![program.path().to_owned()];
        call.extend(args.iter().map(|a| (*a).to_owned()));
        self.calls.borrow_mut().push(call.clone());
        for (prefix, out) in &self.answers {
            if call.len() >= prefix.len() && call.iter().zip(prefix).all(|(a, b)| a == b) {
                return Ok(out.clone());
            }
        }
        Ok(out(1, "", "unexpected call"))
    }

    fn run_with_input(
        &self,
        program: Program,
        args: &[&str],
        input: &[u8],
    ) -> std::io::Result<Output> {
        self.inputs
            .borrow_mut()
            .push(String::from_utf8_lossy(input).into_owned());
        self.run(program, args)
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
            inputs: RefCell::new(Vec::new()),
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
            "--no-block",
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
    // Then the audit_log row, through the CLI as its service account.
    assert_eq!(
        calls[2],
        [
            "/usr/bin/sudo",
            "-n",
            "-u",
            "openvibes-admin",
            "/usr/bin/openvibes-admin",
            "audit",
            "note",
            "restart",
            "openvibes-vulns.service",
            "ok"
        ]
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

#[test]
fn only_the_four_programs_exist() {
    assert_eq!(
        [
            Program::Systemctl,
            Program::Sudo,
            Program::Logger,
            Program::Curl
        ]
        .map(Program::path),
        [
            "/usr/bin/systemctl",
            "/usr/bin/sudo",
            "/usr/bin/logger",
            "/usr/bin/curl"
        ]
    );
}

#[test]
fn config_is_read_and_written_through_the_helper() {
    let host = fake(vec![
        (
            vec![
                "/usr/bin/sudo",
                "-n",
                "/usr/bin/openvibes-admin",
                "helper",
                "config-read",
                "ingest",
            ],
            out(0, "listen = \"0.0.0.0:18423\"\n", ""),
        ),
        (
            vec![
                "/usr/bin/sudo",
                "-n",
                "/usr/bin/openvibes-admin",
                "helper",
                "config-write",
                "ingest",
            ],
            out(0, "", ""),
        ),
        (vec!["/usr/bin/logger"], out(0, "", "")),
    ]);
    assert_eq!(
        host.read_config(Service::Ingest).unwrap(),
        "listen = \"0.0.0.0:18423\"\n"
    );
    host.write_config(Service::Ingest, "listen = \"0.0.0.0:443\"\n")
        .unwrap();
    assert_eq!(*host.runner.inputs.borrow(), ["listen = \"0.0.0.0:443\"\n"]);
    let calls = host.runner.calls.borrow();
    let journal = calls
        .iter()
        .find(|call| call[0] == "/usr/bin/logger")
        .unwrap();
    assert_eq!(journal[1..3], ["-t", "openvibes-admin"]);
    assert!(
        journal[3].ends_with(" config-write ingest ok"),
        "{journal:?}"
    );
}

#[test]
fn config_refusals_are_reported() {
    let host = fake(vec![
        (
            vec![
                "/usr/bin/sudo",
                "-n",
                "/usr/bin/openvibes-admin",
                "helper",
                "config-read",
            ],
            out(1, "", "sudo: a password is required\n"),
        ),
        (
            vec![
                "/usr/bin/sudo",
                "-n",
                "/usr/bin/openvibes-admin",
                "helper",
                "config-write",
            ],
            out(
                1,
                "",
                "openvibes-admin helper: not saved: invalid ingest configuration\n",
            ),
        ),
        (vec!["/usr/bin/logger"], out(0, "", "")),
    ]);
    assert_eq!(
        host.read_config(Service::Vulns),
        Err(HostError::NotOperator)
    );
    assert_eq!(
        host.write_config(Service::Ingest, "x = 1\n"),
        Err(HostError::Failed(
            "openvibes-admin helper: not saved: invalid ingest configuration".into()
        ))
    );
    let calls = host.runner.calls.borrow();
    assert!(
        calls
            .iter()
            .any(|call| call[0] == "/usr/bin/logger"
                && call[3].ends_with(" config-write ingest failed")),
        "{calls:?}"
    );
}

#[test]
fn services_and_their_files_are_a_closed_list() {
    for service in Service::ALL {
        assert_eq!(Service::parse(service.name()), Some(service));
        assert_eq!(
            service.path(),
            format!("/etc/openvibes/{}.toml", service.name())
        );
    }
    for bad in [
        "",
        "ingest.toml",
        "../ingest",
        "llm",
        "Ingest",
        "/etc/openvibes/ingest.toml",
    ] {
        assert_eq!(Service::parse(bad), None, "{bad}");
    }
    assert_eq!(Service::Console.unit(), Some(Unit::Console));
    assert_eq!(Service::Admin.unit(), None);
    assert_eq!(
        Unit::parse("openvibes-console.service"),
        Some(Unit::Console)
    );
}

#[test]
fn the_polkit_rule_lists_exactly_the_units() {
    let rule = include_str!("../../../packaging/rpm/openvibes-operators.polkit.rules");
    for unit in Unit::ALL {
        assert!(
            rule.contains(&format!("\"{}\"", unit.name())),
            "{} missing",
            unit.name()
        );
    }
    let listed = rule.matches(".service\"").count() + rule.matches(".timer\"").count();
    assert_eq!(listed, Unit::ALL.len());
}

#[test]
fn privileged_verbs_pass_the_password_on_stdin_only() {
    let host = fake(vec![
        (
            vec![
                "/usr/bin/sudo",
                "-S",
                "-k",
                "-p",
                "",
                "/usr/bin/openvibes-admin",
                "helper",
                "setup-step",
                "ca",
            ],
            out(0, "done\tintermediate imported\n", ""),
        ),
        (vec!["/usr/bin/logger"], out(0, "", "")),
    ]);
    let password = Secret::new("hunter2 hunter2".into());
    assert_eq!(
        host.privileged(Privileged::SetupStep(Step::Ca), &password)
            .unwrap(),
        "done\tintermediate imported\n"
    );
    assert_eq!(*host.runner.inputs.borrow(), ["hunter2 hunter2\n"]);
    let calls = host.runner.calls.borrow();
    assert!(
        calls
            .iter()
            .all(|call| !call.iter().any(|arg| arg.contains("hunter2"))),
        "{calls:?}"
    );
    let journal = calls
        .iter()
        .find(|call| call[0] == "/usr/bin/logger")
        .unwrap();
    assert!(journal[3].ends_with(" setup-step ca ok"), "{journal:?}");
    assert_eq!(format!("{password:?}"), "Secret(..)");
}

#[test]
fn wrong_password_and_missing_sudo_rights_are_told_apart() {
    let host = fake(vec![
        (
            vec![
                "/usr/bin/sudo",
                "-S",
                "-k",
                "-p",
                "",
                "/usr/bin/openvibes-admin",
                "helper",
                "setup-status",
            ],
            out(1, "", "sudo: 1 incorrect password attempt\n"),
        ),
        (
            vec![
                "/usr/bin/sudo",
                "-S",
                "-k",
                "-p",
                "",
                "/usr/bin/openvibes-admin",
                "helper",
                "unit-enable",
            ],
            out(1, "", "alice is not in the sudoers file.\n"),
        ),
        (
            vec![
                "/usr/bin/sudo",
                "-S",
                "-k",
                "-p",
                "",
                "/usr/bin/openvibes-admin",
                "helper",
                "unit-disable",
            ],
            out(
                1,
                "",
                "openvibes-admin helper: not allowed: not an OpenVIBES unit\n",
            ),
        ),
        (vec!["/usr/bin/logger"], out(0, "", "")),
    ]);
    let password = Secret::new("wrong".into());
    assert_eq!(
        host.privileged(Privileged::SetupStatus, &password),
        Err(HostError::WrongPassword)
    );
    assert_eq!(
        host.privileged(Privileged::UnitEnable(Unit::Ingest), &password),
        Err(HostError::NotSudoer)
    );
    assert_eq!(
        host.privileged(Privileged::UnitDisable(Unit::Ingest), &password),
        Err(HostError::Failed(
            "openvibes-admin helper: not allowed: not an OpenVIBES unit".into()
        ))
    );
}

#[test]
fn verbs_steps_and_states_are_closed_lists() {
    let args = ["--components".to_owned(), "ingest".to_owned()];
    assert_eq!(
        Privileged::SetupPlan(&args).args(),
        ["setup-plan", "--components", "ingest"]
    );
    assert_eq!(Privileged::SetupPlan(&args).journal(), "setup-plan");
    assert_eq!(
        Privileged::UnitEnable(Unit::Vulns).args(),
        ["unit-enable", "openvibes-vulns.service"]
    );
    for step in Step::ALL {
        assert_eq!(Step::parse(step.name()), Some(step));
    }
    for bad in ["", "Packages", "packages ", "../ca", "all"] {
        assert_eq!(Step::parse(bad), None, "{bad}");
    }
    for state in [
        StepState::Done("x y".into()),
        StepState::Todo,
        StepState::Waiting("sign it".into()),
        StepState::Skipped("not chosen".into()),
        StepState::Failed("boom".into()),
    ] {
        assert_eq!(StepState::parse(&state.line()), Some(state));
    }
    assert_eq!(StepState::Done("a\tb\nc".into()).line(), "done\ta b c");
    assert_eq!(StepState::parse("maybe\tx"), None);
}

#[test]
fn update_and_remove_verbs_carry_their_arguments_but_journal_only_the_step() {
    let args = ["--backup".to_owned(), "/home/alice/b.dump".to_owned()];
    assert_eq!(
        Privileged::Update(UpdateStep::Backup, &args).args(),
        ["update-step", "backup", "--backup", "/home/alice/b.dump"]
    );
    assert_eq!(
        Privileged::Update(UpdateStep::Backup, &args).journal(),
        "update-step backup"
    );
    let remove = ["--components".to_owned(), "vulns".to_owned()];
    assert_eq!(
        Privileged::Remove(RemoveStep::Stop, &remove).args(),
        ["remove-step", "stop", "--components", "vulns"]
    );
    assert_eq!(
        Privileged::Remove(RemoveStep::Purge, &remove).journal(),
        "remove-step purge"
    );
    assert_eq!(
        Privileged::Repair(Step::Ca).args(),
        ["setup-step", "ca", "--repair"]
    );
    for step in UpdateStep::ALL {
        assert_eq!(UpdateStep::parse(step.name()), Some(step));
    }
    for step in RemoveStep::ALL {
        assert_eq!(RemoveStep::parse(step.name()), Some(step));
    }
    assert_eq!(RemoveStep::parse("everything"), None);
}

#[test]
fn packages_lists_installed_versions_and_newer_ones() {
    let host = fake(vec![
        (
            vec!["/usr/bin/rpm", "-qa"],
            out(
                0,
                "openvibes-ingest 0.1.0-1.fc44\nopenvibes-agent 0.1.0-1.fc44\nopenvibes-ingest-debuginfo 0.1.0-1.fc44\n",
                "",
            ),
        ),
        (
            vec![
                "/usr/bin/dnf",
                "-q",
                "--setopt=openvibes.metadata_expire=0",
                "list",
                "--upgrades",
            ],
            out(
                0,
                "Available upgrades\nopenvibes-ingest.x86_64 0.2.0-1.fc44 openvibes\n",
                "",
            ),
        ),
    ]);
    assert_eq!(
        host.packages().unwrap(),
        [
            PackageUpdate {
                name: "openvibes-agent".into(),
                installed: "0.1.0-1.fc44".into(),
                available: None
            },
            PackageUpdate {
                name: "openvibes-ingest".into(),
                installed: "0.1.0-1.fc44".into(),
                available: Some("0.2.0-1.fc44".into())
            },
        ]
    );
}

#[test]
fn the_journal_records_the_state_a_step_ended_in() {
    let host = fake(vec![
        (
            vec![
                "/usr/bin/sudo",
                "-S",
                "-k",
                "-p",
                "",
                "/usr/bin/openvibes-admin",
                "helper",
                "setup-step",
                "ca",
            ],
            out(0, "failed\tdatabase down\n", ""),
        ),
        (vec!["/usr/bin/logger"], out(0, "", "")),
    ]);
    host.privileged(Privileged::SetupStep(Step::Ca), &Secret::new("pw".into()))
        .unwrap();
    let calls = host.runner.calls.borrow();
    let journal = calls
        .iter()
        .find(|call| call[0] == "/usr/bin/logger")
        .unwrap();
    assert!(journal[3].ends_with(" setup-step ca failed"), "{journal:?}");
}

#[test]
fn database_commands_run_the_cli_as_its_account_and_changes_are_journalled() {
    let admin = [
        "/usr/bin/sudo",
        "-n",
        "-u",
        "openvibes-admin",
        "/usr/bin/openvibes-admin",
    ];
    let host = fake(vec![
        (
            [&admin[..], &["status"]].concat(),
            out(0, "schema version 25\n", ""),
        ),
        (
            [&admin[..], &["migrate"]].concat(),
            out(1, "", "openvibes-admin: database unavailable\n"),
        ),
        (vec!["/usr/bin/logger"], out(0, "", "")),
    ]);
    assert_eq!(
        host.database(Database::Status).unwrap(),
        "schema version 25\n"
    );
    assert_eq!(
        host.database(Database::Migrate),
        Err(HostError::Failed(
            "openvibes-admin: database unavailable".into()
        ))
    );
    let calls = host.runner.calls.borrow();
    assert_eq!(calls.len(), 3, "status is not journalled: {calls:?}");
    assert!(calls[2][3].ends_with(" migrate failed"), "{:?}", calls[2]);
    assert_eq!(
        Database::FeedsStatus.args(),
        ["feeds", "status"],
        "the CLI's own subcommand"
    );
    assert_eq!(Database::RulesList.args(), ["rules", "list"]);
}

#[test]
fn a_database_command_refused_by_sudo_names_the_group() {
    let host = fake(vec![(
        vec!["/usr/bin/sudo"],
        out(1, "", "sudo: a password is required\n"),
    )]);
    assert_eq!(host.database(Database::Status), Err(HostError::NotOperator));
}

#[test]
fn disk_use_parses_df() {
    let df = "File           Use% Avail\n/var/lib/pgsql  45%   20G\n/var/lib/openvibes-ingest 91% 1.2G\n";
    let host = fake(vec![(vec!["/usr/bin/df"], out(0, df, ""))]);
    let paths = [
        "/var/lib/pgsql".to_owned(),
        "/var/lib/openvibes-ingest".to_owned(),
    ];
    assert_eq!(
        host.df(&paths).unwrap(),
        [
            DiskUse {
                path: "/var/lib/pgsql".into(),
                used_percent: 45,
                available: "20G".into()
            },
            DiskUse {
                path: "/var/lib/openvibes-ingest".into(),
                used_percent: 91,
                available: "1.2G".into()
            }
        ]
    );
    assert_eq!(
        host.runner.calls.borrow()[0],
        [
            "/usr/bin/df",
            "--output=file,pcent,avail",
            "-h",
            "/var/lib/pgsql",
            "/var/lib/openvibes-ingest"
        ]
    );
    assert!(host.df(&[]).unwrap().is_empty());
}

#[test]
fn a_status_check_is_journalled_but_not_noted_in_the_audit_log() {
    let host = fake(vec![
        (vec!["/usr/bin/sudo", "-S"], out(0, "", "")),
        (vec!["/usr/bin/logger"], out(0, "", "")),
    ]);
    host.privileged(Privileged::SetupStatus, &Secret::new("pw".into()))
        .unwrap();
    let calls = host.runner.calls.borrow();
    assert_eq!(calls.len(), 2, "no audit note: {calls:?}");
    assert!(calls[1][3].ends_with(" setup-status ok"), "{:?}", calls[1]);
}

/// sudo's first-use lecture (board #75), as sudo 1.9 prints it to stderr.
const LECTURE: &str = "\nWe trust you have received the usual lecture from the local System\n\
Administrator. It usually boils down to these three things:\n\n    #1) Respect the privacy of others.\n    \
#2) Think before you type.\n    #3) With great power comes great responsibility.\n\n\
For security reasons, the password you type will not be visible.\n\n";

fn helper(verb: &'static str) -> Vec<&'static str> {
    vec![
        "/usr/bin/sudo",
        "-S",
        "-k",
        "-p",
        "",
        "/usr/bin/openvibes-admin",
        "helper",
        verb,
    ]
}

/// Board #75: a new operator's first privileged action showed "failed: We
/// trust you have received the usual lecture…" instead of the real cause.
#[test]
fn sudos_lecture_never_stands_in_for_the_error() {
    let host = fake(vec![
        (
            helper("setup-status"),
            out(
                1,
                "",
                &format!("{LECTURE}sudo: 1 incorrect password attempt\n"),
            ),
        ),
        (
            helper("unit-enable"),
            out(
                1,
                "",
                &format!(
                    "{LECTURE}Sorry, user alice is not allowed to execute \
                     '/usr/bin/openvibes-admin helper unit-enable ingest' as root on metabox.\n"
                ),
            ),
        ),
        (
            helper("unit-disable"),
            out(
                1,
                "",
                &format!("{LECTURE}openvibes-admin helper: database unavailable\n"),
            ),
        ),
        (helper("setup-step"), out(0, "done\tok\n", LECTURE)),
        (vec!["/usr/bin/logger"], out(0, "", "")),
    ]);
    let password = Secret::new("pw".into());
    assert_eq!(
        host.privileged(Privileged::SetupStatus, &password),
        Err(HostError::WrongPassword)
    );
    assert_eq!(
        host.privileged(Privileged::UnitEnable(Unit::Ingest), &password),
        Err(HostError::NotSudoer)
    );
    assert_eq!(
        host.privileged(Privileged::UnitDisable(Unit::Ingest), &password),
        Err(HostError::Failed(
            "openvibes-admin helper: database unavailable".into()
        ))
    );
    assert_eq!(
        host.privileged(Privileged::SetupStep(Step::Ca), &password)
            .unwrap(),
        "done\tok\n"
    );
}

#[test]
fn a_users_home_comes_from_getent_with_etc_passwd_as_fallback() {
    // A directory user (SSSD, FreeIPA, LDAP) is not in /etc/passwd; getent
    // finds it through NSS.
    let host = fake(vec![(
        vec!["/usr/bin/getent", "passwd", "--", "ipa.alice"],
        out(
            0,
            "ipa.alice:*:1234:1234:Alice:/home/ipa.alice:/bin/bash\n",
            "",
        ),
    )]);
    assert_eq!(
        host.user_home("ipa.alice").as_deref(),
        Some("/home/ipa.alice")
    );
    assert_eq!(
        host.runner.calls.borrow()[0],
        ["/usr/bin/getent", "passwd", "--", "ipa.alice"]
    );
    // getent fails or is missing: /etc/passwd still knows root.
    let host = fake(Vec::new());
    assert_eq!(host.user_home("root").as_deref(), Some("/root"));
    assert_eq!(host.user_home("no-such-user-ov"), None);
}

#[test]
fn passwd_home_takes_only_the_named_users_absolute_home() {
    let passwd = "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000:Alice:/home/alice:/bin/bash\n\
                  bob:x:1001:1001:Bob:relative:/bin/sh\n";
    assert_eq!(
        platform_host::passwd_home(passwd, "alice").as_deref(),
        Some("/home/alice")
    );
    assert_eq!(platform_host::passwd_home(passwd, "bob"), None);
    assert_eq!(platform_host::passwd_home(passwd, "carol"), None);
    // A prefix of a name is not the name.
    assert_eq!(platform_host::passwd_home(passwd, "ali"), None);
}
