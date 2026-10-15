use platform_host::{Step, StepState};

use super::rules_check;
use crate::setup::{
    fake::{Fake, plan},
    plan::Component::*,
    run_step,
};

/// #84: the console's "Enroll a host" steps use the paths and owner
/// this step (and the agent package) uses, so a hand enrollment works.
#[test]
fn the_console_enrollment_steps_match_the_packaged_agent() {
    let panel = include_str!("../../../openvibes-console/web/src/panels/admin/EnrollmentTokenPanel.tsx");
    for want in [
        format!("{}/agent.toml", super::AGENT),
        format!("{}/platform-ca.crt", super::AGENT),
        format!(
            "-o openvibes_agent -g openvibes_agent -m 0600 /dev/stdin {}/token",
            super::AGENT
        ),
        super::ROOT_CERT.to_owned(),
        "systemctl restart openvibes-agent".to_owned(),
    ] {
        assert!(panel.contains(&want), "the console snippet lacks {want}");
    }
    assert!(!panel.contains("/etc/openvibes/agent.toml"));
    assert!(!panel.contains("/etc/openvibes/enrollment-token"));
}

const ADMIN: [&str; 5] = [
    "/usr/sbin/runuser",
    "-u",
    "openvibes-admin",
    "--",
    "/usr/bin/openvibes-admin",
];
const TOKEN: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
const KEY: &str = "baseline org.rules AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn admin(rest: &[&str]) -> Vec<&'static str> {
    ADMIN
        .iter()
        .chain(rest)
        .map(|s| &*Box::leak((*s).to_owned().into_boxed_str()))
        .collect()
}

#[test]
fn rules_are_skipped_until_their_package_exists() {
    let fake = Fake::new("rules-missing");
    fake.answer(&admin(&["rules", "list"]), 0, "");
    fake.answer(&["/usr/bin/rpm"], 1, "");
    std::fs::create_dir_all(fake.root.join("srv/rpms")).unwrap();
    let mut plan = plan(&[Ingest, Distribution, Rules]);
    plan.repo_dir = Some("/srv/rpms".into());
    let state = run_step(&fake.ctx(&plan), Step::Rules);
    assert!(matches!(state, StepState::Skipped(_)), "{state:?}");
}

#[test]
fn rules_are_trusted_and_published() {
    let fake = Fake::new("rules");
    fake.answer(&admin(&["rules", "list"]), 0, "");
    fake.answer(
        &["/usr/bin/rpm", "-q", "--quiet", "openvibes-rules-baseline"],
        0,
        "",
    );
    fake.file(
        "/usr/share/openvibes/rules/baseline.key",
        &format!("{KEY}\n"),
    );
    fake.answer(&admin(&["rules", "trust", "add"]), 0, "trusted\n");
    fake.answer(&admin(&["rules", "publish"]), 0, "published baseline v1\n");
    let state = run_step(
        &fake.ctx(&plan(&[Ingest, Distribution, Rules])),
        Step::Rules,
    );
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
    assert_eq!(
        fake.call(&admin(&["rules", "trust"]))[5..],
        [
            "rules",
            "trust",
            "add",
            "baseline",
            "org.rules",
            "--",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ]
    );
    assert_eq!(
        fake.call(&admin(&["rules", "publish"]))[7],
        "/usr/share/openvibes/rules/baseline.json"
    );
}

/// A platform with `baseline v1` published and the package's
/// envelope at `installed`.
fn rules_at(test: &str, installed: u64) -> Fake {
    let fake = Fake::new(test);
    fake.answer(
        &admin(&["rules", "list"]),
        0,
        "baseline v1 keys 1 expires 2028-09-27T00:00:00Z\n",
    );
    fake.file(
        "/usr/share/openvibes/rules/baseline.key",
        &format!("{KEY}\n"),
    );
    fake.file(
        "/usr/share/openvibes/rules/baseline.json",
        &format!("{{\"rule_set_version\":{installed},\"payload\":\"x\"}}"),
    );
    fake
}

#[test]
fn the_published_version_is_done() {
    let fake = rules_at("rules-current", 1);
    let state = rules_check(&fake.ctx(&plan(&[Ingest, Distribution, Rules]))).unwrap();
    assert_eq!(
        state,
        StepState::Done("rule set baseline v1 published".into())
    );
}

#[test]
fn a_newer_installed_package_is_todo_and_gets_published() {
    let fake = rules_at("rules-newer", 2);
    let plan = plan(&[Ingest, Distribution, Rules]);
    assert_eq!(rules_check(&fake.ctx(&plan)).unwrap(), StepState::Todo);
    fake.answer(
        &["/usr/bin/rpm", "-q", "--quiet", "openvibes-rules-baseline"],
        0,
        "",
    );
    fake.answer(&admin(&["rules", "trust", "add"]), 0, "already trusted\n");
    fake.answer(&admin(&["rules", "publish"]), 0, "published baseline v2\n");
    let state = run_step(&fake.ctx(&plan), Step::Rules);
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
    assert_eq!(
        fake.call(&admin(&["rules", "publish"]))[7],
        "/usr/share/openvibes/rules/baseline.json"
    );
}

/// Tester: an admin who retired `baseline` chose to stop serving it; a
/// newer package must not turn the step into a failure it can never fix
/// (`rules publish` refuses a retired set).
#[test]
fn a_retired_baseline_is_not_todo_after_a_newer_package() {
    let fake = Fake::new("rules-retired");
    fake.answer(
        &admin(&["rules", "list"]),
        0,
        "baseline v1 keys 1 expires 2028-09-27T00:00:00Z retired\n",
    );
    fake.file(
        "/usr/share/openvibes/rules/baseline.key",
        &format!("{KEY}\n"),
    );
    fake.file(
        "/usr/share/openvibes/rules/baseline.json",
        "{\"rule_set_version\":2,\"payload\":\"x\"}",
    );
    let state = rules_check(&fake.ctx(&plan(&[Ingest, Distribution, Rules]))).unwrap();
    assert_ne!(
        state,
        StepState::Todo,
        "Repair would fail forever: {state:?}"
    );
}

#[test]
fn the_local_agent_is_configured_started_and_awaited() {
    let fake = Fake::new("agent");
    fake.answer(&["/usr/bin/rpm", "-q", "--quiet", "openvibes-agent"], 0, "");
    fake.answer(&["/usr/bin/systemctl", "is-active"], 3, "");
    fake.answer(
        &admin(&["token", "fleet"]),
        0,
        &format!("token id 3\ntoken {TOKEN}\n"),
    );
    fake.answer(&["/usr/bin/systemctl", "enable", "openvibes-agent"], 0, "");
    fake.answer(&["/usr/bin/systemctl", "restart", "openvibes-agent"], 0, "");
    fake.answer(
        &admin(&["agent", "list"]),
        0,
        "a1b2  active  last seen now  version 0.1.0\n",
    );
    fake.file("/etc/openvibes/pki/root.crt", "ROOT\n");
    fake.file(
        "/usr/share/openvibes/rules/baseline.key",
        &format!("{KEY}\n"),
    );
    let state = run_step(
        &fake.ctx(&plan(&[Ingest, Distribution, Rules, Agent])),
        Step::Agent,
    );
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
    assert_eq!(
        fake.text("/etc/openvibes-agent/token"),
        format!("{TOKEN}\n")
    );
    assert_eq!(fake.text("/etc/openvibes-agent/platform-ca.crt"), "ROOT\n");
    let config = fake.text("/etc/openvibes-agent/agent.toml");
    for want in [
        "platform_url = \"https://localhost\"",
        "distribution_url = \"https://localhost\"",
        "id = \"baseline\"",
        "issuer_key_id = \"org.rules\"",
    ] {
        assert!(config.contains(want), "{want} missing in\n{config}");
    }
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(fake.root.join("etc/openvibes-agent/token"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn an_agent_with_no_repository_is_skipped_without_asking_dnf() {
    let fake = Fake::new("agent-no-repo");
    fake.answer(&["/usr/bin/rpm", "-q", "--quiet", "openvibes-agent"], 1, "");
    let state = run_step(
        &fake.ctx(&plan(&[Ingest, Distribution, Rules, Agent])),
        Step::Agent,
    );
    assert!(matches!(state, StepState::Skipped(_)), "{state:?}");
    assert!(!fake.called(&["/usr/bin/dnf"]));
}

#[test]
fn an_agent_in_the_plans_repo_dir_is_installed_with_dnf() {
    let fake = Fake::new("agent-repo-dir");
    fake.answer(&["/usr/bin/rpm", "-q", "--quiet", "openvibes-agent"], 1, "");
    fake.file("/test/old/openvibes-agent-1.rpm", "");
    fake.fail(&["/usr/bin/dnf"], "stop here");
    let mut plan = plan(&[Ingest, Distribution, Rules, Agent]);
    plan.repo_dir = Some("/test/old".into());
    let state = run_step(&fake.ctx(&plan), Step::Agent);
    assert!(fake.called(&["/usr/bin/dnf"]));
    assert!(matches!(state, StepState::Failed(_)), "{state:?}");
}

#[test]
fn an_unavailable_agent_package_skips_the_step() {
    let fake = Fake::new("agent-offline");
    fake.file("/etc/yum.repos.d/openvibes.repo", "");
    fake.answer(&["/usr/bin/rpm", "-q", "--quiet", "openvibes-agent"], 1, "");
    fake.fail(&["/usr/bin/dnf"], "No match for argument: openvibes-agent");
    let state = run_step(
        &fake.ctx(&plan(&[Ingest, Distribution, Rules, Agent])),
        Step::Agent,
    );
    assert!(matches!(state, StepState::Skipped(_)), "{state:?}");
    assert!(state.detail().contains("add agents from the console"));
}

#[test]
fn the_local_agent_uses_the_chosen_ports() {
    let fake = Fake::new("agent-ports");
    fake.file(
        "/usr/share/openvibes/rules/baseline.key",
        &format!("{KEY}\n"),
    );
    let mut plan = plan(&[Ingest, Distribution, Rules, Agent]);
    plan.ingest_port = 18500;
    plan.distribution_port = 18501;
    let config = super::agent_toml(&fake.ctx(&plan));
    assert!(
        config.contains("platform_url = \"https://localhost:18500\""),
        "{config}"
    );
    assert!(
        config.contains("distribution_url = \"https://localhost:18501\""),
        "{config}"
    );
    // The defaults stay port-less, as before.
    let config = super::agent_toml(&fake.ctx(&plan_defaults()));
    assert!(
        config.contains("platform_url = \"https://localhost\"\n"),
        "{config}"
    );
}

const AGENT_VERSION: &[&str] = &[
    "/usr/bin/rpm",
    "-q",
    "--qf",
    "%{VERSION}",
    "openvibes-agent",
];

/// rpm decides (owners.conf is %doc: a nodocs host has none);
/// anything unclear counts as an agent that would refuse "services".
#[test]
fn the_agent_version_decides_services() {
    let ctx_with = |test: &str, answer: Option<(i32, &str)>| {
        let fake = Fake::new(test);
        if let Some((status, out)) = answer {
            fake.answer(AGENT_VERSION, status, out);
        }
        let plan = plan_defaults();
        super::p15_agent(&fake.ctx(&plan))
    };
    assert!(ctx_with("p15-024", Some((0, "0.2.4"))));
    assert!(ctx_with("p15-022", Some((0, "0.2.2\n"))));
    assert!(ctx_with("p15-100", Some((0, "1.0.0"))));
    assert!(!ctx_with("p15-021", Some((0, "0.2.1"))));
    assert!(!ctx_with("p15-junk", Some((0, "garbage"))));
    assert!(!ctx_with("p15-rc", Some((0, "0.2.4~rc1"))));
    assert!(!ctx_with(
        "p15-missing",
        Some((1, "package openvibes-agent is not installed"))
    ));
    assert!(!ctx_with("p15-none", None));
}

fn plan_defaults() -> crate::setup::plan::Plan {
    plan(&[Ingest, Distribution, Rules, Agent])
}

#[test]
fn an_agent_that_never_reports_fails_the_step() {
    let fake = Fake::new("agent-silent");
    fake.answer(&["/usr/bin/rpm", "-q", "--quiet", "openvibes-agent"], 0, "");
    fake.answer(&["/usr/bin/systemctl", "is-active"], 3, "");
    fake.answer(&admin(&["token", "fleet"]), 0, &format!("token {TOKEN}\n"));
    fake.answer(&["/usr/bin/systemctl"], 0, "");
    fake.answer(&admin(&["agent", "list"]), 0, "");
    fake.file("/etc/openvibes/pki/root.crt", "ROOT\n");
    let state = run_step(&fake.ctx(&plan(&[Ingest, Agent])), Step::Agent);
    assert!(
        state.detail().contains("journalctl -u openvibes-agent"),
        "{state:?}"
    );
}

/// Fedora's default audit rules (`-a task,never`) would leave the
/// alarms just configured silent: the Agent step says so.
#[test]
fn the_agent_step_warns_when_syscall_auditing_is_off() {
    let fake = rules_at("agent-audit-off", 1);
    fake.file(
        "/usr/share/openvibes/rules/alarms.key",
        &format!("{ALARMS_KEY}\n"),
    );
    fake.file("/usr/share/openvibes/rules/alarms.json", "{}");
    fake.file(
        "/etc/audit/rules.d/openvibes-agent.rules",
        "-a always,exit\n",
    );
    fake.file(
        "/etc/audit/audit.rules",
        "-D\n-a task,never\n-a always,exit\n",
    );
    fake.answer(&["/usr/bin/rpm", "-q", "--quiet", "openvibes-agent"], 0, "");
    fake.answer(&admin(&["token", "fleet"]), 0, &format!("token {TOKEN}\n"));
    fake.answer(&["/usr/bin/systemctl"], 0, "");
    fake.answer(&admin(&["agent", "list"]), 0, "agent.x  active  host\n");
    fake.file("/etc/openvibes/pki/root.crt", "ROOT\n");
    let state = run_step(&fake.ctx(&plan_defaults()), Step::Agent);
    assert!(state.detail().contains("-a task,never"), "{state:?}");
    // Without that line the step reads as before.
    fake.file("/etc/audit/audit.rules", "-D\n-a always,exit\n");
    let state = run_step(&fake.ctx(&plan_defaults()), Step::Agent);
    assert!(!state.detail().contains("never"), "{state:?}");
    // An eBPF host (agent #57: the rule is only a template there, not in
    // rules.d) does not read kernel audit: no warning even with the line.
    fake.remove("/etc/audit/rules.d/openvibes-agent.rules");
    fake.file(
        "/usr/share/openvibes-agent/openvibes-agent.rules",
        "-a always,exit\n",
    );
    fake.file(
        "/etc/audit/audit.rules",
        "-D\n-a task,never\n-a always,exit\n",
    );
    let state = run_step(&fake.ctx(&plan_defaults()), Step::Agent);
    assert!(!state.detail().contains("never"), "{state:?}");
}

const ALARMS_KEY: &str = "baseline-alarms org.rules BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

/// Rules v2 carries the alarm rules: both sets are trusted and published,
/// and the step stays Todo until the alarm set is published too.
#[test]
fn the_alarm_rule_set_is_published_beside_the_baseline() {
    let fake = rules_at("rules-alarms", 1);
    fake.file(
        "/usr/share/openvibes/rules/alarms.key",
        &format!("{ALARMS_KEY}\n"),
    );
    fake.file(
        "/usr/share/openvibes/rules/alarms.json",
        "{\"rule_set_version\":1,\"payload\":\"x\"}",
    );
    let plan = plan(&[Ingest, Distribution, Rules]);
    assert_eq!(rules_check(&fake.ctx(&plan)).unwrap(), StepState::Todo);
    fake.answer(
        &["/usr/bin/rpm", "-q", "--quiet", "openvibes-rules-baseline"],
        0,
        "",
    );
    fake.answer(&admin(&["rules", "trust", "add"]), 0, "trusted\n");
    fake.answer(&admin(&["rules", "publish"]), 0, "published\n");
    let state = run_step(&fake.ctx(&plan), Step::Rules);
    assert!(
        state.detail().contains("baseline-alarms published"),
        "{state:?}"
    );
    let published: Vec<String> = fake
        .calls
        .borrow()
        .iter()
        .filter(|call| call.get(6).is_some_and(|word| word == "publish"))
        .map(|call| call[7].clone())
        .collect();
    assert_eq!(
        published,
        [
            "/usr/share/openvibes/rules/baseline.json",
            "/usr/share/openvibes/rules/alarms.json"
        ]
    );
}

const L1_KEY: &str = "hardening-linux-l1 openvibes-1 CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";

/// Rules v5 carries hardening L1 (L2 later): every stem present is
/// trusted and published after the alarms, an absent one is skipped,
/// and the step stays Todo until each present set is published.
#[test]
fn the_hardening_sets_are_published_when_present() {
    let fake = Fake::new("rules-hardening");
    fake.answer(
        &admin(&["rules", "list"]),
        0,
        "baseline v1 keys 1\nbaseline-alarms v1 keys 1\n",
    );
    let rules = "/usr/share/openvibes/rules";
    for (stem, key) in [
        ("baseline", KEY),
        ("alarms", ALARMS_KEY),
        ("hardening-linux-l1", L1_KEY),
    ] {
        fake.file(&format!("{rules}/{stem}.key"), &format!("{key}\n"));
        fake.file(&format!("{rules}/{stem}.json"), "{\"rule_set_version\":1}");
    }
    let plan = plan(&[Ingest, Distribution, Rules]);
    assert_eq!(rules_check(&fake.ctx(&plan)).unwrap(), StepState::Todo);
    fake.answer(
        &["/usr/bin/rpm", "-q", "--quiet", "openvibes-rules-baseline"],
        0,
        "",
    );
    fake.answer(&admin(&["rules", "trust", "add"]), 0, "trusted\n");
    fake.answer(&admin(&["rules", "publish"]), 0, "published\n");
    let state = run_step(&fake.ctx(&plan), Step::Rules);
    assert!(
        state
            .detail()
            .ends_with("baseline-alarms published, hardening-linux-l1 published"),
        "{state:?}"
    );
    let calls = fake.calls.borrow();
    let trusted: Vec<&str> = calls
        .iter()
        .filter(|call| call.get(6).is_some_and(|word| word == "trust"))
        .map(|call| call[8].as_str())
        .collect();
    assert_eq!(
        trusted,
        ["baseline", "baseline-alarms", "hardening-linux-l1"]
    );
    let published: Vec<&str> = calls
        .iter()
        .filter(|call| call.get(6).is_some_and(|word| word == "publish"))
        .map(|call| call[7].as_str())
        .collect();
    assert_eq!(
        published,
        [
            "/usr/share/openvibes/rules/baseline.json",
            "/usr/share/openvibes/rules/alarms.json",
            "/usr/share/openvibes/rules/hardening-linux-l1.json"
        ]
    );
}

/// The local agent gets the alarm rules and `process_events` only when
/// its package ships the audit rule (a P14 agent); an older agent would
/// refuse the collector name and not start.
#[test]
fn only_a_p14_agent_is_configured_for_alarms() {
    let fake = rules_at("agent-alarms", 1);
    fake.file(
        "/usr/share/openvibes/rules/alarms.key",
        &format!("{ALARMS_KEY}\n"),
    );
    fake.file("/usr/share/openvibes/rules/alarms.json", "{}");
    let old = super::agent_toml(&fake.ctx(&plan_defaults()));
    assert!(!old.contains("process_events"), "{old}");
    assert!(!old.contains("baseline-alarms"), "{old}");
    fake.file(
        "/etc/audit/rules.d/openvibes-agent.rules",
        "-a always,exit\n",
    );
    // Agents 0.2.0–0.2.1 know process_events but refuse "services".
    let p14 = super::agent_toml(&fake.ctx(&plan_defaults()));
    assert!(
        p14.contains("collectors = [\"processes\", \"packages\", \"ports\", \"process_events\"]\n"),
        "{p14}"
    );
    // A P15 agent (rpm says 0.2.2 on, docs or not): the explicit list
    // keeps services (v0.2.7 fix).
    fake.answer(AGENT_VERSION, 0, "0.2.4");
    let new = super::agent_toml(&fake.ctx(&plan_defaults()));
    assert!(
        new.contains(
            "collectors = [\"processes\", \"packages\", \"ports\", \"process_events\", \"services\"]\n"
        ),
        "{new}"
    );
    assert!(new.contains("id = \"baseline-alarms\""), "{new}");
    // collectors is a top-level key: it must come before any table.
    assert!(new.find("collectors").unwrap() < new.find("[[rule_sets]]").unwrap());
    assert!(toml::from_str::<toml::Value>(&new).is_ok(), "{new}");
    // An eBPF-era agent (agent #57) ships the rule only as a template, and
    // an eBPF host has nothing in rules.d: it still gets the alarms.
    fake.remove("/etc/audit/rules.d/openvibes-agent.rules");
    fake.file(
        "/usr/share/openvibes-agent/openvibes-agent.rules",
        "-a always,exit\n",
    );
    let ebpf = super::agent_toml(&fake.ctx(&plan_defaults()));
    assert!(ebpf.contains("process_events"), "{ebpf}");
    assert!(ebpf.contains("\"services\"]"), "{ebpf}");
    // Setup's pre-0.2.7 file is not "configured": Repair rewrites it.
    fake.answer(&["/usr/bin/systemctl", "is-active"], 0, "");
    fake.file("/etc/openvibes-agent/agent.toml", &ebpf);
    let plan = plan_defaults();
    let ctx = fake.ctx(&plan);
    assert!(matches!(super::agent_check(&ctx), Ok(StepState::Done(_))));
    fake.file(
        "/etc/openvibes-agent/agent.toml",
        &ebpf.replace(super::COLLECTORS, super::OLD_COLLECTORS),
    );
    assert_eq!(super::agent_check(&ctx), Ok(StepState::Todo));
    assert!(ebpf.contains("id = \"baseline-alarms\""), "{ebpf}");
}

#[test]
fn a_malformed_alarms_key_fails_the_rules_step() {
    let fake = rules_at("rules-alarms-bad", 1);
    fake.file("/usr/share/openvibes/rules/alarms.json", "{}");
    fake.file("/usr/share/openvibes/rules/alarms.key", "only-two fields\n");
    let error = rules_check(&fake.ctx(&plan(&[Ingest, Distribution, Rules]))).unwrap_err();
    assert!(error.contains("alarms.key"), "{error}");
}
