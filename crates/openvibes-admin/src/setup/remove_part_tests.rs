//! Removing one optional part: its data and account go, nothing else.
use platform_host::{RemoveStep, StepState};

use super::{RemoveArgs, run, tests::args};
use crate::setup::{
    fake::{Fake, plan},
    plan::Component::*,
};

const BASE: &str = "development_listen = \"127.0.0.1:8443\"\nhealth_listen = \"127.0.0.1:8444\"\n";
const FOREIGN: &str = "[assistant]\nenabled = true\nprofile = \"large\"\n[assistant.backend]\nurl = \"https://gpu.lan/v1\"\nmodel = \"m\"\n";

fn purge(fake: &Fake, plan: &crate::setup::plan::Plan, args: &RemoveArgs) -> StepState {
    run(&fake.ctx(plan), RemoveStep::Purge, args)
}

fn seed(fake: &Fake) {
    fake.answer(
        &["/usr/bin/rpm", "-q", "--quiet", "openvibes-console"],
        0,
        "",
    );
    fake.answer(&["/usr/sbin/userdel"], 0, "");
    fake.answer(&["/usr/sbin/groupdel"], 0, "");
    fake.answer(&["/usr/bin/systemctl", "try-restart"], 0, "");
    for file in [
        "/etc/openvibes-agent/agent.toml",
        "/var/lib/openvibes-agent/queue",
        "/var/lib/openvibes-llm/model.gguf",
        "/etc/openvibes/llm-api-key",
    ] {
        fake.file(file, "x");
    }
}

#[test]
fn removing_the_agent_removes_its_data_and_account() {
    let fake = Fake::new("part-agent");
    seed(&fake);
    let state = purge(&fake, &plan(&[Ingest]), &args(&[Agent], None));
    assert_eq!(
        state,
        StepState::Done("removed the agent's data and account".into())
    );
    assert!(!fake.root.join("etc/openvibes-agent").exists());
    assert!(!fake.root.join("var/lib/openvibes-agent").exists());
    assert_eq!(
        fake.call(&["/usr/sbin/userdel"])[1],
        "openvibes_agent",
        "{:?}",
        fake.call(&["/usr/sbin/userdel"])
    );
    assert!(fake.root.join("var/lib/openvibes-llm/model.gguf").exists());
}

#[test]
fn a_part_removal_removes_only_that_part() {
    let fake = Fake::new("part-only");
    seed(&fake);
    purge(&fake, &plan(&[Ingest, Assistant]), &args(&[Agent], None));
    assert!(fake.root.join("var/lib/openvibes-llm/model.gguf").exists());
    assert!(fake.root.join("etc/openvibes/llm-api-key").exists());
}

#[test]
fn removing_the_assistant_removes_model_key_account_and_its_console_section() {
    let fake = Fake::new("part-assistant");
    seed(&fake);
    for file in ["/etc/passwd", "/etc/group"] {
        let text = fake.text(file);
        fake.file(
            file,
            &format!("{text}openvibes-llm:x:1:1::/:/sbin/nologin\n"),
        );
    }
    let local = crate::assistant_setup::configure(BASE, &Default::default(), false).unwrap();
    fake.file("/etc/openvibes/console.toml", &local);
    let state = purge(&fake, &plan(&[Ingest]), &args(&[Assistant], None));
    assert_eq!(
        state,
        StepState::Done("removed the assistant's data, model and account".into())
    );
    assert_eq!(fake.text("/etc/openvibes/console.toml"), BASE);
    assert!(!fake.root.join("etc/openvibes/llm-api-key").exists());
    assert!(!fake.root.join("var/lib/openvibes-llm").exists());
    assert_eq!(fake.call(&["/usr/sbin/userdel"])[1], "openvibes-llm");
    assert!(fake.called(&["/usr/bin/systemctl", "try-restart", "openvibes-console"]));
    // Written by config_file::replace: a backup of the old file is left.
    assert!(fake.root.join("etc/openvibes/console.toml.bak").exists());
    assert!(fake.root.join("var/lib/openvibes-agent").exists());
}

#[test]
fn a_foreign_assistant_backend_stays() {
    let fake = Fake::new("part-foreign");
    seed(&fake);
    fake.file("/etc/openvibes/console.toml", FOREIGN);
    purge(&fake, &plan(&[Ingest]), &args(&[Assistant], None));
    assert_eq!(fake.text("/etc/openvibes/console.toml"), FOREIGN);
}

#[test]
fn removing_both_parts_joins_the_text_and_deletes_the_groups() {
    let fake = Fake::new("part-both");
    seed(&fake);
    let state = purge(&fake, &plan(&[Ingest]), &args(&[Agent, Assistant], None));
    assert_eq!(
        state,
        StepState::Done(
            "removed the agent's data and account; removed the assistant's data, model and account"
                .into()
        )
    );
    assert!(fake.called(&["/usr/sbin/groupdel", "openvibes_agent"]));
}

#[test]
fn a_keep_data_uninstall_still_keeps_everything() {
    let fake = Fake::new("part-keep");
    seed(&fake);
    let state = purge(&fake, &plan(&[Ingest]), &args(&[Ingest], None));
    assert_eq!(state, StepState::Skipped("data kept".into()));
    let state = purge(&fake, &plan(&[Ingest, Agent]), &args(&[Agent], None));
    assert_eq!(state, StepState::Skipped("data kept".into()));
    assert!(fake.root.join("var/lib/openvibes-agent/queue").exists());
}

#[test]
fn a_part_removal_clears_the_job_mark() {
    let fake = Fake::new("part-job");
    seed(&fake);
    let plan = plan(&[Ingest]);
    let args = args(&[Agent], None);
    for step in RemoveStep::ALL {
        let state = run(&fake.ctx(&plan), step, &args);
        assert!(state.finished(), "{step:?}: {state:?}");
    }
    assert!(!fake.root.join("run/openvibes-admin/job").exists());
}

#[test]
fn a_part_removal_leaves_no_half_done_mark_but_a_whole_uninstall_does() {
    let fake = Fake::new("part-no-mark");
    seed(&fake);
    run(
        &fake.ctx(&plan(&[Ingest])),
        RemoveStep::Stop,
        &args(&[Agent], None),
    );
    assert!(!fake.root.join("run/openvibes-admin/job").exists());
    let whole = Fake::new("whole-mark");
    seed(&whole);
    run(
        &whole.ctx(&plan(&[Ingest])),
        RemoveStep::Stop,
        &args(&[Ingest], None),
    );
    assert!(whole.root.join("run/openvibes-admin/job").exists());
}
