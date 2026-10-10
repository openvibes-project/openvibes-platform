//! The assistant's model step: `helper assistant-setup` (as root) downloads
//! the pinned model when it is missing, selects it and turns the model
//! server on. Skipped when the user declined the download.

use platform_host::{
    StepState,
    runner::{
        Program::{Admin, Systemctl},
        Runner,
    },
};

use super::{
    Ctx,
    plan::{Component, ModelChoice},
};

const OFF: &str = "assistant: off until its model is installed; turn the assistant on in Setup again to download it";

/// Whether `model.conf` selects a model file that exists. Read without
/// following a symlink or blocking on a FIFO (the directory is group-writable).
fn installed<R: Runner>(ctx: &Ctx<R>) -> bool {
    crate::model::read_config(&ctx.path("/var/lib/openvibes-llm/model.conf"))
        .ok()
        .and_then(|text| crate::assistant_setup::parse_env(&text).remove("OPENVIBES_LLM_MODEL"))
        .is_some_and(|file| ctx.path(&file).is_file())
}

/// The console already sends the assistant to another backend: not ours to
/// replace (that needs `--force`).
fn external<R: Runner>(ctx: &Ctx<R>) -> Result<bool, String> {
    let Ok(console) = ctx.read("/etc/openvibes/console.toml") else {
        return Ok(false);
    };
    let mut env =
        crate::assistant_setup::parse_env(&ctx.read("/etc/openvibes/llm.conf").unwrap_or_default());
    env.extend(crate::assistant_setup::parse_env(
        &crate::model::read_config(&ctx.path("/var/lib/openvibes-llm/model.conf"))
            .unwrap_or_default(),
    ));
    match crate::assistant_setup::configure(&console, &env, false) {
        Ok(_) => Ok(false),
        Err(error) if error.contains("already sends the assistant to") => Ok(true),
        Err(error) => Err(error),
    }
}

fn remove_staged(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_dir(path.parent().unwrap_or(path));
}

pub fn check<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    if !ctx.plan.has(Component::Assistant) {
        return Ok(StepState::Skipped("assistant not chosen".into()));
    }
    if external(ctx)? {
        return Ok(StepState::Skipped("using an external assistant".into()));
    }
    let present = installed(ctx);
    // Status only reads: a staged copy of an installed model (2.7 GB in the
    // way) is removed by apply, which this makes Setup run.
    if crate::model_fetch::staged_in(ctx.root).is_some() && ctx.plan.model != ModelChoice::Skip {
        // Staged by the offline installer: installed unless declined.
        return Ok(StepState::Todo);
    }
    let on = present
        && ctx.succeeds(
            Systemctl,
            &["is-enabled", "--quiet", "openvibes-llm.socket"],
        );
    // Tuned once the model server is on; a missing tuning (it was skipped or
    // failed) is retried by running the step again.
    let tuned = ctx.path("/var/lib/openvibes-llm/tuning.conf").is_file();
    Ok(if on && !tuned && ctx.plan.model != ModelChoice::Skip {
        StepState::Todo
    } else if on {
        StepState::Done("assistant on: model installed, model server enabled".into())
    } else if ctx.plan.model == ModelChoice::Skip {
        StepState::Skipped(if present {
            "assistant: off (turn it on in Setup)".into()
        } else {
            OFF.into()
        })
    } else {
        StepState::Todo
    })
}

pub fn apply<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    // The offline kit's staged model: installed as openvibes-admin (never
    // root), checked against the pin, and removed once installed. A failure
    // keeps the file.
    let staged = crate::model_fetch::staged_in(ctx.root);
    if let Some((_, path)) = &staged
        && installed(ctx)
    {
        remove_staged(path);
    }
    let staged = staged.filter(|_| !installed(ctx));
    if let Some((abs, _)) = &staged {
        let pin = crate::model_fetch::pin_or_embedded()?;
        ctx.as_admin(&[
            "assistant",
            "model",
            "install",
            abs,
            "--sha256",
            &pin.sha256,
        ])
        .map_err(|error| {
            // Only what the install said, not the command line before it.
            let marker = format!("--sha256 {}: ", pin.sha256);
            let why = error
                .split_once(&marker)
                .map_or(error.as_str(), |(_, why)| why);
            format!("the staged model was not installed: {why}")
        })?;
        // Installed: the staged copy goes now, whatever assistant-setup does.
        if let Some((_, path)) = &staged {
            remove_staged(path);
        }
    }
    // The command's own text is internal: only what it said is shown.
    let out = ctx
        .ok(Admin, &["helper", "assistant-setup"])
        .map_err(|error| {
            let prefix = format!("{} helper assistant-setup: ", Admin.path());
            error.strip_prefix(&prefix).unwrap_or(&error).to_owned()
        })?;
    let mut done = String::from("assistant on: model installed, model server enabled");
    // On, but not tuned: say why, here and in Status.
    if let Some(line) = out.lines().find(|line| line.starts_with("tuning skipped")) {
        done.push_str("; ");
        done.push_str(line);
    }
    Ok(StepState::Done(done))
}

#[cfg(test)]
mod tests {
    use platform_host::{Step, StepState};

    use crate::setup::{
        fake::{Fake, plan},
        plan::{Component::*, ModelChoice},
        run_step,
    };

    const CONF: &str = "/var/lib/openvibes-llm/model.conf";

    #[test]
    fn a_missing_model_is_fetched_by_assistant_setup() {
        let fake = Fake::new("model-fetch");
        fake.answer(&["/usr/bin/systemctl", "is-enabled"], 1, "");
        fake.answer(
            &["/usr/bin/openvibes-admin", "helper", "assistant-setup"],
            0,
            "",
        );
        let mut plan = plan(&[Ingest, Assistant]);
        plan.model = ModelChoice::Fetch;
        let state = run_step(&fake.ctx(&plan), Step::AssistantModel);
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
        assert_eq!(
            fake.call(&["/usr/bin/openvibes-admin"]),
            ["/usr/bin/openvibes-admin", "helper", "assistant-setup"]
        );
    }

    #[test]
    fn a_failed_assistant_setup_shows_only_what_it_said() {
        let fake = Fake::new("model-fail-text");
        fake.answer(&["/usr/bin/systemctl", "is-enabled"], 1, "");
        fake.fail(
            &["/usr/bin/openvibes-admin", "helper", "assistant-setup"],
            "no space left",
        );
        let mut plan = plan(&[Ingest, Assistant]);
        plan.model = ModelChoice::Fetch;
        let state = run_step(&fake.ctx(&plan), Step::AssistantModel);
        assert!(matches!(state, StepState::Failed(_)), "{state:?}");
        assert_eq!(state.detail(), "no space left");
    }

    #[test]
    fn an_unreadable_console_config_fails_the_step_instead_of_skipping_it() {
        let fake = Fake::new("model-bad-console");
        fake.file("/etc/openvibes/console.toml", "[assistant\n");
        let mut plan = plan(&[Ingest, Assistant]);
        plan.model = ModelChoice::Fetch;
        let state = run_step(&fake.ctx(&plan), Step::AssistantModel);
        assert!(matches!(state, StepState::Failed(_)), "{state:?}");
    }

    #[test]
    fn declining_leaves_the_assistant_off_without_a_command() {
        let fake = Fake::new("model-skip");
        fake.answer(&["/usr/bin/systemctl", "is-enabled"], 1, "");
        let state = run_step(&fake.ctx(&plan(&[Ingest, Assistant])), Step::AssistantModel);
        assert!(matches!(state, StepState::Skipped(_)), "{state:?}");
        assert!(
            state
                .detail()
                .contains("turn the assistant on in Setup again")
        );
        assert!(!state.detail().contains('`'));
        assert!(!fake.called(&["/usr/bin/openvibes-admin"]));
    }

    #[test]
    fn an_installed_model_with_the_server_on_is_done_and_not_fetched() {
        let fake = Fake::new("model-done");
        fake.file("/var/lib/openvibes-llm/models/m.gguf", "x");
        fake.file(
            CONF,
            "OPENVIBES_LLM_MODEL=/var/lib/openvibes-llm/models/m.gguf\n",
        );
        fake.file("/var/lib/openvibes-llm/tuning.conf", "x");
        fake.answer(&["/usr/bin/systemctl", "is-enabled"], 0, "");
        let mut plan = plan(&[Ingest, Assistant]);
        plan.model = ModelChoice::Fetch;
        let state = run_step(&fake.ctx(&plan), Step::AssistantModel);
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
        assert!(!fake.called(&["/usr/bin/openvibes-admin"]));
    }

    #[test]
    fn a_skipped_tuning_is_named_in_the_done_detail() {
        let fake = Fake::new("model-tune-skipped");
        fake.answer(&["/usr/bin/systemctl", "is-enabled"], 1, "");
        fake.answer(
            &["/usr/bin/openvibes-admin", "helper", "assistant-setup"],
            0,
            "the assistant now uses the pinned model (m)\ntuning skipped: boom; open Setup and turn the assistant on again to retry\n",
        );
        let mut plan = plan(&[Ingest, Assistant]);
        plan.model = ModelChoice::Fetch;
        let state = run_step(&fake.ctx(&plan), Step::AssistantModel);
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
        assert!(state.detail().contains("tuning skipped: boom"));
    }

    #[test]
    fn an_untuned_assistant_is_run_again_to_tune_it() {
        let fake = Fake::new("model-untuned");
        fake.file("/var/lib/openvibes-llm/models/m.gguf", "x");
        fake.file(
            CONF,
            "OPENVIBES_LLM_MODEL=/var/lib/openvibes-llm/models/m.gguf\n",
        );
        fake.answer(&["/usr/bin/systemctl", "is-enabled"], 0, "");
        fake.answer(
            &["/usr/bin/openvibes-admin", "helper", "assistant-setup"],
            0,
            "",
        );
        let mut plan = plan(&[Ingest, Assistant]);
        plan.model = ModelChoice::Fetch;
        assert!(matches!(
            super::check(&fake.ctx(&plan)),
            Ok(StepState::Todo)
        ));
        let state = run_step(&fake.ctx(&plan), Step::AssistantModel);
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
        assert!(fake.called(&["/usr/bin/openvibes-admin", "helper", "assistant-setup"]));
    }

    #[test]
    fn without_the_assistant_the_step_is_skipped() {
        let fake = Fake::new("model-none");
        let state = run_step(&fake.ctx(&plan(&[Ingest])), Step::AssistantModel);
        assert!(matches!(state, StepState::Skipped(_)));
    }

    #[test]
    fn an_external_backend_is_left_alone() {
        let fake = Fake::new("model-external");
        fake.file(
            "/etc/openvibes/console.toml",
            "[assistant]\nenabled = true\n[assistant.backend]\nurl = \"https://gpu.lan/v1\"\nmodel = \"m\"\n",
        );
        let mut plan = plan(&[Ingest, Assistant]);
        plan.model = ModelChoice::Fetch;
        let state = run_step(&fake.ctx(&plan), Step::AssistantModel);
        assert!(matches!(state, StepState::Skipped(_)), "{state:?}");
        assert!(!fake.called(&["/usr/bin/openvibes-admin"]));
    }

    #[test]
    fn an_installed_model_with_the_server_off_and_skip_does_not_say_to_install_it() {
        let fake = Fake::new("model-off");
        fake.file("/var/lib/openvibes-llm/models/m.gguf", "x");
        fake.file(
            CONF,
            "OPENVIBES_LLM_MODEL=/var/lib/openvibes-llm/models/m.gguf\n",
        );
        fake.answer(&["/usr/bin/systemctl", "is-enabled"], 1, "");
        let state = run_step(&fake.ctx(&plan(&[Ingest, Assistant])), Step::AssistantModel);
        assert_eq!(state.detail(), "assistant: off (turn it on in Setup)");
    }

    fn staged_name() -> String {
        crate::model_fetch::pin_or_embedded().unwrap().file
    }

    #[test]
    fn a_staged_model_is_installed_as_the_admin_user_and_removed() {
        let fake = Fake::new("model-staged");
        let staged = format!("/var/lib/openvibes-offline/{}", staged_name());
        fake.file(&staged, "x");
        fake.answer(&["/usr/bin/systemctl", "is-enabled"], 1, "");
        fake.answer(&["/usr/sbin/runuser"], 0, "");
        fake.answer(
            &["/usr/bin/openvibes-admin", "helper", "assistant-setup"],
            0,
            "",
        );
        let mut plan = plan(&[Ingest, Assistant]);
        plan.model = ModelChoice::Fetch;
        let ctx = fake.ctx(&plan);
        assert!(matches!(super::check(&ctx), Ok(StepState::Todo)));
        let state = run_step(&ctx, Step::AssistantModel);
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
        let install = fake.call(&["/usr/sbin/runuser"]);
        assert!(install.join(" ").contains(&format!(
            "assistant model install {staged} --sha256 {}",
            crate::model_fetch::pin_or_embedded().unwrap().sha256
        )));
        assert!(fake.called(&["/usr/bin/openvibes-admin", "helper", "assistant-setup"]));
        assert!(!fake.root.join(staged.trim_start_matches('/')).exists());
    }

    #[test]
    fn a_staged_model_that_fails_the_install_is_kept_and_reported() {
        let fake = Fake::new("model-staged-bad");
        let staged = format!("/var/lib/openvibes-offline/{}", staged_name());
        fake.file(&staged, "x");
        fake.answer(&["/usr/bin/systemctl", "is-enabled"], 1, "");
        fake.fail(&["/usr/sbin/runuser"], "sha256 mismatch");
        let mut plan = plan(&[Ingest, Assistant]);
        plan.model = ModelChoice::Fetch;
        let state = run_step(&fake.ctx(&plan), Step::AssistantModel);
        assert!(matches!(state, StepState::Failed(_)), "{state:?}");
        assert_eq!(
            state.detail(),
            "the staged model was not installed: sha256 mismatch"
        );
        assert!(!fake.called(&["/usr/bin/openvibes-admin", "helper"]));
        assert!(fake.root.join(staged.trim_start_matches('/')).exists());
    }

    #[test]
    fn a_symlink_at_the_staged_path_is_ignored() {
        let fake = Fake::new("model-staged-link");
        let path = fake
            .root
            .join(format!("var/lib/openvibes-offline/{}", staged_name()));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", &path).unwrap();
        assert!(crate::model_fetch::staged_in(&fake.root).is_none());
    }

    #[test]
    fn an_explicit_skip_is_honoured_and_an_installed_model_removes_the_staged_copy() {
        let fake = Fake::new("model-staged-skip");
        let staged = format!("/var/lib/openvibes-offline/{}", staged_name());
        fake.file(&staged, "x");
        fake.answer(&["/usr/bin/systemctl", "is-enabled"], 1, "");
        let mut plan = plan(&[Ingest, Assistant]);
        plan.model = ModelChoice::Skip;
        assert!(matches!(
            super::check(&fake.ctx(&plan)),
            Ok(StepState::Skipped(_))
        ));
        assert!(fake.root.join(staged.trim_start_matches('/')).exists());
        fake.file("/var/lib/openvibes-llm/models/m.gguf", "x");
        fake.file(
            CONF,
            "OPENVIBES_LLM_MODEL=/var/lib/openvibes-llm/models/m.gguf\n",
        );
        // Status only reads; with the model chosen, apply removes the copy.
        let _ = super::check(&fake.ctx(&plan));
        assert!(fake.root.join(staged.trim_start_matches('/')).exists());
        plan.model = ModelChoice::Fetch;
        fake.answer(
            &["/usr/bin/openvibes-admin", "helper", "assistant-setup"],
            0,
            "",
        );
        let _ = super::apply(&fake.ctx(&plan));
        assert!(!fake.root.join(staged.trim_start_matches('/')).exists());
    }
}
