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
fn external<R: Runner>(ctx: &Ctx<R>) -> bool {
    let Ok(console) = ctx.read("/etc/openvibes/console.toml") else {
        return false;
    };
    let mut env =
        crate::assistant_setup::parse_env(&ctx.read("/etc/openvibes/llm.conf").unwrap_or_default());
    env.extend(crate::assistant_setup::parse_env(
        &crate::model::read_config(&ctx.path("/var/lib/openvibes-llm/model.conf"))
            .unwrap_or_default(),
    ));
    crate::assistant_setup::configure(&console, &env, false).is_err()
}

pub fn check<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    if !ctx.plan.has(Component::Assistant) {
        return Ok(StepState::Skipped("assistant not chosen".into()));
    }
    if external(ctx) {
        return Ok(StepState::Skipped("using an external assistant".into()));
    }
    let present = installed(ctx);
    // A model the offline installer staged is installed whatever was chosen.
    if !present && crate::model_fetch::staged_in(ctx.root).is_some() {
        return Ok(StepState::Todo);
    }
    let on = present
        && ctx.succeeds(
            Systemctl,
            &["is-enabled", "--quiet", "openvibes-llm.socket"],
        );
    Ok(if on {
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
    let staged = crate::model_fetch::staged_in(ctx.root).filter(|_| !installed(ctx));
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
        .map_err(|error| format!("the staged model was not installed ({error})"))?;
    }
    ctx.ok(Admin, &["helper", "assistant-setup"])?;
    if let Some((_, path)) = staged {
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(path.parent().unwrap_or(&path));
    }
    Ok(StepState::Done(
        "assistant on: model installed, model server enabled".into(),
    ))
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
        fake.answer(&["/usr/bin/systemctl", "is-enabled"], 0, "");
        let mut plan = plan(&[Ingest, Assistant]);
        plan.model = ModelChoice::Fetch;
        let state = run_step(&fake.ctx(&plan), Step::AssistantModel);
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
        assert!(!fake.called(&["/usr/bin/openvibes-admin"]));
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
        let plan = plan(&[Ingest, Assistant]); // Skip: staged overrides it
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
        assert!(state.detail().contains("staged model was not installed"));
        assert!(!fake.called(&["/usr/bin/openvibes-admin", "helper"]));
        assert!(fake.root.join(staged.trim_start_matches('/')).exists());
    }
}
