//! Removing one optional part (the agent or the assistant) after the plan
//! no longer lists it: its data and accounts go with it, nothing else.
//! Split from `remove.rs` (size).

use platform_host::{
    StepState,
    runner::{
        Program::{Groupdel, Systemctl, Userdel},
        Runner,
    },
};

use super::{Ctx, remove_file_or_dir};
use crate::setup::plan::{Component, Plan};

const CONSOLE: &str = "/etc/openvibes/console.toml";

/// Only the agent and/or assistant, none of them still in the plan.
pub(super) fn is_part_removal(plan: &Plan, components: &[Component]) -> bool {
    !components.is_empty()
        && components
            .iter()
            .all(|c| matches!(c, Component::Agent | Component::Assistant) && !plan.has(*c))
}

fn account<R: Runner>(ctx: &Ctx<R>, name: &str) -> Result<(), String> {
    let has = |file: &str| {
        ctx.read(file)
            .is_ok_and(|text| text.lines().any(|l| l.starts_with(&format!("{name}:"))))
    };
    if has("/etc/passwd") {
        ctx.ok(Userdel, &[name])?;
    }
    if has("/etc/group") {
        // userdel already removed a user's own group on most hosts.
        let _ = ctx.ok(Groupdel, &[name]);
    }
    Ok(())
}

fn wipe<R: Runner>(ctx: &Ctx<R>, paths: &[&str]) -> Result<(), String> {
    paths
        .iter()
        .try_for_each(|path| remove_file_or_dir(&ctx.path(path)))
}

/// The console's `[assistant]` section, when it is the local one. Written
/// like `assistant_setup` does: owner and mode kept, validated, a `.bak`.
fn console_section<R: Runner>(ctx: &Ctx<R>) -> Result<(), String> {
    let Ok(text) = ctx.read(CONSOLE) else {
        return Ok(());
    };
    match crate::assistant_setup::unconfigure(&text)? {
        Some(updated) => crate::config_file::replace(
            &ctx.path("/etc/openvibes"),
            platform_host::Service::Console,
            &updated,
        ),
        None => Ok(()),
    }
}

pub(super) fn purge<R: Runner>(
    ctx: &Ctx<R>,
    components: &[Component],
) -> Result<StepState, String> {
    let mut done = Vec::new();
    if components.contains(&Component::Agent) {
        wipe(ctx, &["/etc/openvibes-agent", "/var/lib/openvibes-agent"])?;
        account(ctx, "openvibes_agent")?;
        done.push("removed the agent's data and account");
    }
    if components.contains(&Component::Assistant) {
        // The console stops pointing at the model before the model goes.
        console_section(ctx)?;
        wipe(
            ctx,
            &["/var/lib/openvibes-llm", "/etc/openvibes/llm-api-key"],
        )?;
        account(ctx, "openvibes-llm")?;
        // Every run, so Try again after a failed restart restarts.
        if super::installed(ctx, "openvibes-console") {
            ctx.ok(Systemctl, &["try-restart", "openvibes-console"])?;
        }
        done.push("removed the assistant's data, model and account");
    }
    Ok(StepState::Done(done.join("; ")))
}
