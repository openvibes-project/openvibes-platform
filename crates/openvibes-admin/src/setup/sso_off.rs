//! `helper sso-off`: turns single sign-on off (Maintenance › Console
//! sign-in). The CLI does the write and the audit; this only runs it as
//! `openvibes-admin` and puts the answer on one line.

use std::process::ExitCode;

use platform_host::{StepState, runner::Runner};

use super::Ctx;

/// `off`, `already off` or `not set up`, from the CLI.
pub fn sso_off<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let out = ctx
        .as_admin(&["sso", "off"])
        .map_err(|error| super::admin_reset::reason(&error))?;
    Ok(StepState::Done(out.trim().to_owned()))
}

/// `helper sso-off`: prints `done<TAB>RESULT` or `failed<TAB>WHY`.
pub fn run() -> ExitCode {
    let (_lock, plan) = match super::begin() {
        Ok(v) => v,
        Err(code) => return code,
    };
    let state = sso_off(&super::host_ctx(&plan, false)).unwrap_or_else(StepState::Failed);
    println!("{}", state.line());
    ExitCode::SUCCESS
}
