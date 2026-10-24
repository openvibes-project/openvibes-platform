//! `helper certificates-renew`: the daily timer's run of the certificates
//! step (it renews what is within `RENEW_AT_DAYS` of expiry, and only that).

use std::{path::Path, process::ExitCode};

use platform_host::{Step, StepState, runner::Runner};

use super::{Ctx, host_ctx, load_plan, pki, run_step, setup_guard, system};

/// A held Setup lock is no failure: that run changes the certificates or
/// the timer comes again tomorrow. Any other lock error is.
fn renew_gate<T>(locked: &Result<T, String>) -> Option<(String, ExitCode)> {
    match locked {
        Ok(_) => None,
        Err(error) if error.starts_with("another Setup run is in progress") => Some((
            "certificate renewal skipped: another Setup run is in progress".into(),
            ExitCode::SUCCESS,
        )),
        Err(error) => Some((format!("openvibes-admin: {error}"), ExitCode::FAILURE)),
    }
}

/// The step, then the old intermediate's removal; the log text and exit code.
fn renew_run<R: Runner>(ctx: &Ctx<R>) -> (String, ExitCode) {
    let state = run_step(ctx, Step::Certificates);
    let mut text = state.line();
    let mut failed = matches!(state, StepState::Failed(_) | StepState::Waiting(_));
    match pki::drop_previous(ctx) {
        Ok(Some(line)) => text = format!("{text}\n{line}"),
        Ok(None) => {}
        Err(error) => {
            text = format!("{text}\nfailed\t{error}");
            failed = true;
        }
    }
    let code = if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    };
    (text, code)
}

/// `helper certificates-renew`, run as root by the timer.
pub fn renew() -> ExitCode {
    let locked = system::lock(Path::new("/"));
    if let Some((text, code)) = renew_gate(&locked) {
        println!("{text}");
        return code;
    }
    let Ok(plan) = load_plan() else {
        println!("certificate renewal skipped: OpenVIBES is not set up on this host");
        return ExitCode::SUCCESS;
    };
    if let Err(code) = setup_guard() {
        return code;
    }
    let (text, code) = renew_run(&host_ctx(&plan, true));
    println!("{text}");
    code
}

#[cfg(test)]
#[path = "renew_tests.rs"]
mod tests;
