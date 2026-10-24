//! `helper certificates-renew`: the daily timer's run of the certificates
//! step (it renews what is within `RENEW_AT_DAYS` of expiry, and only that).

use std::{path::Path, process::ExitCode};

use platform_host::{Step, StepState, runner::Runner};

use super::{Ctx, host_ctx, load_plan, plan::Plan, replace, run_step, setup_guard, system};

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
    // A Replace a crash cut short first: its key may not match the bundle.
    let (recovered, mut failed) = match replace::finish_interrupted(ctx) {
        Ok(line) => (line, false),
        Err(error) => (Some(format!("failed\t{error}")), true),
    };
    let state = run_step(ctx, Step::Certificates);
    let mut text = state.line();
    failed |= matches!(state, StepState::Failed(_) | StepState::Waiting(_));
    // Not after a failed reissue: ingest may still issue from the old one.
    let dropped = match state {
        StepState::Done(_) => replace::drop_previous(ctx),
        _ => Ok(None),
    };
    match dropped {
        Ok(Some(line)) => text = format!("{text}\n{line}"),
        Ok(None) => {}
        Err(error) => {
            text = format!("{text}\nfailed\t{error}");
            failed = true;
        }
    }
    if let Some(line) = recovered {
        text = format!("{line}\n{text}");
    }
    let code = if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    };
    (text, code)
}

/// The plan under `root`, or the log text and exit code. The unit runs
/// only once `setup.toml` exists, so one it cannot read is a failure.
fn renew_plan(root: &Path) -> Result<Plan, (String, ExitCode)> {
    load_plan(root).map_err(|error| (format!("openvibes-admin: {error}"), ExitCode::FAILURE))
}

/// `helper certificates-renew`, run as root by the timer.
pub fn renew() -> ExitCode {
    let locked = system::lock(Path::new("/"));
    if let Some((text, code)) = renew_gate(&locked) {
        println!("{text}");
        return code;
    }
    let plan = match renew_plan(Path::new("/")) {
        Ok(plan) => plan,
        Err((text, code)) => {
            println!("{text}");
            return code;
        }
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
