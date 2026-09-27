//! The root side of Setup (admin TUI spec §6): each step's check and
//! action, run by `helper setup-step` (the TUI, through sudo) and
//! `setup --quick` (as root). Every step checks first, so re-running is
//! safe and resumes.

mod backup;
mod base;
mod console;
#[cfg(test)]
mod fake;
mod fleet;
mod pki;
#[cfg(test)]
mod pki_tests;
pub mod plan;
pub mod remove;
mod run;
mod system;
pub mod update;

use std::{path::Path, process::ExitCode, time::Duration};

use plan::{Plan, PlanArgs};
use platform_host::{
    Step, StepState,
    runner::{Runner, SystemRunner},
};

pub use system::Ctx;

/// Whether the step is done (a check that cannot run is `Failed`).
pub fn check<R: Runner>(ctx: &Ctx<R>, step: Step) -> StepState {
    let result = match step {
        Step::Packages => base::packages_check(ctx),
        Step::Postgres => base::postgres_check(ctx),
        Step::Operators => base::operators_check(ctx),
        Step::Database => base::database_check(ctx),
        Step::Schema => base::schema_check(ctx),
        Step::Ca => pki::ca_check(ctx),
        Step::Certificates => pki::certificates_check(ctx),
        Step::Console => console::console_check(ctx),
        Step::Services => run::services_check(ctx),
        Step::Firewall => run::firewall_check(ctx),
        Step::Rules => fleet::rules_check(ctx),
        Step::Agent => fleet::agent_check(ctx),
        Step::Ready => run::ready_check(ctx),
    };
    result.unwrap_or_else(StepState::Failed)
}

/// Does the step.
pub fn apply<R: Runner>(ctx: &Ctx<R>, step: Step) -> StepState {
    let result = match step {
        Step::Packages => base::packages_apply(ctx),
        Step::Postgres => base::postgres_apply(ctx),
        Step::Operators => base::operators_apply(ctx),
        Step::Database => base::database_apply(ctx),
        Step::Schema => base::schema_apply(ctx),
        Step::Ca => pki::ca_apply(ctx),
        Step::Certificates => pki::certificates_apply(ctx),
        Step::Console => console::console_apply(ctx),
        Step::Services => run::services_apply(ctx),
        Step::Firewall => run::firewall_apply(ctx),
        Step::Rules => fleet::rules_apply(ctx),
        Step::Agent => fleet::agent_apply(ctx),
        Step::Ready => run::ready_apply(ctx),
    };
    result.unwrap_or_else(StepState::Failed)
}

/// Checks the step and does it unless it is done or skipped.
pub fn run_step<R: Runner>(ctx: &Ctx<R>, step: Step) -> StepState {
    // Readiness always runs: it also creates the endpoint token the last
    // screen shows, and on a first install every service is ready by then.
    if step == Step::Ready {
        return apply(ctx, step);
    }
    match check(ctx, step) {
        // A failed check (e.g. a certificate about to expire) is reported,
        // not acted on.
        state @ (StepState::Done(_) | StepState::Skipped(_) | StepState::Failed(_)) => state,
        _ => apply(ctx, step),
    }
}

/// Runs every step in order until one fails or waits; true when all
/// finished.
pub fn run_all<R: Runner>(ctx: &Ctx<R>, mut report: impl FnMut(Step, &StepState)) -> bool {
    for step in Step::ALL {
        let state = run_step(ctx, step);
        report(step, &state);
        if !state.finished() {
            return false;
        }
    }
    true
}

fn host_ctx(plan: &Plan, repair: bool) -> Ctx<'_, SystemRunner> {
    Ctx {
        runner: &SystemRunner,
        plan,
        root: Path::new("/"),
        pause: Duration::from_secs(1),
        repair,
    }
}

/// `helper setup-status`: `STEP<TAB>STATE<TAB>DETAIL` per step.
pub fn status() -> ExitCode {
    let plan = match Plan::load(Path::new("/")) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("openvibes-admin helper: {error}");
            return ExitCode::FAILURE;
        }
    };
    let ctx = host_ctx(&plan, false);
    for step in Step::ALL {
        println!("{}\t{}", step.name(), check(&ctx, step).line());
    }
    ExitCode::SUCCESS
}

/// `helper setup-step STEP`: `STATE<TAB>DETAIL`; exit 0 whatever the state.
pub fn step(step: Step) -> ExitCode {
    let plan = match Plan::load(Path::new("/")) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("openvibes-admin helper: {error}");
            return ExitCode::FAILURE;
        }
    };
    println!("{}", run_step(&host_ctx(&plan, false), step).line());
    ExitCode::SUCCESS
}

/// `setup --quick`: as root, writes the plan and runs every step; exit 0
/// when all finished, 3 when a step waits (careful CA), 1 on failure.
pub fn quick(args: &PlanArgs) -> ExitCode {
    let plan = match args.plan(plan::operator_from_env()) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("openvibes-admin: {error}");
            return ExitCode::from(2);
        }
    };
    if crate::helper::effective_uid().as_deref() != Some("0") {
        eprintln!("openvibes-admin: setup --quick must run as root");
        return ExitCode::from(1);
    }
    if let Err(error) = plan.save(Path::new("/")) {
        eprintln!("openvibes-admin: {error}");
        return ExitCode::FAILURE;
    }
    let mut waiting = false;
    let finished = run_all(&host_ctx(&plan, false), |step, state| {
        waiting = matches!(state, StepState::Waiting(_));
        println!("{}: {} {}", step.title(), state.label(), state.detail());
    });
    match (finished, waiting) {
        (true, _) => ExitCode::SUCCESS,
        (false, true) => ExitCode::from(3),
        (false, false) => ExitCode::FAILURE,
    }
}
