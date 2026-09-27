//! The root side of Setup (admin TUI spec §6): each step's check and
//! action, run by `helper setup-step` (the TUI, through sudo) and
//! `setup --quick` (as root). Every step checks first, so re-running is
//! safe and resumes.

mod base;
#[cfg(test)]
mod fake;
pub mod plan;
mod system;

use platform_host::{Step, StepState, runner::Runner};

pub use system::Ctx;

/// Whether the step is done (a check that cannot run is `Failed`).
pub fn check<R: Runner>(ctx: &Ctx<R>, step: Step) -> StepState {
    let result = match step {
        Step::Packages => base::packages_check(ctx),
        Step::Postgres => base::postgres_check(ctx),
        // Removed in Task 8, when every step has its module.
        other => Err(format!("{} is not implemented yet", other.name())),
    };
    result.unwrap_or_else(StepState::Failed)
}

/// Does the step.
pub fn apply<R: Runner>(ctx: &Ctx<R>, step: Step) -> StepState {
    let result = match step {
        Step::Packages => base::packages_apply(ctx),
        Step::Postgres => base::postgres_apply(ctx),
        other => Err(format!("{} is not implemented yet", other.name())),
    };
    result.unwrap_or_else(StepState::Failed)
}

/// Checks the step and does it unless it is done or skipped.
pub fn run_step<R: Runner>(ctx: &Ctx<R>, step: Step) -> StepState {
    match check(ctx, step) {
        state @ (StepState::Done(_) | StepState::Skipped(_)) => state,
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
