//! Update (admin TUI spec §6.5a): backup offered, the active OpenVIBES
//! units stopped (and remembered), exactly the installed OpenVIBES packages
//! upgraded, the database migrated, the remembered units started again.

use std::path::PathBuf;

use platform_host::{
    REFRESH_OURS, StepState, Unit, UpdateStep,
    runner::{
        Program::{Dnf, Rpm, Systemctl},
        Runner,
    },
};

use super::{Ctx, backup, base::local_rpm, fleet, pg_health, run::ready};

const ACTIVE: &str = "/run/openvibes-admin/update-active";
const AGENT: &str = "openvibes-agent.service";
/// The agent was running before the update: Ready starts it once the
/// platform answers (board #111: started together, it found distribution
/// not listening and waited a scan interval without rules).
pub(super) const AGENT_PENDING: &str = "/run/openvibes-admin/update-agent";

#[derive(clap::Args, Clone, Debug, Default)]
pub struct UpdateArgs {
    /// Write a database backup here first (a new file).
    #[arg(long)]
    pub backup: Option<PathBuf>,
    /// Upgrade from this folder of package files (test builds).
    #[arg(long)]
    pub repo_dir: Option<PathBuf>,
    /// Record in backup.toml whether this run backs up first (the TUI's
    /// Back up first, remembered for next time).
    #[arg(long)]
    pub remember_choice: bool,
}

impl UpdateArgs {
    pub fn check(&self) -> Result<(), String> {
        for path in [&self.backup, &self.repo_dir].into_iter().flatten() {
            backup::check_path(path)?;
        }
        Ok(())
    }
}

fn units() -> Vec<&'static str> {
    Unit::ALL
        .iter()
        .map(|unit| unit.name())
        .chain([AGENT])
        .collect()
}

fn stop<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let running: Vec<&str> = units()
        .into_iter()
        .filter(|unit| ctx.succeeds(Systemctl, &["is-active", "--quiet", unit]))
        .collect();
    // A re-run after a failure keeps what the first run stopped; a unit
    // that is enabled but was down (a crash) comes back with the others.
    let earlier = ctx.read(ACTIVE).unwrap_or_default();
    let remembered: Vec<&str> = units()
        .into_iter()
        .filter(|unit| {
            running.contains(unit)
                || earlier.lines().any(|line| line == *unit)
                || ctx.succeeds(Systemctl, &["is-enabled", "--quiet", unit])
        })
        .collect();
    ctx.job_begin("update")?;
    ctx.put(
        ACTIVE,
        format!("{}\n", remembered.join("\n")).as_bytes(),
        None,
        0o600,
    )?;
    if !running.is_empty() {
        let mut args = vec!["stop"];
        args.extend(&running);
        ctx.ok(Systemctl, &args)?;
    }
    Ok(StepState::Done(format!(
        "stopped: {}; started again after the update: {}",
        running.join(" "),
        remembered.join(" ")
    )))
}

fn upgrade<R: Runner>(ctx: &Ctx<R>, args: &UpdateArgs) -> Result<StepState, String> {
    let installed = ctx.ok(Rpm, &["-qa", "--qf", "%{NAME}\n", "openvibes-*"])?;
    let mut names: Vec<&str> = installed
        .lines()
        .filter(|name| !name.ends_with("-debuginfo") && !name.ends_with("-debugsource"))
        .collect();
    names.sort_unstable();
    let mut argv = vec!["upgrade".to_owned(), "-y".to_owned()];
    match args.repo_dir.as_ref().or(ctx.plan.repo_dir.as_ref()) {
        None => {
            // dnf keeps repository metadata up to 48 hours; without a
            // refresh, a release from today reads as "nothing to do".
            // Only our repository is refreshed, not the whole system's.
            argv.push(REFRESH_OURS.to_owned());
            argv.extend(names.iter().map(|name| (*name).to_owned()));
        }
        Some(dir) => {
            let check = if ctx.plan.allow_unsigned_local {
                "0"
            } else {
                "1"
            };
            argv.push(format!("--setopt=localpkg_gpgcheck={check}"));
            let before = argv.len();
            for name in &names {
                match local_rpm(ctx, dir, name) {
                    Ok(file) => argv.push(file),
                    // A package the folder does not have stays as it is.
                    Err(error) if error.starts_with("no ") => {}
                    Err(error) => return Err(error),
                }
            }
            if argv.len() == before {
                // A bare `dnf upgrade` would upgrade the whole system.
                return Ok(StepState::Done(format!(
                    "nothing to upgrade: {} has none of the installed packages",
                    dir.display()
                )));
            }
        }
    }
    let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    ctx.ok(Dnf, &argv)?;
    Ok(StepState::Done(format!(
        "upgraded where newer: {}",
        names.join(" ")
    )))
}

pub(super) fn migrate<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let migrated = ctx.as_admin(&["migrate"])?;
    let maintained = ctx.as_admin(&["maintenance"])?;
    let mut detail = format!(
        "{}; {}",
        migrated.trim(),
        super::base::one_line(&maintained)
    );
    // A newer rules package arrived with the upgrade: publish it now, so
    // agents get it without a separate Repair. Never fatal: a rules problem
    // must not leave the services stopped (Health and Repair show it).
    let rules = fleet::rules_check(ctx).and_then(|state| match state {
        StepState::Todo => fleet::rules_apply(ctx).map(|done| Some(done.detail().to_owned())),
        _ => Ok(None),
    });
    match rules {
        Ok(Some(done)) => detail = format!("{detail}; {done}"),
        Ok(None) => {}
        Err(error) => detail = format!("{detail}; rules not published: {error}"),
    }
    Ok(StepState::Done(detail))
}

fn start<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let text = ctx
        .read(ACTIVE)
        .map_err(|_| "no record of the stopped services: run the Stop step first".to_owned())?;
    let active: Vec<&str> = text.lines().filter(|line| units().contains(line)).collect();
    let platform: Vec<&str> = active
        .iter()
        .copied()
        .filter(|unit| *unit != AGENT)
        .collect();
    let agent = active.contains(&AGENT);
    if !platform.is_empty() {
        let mut args = vec!["start"];
        args.extend(&platform);
        if let Err(error) = ctx.ok(Systemctl, &args) {
            // Never leave the security tool switched off: the agent runs
            // on and fetches its rules again itself (reviewer, #157).
            if agent {
                let _ = ctx.ok(Systemctl, &["start", AGENT]);
            }
            return Err(error);
        }
    }
    if agent {
        ctx.put(AGENT_PENDING, b"\n", None, 0o600)?;
    }
    let _ = std::fs::remove_file(ctx.path(ACTIVE));
    Ok(StepState::Done(format!(
        "started again: {}{}",
        platform.join(" "),
        if agent {
            " (the agent once they are ready)"
        } else {
            ""
        }
    )))
}

/// Starts the agent an earlier Update stopped and never started again (it
/// was quit between Start and Ready); run when an Update or Setup begins.
pub(super) fn resume_agent<R: Runner>(ctx: &Ctx<R>) {
    if ctx.exists(AGENT_PENDING) && ctx.ok(Systemctl, &["start", AGENT]).is_ok() {
        let _ = std::fs::remove_file(ctx.path(AGENT_PENDING));
    }
}

/// Gives up a half-done Update (an Uninstall replaces it): starts the agent
/// again and forgets the stopped-services record. Only the agent is
/// started (Stop lists it, but only Start leaves AGENT_PENDING, so an update
/// quit in between would leave it off for good); the platform units in the
/// record stay stopped: they would run on a half-migrated database.
/// `keep_agent_off`: the uninstall removes the agent, so it is not started.
pub(super) fn abandon<R: Runner>(ctx: &Ctx<R>, keep_agent_off: bool) {
    if !keep_agent_off {
        resume_agent(ctx);
    }
    if !keep_agent_off
        && ctx
            .read(ACTIVE)
            .is_ok_and(|t| t.lines().any(|l| l == AGENT))
    {
        let _ = ctx.ok(Systemctl, &["start", AGENT]);
    }
    let _ = std::fs::remove_file(ctx.path(ACTIVE));
}

fn wait_ready<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let running: Vec<Unit> = Unit::ALL
        .into_iter()
        .filter(|unit| ctx.succeeds(Systemctl, &["is-active", "--quiet", unit.name()]))
        .collect();
    let mut not_ready = None;
    let mut notes = String::new();
    'units: for unit in &running {
        let mut attempts = 0;
        while !ready(ctx, *unit) {
            attempts += 1;
            if attempts == super::run::READY_ATTEMPTS {
                let why = super::run::not_ready(ctx, *unit);
                if super::run::optional(*unit) {
                    notes.push_str(&format!("; heads-up: {why}"));
                    continue 'units;
                }
                not_ready = Some(why);
                break 'units;
            }
            ctx.pause();
        }
    }
    // The agent last, once the platform answers; started even when a
    // service isn't ready, since it fetches its rules again soon itself.
    let agent = ctx.exists(AGENT_PENDING);
    if agent {
        ctx.ok(Systemctl, &["start", AGENT])?;
        let _ = std::fs::remove_file(ctx.path(AGENT_PENDING));
    }
    if let Some(error) = not_ready {
        return Err(error);
    }
    let names: Vec<&str> = running.iter().map(|unit| unit.name()).collect();
    Ok(StepState::Done(format!(
        "ready: {}{}{notes}",
        names.join(" "),
        if agent { "; agent started" } else { "" }
    )))
}

pub fn run<R: Runner>(ctx: &Ctx<R>, step: UpdateStep, args: &UpdateArgs) -> StepState {
    if let Err(error) = super::system::job_guard(ctx.root, "update") {
        return StepState::Failed(error);
    }
    if matches!(step, UpdateStep::Backup | UpdateStep::Stop) {
        resume_agent(ctx);
    }
    let result = match step {
        UpdateStep::Backup => {
            // A removed or stopped PostgreSQL is put back before anything stops.
            let note = match pg_health::ensure(ctx) {
                Ok(note) => note,
                Err(error) => return StepState::Failed(error),
            };
            if args.remember_choice {
                // ponytail: best effort; the choice only presets a checkbox.
                let _ = backup::remember(ctx, None, Some(args.backup.is_some()));
            }
            let join = |text: String| match &note {
                Some(note) => format!("{note}; {text}"),
                None => text,
            };
            match &args.backup {
                None => Ok(StepState::Skipped(join("no backup chosen".into()))),
                Some(path) => backup::dump(ctx, path)
                    .map(|done| StepState::Done(join(done)))
                    .map_err(join),
            }
        }
        UpdateStep::Stop => stop(ctx),
        UpdateStep::Upgrade => upgrade(ctx, args),
        UpdateStep::Migrate => pg_health::ensure(ctx).and_then(|note| {
            let done = migrate(ctx)?;
            Ok(match (note, done) {
                (Some(note), StepState::Done(text)) => StepState::Done(format!("{note}; {text}")),
                (_, done) => done,
            })
        }),
        UpdateStep::Start => start(ctx),
        UpdateStep::Ready => wait_ready(ctx).inspect(|_| ctx.job_end()),
    };
    result.unwrap_or_else(StepState::Failed)
}

#[cfg(test)]
#[path = "update_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "update_migrate_tests.rs"]
mod migrate_tests;
#[cfg(test)]
#[path = "update_pg_tests.rs"]
mod pg_tests;
