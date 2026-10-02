//! The root side of Setup (admin TUI spec §6): each step's check and
//! action, run by `helper setup-step` (the TUI, through sudo) and
//! `setup --quick` (as root). Every step checks first, so re-running is
//! safe and resumes.

mod backup;
mod base;
#[cfg(test)]
mod command_tests;
mod console;
#[cfg(test)]
mod fake;
mod fleet;
pub(crate) mod pki;
#[cfg(test)]
mod pki_tests;
pub mod plan;
#[cfg(test)]
mod plan_tests;
pub(crate) mod ports;
#[cfg(test)]
mod ports_tests;
pub mod remove;
mod run;
#[cfg(test)]
mod run_tests;
mod system;
pub mod update;

use std::{path::Path, process::ExitCode, time::Duration};

use plan::{Plan, PlanArgs};
use platform_host::{
    RemoveStep, Step, StepState, UpdateStep,
    runner::{Runner, SystemRunner},
};

pub use system::{Ctx, lock};

pub(crate) use pki::fingerprint;
pub(crate) use run::token_from;

/// Where the baseline rules package puts its trust line.
pub const BASELINE_KEY: &str = "/usr/share/openvibes/rules/baseline.key";
/// The threat-alarm rule set's trust line (rules v2 and later).
pub const ALARMS_KEY: &str = "/usr/share/openvibes/rules/alarms.key";
/// The site key's trust lines (`site` and `site-alarms`), saved by Setup
/// from `openvibes-signer seed` (board #107); public, 0644.
pub const SITE_KEY: &str = "/etc/openvibes/site-rules.trust";

/// The one line that installs and enrolls an agent (releases spec §5), with
/// `--rules SET,ISSUER,KEY` when the platform has the baseline rules, so the
/// agent trusts the same key the platform published with. `ports` are
/// (ingest, distribution); each is named only when it is not the default,
/// so a default platform prints the line every installer accepts.
pub fn agent_install_command(
    platform: &str,
    (ingest, distribution): (u16, u16),
    token: &str,
    fingerprint: &str,
    rules: Option<&str>,
    alarm_rules: Option<&str>,
) -> String {
    let platform = if ingest == ports::INGEST_DEFAULT {
        platform.to_owned()
    } else {
        format!("{platform}:{ingest}")
    };
    let rules = rules.map_or_else(String::new, |rules| {
        if distribution == ports::DISTRIBUTION_DEFAULT {
            format!(" --rules {rules}")
        } else {
            format!(" --rules {rules} --distribution-port {distribution}")
        }
    });
    // The installer adds the alarm rules (and process_events) only for a
    // P14 agent, and only with --rules (they share the distribution URL).
    let alarms = match (rules.is_empty(), alarm_rules) {
        (false, Some(alarms)) => format!(" --alarm-rules {alarms}"),
        _ => String::new(),
    };
    format!(
        "curl -fsSL https://openvibes-project.github.io/install.sh | sudo sh -s -- \
         --agent --platform {platform} --token {token} --ca-sha256 {fingerprint}{rules}{alarms}"
    )
}

/// `--rules` for the install line: the package's trust line, only while the
/// platform serves its set with a bundle signed by that same key, so remote
/// agents are never told to fetch what they cannot verify.
pub fn published_rules_arg(key_line: &str, served: &[Served]) -> Option<String> {
    let [set, issuer, key] = key_line.split_whitespace().collect::<Vec<_>>()[..] else {
        return None;
    };
    served
        .iter()
        .any(|s| s.set == set && s.issuer == issuer && s.key == key)
        .then(|| rules_arg(key_line))
        .flatten()
}

/// A rule set the platform serves: its current, non-retired bundle's issuer
/// and that issuer's active trusted key (base64url). Remote agents get
/// `--rules` only when baseline.key names exactly this, so they can verify
/// what they fetch.
#[derive(Debug)]
pub struct Served {
    pub set: String,
    pub issuer: String,
    pub key: String,
}

/// The `agent.toml` lines for the site's own rule sets (board #107, D5),
/// from the saved trust lines: an agent installed with `--rules` (so it
/// has a `distribution_url`) gets them pasted in. No `restricted` key, so
/// the agent restricts both sets. `None` unless both lines are valid.
pub fn site_rules_block(trust: &str) -> Option<String> {
    let mut block = String::new();
    for set in ["site", "site-alarms"] {
        let line = trust
            .lines()
            .find(|line| line.split_whitespace().next() == Some(set))?;
        let arg = rules_arg(line)?;
        let [_, issuer, key] = arg.split(',').collect::<Vec<_>>()[..] else {
            return None;
        };
        block.push_str(&format!(
            "[[rule_sets]]\nid = \"{set}\"\ntrusted_keys = [{{ issuer_key_id = \"{issuer}\", public_key = \"{key}\" }}]\n"
        ));
    }
    Some(block)
}

/// `SET,ISSUER,KEY` from a `baseline.key` line, or `None` when any part has
/// characters outside identifiers and base64url (nothing to quote).
pub fn rules_arg(key_line: &str) -> Option<String> {
    let fields: Vec<&str> = key_line.split_whitespace().collect();
    let [set, issuer, key] = fields.as_slice() else {
        return None;
    };
    let id = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".:_-".contains(&b))
    };
    let key_ok = key.len() == 43
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    (id(set) && id(issuer) && key_ok).then(|| format!("{set},{issuer},{key}"))
}

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
    let plan = match load_plan() {
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

/// Install and repair wait while an update or uninstall is half done.
fn setup_guard() -> Result<(), ExitCode> {
    system::job_guard(Path::new("/"), "setup").map_err(|error| {
        eprintln!("openvibes-admin: {error}");
        ExitCode::FAILURE
    })
}

/// Loads the plan and holds the run lock; prints the error otherwise.
fn begin() -> Result<(std::fs::File, Plan), ExitCode> {
    let lock = system::lock(Path::new("/")).map_err(|error| {
        eprintln!("openvibes-admin: {error}");
        ExitCode::FAILURE
    })?;

    let plan = load_plan().map_err(|error| {
        eprintln!("openvibes-admin: {error}");
        ExitCode::FAILURE
    })?;
    Ok((lock, plan))
}

/// The plan; one from before the port choices is saved with the ports its
/// services use (#76), so the TUI, which reads setup.toml, shows them too.
fn load_plan() -> Result<Plan, String> {
    let (plan, filled) = Plan::load_filled(Path::new("/"))?;
    if filled {
        plan.save(Path::new("/"))?;
    }
    Ok(plan)
}

/// `helper setup-step STEP [--repair]`.
pub fn step(step: Step, repair: bool) -> ExitCode {
    let (_lock, plan) = match begin() {
        Ok(v) => v,
        Err(code) => return code,
    };
    if let Err(code) = setup_guard() {
        return code;
    }
    println!("{}", run_step(&host_ctx(&plan, repair), step).line());
    ExitCode::SUCCESS
}

/// `helper update-step STEP …`.
pub fn update(step: UpdateStep, args: &update::UpdateArgs) -> ExitCode {
    let (_lock, plan) = match begin() {
        Ok(v) => v,
        Err(code) => return code,
    };
    println!(
        "{}",
        update::run(&host_ctx(&plan, false), step, args).line()
    );
    ExitCode::SUCCESS
}

/// `helper remove-step STEP …`.
pub fn remove(step: RemoveStep, args: &remove::RemoveArgs) -> ExitCode {
    let (_lock, plan) = match begin() {
        Ok(v) => v,
        Err(code) => return code,
    };
    println!(
        "{}",
        remove::run(&host_ctx(&plan, false), step, args).line()
    );
    ExitCode::SUCCESS
}

fn root_or_exit() -> Result<(), ExitCode> {
    if crate::helper::effective_uid().as_deref() == Some("0") {
        Ok(())
    } else {
        eprintln!("openvibes-admin: setup must run as root");
        Err(ExitCode::from(1))
    }
}

/// Prints one line per step; exit 0 when all finished, 3 waiting, 1 failed.
fn report(results: impl Iterator<Item = (&'static str, StepState)>) -> ExitCode {
    for (title, state) in results {
        println!("{title}: {} {}", state.label(), state.detail());
        if !state.finished() {
            return ExitCode::from(if matches!(state, StepState::Waiting(_)) {
                3
            } else {
                1
            });
        }
    }
    ExitCode::SUCCESS
}

/// `setup --repair`.
/// `setup --repair [--console-port N] [--ingest-port N] [--distribution-port N]
/// [--move-agent-ports]`: given ports go into the plan first (#61), then
/// every step is checked. Moving an agent port needs `move_agent_ports`:
/// agents enrolled from other hosts keep calling the old one.
pub fn repair_all(
    ports: (Option<u16>, Option<u16>, Option<u16>),
    move_agent_ports: bool,
) -> ExitCode {
    if let Err(code) = root_or_exit() {
        return code;
    }
    let (_lock, plan) = match begin() {
        Ok(v) => v,
        Err(code) => return code,
    };
    let old = plan.clone();
    let plan = if ports == (None, None, None) {
        plan
    } else {
        let plan = match plan.with_ports(ports.0, ports.1, ports.2) {
            Ok(plan) => plan,
            Err(error) => {
                eprintln!("openvibes-admin: {error} (nothing changed)");
                return ExitCode::from(2);
            }
        };
        let moved = ports::moved_agent_ports(&old, &plan);
        if !moved.is_empty() && !move_agent_ports {
            for (what, from, to) in &moved {
                eprintln!(
                    "openvibes-admin: moving {what} from {from} to {to} leaves agents on other \
                     hosts calling {from}; add --move-agent-ports, then re-run the line from \
                     `openvibes-admin agent command` on each of them (nothing changed)"
                );
            }
            return ExitCode::from(2);
        }
        // Checked before the plan is saved: a taken port changes nothing.
        if let Err(error) =
            ports::check(&host_ctx(&plan, true)).and_then(|_| plan.save(Path::new("/")))
        {
            eprintln!("openvibes-admin: {error} (nothing changed)");
            return ExitCode::FAILURE;
        }
        for (what, from, to) in moved {
            println!(
                "Agents: {what} moved from {from} to {to}; agents on other hosts still call \
                 {from}: re-run the line from `openvibes-admin agent command` on each of them"
            );
        }
        plan
    };
    if let Err(code) = setup_guard() {
        return code;
    }
    let ctx = host_ctx(&plan, true);
    let states: Vec<_> = Step::ALL
        .into_iter()
        .map(|step| (step.title(), run_step(&ctx, step)))
        .collect();
    // Old ports close only once every step worked: until then the services
    // may still listen there.
    if states
        .iter()
        .all(|(_, state)| matches!(state, StepState::Done(_) | StepState::Skipped(_)))
    {
        match ports::close_old(&ctx, &old) {
            Ok((closed, kept)) => {
                if !closed.is_empty() {
                    println!("Firewall: closed {}", closed.join(" "));
                }
                for line in kept {
                    println!("Firewall: {line}");
                }
            }
            Err(error) => eprintln!("openvibes-admin: {error}"),
        }
    }
    report(states.into_iter())
}

/// `setup --update [--backup PATH] [--repo-dir DIR]`.
pub fn update_all(args: &update::UpdateArgs) -> ExitCode {
    if let Err(error) = args.check() {
        eprintln!("openvibes-admin: {error}");
        return ExitCode::from(2);
    }
    if let Err(code) = root_or_exit() {
        return code;
    }
    let (_lock, plan) = match begin() {
        Ok(v) => v,
        Err(code) => return code,
    };
    let ctx = host_ctx(&plan, false);
    report(
        UpdateStep::ALL
            .into_iter()
            .map(|step| (step.title(), update::run(&ctx, step, args))),
    )
}

/// `setup --uninstall --keep-data|--everything [--confirm HOST] [--backup PATH]`.
pub fn uninstall_all(
    everything: bool,
    confirm: Option<String>,
    backup: Option<std::path::PathBuf>,
) -> ExitCode {
    if let Err(code) = root_or_exit() {
        return code;
    }
    let (_lock, plan) = match begin() {
        Ok(v) => v,
        Err(code) => return code,
    };
    let args = remove::RemoveArgs {
        components: plan.components.clone(),
        backup,
        confirm: if everything { confirm } else { None },
    };
    if let Err(error) = args.check() {
        eprintln!("openvibes-admin: {error}");
        return ExitCode::from(2);
    }
    let ctx = host_ctx(&plan, false);
    report(
        RemoveStep::ALL
            .into_iter()
            .map(|step| (step.title(), remove::run(&ctx, step, &args))),
    )
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
    let _lock = match system::lock(Path::new("/")) {
        Ok(lock) => lock,
        Err(error) => {
            eprintln!("openvibes-admin: {error}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(code) = setup_guard() {
        return code;
    }
    // Before anything changes: a port another process holds stops here.
    if let Err(error) = ports::check(&host_ctx(&plan, false)) {
        eprintln!("openvibes-admin: {error} (nothing changed)");
        return ExitCode::FAILURE;
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

/// The rules auditd loads at boot (`augenrules` writes them here).
pub const AUDIT_RULES: &str = "/etc/audit/audit.rules";

/// True when `audit.rules` switches syscall auditing off for every task
/// (`-a task,never`, Fedora's default): the kernel then reports no
/// program starts, so threat alarms can never fire.
pub fn audit_off(rules: &str) -> bool {
    rules.lines().any(|line| {
        let mut words = line.split_whitespace();
        words.next() == Some("-a") && matches!(words.next(), Some("task,never" | "never,task"))
    })
}
