//! Steps 11–12: the baseline rules and the agent on this host.

use platform_host::{
    StepState,
    runner::{
        Program::{Rpm, Systemctl},
        Runner,
    },
};

use super::{Ctx, base::install, pki::ROOT_CERT, plan::Component, run::token_from};

const RULES: &str = "/usr/share/openvibes/rules";
const AGENT: &str = "/etc/openvibes-agent";
const AGENT_WAIT: u32 = 60;

/// The rule sets the rules package may carry, as `STEM.json` and
/// `STEM.key`: the baseline findings rules, always; then, when present, the
/// threat-alarm rules (rules v2, only a P14 agent runs them) and the
/// project's hardening sets (L1 from rules v5, L2 once signed), which the
/// platform switches per asset group.
const BASELINE: &str = "baseline";
const ALARMS: &str = "alarms";
const OPTIONAL: [&str; 3] = [ALARMS, "hardening-linux-l1", "hardening-linux-l2"];

/// The exec audit rule a P14 agent package ships; agent #57 on keeps it only
/// as a template and copies it here on audit-fallback hosts, so here it
/// also means "this host's agent reads kernel audit".
pub const AGENT_AUDIT_RULE: &str = "/etc/audit/rules.d/openvibes-agent.rules";
/// The template of that rule (agent #57 on, eBPF hosts included).
const AGENT_AUDIT_TEMPLATE: &str = "/usr/share/openvibes-agent/openvibes-agent.rules";

/// The local agent knows the `process_events` collector (an older one
/// refuses the name): its package ships the exec audit rule or its template.
fn p14_agent<R: Runner>(ctx: &Ctx<R>) -> bool {
    ctx.exists(AGENT_AUDIT_RULE) || ctx.exists(AGENT_AUDIT_TEMPLATE)
}

/// The `collectors` line Setup wrote before services (P15) were listed:
/// replacing the agent's default, it turned services off (v0.2.7 fix).
pub(super) const OLD_COLLECTORS: &str =
    "collectors = [\"processes\", \"packages\", \"ports\", \"process_events\"]";
pub(super) const COLLECTORS: &str =
    "collectors = [\"processes\", \"packages\", \"ports\", \"process_events\", \"services\"]";

/// The local agent knows the `services` collector (agents 0.2.0–0.2.1 refuse
/// the name and would not start): rpm says 0.2.2 or later. An rpm error or
/// a version that does not parse counts as older. Only without rpm at all
/// do files decide: 0.2.2–0.2.5 ship the owners.conf example (a %doc file),
/// 0.2.6 on the audit rule template.
pub(super) fn p15_agent<R: Runner>(ctx: &Ctx<R>) -> bool {
    match ctx
        .runner
        .run(Rpm, &["-q", "--qf", "%{VERSION}", "openvibes-agent"])
    {
        Ok(out) => out.status == 0 && version_at_least(out.stdout.trim(), [0, 2, 2]),
        Err(_) => {
            ctx.exists(AGENT_AUDIT_TEMPLATE)
                || ctx.exists("/usr/share/doc/openvibes-agent/owners.conf")
        }
    }
}

/// `MAJOR.MINOR.PATCH` (digits only) at least `min`.
fn version_at_least(version: &str, min: [u64; 3]) -> bool {
    let parts: Option<Vec<u64>> = version.split('.').map(|part| part.parse().ok()).collect();
    parts.is_some_and(|parts| parts.len() == 3 && parts[..] >= min[..])
}

/// `RULE_SET ISSUER_KEY_ID PUBLIC_KEY` from `STEM.key`.
fn set_key<R: Runner>(ctx: &Ctx<R>, stem: &str) -> Result<[String; 3], String> {
    let text = ctx.read(&format!("{RULES}/{stem}.key"))?;
    let fields: Vec<String> = text.split_whitespace().map(str::to_owned).collect();
    <[String; 3]>::try_from(fields)
        .map_err(|_| format!("{RULES}/{stem}.key: want RULE_SET ISSUER_KEY_ID PUBLIC_KEY"))
}

fn baseline_key<R: Runner>(ctx: &Ctx<R>) -> Result<[String; 3], String> {
    set_key(ctx, BASELINE)
}

/// The trust line of an optional set when the package carries it; an
/// unreadable or malformed key next to `STEM.json` is an error, as for the
/// baseline, so the rules are never silently left unpublished.
fn optional_key<R: Runner>(ctx: &Ctx<R>, stem: &str) -> Result<Option<[String; 3]>, String> {
    if ctx.exists(&format!("{RULES}/{stem}.json")) {
        set_key(ctx, stem).map(Some)
    } else {
        Ok(None)
    }
}

/// The published version of `set` (`rules list`: `SET vN keys …`).
fn published<R: Runner>(ctx: &Ctx<R>, set: &str) -> Result<Option<u64>, String> {
    Ok(ctx.as_admin(&["rules", "list"])?.lines().find_map(|line| {
        line.strip_prefix(&format!("{set} v"))?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    }))
}

/// Whether `rules list` marks `set` retired (its line ends in ` retired`).
fn retired<R: Runner>(ctx: &Ctx<R>, set: &str) -> Result<bool, String> {
    Ok(ctx
        .as_admin(&["rules", "list"])?
        .lines()
        .any(|line| line.split_whitespace().next() == Some(set) && line.ends_with(" retired")))
}

/// The version of the envelope the installed package carries, if any.
fn installed<R: Runner>(ctx: &Ctx<R>, stem: &str) -> Option<u64> {
    let text = ctx.read(&format!("{RULES}/{stem}.json")).ok()?;
    serde_json::from_str::<serde_json::Value>(&text).ok()?["rule_set_version"].as_u64()
}

/// Done while the published version is at least the installed package's,
/// so a newer package (Update, or dnf) makes the step Todo and Repair or
/// Update publishes it.
pub fn rules_check<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    if !ctx.plan.has(Component::Rules) {
        return Ok(StepState::Skipped("baseline rules not chosen".into()));
    }
    let set = baseline_key(ctx).map_or_else(|_| "baseline".to_owned(), |[set, _, _]| set);
    // An admin who retired the set stopped serving it on purpose, and
    // `rules publish` refuses a retired set: nothing for Repair to fix.
    if retired(ctx, &set)? {
        return Ok(StepState::Skipped(format!("rule set {set} retired")));
    }
    let current = |set: &str, stem: &str| -> Result<Option<u64>, String> {
        Ok(published(ctx, set)?
            .filter(|version| installed(ctx, stem).is_none_or(|newest| newest <= *version)))
    };
    let Some(version) = current(&set, BASELINE)? else {
        return Ok(StepState::Todo);
    };
    let mut done = format!("rule set {set} v{version} published");
    for stem in OPTIONAL {
        if let Some([set, _, _]) = optional_key(ctx, stem)?
            && !retired(ctx, &set)?
        {
            match current(&set, stem)? {
                Some(version) => done.push_str(&format!(", {set} v{version}")),
                None => return Ok(StepState::Todo),
            }
        }
    }
    Ok(StepState::Done(done))
}

pub fn rules_apply<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    if !ctx.plan.has(Component::Rules) {
        return rules_check(ctx);
    }
    if !ctx.succeeds(Rpm, &["-q", "--quiet", "openvibes-rules-baseline"]) {
        match install(ctx, &["openvibes-rules-baseline"]) {
            Ok(()) => {}
            Err(error)
                if error.contains("No match for argument")
                    || error.starts_with("no openvibes-rules-baseline package") =>
            {
                return Ok(StepState::Skipped(
                    "the baseline rules package is not available yet".into(),
                ));
            }
            Err(error) => return Err(error),
        }
    }
    let [set, issuer, key] = baseline_key(ctx)?;
    ctx.as_admin(&["rules", "trust", "add", &set, &issuer, "--", &key])?;
    ctx.as_admin(&["rules", "publish", &format!("{RULES}/{BASELINE}.json")])?;
    let mut done = format!("rule set {set} published");
    for stem in OPTIONAL {
        if let Some([set, issuer, key]) = optional_key(ctx, stem)?
            && !retired(ctx, &set)?
        {
            ctx.as_admin(&["rules", "trust", "add", &set, &issuer, "--", &key])?;
            ctx.as_admin(&["rules", "publish", &format!("{RULES}/{stem}.json")])?;
            done.push_str(&format!(", {set} published"));
        }
    }
    Ok(StepState::Done(done))
}

/// `https://localhost`, with `:PORT` unless it is the agent's default.
fn local_url(port: u16, default: u16) -> String {
    if port == default {
        "https://localhost".into()
    } else {
        format!("https://localhost:{port}")
    }
}

pub(super) fn agent_toml<R: Runner>(ctx: &Ctx<R>) -> String {
    let platform = local_url(ctx.plan.ingest_port, super::ports::INGEST_DEFAULT);
    let mut text = format!(
        "# Written by openvibes-admin setup: the agent on the platform host.\n\
         state_dir = \"/var/lib/openvibes-agent\"\n\
         platform_url = \"{platform}\"\n\
         platform_ca_file = \"/etc/openvibes-agent/platform-ca.crt\"\n\
         enrollment_token_file = \"/etc/openvibes-agent/token\"\n",
    );
    if ctx.plan.has(Component::Rules)
        && let Ok(baseline) = baseline_key(ctx)
    {
        let distribution = local_url(
            ctx.plan.distribution_port,
            super::ports::DISTRIBUTION_DEFAULT,
        );
        // Threat alarms (P14): only for an agent that knows the collector,
        // and only when the rules package carries the alarm rules.
        // (A broken alarms.key already failed the rules step.)
        let alarms = optional_key(ctx, ALARMS)
            .ok()
            .flatten()
            .filter(|_| p14_agent(ctx));
        if alarms.is_some() {
            // An explicit list replaces the agent's default: keep services.
            let collectors = if p15_agent(ctx) {
                COLLECTORS
            } else {
                OLD_COLLECTORS
            };
            text.push_str(&format!(
                "# Threat alarms: the agent's eBPF watcher, or kernel audit (auditd) as the fallback.\n\
                 {collectors}\n",
            ));
        }
        text.push_str(&format!("distribution_url = \"{distribution}\"\n"));
        for [set, issuer, key] in std::iter::once(baseline).chain(alarms) {
            text.push_str(&format!(
                "\n[[rule_sets]]\nid = \"{set}\"\n\
                 trusted_keys = [{{ issuer_key_id = \"{issuer}\", public_key = \"{key}\" }}]\n"
            ));
        }
    }
    text
}

/// Fedora's default audit rules switch syscall auditing off, so alarms
/// configured for this host's agent could never fire: a note for the
/// Agent step's line (empty when alarms are off or auditing is on).
fn audit_note<R: Runner>(ctx: &Ctx<R>) -> &'static str {
    // Only an agent reading kernel audit is silenced by it: on an eBPF
    // host the exec rule is not in rules.d (agent #57).
    let off = agent_toml(ctx).contains("process_events")
        && ctx.exists(AGENT_AUDIT_RULE)
        && ctx
            .read(super::AUDIT_RULES)
            .is_ok_and(|rules| super::audit_off(&rules));
    if off {
        "; but threat alarms can't fire: /etc/audit/audit.rules has `-a task,never`. \
         Comment it out in /etc/audit/rules.d/audit.rules, run `augenrules --load`; new logins and restarted services are watched, a reboot covers everything (see Health)"
    } else {
        ""
    }
}

/// Whether an agent package can be had: installed, or a plan's `--repo-dir` holding
/// one.
fn agent_available(root: &std::path::Path, repo_dir: Option<&std::path::Path>) -> bool {
    root.join("usr/bin/openvibes-agent").exists()
        || repo_dir.is_some_and(|dir| {
            std::fs::read_dir(root.join(dir.strip_prefix("/").unwrap_or(dir))).is_ok_and(|dir| {
                dir.flatten().any(|entry| {
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    name.starts_with("openvibes-agent-") && name.ends_with(".rpm")
                })
            })
        })
        || std::fs::read_dir(root.join("etc/yum.repos.d")).is_ok_and(|dir| {
            dir.flatten().any(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.starts_with("openvibes") && name.ends_with(".repo")
            })
        })
}

const NO_AGENT: &str = "agent: package not available on this host (offline install); add agents from the console's Enroll page";

pub fn agent_check<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    if !ctx.plan.has(Component::Agent) {
        return Ok(StepState::Skipped("agent on this host not chosen".into()));
    }
    let configured = ctx
        .read(&format!("{AGENT}/agent.toml"))
        .is_ok_and(|text| text == agent_toml(ctx));
    Ok(
        if configured && ctx.succeeds(Systemctl, &["is-active", "--quiet", "openvibes-agent"]) {
            StepState::Done(format!(
                "the agent on this host is running{}",
                audit_note(ctx)
            ))
        } else {
            StepState::Todo
        },
    )
}

fn reporting<R: Runner>(ctx: &Ctx<R>) -> bool {
    ctx.as_admin(&["agent", "list"]).is_ok_and(|list| {
        list.lines()
            .any(|line| line.split("  ").nth(1) == Some("active"))
    })
}

pub fn agent_apply<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    if !ctx.plan.has(Component::Agent) {
        return agent_check(ctx);
    }
    if !ctx.succeeds(Rpm, &["-q", "--quiet", "openvibes-agent"]) {
        // Offline, dnf fails on unreachable metadata before it can say
        // "No match": do not ask it when nothing could supply the package.
        if !agent_available(ctx.root, ctx.plan.repo_dir.as_deref()) {
            return Ok(StepState::Skipped(NO_AGENT.into()));
        }
        match install(ctx, &["openvibes-agent"]) {
            Ok(()) => {}
            Err(error) if error.contains("No match for argument") => {
                return Ok(StepState::Skipped(NO_AGENT.into()));
            }
            Err(error) => return Err(error),
        }
    }
    let token = token_from(&ctx.as_admin(&["token", "fleet"])?)?;
    let agent = Some(("openvibes_agent", "openvibes_agent"));
    ctx.copy(ROOT_CERT, &format!("{AGENT}/platform-ca.crt"), None, 0o644)?;
    ctx.put(
        &format!("{AGENT}/token"),
        format!("{token}\n").as_bytes(),
        agent,
        0o600,
    )?;
    ctx.put(
        &format!("{AGENT}/agent.toml"),
        agent_toml(ctx).as_bytes(),
        Some(("root", "openvibes_agent")),
        0o640,
    )?;
    // Distribution first (board #111): an agent started before it answers
    // has no rules until its next fetch. Never fatal: the agent retries.
    if ctx.plan.has(Component::Distribution) {
        for _ in 0..super::run::READY_ATTEMPTS {
            if super::run::ready(ctx, platform_host::Unit::Distribution) {
                break;
            }
            ctx.pause();
        }
    }
    ctx.ok(Systemctl, &["enable", "openvibes-agent"])?;
    ctx.ok(Systemctl, &["restart", "openvibes-agent"])?;
    for _ in 0..AGENT_WAIT {
        if reporting(ctx) {
            return Ok(StepState::Done(format!(
                "the agent on this host enrolled and is reporting{}",
                audit_note(ctx)
            )));
        }
        ctx.pause();
    }
    Err(format!(
        "the agent did not show as active within {AGENT_WAIT} seconds; see journalctl -u openvibes-agent"
    ))
}

#[cfg(test)]
#[path = "fleet_tests.rs"]
mod tests;
