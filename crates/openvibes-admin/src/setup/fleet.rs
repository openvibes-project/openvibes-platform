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
/// `STEM.key`: the baseline findings rules, and (from rules v2) the
/// threat-alarm rules, which only a P14 agent can run.
const BASELINE: &str = "baseline";
const ALARMS: &str = "alarms";

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

/// The alarm rule set's trust line when the package carries the set; an
/// unreadable or malformed key next to `alarms.json` is an error, as for
/// the baseline, so the rules are never silently left unpublished.
fn alarms_key<R: Runner>(ctx: &Ctx<R>) -> Result<Option<[String; 3]>, String> {
    if ctx.exists(&format!("{RULES}/{ALARMS}.json")) {
        set_key(ctx, ALARMS).map(Some)
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
    if let Some([alarms, _, _]) = alarms_key(ctx)?
        && !retired(ctx, &alarms)?
    {
        match current(&alarms, ALARMS)? {
            Some(version) => done.push_str(&format!(", {alarms} v{version}")),
            None => return Ok(StepState::Todo),
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
    if let Some([alarms, issuer, key]) = alarms_key(ctx)?
        && !retired(ctx, &alarms)?
    {
        ctx.as_admin(&["rules", "trust", "add", &alarms, &issuer, "--", &key])?;
        ctx.as_admin(&["rules", "publish", &format!("{RULES}/{ALARMS}.json")])?;
        done.push_str(&format!(", {alarms} published"));
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
        let alarms = alarms_key(ctx).ok().flatten().filter(|_| p14_agent(ctx));
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

/// Whether the form ticks "agent on this host": only when the agent package
/// is installed or an OpenVIBES repository could supply it (an offline kit
/// carries neither; agents are added from the console).
pub(crate) fn agent_by_default(root: &std::path::Path) -> bool {
    agent_available(root, None)
}

/// As above, and a plan's `--repo-dir` holding an agent package counts too.
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
mod tests {
    use platform_host::{Step, StepState};

    use super::rules_check;
    use crate::setup::{
        fake::{Fake, plan},
        plan::Component::*,
        run_step,
    };

    /// #84: the console's "Enroll a host" steps use the paths and owner
    /// this step (and the agent package) uses, so a hand enrollment works.
    #[test]
    fn the_console_enrollment_steps_match_the_packaged_agent() {
        let panel = include_str!("../../../openvibes-console/web/src/panels/OpsPanels.tsx");
        for want in [
            format!("{}/agent.toml", super::AGENT),
            format!("{}/platform-ca.crt", super::AGENT),
            format!(
                "-o openvibes_agent -g openvibes_agent -m 0600 /dev/stdin {}/token",
                super::AGENT
            ),
            super::ROOT_CERT.to_owned(),
            "systemctl restart openvibes-agent".to_owned(),
        ] {
            assert!(panel.contains(&want), "the console snippet lacks {want}");
        }
        assert!(!panel.contains("/etc/openvibes/agent.toml"));
        assert!(!panel.contains("/etc/openvibes/enrollment-token"));
    }

    const ADMIN: [&str; 5] = [
        "/usr/sbin/runuser",
        "-u",
        "openvibes-admin",
        "--",
        "/usr/bin/openvibes-admin",
    ];
    const TOKEN: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
    const KEY: &str = "baseline org.rules AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn admin(rest: &[&str]) -> Vec<&'static str> {
        ADMIN
            .iter()
            .chain(rest)
            .map(|s| &*Box::leak((*s).to_owned().into_boxed_str()))
            .collect()
    }

    #[test]
    fn rules_are_skipped_until_their_package_exists() {
        let fake = Fake::new("rules-missing");
        fake.answer(&admin(&["rules", "list"]), 0, "");
        fake.answer(&["/usr/bin/rpm"], 1, "");
        std::fs::create_dir_all(fake.root.join("srv/rpms")).unwrap();
        let mut plan = plan(&[Ingest, Distribution, Rules]);
        plan.repo_dir = Some("/srv/rpms".into());
        let state = run_step(&fake.ctx(&plan), Step::Rules);
        assert!(matches!(state, StepState::Skipped(_)), "{state:?}");
    }

    #[test]
    fn rules_are_trusted_and_published() {
        let fake = Fake::new("rules");
        fake.answer(&admin(&["rules", "list"]), 0, "");
        fake.answer(
            &["/usr/bin/rpm", "-q", "--quiet", "openvibes-rules-baseline"],
            0,
            "",
        );
        fake.file(
            "/usr/share/openvibes/rules/baseline.key",
            &format!("{KEY}\n"),
        );
        fake.answer(&admin(&["rules", "trust", "add"]), 0, "trusted\n");
        fake.answer(&admin(&["rules", "publish"]), 0, "published baseline v1\n");
        let state = run_step(
            &fake.ctx(&plan(&[Ingest, Distribution, Rules])),
            Step::Rules,
        );
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
        assert_eq!(
            fake.call(&admin(&["rules", "trust"]))[5..],
            [
                "rules",
                "trust",
                "add",
                "baseline",
                "org.rules",
                "--",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            ]
        );
        assert_eq!(
            fake.call(&admin(&["rules", "publish"]))[7],
            "/usr/share/openvibes/rules/baseline.json"
        );
    }

    /// A platform with `baseline v1` published and the package's
    /// envelope at `installed`.
    fn rules_at(test: &str, installed: u64) -> Fake {
        let fake = Fake::new(test);
        fake.answer(
            &admin(&["rules", "list"]),
            0,
            "baseline v1 keys 1 expires 2028-09-27T00:00:00Z\n",
        );
        fake.file(
            "/usr/share/openvibes/rules/baseline.key",
            &format!("{KEY}\n"),
        );
        fake.file(
            "/usr/share/openvibes/rules/baseline.json",
            &format!("{{\"rule_set_version\":{installed},\"payload\":\"x\"}}"),
        );
        fake
    }

    #[test]
    fn the_published_version_is_done() {
        let fake = rules_at("rules-current", 1);
        let state = rules_check(&fake.ctx(&plan(&[Ingest, Distribution, Rules]))).unwrap();
        assert_eq!(
            state,
            StepState::Done("rule set baseline v1 published".into())
        );
    }

    #[test]
    fn a_newer_installed_package_is_todo_and_gets_published() {
        let fake = rules_at("rules-newer", 2);
        let plan = plan(&[Ingest, Distribution, Rules]);
        assert_eq!(rules_check(&fake.ctx(&plan)).unwrap(), StepState::Todo);
        fake.answer(
            &["/usr/bin/rpm", "-q", "--quiet", "openvibes-rules-baseline"],
            0,
            "",
        );
        fake.answer(&admin(&["rules", "trust", "add"]), 0, "already trusted\n");
        fake.answer(&admin(&["rules", "publish"]), 0, "published baseline v2\n");
        let state = run_step(&fake.ctx(&plan), Step::Rules);
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
        assert_eq!(
            fake.call(&admin(&["rules", "publish"]))[7],
            "/usr/share/openvibes/rules/baseline.json"
        );
    }

    /// Tester: an admin who retired `baseline` chose to stop serving it; a
    /// newer package must not turn the step into a failure it can never fix
    /// (`rules publish` refuses a retired set).
    #[test]
    fn a_retired_baseline_is_not_todo_after_a_newer_package() {
        let fake = Fake::new("rules-retired");
        fake.answer(
            &admin(&["rules", "list"]),
            0,
            "baseline v1 keys 1 expires 2028-09-27T00:00:00Z retired\n",
        );
        fake.file(
            "/usr/share/openvibes/rules/baseline.key",
            &format!("{KEY}\n"),
        );
        fake.file(
            "/usr/share/openvibes/rules/baseline.json",
            "{\"rule_set_version\":2,\"payload\":\"x\"}",
        );
        let state = rules_check(&fake.ctx(&plan(&[Ingest, Distribution, Rules]))).unwrap();
        assert_ne!(
            state,
            StepState::Todo,
            "Repair would fail forever: {state:?}"
        );
    }

    #[test]
    fn the_local_agent_is_configured_started_and_awaited() {
        let fake = Fake::new("agent");
        fake.answer(&["/usr/bin/rpm", "-q", "--quiet", "openvibes-agent"], 0, "");
        fake.answer(&["/usr/bin/systemctl", "is-active"], 3, "");
        fake.answer(
            &admin(&["token", "fleet"]),
            0,
            &format!("token id 3\ntoken {TOKEN}\n"),
        );
        fake.answer(&["/usr/bin/systemctl", "enable", "openvibes-agent"], 0, "");
        fake.answer(&["/usr/bin/systemctl", "restart", "openvibes-agent"], 0, "");
        fake.answer(
            &admin(&["agent", "list"]),
            0,
            "a1b2  active  last seen now  version 0.1.0\n",
        );
        fake.file("/etc/openvibes/pki/root.crt", "ROOT\n");
        fake.file(
            "/usr/share/openvibes/rules/baseline.key",
            &format!("{KEY}\n"),
        );
        let state = run_step(
            &fake.ctx(&plan(&[Ingest, Distribution, Rules, Agent])),
            Step::Agent,
        );
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
        assert_eq!(
            fake.text("/etc/openvibes-agent/token"),
            format!("{TOKEN}\n")
        );
        assert_eq!(fake.text("/etc/openvibes-agent/platform-ca.crt"), "ROOT\n");
        let config = fake.text("/etc/openvibes-agent/agent.toml");
        for want in [
            "platform_url = \"https://localhost\"",
            "distribution_url = \"https://localhost\"",
            "id = \"baseline\"",
            "issuer_key_id = \"org.rules\"",
        ] {
            assert!(config.contains(want), "{want} missing in\n{config}");
        }
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(fake.root.join("etc/openvibes-agent/token"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn an_agent_with_no_repository_is_skipped_without_asking_dnf() {
        let fake = Fake::new("agent-no-repo");
        fake.answer(&["/usr/bin/rpm", "-q", "--quiet", "openvibes-agent"], 1, "");
        let state = run_step(
            &fake.ctx(&plan(&[Ingest, Distribution, Rules, Agent])),
            Step::Agent,
        );
        assert!(matches!(state, StepState::Skipped(_)), "{state:?}");
        assert!(!fake.called(&["/usr/bin/dnf"]));
    }

    #[test]
    fn an_agent_in_the_plans_repo_dir_is_installed_with_dnf() {
        let fake = Fake::new("agent-repo-dir");
        fake.answer(&["/usr/bin/rpm", "-q", "--quiet", "openvibes-agent"], 1, "");
        fake.file("/test/old/openvibes-agent-1.rpm", "");
        fake.fail(&["/usr/bin/dnf"], "stop here");
        let mut plan = plan(&[Ingest, Distribution, Rules, Agent]);
        plan.repo_dir = Some("/test/old".into());
        let state = run_step(&fake.ctx(&plan), Step::Agent);
        assert!(fake.called(&["/usr/bin/dnf"]));
        assert!(matches!(state, StepState::Failed(_)), "{state:?}");
    }

    #[test]
    fn an_unavailable_agent_package_skips_the_step() {
        let fake = Fake::new("agent-offline");
        fake.file("/etc/yum.repos.d/openvibes.repo", "");
        fake.answer(&["/usr/bin/rpm", "-q", "--quiet", "openvibes-agent"], 1, "");
        fake.fail(&["/usr/bin/dnf"], "No match for argument: openvibes-agent");
        let state = run_step(
            &fake.ctx(&plan(&[Ingest, Distribution, Rules, Agent])),
            Step::Agent,
        );
        assert!(matches!(state, StepState::Skipped(_)), "{state:?}");
        assert!(state.detail().contains("add agents from the console"));
    }

    #[test]
    fn the_local_agent_uses_the_chosen_ports() {
        let fake = Fake::new("agent-ports");
        fake.file(
            "/usr/share/openvibes/rules/baseline.key",
            &format!("{KEY}\n"),
        );
        let mut plan = plan(&[Ingest, Distribution, Rules, Agent]);
        plan.ingest_port = 18500;
        plan.distribution_port = 18501;
        let config = super::agent_toml(&fake.ctx(&plan));
        assert!(
            config.contains("platform_url = \"https://localhost:18500\""),
            "{config}"
        );
        assert!(
            config.contains("distribution_url = \"https://localhost:18501\""),
            "{config}"
        );
        // The defaults stay port-less, as before.
        let config = super::agent_toml(&fake.ctx(&plan_defaults()));
        assert!(
            config.contains("platform_url = \"https://localhost\"\n"),
            "{config}"
        );
    }

    const AGENT_VERSION: &[&str] = &[
        "/usr/bin/rpm",
        "-q",
        "--qf",
        "%{VERSION}",
        "openvibes-agent",
    ];

    /// rpm decides (owners.conf is %doc: a nodocs host has none);
    /// anything unclear counts as an agent that would refuse "services".
    #[test]
    fn the_agent_version_decides_services() {
        let ctx_with = |test: &str, answer: Option<(i32, &str)>| {
            let fake = Fake::new(test);
            if let Some((status, out)) = answer {
                fake.answer(AGENT_VERSION, status, out);
            }
            let plan = plan_defaults();
            super::p15_agent(&fake.ctx(&plan))
        };
        assert!(ctx_with("p15-024", Some((0, "0.2.4"))));
        assert!(ctx_with("p15-022", Some((0, "0.2.2\n"))));
        assert!(ctx_with("p15-100", Some((0, "1.0.0"))));
        assert!(!ctx_with("p15-021", Some((0, "0.2.1"))));
        assert!(!ctx_with("p15-junk", Some((0, "garbage"))));
        assert!(!ctx_with("p15-rc", Some((0, "0.2.4~rc1"))));
        assert!(!ctx_with(
            "p15-missing",
            Some((1, "package openvibes-agent is not installed"))
        ));
        assert!(!ctx_with("p15-none", None));
    }

    fn plan_defaults() -> crate::setup::plan::Plan {
        plan(&[Ingest, Distribution, Rules, Agent])
    }

    #[test]
    fn an_agent_that_never_reports_fails_the_step() {
        let fake = Fake::new("agent-silent");
        fake.answer(&["/usr/bin/rpm", "-q", "--quiet", "openvibes-agent"], 0, "");
        fake.answer(&["/usr/bin/systemctl", "is-active"], 3, "");
        fake.answer(&admin(&["token", "fleet"]), 0, &format!("token {TOKEN}\n"));
        fake.answer(&["/usr/bin/systemctl"], 0, "");
        fake.answer(&admin(&["agent", "list"]), 0, "");
        fake.file("/etc/openvibes/pki/root.crt", "ROOT\n");
        let state = run_step(&fake.ctx(&plan(&[Ingest, Agent])), Step::Agent);
        assert!(
            state.detail().contains("journalctl -u openvibes-agent"),
            "{state:?}"
        );
    }

    /// Fedora's default audit rules (`-a task,never`) would leave the
    /// alarms just configured silent: the Agent step says so.
    #[test]
    fn the_agent_step_warns_when_syscall_auditing_is_off() {
        let fake = rules_at("agent-audit-off", 1);
        fake.file(
            "/usr/share/openvibes/rules/alarms.key",
            &format!("{ALARMS_KEY}\n"),
        );
        fake.file("/usr/share/openvibes/rules/alarms.json", "{}");
        fake.file(
            "/etc/audit/rules.d/openvibes-agent.rules",
            "-a always,exit\n",
        );
        fake.file(
            "/etc/audit/audit.rules",
            "-D\n-a task,never\n-a always,exit\n",
        );
        fake.answer(&["/usr/bin/rpm", "-q", "--quiet", "openvibes-agent"], 0, "");
        fake.answer(&admin(&["token", "fleet"]), 0, &format!("token {TOKEN}\n"));
        fake.answer(&["/usr/bin/systemctl"], 0, "");
        fake.answer(&admin(&["agent", "list"]), 0, "agent.x  active  host\n");
        fake.file("/etc/openvibes/pki/root.crt", "ROOT\n");
        let state = run_step(&fake.ctx(&plan_defaults()), Step::Agent);
        assert!(state.detail().contains("-a task,never"), "{state:?}");
        // Without that line the step reads as before.
        fake.file("/etc/audit/audit.rules", "-D\n-a always,exit\n");
        let state = run_step(&fake.ctx(&plan_defaults()), Step::Agent);
        assert!(!state.detail().contains("never"), "{state:?}");
        // An eBPF host (agent #57: the rule is only a template there, not in
        // rules.d) does not read kernel audit: no warning even with the line.
        fake.remove("/etc/audit/rules.d/openvibes-agent.rules");
        fake.file(
            "/usr/share/openvibes-agent/openvibes-agent.rules",
            "-a always,exit\n",
        );
        fake.file(
            "/etc/audit/audit.rules",
            "-D\n-a task,never\n-a always,exit\n",
        );
        let state = run_step(&fake.ctx(&plan_defaults()), Step::Agent);
        assert!(!state.detail().contains("never"), "{state:?}");
    }

    const ALARMS_KEY: &str =
        "baseline-alarms org.rules BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    /// Rules v2 carries the alarm rules: both sets are trusted and published,
    /// and the step stays Todo until the alarm set is published too.
    #[test]
    fn the_alarm_rule_set_is_published_beside_the_baseline() {
        let fake = rules_at("rules-alarms", 1);
        fake.file(
            "/usr/share/openvibes/rules/alarms.key",
            &format!("{ALARMS_KEY}\n"),
        );
        fake.file(
            "/usr/share/openvibes/rules/alarms.json",
            "{\"rule_set_version\":1,\"payload\":\"x\"}",
        );
        let plan = plan(&[Ingest, Distribution, Rules]);
        assert_eq!(rules_check(&fake.ctx(&plan)).unwrap(), StepState::Todo);
        fake.answer(
            &["/usr/bin/rpm", "-q", "--quiet", "openvibes-rules-baseline"],
            0,
            "",
        );
        fake.answer(&admin(&["rules", "trust", "add"]), 0, "trusted\n");
        fake.answer(&admin(&["rules", "publish"]), 0, "published\n");
        let state = run_step(&fake.ctx(&plan), Step::Rules);
        assert!(
            state.detail().contains("baseline-alarms published"),
            "{state:?}"
        );
        let published: Vec<String> = fake
            .calls
            .borrow()
            .iter()
            .filter(|call| call.get(6).is_some_and(|word| word == "publish"))
            .map(|call| call[7].clone())
            .collect();
        assert_eq!(
            published,
            [
                "/usr/share/openvibes/rules/baseline.json",
                "/usr/share/openvibes/rules/alarms.json"
            ]
        );
    }

    /// The local agent gets the alarm rules and `process_events` only when
    /// its package ships the audit rule (a P14 agent); an older agent would
    /// refuse the collector name and not start.
    #[test]
    fn only_a_p14_agent_is_configured_for_alarms() {
        let fake = rules_at("agent-alarms", 1);
        fake.file(
            "/usr/share/openvibes/rules/alarms.key",
            &format!("{ALARMS_KEY}\n"),
        );
        fake.file("/usr/share/openvibes/rules/alarms.json", "{}");
        let old = super::agent_toml(&fake.ctx(&plan_defaults()));
        assert!(!old.contains("process_events"), "{old}");
        assert!(!old.contains("baseline-alarms"), "{old}");
        fake.file(
            "/etc/audit/rules.d/openvibes-agent.rules",
            "-a always,exit\n",
        );
        // Agents 0.2.0–0.2.1 know process_events but refuse "services".
        let p14 = super::agent_toml(&fake.ctx(&plan_defaults()));
        assert!(
            p14.contains(
                "collectors = [\"processes\", \"packages\", \"ports\", \"process_events\"]\n"
            ),
            "{p14}"
        );
        // A P15 agent (rpm says 0.2.2 on, docs or not): the explicit list
        // keeps services (v0.2.7 fix).
        fake.answer(AGENT_VERSION, 0, "0.2.4");
        let new = super::agent_toml(&fake.ctx(&plan_defaults()));
        assert!(
            new.contains(
                "collectors = [\"processes\", \"packages\", \"ports\", \"process_events\", \"services\"]\n"
            ),
            "{new}"
        );
        assert!(new.contains("id = \"baseline-alarms\""), "{new}");
        // collectors is a top-level key: it must come before any table.
        assert!(new.find("collectors").unwrap() < new.find("[[rule_sets]]").unwrap());
        assert!(toml::from_str::<toml::Value>(&new).is_ok(), "{new}");
        // An eBPF-era agent (agent #57) ships the rule only as a template, and
        // an eBPF host has nothing in rules.d: it still gets the alarms.
        fake.remove("/etc/audit/rules.d/openvibes-agent.rules");
        fake.file(
            "/usr/share/openvibes-agent/openvibes-agent.rules",
            "-a always,exit\n",
        );
        let ebpf = super::agent_toml(&fake.ctx(&plan_defaults()));
        assert!(ebpf.contains("process_events"), "{ebpf}");
        assert!(ebpf.contains("\"services\"]"), "{ebpf}");
        // Setup's pre-0.2.7 file is not "configured": Repair rewrites it.
        fake.answer(&["/usr/bin/systemctl", "is-active"], 0, "");
        fake.file("/etc/openvibes-agent/agent.toml", &ebpf);
        let plan = plan_defaults();
        let ctx = fake.ctx(&plan);
        assert!(matches!(super::agent_check(&ctx), Ok(StepState::Done(_))));
        fake.file(
            "/etc/openvibes-agent/agent.toml",
            &ebpf.replace(super::COLLECTORS, super::OLD_COLLECTORS),
        );
        assert_eq!(super::agent_check(&ctx), Ok(StepState::Todo));
        assert!(ebpf.contains("id = \"baseline-alarms\""), "{ebpf}");
    }

    #[test]
    fn a_malformed_alarms_key_fails_the_rules_step() {
        let fake = rules_at("rules-alarms-bad", 1);
        fake.file("/usr/share/openvibes/rules/alarms.json", "{}");
        fake.file("/usr/share/openvibes/rules/alarms.key", "only-two fields\n");
        let error = rules_check(&fake.ctx(&plan(&[Ingest, Distribution, Rules]))).unwrap_err();
        assert!(error.contains("alarms.key"), "{error}");
    }
}
