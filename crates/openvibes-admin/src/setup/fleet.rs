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

/// `RULE_SET ISSUER_KEY_ID PUBLIC_KEY` from `baseline.key`.
fn baseline_key<R: Runner>(ctx: &Ctx<R>) -> Result<[String; 3], String> {
    let text = ctx.read(&format!("{RULES}/baseline.key"))?;
    let fields: Vec<String> = text.split_whitespace().map(str::to_owned).collect();
    <[String; 3]>::try_from(fields)
        .map_err(|_| format!("{RULES}/baseline.key: want RULE_SET ISSUER_KEY_ID PUBLIC_KEY"))
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

/// The version of the envelope the installed package carries, if any.
fn installed<R: Runner>(ctx: &Ctx<R>) -> Option<u64> {
    let text = ctx.read(&format!("{RULES}/baseline.json")).ok()?;
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
    Ok(match published(ctx, &set)? {
        Some(version) if installed(ctx).is_none_or(|newest| newest <= version) => {
            StepState::Done(format!("rule set {set} v{version} published"))
        }
        _ => StepState::Todo,
    })
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
    ctx.as_admin(&["rules", "publish", &format!("{RULES}/baseline.json")])?;
    Ok(StepState::Done(format!("rule set {set} published")))
}

fn agent_toml<R: Runner>(ctx: &Ctx<R>) -> String {
    let mut text = String::from(
        "# Written by openvibes-admin setup: the agent on the platform host.\n\
         state_dir = \"/var/lib/openvibes-agent\"\n\
         platform_url = \"https://localhost\"\n\
         platform_ca_file = \"/etc/openvibes-agent/platform-ca.crt\"\n\
         enrollment_token_file = \"/etc/openvibes-agent/token\"\n",
    );
    if ctx.plan.has(Component::Rules)
        && let Ok([set, issuer, key]) = baseline_key(ctx)
    {
        text.push_str(&format!(
            "distribution_url = \"https://localhost\"\n\n[[rule_sets]]\nid = \"{set}\"\n\
             trusted_keys = [{{ issuer_key_id = \"{issuer}\", public_key = \"{key}\" }}]\n"
        ));
    }
    text
}

pub fn agent_check<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    if !ctx.plan.has(Component::Agent) {
        return Ok(StepState::Skipped("agent on this host not chosen".into()));
    }
    let configured = ctx
        .read(&format!("{AGENT}/agent.toml"))
        .is_ok_and(|text| text.contains("platform_url = \"https://localhost\""));
    Ok(
        if configured && ctx.succeeds(Systemctl, &["is-active", "--quiet", "openvibes-agent"]) {
            StepState::Done("the agent on this host is running".into())
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
        install(ctx, &["openvibes-agent"])?;
    }
    let token = token_from(&ctx.as_admin(&["token", "create", "--expires", "1h"])?)?;
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
    ctx.ok(Systemctl, &["enable", "openvibes-agent"])?;
    ctx.ok(Systemctl, &["restart", "openvibes-agent"])?;
    for _ in 0..AGENT_WAIT {
        if reporting(ctx) {
            return Ok(StepState::Done(
                "the agent on this host enrolled and is reporting".into(),
            ));
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

    #[test]
    fn the_local_agent_is_configured_started_and_awaited() {
        let fake = Fake::new("agent");
        fake.answer(&["/usr/bin/rpm", "-q", "--quiet", "openvibes-agent"], 0, "");
        fake.answer(&["/usr/bin/systemctl", "is-active"], 3, "");
        fake.answer(
            &admin(&["token", "create", "--expires", "1h"]),
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
    fn an_agent_that_never_reports_fails_the_step() {
        let fake = Fake::new("agent-silent");
        fake.answer(&["/usr/bin/rpm", "-q", "--quiet", "openvibes-agent"], 0, "");
        fake.answer(&["/usr/bin/systemctl", "is-active"], 3, "");
        fake.answer(&admin(&["token", "create"]), 0, &format!("token {TOKEN}\n"));
        fake.answer(&["/usr/bin/systemctl"], 0, "");
        fake.answer(&admin(&["agent", "list"]), 0, "");
        fake.file("/etc/openvibes/pki/root.crt", "ROOT\n");
        let state = run_step(&fake.ctx(&plan(&[Ingest, Agent])), Step::Agent);
        assert!(
            state.detail().contains("journalctl -u openvibes-agent"),
            "{state:?}"
        );
    }
}
