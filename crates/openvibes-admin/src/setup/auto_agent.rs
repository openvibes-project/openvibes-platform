//! `helper agent-config-upgrade`: run by openvibes-admin's `%posttrans` and
//! by its file trigger on the agent's binary (an agent upgraded alone).
//! Before v0.2.7, Setup wrote the local agent a `collectors` list without
//! `services` (an explicit list replaces the agent's default), so the
//! platform host never reported open ports and services (P15). Only that
//! exact line is replaced, then the agent is restarted if it runs; a list
//! someone edited is left alone with one log line (printed once while it
//! stays the same). Never fatal.

use std::{fs, os::unix::fs::MetadataExt, path::Path};

use platform_host::runner::{Program::Systemctl, Runner};

use super::{
    Ctx,
    fleet::{COLLECTORS, OLD_COLLECTORS, p15_agent},
    plan::Plan,
};

const FILE: &str = "/etc/openvibes-agent/agent.toml";
/// The last "services stay off" line printed: the same one is not printed
/// again on every upgrade.
const NOTED: &str = "/var/lib/openvibes-admin/agent-services-note";

/// The line to log, if there is anything to say.
pub fn run<R: Runner>(root: &Path, runner: &R) -> Option<String> {
    // Only Setup writes the old line, so a host it never ran on has none.
    let plan = Plan::load(root).ok()?;
    let ctx = Ctx {
        runner,
        plan: &plan,
        root,
        pause: std::time::Duration::from_secs(1),
        repair: false,
    };
    match upgrade(&ctx)? {
        Ok(done) => Some(done),
        Err(off) => {
            let off =
                format!("the agent on this host does not report open ports and services: {off}");
            if ctx.read(NOTED).is_ok_and(|noted| noted == off) {
                return None;
            }
            // Best effort: at worst the line is printed again next time.
            let _ = ctx.put(NOTED, off.as_bytes(), None, 0o644);
            Some(off)
        }
    }
}

/// `Ok`: what was done; `Err`: why services stay off; `None`: nothing to say.
fn upgrade<R: Runner>(ctx: &Ctx<R>) -> Option<Result<String, String>> {
    if !ctx.exists("/usr/bin/openvibes-agent") {
        return None;
    }
    let meta = fs::symlink_metadata(ctx.path(FILE)).ok()?;
    if !meta.is_file() {
        return Some(Err(format!("{FILE} is not a regular file; left alone")));
    }
    let text = ctx.read(FILE).ok()?;
    let mut found = false;
    let new: Vec<&str> = text
        .split('\n')
        .map(|line| {
            if line == OLD_COLLECTORS {
                found = true;
                COLLECTORS
            } else {
                line
            }
        })
        .collect();
    if !found {
        let edited = text.lines().any(|line| {
            line.trim_start().starts_with("collectors") && !line.contains("\"services\"")
        });
        return edited.then(|| Err(format!("{FILE} has a collectors list Setup did not write, so it was left alone; add \"services\" to it")));
    }
    if !p15_agent(ctx) {
        return Some(Err(
            "the installed openvibes-agent predates them; upgrade it, then run Repair in Setup"
                .into(),
        ));
    }
    let ids = Some((meta.uid(), meta.gid()));
    // Its own temp name: a concurrent Setup Repair writes `.agent.toml.setup`.
    if let Err(error) = ctx.put_ids(
        FILE,
        new.join("\n").as_bytes(),
        ids,
        meta.mode() & 0o777,
        "upgrade",
    ) {
        return Some(Err(format!("{FILE} not updated: {error}")));
    }
    // --no-block: the package transaction does not wait for the agent.
    Some(Ok(
        match ctx.ok(
            Systemctl,
            &["--no-block", "try-restart", "openvibes-agent.service"],
        ) {
            Ok(_) => format!(
                "{FILE}: services added to the collectors Setup wrote; the agent restarts if it was running"
            ),
            Err(error) => format!(
                "{FILE}: services added to the collectors Setup wrote; restarting the agent failed ({error}), it reports them from its next start"
            ),
        },
    ))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::{FILE, run};
    use crate::setup::{
        fake::{Fake, plan},
        plan::Component::*,
    };

    const HEAD: &str = "state_dir = \"/var/lib/openvibes-agent\"\n# Threat alarms.\n";
    const OLD: &str = "collectors = [\"processes\", \"packages\", \"ports\", \"process_events\"]\n";
    const NEW: &str =
        "collectors = [\"processes\", \"packages\", \"ports\", \"process_events\", \"services\"]\n";
    const TAIL: &str =
        "distribution_url = \"https://localhost:8444\"\n\n[[rule_sets]]\nid = \"baseline\"\n";
    const RESTART: [&str; 4] = [
        "/usr/bin/systemctl",
        "--no-block",
        "try-restart",
        "openvibes-agent.service",
    ];
    const VERSION: [&str; 5] = [
        "/usr/bin/rpm",
        "-q",
        "--qf",
        "%{VERSION}",
        "openvibes-agent",
    ];

    fn host(test: &str, config: Option<&str>) -> Fake {
        host_with(test, config, "0.2.6")
    }

    /// No agent files beyond the binary: rpm's version decides (a nodocs
    /// install of 0.2.2–0.2.5 has no owners.conf).
    fn host_with(test: &str, config: Option<&str>, agent: &str) -> Fake {
        let fake = Fake::new(test);
        plan(&[Ingest, Distribution, Rules, Agent])
            .save(&fake.root)
            .unwrap();
        fake.file("/usr/bin/openvibes-agent", "");
        fake.answer(&VERSION, 0, agent);
        fake.answer(&RESTART, 0, "");
        if let Some(config) = config {
            fake.file(FILE, config);
        }
        fake
    }

    #[test]
    fn setups_old_line_gets_services_and_the_agent_restarts() {
        // 0.2.4 from rpm, no owners.conf (a tsflags=nodocs image).
        let fake = host_with("agentcfg-old", Some(&format!("{HEAD}{OLD}{TAIL}")), "0.2.4");
        let path = fake.root.join(FILE.trim_start_matches('/'));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let line = run(&fake.root, &fake).unwrap();
        assert!(line.contains("services added"), "{line}");
        assert_eq!(fake.text(FILE), format!("{HEAD}{NEW}{TAIL}"));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
        assert!(fake.called(&RESTART));
        // Run again (the next upgrade): nothing left to do.
        fake.calls.borrow_mut().clear();
        assert_eq!(run(&fake.root, &fake), None);
        assert!(!fake.called(&RESTART));
    }

    #[test]
    fn an_edited_list_is_left_alone_with_a_log_line() {
        for (n, edited) in [
            "collectors = [\"processes\",  \"packages\", \"ports\", \"process_events\"]\n",
            "collectors = [\"packages\", \"processes\", \"ports\", \"process_events\"]\n",
            "collectors = [\"processes\", \"packages\", \"ports\", \"process_events\", \"users\"]\n",
            "collectors = [\"processes\", \"packages\", \"ports\", \"process_events\"] \n",
            "  collectors = [\"processes\", \"packages\", \"ports\", \"process_events\"]\n",
            "collectors = [\"processes\", \"packages\", \"ports\", \"process_events\"]\r\n",
        ]
        .iter()
        .enumerate()
        {
            let config = format!("{HEAD}{edited}{TAIL}");
            let fake = host(&format!("agentcfg-edited-{n}"), Some(&config));
            let line = run(&fake.root, &fake).unwrap();
            assert!(line.contains("does not report open ports"), "{line}");
            assert!(line.contains("left alone"), "{line}");
            assert_eq!(fake.text(FILE), config);
            assert!(!fake.called(&RESTART));
            // Printed once: the next upgrade stays quiet while it is the same.
            assert_eq!(run(&fake.root, &fake), None);
        }
    }

    #[test]
    fn a_new_reason_is_printed_again() {
        let fake = host_with(
            "agentcfg-renote",
            Some(&format!("{HEAD}{OLD}{TAIL}")),
            "0.2.1",
        );
        assert!(run(&fake.root, &fake).unwrap().contains("predates"));
        assert_eq!(run(&fake.root, &fake), None);
        fake.file(FILE, &format!("{HEAD}collectors = [\"ports\"]\n{TAIL}"));
        assert!(run(&fake.root, &fake).unwrap().contains("left alone"));
    }

    #[test]
    fn a_list_with_services_or_none_is_quiet() {
        for (n, config) in [format!("{HEAD}{NEW}{TAIL}"), format!("{HEAD}{TAIL}")]
            .iter()
            .enumerate()
        {
            let fake = host(&format!("agentcfg-fine-{n}"), Some(config));
            assert_eq!(run(&fake.root, &fake), None);
            assert_eq!(&fake.text(FILE), config);
            assert!(fake.calls.borrow().is_empty());
        }
    }

    #[test]
    fn no_agent_toml_or_no_agent_does_nothing() {
        let fake = host("agentcfg-none", None);
        assert_eq!(run(&fake.root, &fake), None);
        let fake = host("agentcfg-noagent", Some(&format!("{HEAD}{OLD}{TAIL}")));
        fake.remove("/usr/bin/openvibes-agent");
        assert_eq!(run(&fake.root, &fake), None);
        assert_eq!(fake.text(FILE), format!("{HEAD}{OLD}{TAIL}"));
        assert!(fake.calls.borrow().is_empty());
    }

    /// Agents 0.2.0–0.2.1 refuse the name and would not start.
    #[test]
    fn an_agent_before_services_keeps_the_old_line() {
        let fake = host_with("agentcfg-p14", Some(&format!("{HEAD}{OLD}{TAIL}")), "0.2.1");
        let line = run(&fake.root, &fake).unwrap();
        assert!(line.contains("predates"), "{line}");
        assert_eq!(fake.text(FILE), format!("{HEAD}{OLD}{TAIL}"));
        assert!(!fake.called(&RESTART));
    }

    #[test]
    fn a_symlink_is_not_followed() {
        let fake = host("agentcfg-link", None);
        fake.file("/etc/elsewhere.toml", &format!("{HEAD}{OLD}{TAIL}"));
        std::fs::create_dir_all(fake.root.join("etc/openvibes-agent")).unwrap();
        std::os::unix::fs::symlink(
            fake.root.join("etc/elsewhere.toml"),
            fake.root.join(FILE.trim_start_matches('/')),
        )
        .unwrap();
        let line = run(&fake.root, &fake).unwrap();
        assert!(line.contains("not a regular file"), "{line}");
        assert_eq!(
            fake.text("/etc/elsewhere.toml"),
            format!("{HEAD}{OLD}{TAIL}")
        );
    }

    #[test]
    fn setup_never_ran_does_nothing() {
        let fake = Fake::new("agentcfg-nosetup");
        fake.file("/usr/bin/openvibes-agent", "");
        fake.file(FILE, &format!("{HEAD}{OLD}{TAIL}"));
        assert_eq!(run(&fake.root, &fake), None);
    }
}
