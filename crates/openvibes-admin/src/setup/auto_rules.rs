//! `helper rules-apply`: Update's trust-and-publish path (`fleet::rules_check`
//! then `fleet::rules_apply`) without the TUI, started by the rules package's
//! file trigger. Never fatal: every outcome is one log line.

use std::path::Path;

use platform_host::{StepState, runner::Runner};

use super::{Ctx, fleet, plan::Plan, system};

/// Publishes the installed rules package when Setup's own check says it is
/// newer than what is published; returns the one line to log.
pub fn run<R: Runner>(root: &Path, runner: &R) -> String {
    // Setup (or Update, which publishes rules itself) holds this lock.
    let _lock = match system::lock(root) {
        Ok(lock) => lock,
        Err(error) if error.contains("another Setup run") => {
            return "Setup is running; it publishes the rules itself".into();
        }
        Err(error) => return format!("rules not published: {error}"),
    };
    if let Err(error) = system::job_guard(root, "setup") {
        return format!("rules not published: {error}");
    }
    let plan = match Plan::load(root) {
        Ok(plan) => plan,
        Err(_) => return "Setup has not run on this host; nothing to publish".into(),
    };
    let ctx = Ctx {
        runner,
        plan: &plan,
        root,
        pause: std::time::Duration::from_secs(1),
        repair: false,
    };
    match fleet::rules_check(&ctx) {
        Ok(StepState::Todo) => match fleet::rules_apply(&ctx) {
            Ok(state) => state.detail().to_owned(),
            Err(error) => format!("rules not published: {error}"),
        },
        Ok(state) => format!("nothing to publish: {}", state.detail()),
        Err(error) => format!("rules not published: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::run;
    use crate::setup::{
        fake::{Fake, plan},
        plan::Component::*,
        system,
    };

    const ADMIN: [&str; 5] = [
        "/usr/sbin/runuser",
        "-u",
        "openvibes-admin",
        "--",
        "/usr/bin/openvibes-admin",
    ];
    const KEY: &str = "baseline openvibes-1 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n";

    fn admin(args: &[&str]) -> Vec<String> {
        ADMIN.iter().chain(args).map(|s| (*s).to_owned()).collect()
    }

    fn host(test: &str, published: &str, key: &str) -> Fake {
        let fake = Fake::new(test);
        plan(&[Ingest, Distribution, Rules])
            .save(&fake.root)
            .unwrap();
        let list = admin(&["rules", "list"]);
        fake.answer(
            &list.iter().map(String::as_str).collect::<Vec<_>>(),
            0,
            published,
        );
        fake.answer(
            &["/usr/bin/rpm", "-q", "--quiet", "openvibes-rules-baseline"],
            0,
            "",
        );
        fake.answer(&["/usr/sbin/runuser"], 0, "ok\n");
        fake.file("/usr/share/openvibes/rules/baseline.key", key);
        fake.file(
            "/usr/share/openvibes/rules/baseline.json",
            "{\"rule_set_version\":2}",
        );
        fake
    }

    fn published(fake: &Fake) -> bool {
        fake.called(&[
            "/usr/sbin/runuser",
            "-u",
            "openvibes-admin",
            "--",
            ADMIN[4],
            "rules",
            "publish",
        ])
    }

    #[test]
    fn a_newer_package_is_published() {
        let fake = host("auto-new", "baseline v1 keys 1\n", KEY);
        let line = run(&fake.root, &fake);
        assert_eq!(line, "rule set baseline published", "{line}");
        assert!(published(&fake));
    }

    #[test]
    fn nothing_changed_publishes_nothing() {
        let fake = host("auto-same", "baseline v2 keys 1\n", KEY);
        let line = run(&fake.root, &fake);
        assert!(line.starts_with("nothing to publish"), "{line}");
        assert!(!published(&fake));
    }

    #[test]
    fn a_retired_set_stays_retired() {
        let fake = host("auto-retired", "baseline v1 keys 1 retired\n", KEY);
        let line = run(&fake.root, &fake);
        assert!(line.starts_with("nothing to publish"), "{line}");
        assert!(!published(&fake));
    }

    #[test]
    fn a_malformed_key_is_not_trusted() {
        let fake = host("auto-badkey", "baseline v1 keys 1\n", "baseline only-two\n");
        let line = run(&fake.root, &fake);
        assert!(line.starts_with("rules not published"), "{line}");
        assert!(!fake.called(&[
            "/usr/sbin/runuser",
            "-u",
            "openvibes-admin",
            "--",
            ADMIN[4],
            "rules",
            "trust"
        ]));
    }

    #[test]
    fn a_half_done_update_or_uninstall_skips() {
        for kind in ["update", "uninstall"] {
            let fake = host(&format!("auto-job-{kind}"), "baseline v1 keys 1\n", KEY);
            fake.file("/run/openvibes-admin/job", kind);
            let line = run(&fake.root, &fake);
            assert!(line.starts_with("rules not published"), "{line}");
            assert!(line.contains("half done"), "{line}");
            assert!(!published(&fake));
        }
    }

    #[test]
    fn setup_never_ran_skips() {
        let fake = Fake::new("auto-no-setup");
        let line = run(&fake.root, &fake);
        assert!(line.contains("Setup has not run"), "{line}");
        assert!(fake.calls.borrow().is_empty());
    }

    #[test]
    fn a_held_setup_lock_skips() {
        let fake = host("auto-locked", "baseline v1 keys 1\n", KEY);
        let _held = system::lock(&fake.root).unwrap();
        let line = run(&fake.root, &fake);
        assert_eq!(line, "Setup is running; it publishes the rules itself");
        assert!(!published(&fake));
    }
}
