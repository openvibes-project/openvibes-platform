//! Switching a host to a newly pinned model after an upgrade (#264; user
//! decision 2026-10-10: updates switch automatically). Run by
//! `helper assistant-tune --auto` before tuning, as root, under `root`.
//!
//! Only a host whose assistant uses a model an earlier release pinned is
//! switched; an admin's own model is never touched. The old model keeps
//! serving until the new one is downloaded and verified (`assistant model
//! fetch`, which also selects it in model.conf); then the console asks for
//! the new alias, the tuning is reset so `--auto` tunes the new model, the
//! server and console restart, and the old file is removed. A failed
//! download changes nothing and says so.

use std::{fs, path::Path};

use platform_host::Service;
use toml_edit::{DocumentMut, value};

use crate::{assistant_setup::parse_env, config_file, model_fetch::Pin, tune_run::Restarter};

const DATA_DIR: &str = "var/lib/openvibes-llm";

/// File names earlier releases pinned (`packaging/llm/past-models`).
fn past_models() -> impl Iterator<Item = &'static str> {
    include_str!("../../../packaging/llm/past-models")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
}

/// What to do, from what the host has.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Nothing(&'static str),
    /// Switch from this past pinned file (and its alias, if any).
    Switch {
        old_file: String,
        old_alias: Option<String>,
    },
}

/// `selected` is model.conf's `OPENVIBES_LLM_MODEL` file name.
pub fn decide(
    console_local: bool,
    selected: Option<&str>,
    alias: Option<&str>,
    pin: &Pin,
) -> Decision {
    let Some(selected) = selected else {
        return Decision::Nothing("no model is selected");
    };
    if !console_local {
        return Decision::Nothing("the console's assistant is not enabled with the local model");
    }
    if selected == pin.file {
        return Decision::Nothing("the pinned model is already selected");
    }
    if !past_models().any(|past| past == selected) {
        return Decision::Nothing("an admin's own model is selected");
    }
    Decision::Switch {
        old_file: selected.to_owned(),
        old_alias: alias.map(str::to_owned),
    }
}

/// Switches when [`decide`] says so; returns the one line to log. `fetch`
/// is `assistant model fetch` as openvibes-admin. Never fails.
pub fn auto(
    root: &Path,
    console_local: bool,
    pin: &Pin,
    restarter: &dyn Restarter,
    fetch: &dyn Fn() -> Result<(), String>,
) -> String {
    let data = root.join(DATA_DIR);
    let conf = parse_env(&fs::read_to_string(data.join("model.conf")).unwrap_or_default());
    let selected = conf
        .get("OPENVIBES_LLM_MODEL")
        .and_then(|path| Path::new(path).file_name())
        .and_then(|name| name.to_str());
    let decision = decide(
        console_local,
        selected,
        conf.get("OPENVIBES_LLM_ALIAS").map(String::as_str),
        pin,
    );
    let Decision::Switch {
        old_file,
        old_alias,
    } = decision
    else {
        let Decision::Nothing(why) = decision else {
            unreachable!()
        };
        return format!("assistant-model: nothing to do: {why}");
    };
    if let Err(error) = fetch() {
        return format!(
            "assistant-model: not switched to {}: {}; the assistant keeps using {old_file}; retried at the next upgrade",
            pin.file,
            error.lines().next().unwrap_or("the download failed")
        );
    }
    let mut notes = Vec::new();
    // The console asks the server for the model by alias.
    let etc = root.join("etc/openvibes");
    if let Some(old_alias) = &old_alias
        && old_alias != &pin.alias
    {
        let renamed = config_file::read(&etc, Service::Console).and_then(|text| {
            let mut doc = text
                .parse::<DocumentMut>()
                .map_err(|e| format!("console.toml: {e}"))?;
            if doc["assistant"]["backend"]["model"].as_str() != Some(old_alias.as_str()) {
                return Ok(false);
            }
            doc["assistant"]["backend"]["model"] = value(pin.alias.as_str());
            config_file::replace(&etc, Service::Console, &doc.to_string()).map(|()| true)
        });
        match renamed {
            Ok(true) => {}
            Ok(false) => notes.push("console.toml names another model; left as it is".to_owned()),
            Err(e) => notes.push(format!("console.toml not updated: {e}")),
        }
    }
    // The tuning measured the old model: --auto tunes the new one next.
    for file in ["tuning.conf", "tune.json"] {
        let _ = fs::remove_file(data.join(file));
    }
    for args in [
        &[
            "stop",
            "openvibes-llm-proxy.service",
            "openvibes-llm.service",
        ][..],
        &["try-restart", "openvibes-console.service"][..],
    ] {
        if let Err(e) = restarter.systemctl(args) {
            notes.push(e);
        }
    }
    if let Err(e) = fs::remove_file(data.join("models").join(&old_file)) {
        notes.push(format!("{old_file} not removed: {e}"));
    }
    let mut line = format!("assistant-model: switched from {old_file} to {}", pin.file);
    for note in notes {
        line.push_str("; ");
        line.push_str(&note);
    }
    line
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, path::PathBuf};

    use super::*;

    fn pin() -> Pin {
        Pin {
            file: "Qwen3.5-4B-Q4_K_M.gguf".into(),
            url: "https://example.test/new.gguf".into(),
            sha256: "a".repeat(64),
            alias: "qwen3.5-4b".into(),
            license_url: "https://example.test/LICENSE".into(),
        }
    }

    #[derive(Default)]
    struct Recorder(RefCell<Vec<String>>);
    impl Restarter for Recorder {
        fn systemctl(&self, args: &[&str]) -> Result<(), String> {
            self.0.borrow_mut().push(args.join(" "));
            Ok(())
        }
        fn llm_socket_holds(&self, _: &str) -> Result<(), String> {
            Ok(())
        }
        fn llm_socket_enabled(&self) -> bool {
            true
        }
    }

    const CONSOLE: &str = "development_listen = \"127.0.0.1:8443\"\nhealth_listen = \"127.0.0.1:8444\"\n[assistant]\nenabled = true\n[assistant.backend]\nurl = \"http://127.0.0.1:18430/v1\"\nmodel = \"qwen3-4b\"\n";

    /// A host on the old pinned model, tuned.
    fn host(name: &str, model: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("ov-model-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("var/lib/openvibes-llm/models")).unwrap();
        fs::create_dir_all(root.join("etc/openvibes")).unwrap();
        fs::write(root.join("var/lib/openvibes-llm/models").join(model), "old").unwrap();
        fs::write(
            root.join("var/lib/openvibes-llm/model.conf"),
            format!("OPENVIBES_LLM_MODEL=/var/lib/openvibes-llm/models/{model}\nOPENVIBES_LLM_ALIAS=qwen3-4b\n"),
        )
        .unwrap();
        fs::write(
            root.join("var/lib/openvibes-llm/tuning.conf"),
            "OPENVIBES_LLM_THREADS=4\n",
        )
        .unwrap();
        fs::write(root.join("etc/openvibes/console.toml"), CONSOLE).unwrap();
        root
    }

    /// What `assistant model fetch` leaves: the new file, selected.
    fn fetched(root: &Path) -> impl Fn() -> Result<(), String> + '_ {
        move || {
            let pin = pin();
            fs::write(
                root.join("var/lib/openvibes-llm/models").join(&pin.file),
                "new",
            )
            .unwrap();
            fs::write(
                root.join("var/lib/openvibes-llm/model.conf"),
                format!("OPENVIBES_LLM_MODEL=/var/lib/openvibes-llm/models/{}\nOPENVIBES_LLM_ALIAS={}\n", pin.file, pin.alias),
            )
            .unwrap();
            Ok(())
        }
    }

    #[test]
    fn a_host_on_a_past_pin_switches_and_drops_the_old_model() {
        let root = host("switch", "Qwen3-4B-Q4_K_M.gguf");
        let systemd = Recorder::default();
        let line = auto(&root, true, &pin(), &systemd, &fetched(&root));
        assert!(
            line.starts_with("assistant-model: switched from Qwen3-4B-Q4_K_M.gguf to Qwen3.5-4B"),
            "{line}"
        );
        let models = root.join("var/lib/openvibes-llm/models");
        assert!(
            !models.join("Qwen3-4B-Q4_K_M.gguf").exists(),
            "old model removed"
        );
        assert!(models.join("Qwen3.5-4B-Q4_K_M.gguf").exists());
        let console = fs::read_to_string(root.join("etc/openvibes/console.toml")).unwrap();
        assert!(console.contains("model = \"qwen3.5-4b\""), "{console}");
        assert!(
            !root.join("var/lib/openvibes-llm/tuning.conf").exists(),
            "re-tuned next"
        );
        assert_eq!(
            *systemd.0.borrow(),
            [
                "stop openvibes-llm-proxy.service openvibes-llm.service",
                "try-restart openvibes-console.service"
            ]
        );
    }

    #[test]
    fn a_failed_download_changes_nothing() {
        let root = host("fail", "Qwen3-4B-Q4_K_M.gguf");
        let systemd = Recorder::default();
        let line = auto(&root, true, &pin(), &systemd, &|| {
            Err("cannot download: offline\nmore".into())
        });
        assert!(
            line.contains("keeps using Qwen3-4B-Q4_K_M.gguf") && line.contains("offline"),
            "{line}"
        );
        assert!(
            root.join("var/lib/openvibes-llm/models/Qwen3-4B-Q4_K_M.gguf")
                .exists()
        );
        assert!(root.join("var/lib/openvibes-llm/tuning.conf").exists());
        assert_eq!(
            fs::read_to_string(root.join("etc/openvibes/console.toml")).unwrap(),
            CONSOLE
        );
        assert!(systemd.0.borrow().is_empty());
    }

    #[test]
    fn an_admins_own_model_is_never_touched() {
        let root = host("own", "my-model.gguf");
        let systemd = Recorder::default();
        let line = auto(&root, true, &pin(), &systemd, &|| {
            panic!("must not download")
        });
        assert!(line.contains("an admin's own model"), "{line}");
        assert!(
            root.join("var/lib/openvibes-llm/models/my-model.gguf")
                .exists()
        );
        assert!(systemd.0.borrow().is_empty());
    }

    #[test]
    fn nothing_happens_when_current_or_not_local() {
        let p = pin();
        assert_eq!(
            decide(true, Some(&p.file), None, &p),
            Decision::Nothing("the pinned model is already selected")
        );
        assert!(matches!(
            decide(false, Some("Qwen3-4B-Q4_K_M.gguf"), None, &p),
            Decision::Nothing(_)
        ));
        assert!(matches!(decide(true, None, None, &p), Decision::Nothing(_)));
        assert!(matches!(
            decide(true, Some("Qwen3-4B-Q4_K_M.gguf"), Some("qwen3-4b"), &p),
            Decision::Switch { .. }
        ));
    }

    #[test]
    fn a_console_pointing_at_another_model_name_is_left_alone() {
        let root = host("rename", "Qwen3-4B-Q4_K_M.gguf");
        fs::write(
            root.join("etc/openvibes/console.toml"),
            CONSOLE.replace("qwen3-4b", "local-model"),
        )
        .unwrap();
        let line = auto(&root, true, &pin(), &Recorder::default(), &fetched(&root));
        assert!(line.contains("names another model"), "{line}");
        assert!(
            fs::read_to_string(root.join("etc/openvibes/console.toml"))
                .unwrap()
                .contains("local-model")
        );
    }
}
