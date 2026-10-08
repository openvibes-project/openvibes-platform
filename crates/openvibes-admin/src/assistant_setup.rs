//! `openvibes-admin helper assistant-setup`: points the console's assistant
//! at the bundled `openvibes-llm` service in one step. As root it hands the
//! shared API key to the console's account, writes `[assistant]` into
//! `console.toml` (kept layout and comments), enables the model service and
//! restarts the console. The model itself ships in the `openvibes-llm`
//! package, pinned by SHA-256 in `/var/lib/openvibes-llm/model.conf`.

use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{PermissionsExt, chown},
    path::Path,
};

use platform_host::{
    CONFIG_DIR, Service,
    runner::{Program::Systemctl, Runner, SystemRunner},
};
use toml_edit::{DocumentMut, Item, Table, value};

use crate::config_file;

const LLM_CONF: &str = "/etc/openvibes/llm.conf";
const MODEL_CONF: &str = "/var/lib/openvibes-llm/model.conf";
const API_KEY: &str = "/etc/openvibes/llm-api-key";
const CONSOLE_USER: &str = "openvibes-console";
const DEFAULT_PORT: &str = "18430";
const DEFAULT_ALIAS: &str = "local-model";

/// `KEY=VALUE` lines of a systemd environment file; later lines win.
pub(crate) fn parse_env(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| {
            (
                key.trim().to_owned(),
                value.trim().trim_matches('"').to_owned(),
            )
        })
        .collect()
}

/// The console configuration with `[assistant]` pointing at the local model
/// server. `force` replaces a backend that is already configured.
pub fn configure(
    console: &str,
    env: &BTreeMap<String, String>,
    force: bool,
) -> Result<String, String> {
    let port = env
        .get("OPENVIBES_LLM_PORT")
        .map_or(DEFAULT_PORT, String::as_str);
    let alias = env
        .get("OPENVIBES_LLM_ALIAS")
        .map_or(DEFAULT_ALIAS, String::as_str);
    let url = format!("http://127.0.0.1:{port}/v1");
    let mut doc: DocumentMut = console
        .parse()
        .map_err(|error| format!("console.toml: {error}"))?;
    let assistant = doc
        .entry("assistant")
        .or_insert_with(|| Item::Table(Table::new()))
        .as_table_mut()
        .ok_or("console.toml: [assistant] is not a table")?;
    let existing = assistant
        .get("backend")
        .and_then(Item::as_table_like)
        .and_then(|backend| backend.get("url")?.as_str().map(str::to_owned));
    if let Some(existing) = existing.filter(|existing| *existing != url)
        && !force
    {
        return Err(format!(
            "console.toml already sends the assistant to {existing}; use --force to point it at the bundled model instead"
        ));
    }
    assistant["enabled"] = value(true);
    if !assistant.contains_key("profile") {
        assistant["profile"] = value("small");
    }
    if !assistant.contains_key("lookup_mode") {
        assistant["lookup_mode"] = value("auto");
    }
    let mut backend = Table::new();
    backend["url"] = value(url);
    backend["model"] = value(alias);
    backend["api_key_file"] = value(API_KEY);
    assistant["backend"] = Item::Table(backend);
    Ok(doc.to_string())
}

/// The numeric ids of `name` in `/etc/passwd`.
fn account(name: &str) -> Result<(u32, u32), String> {
    let passwd =
        fs::read_to_string("/etc/passwd").map_err(|error| format!("/etc/passwd: {error}"))?;
    passwd
        .lines()
        .find_map(|line| {
            let mut fields = line.split(':');
            (fields.next()? == name).then(|| {
                let uid = fields.nth(1)?.parse().ok()?;
                let gid = fields.next()?.parse().ok()?;
                Some((uid, gid))
            })?
        })
        .ok_or_else(|| format!("no {name} account: is openvibes-console installed?"))
}

/// Runs as root. Safe to repeat.
pub fn run(force: bool) -> Result<String, String> {
    if !Path::new(MODEL_CONF).exists() {
        return Err(
            "no model selected: this host has no bundled model; install one with `openvibes-admin assistant model install`, then run this again"
                .into(),
        );
    }
    let mut env =
        parse_env(&fs::read_to_string(LLM_CONF).map_err(|error| format!("{LLM_CONF}: {error}"))?);
    env.extend(parse_env(
        &fs::read_to_string(MODEL_CONF).unwrap_or_default(),
    ));
    let dir = Path::new(CONFIG_DIR);
    let console = config_file::read(dir, Service::Console)?;
    let updated = configure(&console, &env, force)?;
    // The console reads the key itself (it must be owner-only), the model
    // service gets it as a systemd credential, loaded by root.
    let (uid, gid) = account(CONSOLE_USER)?;
    chown(API_KEY, Some(uid), Some(gid)).map_err(|error| format!("{API_KEY}: {error}"))?;
    fs::set_permissions(API_KEY, fs::Permissions::from_mode(0o400))
        .map_err(|error| format!("{API_KEY}: {error}"))?;
    config_file::replace(dir, Service::Console, &updated)?;
    for args in [
        &["enable", "--now", "openvibes-llm"][..],
        &["restart", "openvibes-llm"],
        &["try-restart", "openvibes-console"],
    ] {
        let out = SystemRunner
            .run(Systemctl, args)
            .map_err(|error| error.to_string())?;
        if out.status != 0 {
            return Err(format!(
                "systemctl {}: {}",
                args.join(" "),
                out.stderr.trim()
            ));
        }
    }
    // Tuning is best effort: a model that cannot answer yet is reported.
    let tuned = crate::tune_run::run(
        &crate::tune_run::TuneOptions {
            cpu: true,
            no_install: false,
            json: false,
        },
        Path::new("/"),
        &crate::tune_run::Systemd,
    )
    .unwrap_or_else(|error| {
        format!("tuning skipped: {error}; rerun `sudo openvibes-admin helper assistant-tune`\n")
    });
    Ok(format!(
        "the assistant now uses the bundled model ({})\n{tuned}next: sign in to the console; users with the assistant permission see the chat dock (Ctrl+J)\ncheck: sudo -u openvibes-console openvibes-admin assistant check\n",
        env.get("OPENVIBES_LLM_ALIAS")
            .map_or(DEFAULT_ALIAS, String::as_str)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect()
    }

    #[test]
    fn writes_the_local_backend_and_keeps_the_rest() {
        let out = configure(
            "# mine\npublic_origin = \"https://x\"\n",
            &env(&[
                ("OPENVIBES_LLM_PORT", "9000"),
                ("OPENVIBES_LLM_ALIAS", "qwen"),
            ]),
            false,
        )
        .unwrap();
        assert!(out.starts_with("# mine\npublic_origin"));
        let table: toml::Table = toml::from_str(&out).unwrap();
        let assistant = table["assistant"].as_table().unwrap();
        assert_eq!(assistant["enabled"].as_bool(), Some(true));
        assert_eq!(assistant["profile"].as_str(), Some("small"));
        let backend = assistant["backend"].as_table().unwrap();
        assert_eq!(backend["url"].as_str(), Some("http://127.0.0.1:9000/v1"));
        assert_eq!(backend["model"].as_str(), Some("qwen"));
        assert_eq!(backend["api_key_file"].as_str(), Some(API_KEY));
    }

    #[test]
    fn repeating_is_a_no_op_and_a_foreign_backend_needs_force() {
        let once = configure("", &env(&[]), false).unwrap();
        assert_eq!(configure(&once, &env(&[]), false).unwrap(), once);
        let foreign = "[assistant]\nenabled = true\nprofile = \"large\"\n[assistant.backend]\nurl = \"https://gpu.lan/v1\"\nmodel = \"m\"\n";
        assert!(configure(foreign, &env(&[]), false).is_err());
        let forced = configure(foreign, &env(&[]), true).unwrap();
        assert!(forced.contains("http://127.0.0.1:18430/v1"));
        assert!(
            forced.contains("profile = \"large\""),
            "keeps the chosen profile"
        );
    }

    #[test]
    fn env_file_later_lines_and_comments() {
        let parsed = parse_env("# A=1\nA=2\nA=3\nB=\"x\"\n");
        assert_eq!(parsed["A"], "3");
        assert_eq!(parsed["B"], "x");
    }
}
