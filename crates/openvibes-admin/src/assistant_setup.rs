//! `openvibes-admin helper assistant-setup`: points the console's assistant
//! at the bundled `openvibes-llm` service in one step. As root it hands the
//! shared API key to the console's account, writes `[assistant]` into
//! `console.toml` (kept layout and comments), enables the model server's
//! socket and restarts the console. The model itself ships in the `openvibes-llm`
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

/// The model server is started by its socket on the first request; a
/// running one is stopped first so the next request loads the new settings.
const SYSTEMCTL_STEPS: [&[&str]; 3] = [
    &[
        "stop",
        "openvibes-llm-proxy.service",
        "openvibes-llm.service",
    ],
    &["enable", "--now", "openvibes-llm.socket"],
    &["try-restart", "openvibes-console"],
];

/// Whether `model.conf` selects a model file that exists (Setup asks
/// before downloading only when this is false).
pub(crate) fn model_installed() -> bool {
    crate::model::read_config(Path::new(MODEL_CONF))
        .ok()
        .and_then(|text| parse_env(&text).remove("OPENVIBES_LLM_MODEL"))
        .is_some_and(|file| Path::new(&file).is_file())
}

/// Makes sure the selected model file exists, fetching the pinned model
/// (through `fetch`) when it is missing and the pinned one is the selection.
fn ensure_model(
    model_conf: &Path,
    pin: &Path,
    no_download: bool,
    fetch: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    let selected = |conf: &Path| {
        let text = crate::model::read_config(conf)?;
        Ok::<_, String>(
            parse_env(&text)
                .get("OPENVIBES_LLM_MODEL")
                .cloned()
                .filter(|file| Path::new(file).is_file()),
        )
    };
    if selected(model_conf)?.is_some() {
        return Ok(());
    }
    // Missing: only the pinned model is ours to download.
    let pin = crate::model_fetch::read_pin(pin)?;
    let chosen = parse_env(&crate::model::read_config(model_conf)?)
        .get("OPENVIBES_LLM_MODEL")
        .cloned();
    if let Some(chosen) = chosen
        && Path::new(&chosen).file_name().and_then(|n| n.to_str()) != Some(pin.file.as_str())
    {
        return Err(format!("the selected model {chosen} is missing"));
    }
    if no_download {
        return Err("the assistant's model is not installed; turn the assistant on in Setup to download it (offline: see the offline install guide)".into());
    }
    fetch()?;
    selected(model_conf)?
        .map(|_| ())
        .ok_or_else(|| "the model was fetched but is not selected".into())
}

/// Runs as root. Safe to repeat. Downloads the pinned model first when it
/// is not installed, unless `no_download`.
pub fn run(force: bool, no_download: bool) -> Result<String, String> {
    ensure_model(
        Path::new(MODEL_CONF),
        Path::new(crate::model_fetch::PIN_PATH),
        no_download,
        crate::model_fetch::fetch_as_admin,
    )?;
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
    for args in SYSTEMCTL_STEPS {
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
    // Tune sends the server's key to the port: only once systemd's socket
    // is confirmed to hold it (tune checks again itself).
    let port = env
        .get("OPENVIBES_LLM_PORT")
        .map_or(DEFAULT_PORT, String::as_str);
    crate::tune_run::Restarter::llm_socket_holds(&crate::tune_run::Systemd, port)?;
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
    fn the_socket_is_enabled_and_a_running_server_stopped_first() {
        assert_eq!(
            SYSTEMCTL_STEPS,
            [
                &[
                    "stop",
                    "openvibes-llm-proxy.service",
                    "openvibes-llm.service"
                ][..],
                &["enable", "--now", "openvibes-llm.socket"],
                &["try-restart", "openvibes-console"],
            ]
        );
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

    fn setup(name: &str) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("ov-as-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let pin = dir.join("model.pin");
        fs::write(
            &pin,
            format!(
                "LLM_MODEL_FILE=m.gguf\nLLM_MODEL_URL=https://example.test/m.gguf\nLLM_MODEL_SHA256={}\nLLM_MODEL_ALIAS=m\nLLM_MODEL_LICENSE_URL=https://example.test/L\n",
                "a".repeat(64)
            ),
        )
        .unwrap();
        (dir.clone(), dir.join("model.conf"), pin)
    }

    #[test]
    fn a_missing_pinned_model_is_fetched_first() {
        let (dir, conf, pin) = setup("fetch");
        let model = dir.join("m.gguf");
        let (conf2, model2) = (conf.clone(), model.clone());
        let mut called = false;
        ensure_model(&conf, &pin, false, || {
            called = true;
            fs::write(&model2, b"x").unwrap();
            fs::write(
                &conf2,
                format!("OPENVIBES_LLM_MODEL={}\n", model2.display()),
            )
            .unwrap();
            Ok(())
        })
        .unwrap();
        assert!(called);
    }

    #[test]
    fn a_present_model_is_not_downloaded() {
        let (dir, conf, pin) = setup("present");
        let model = dir.join("m.gguf");
        fs::write(&model, b"x").unwrap();
        fs::write(&conf, format!("OPENVIBES_LLM_MODEL={}\n", model.display())).unwrap();
        ensure_model(&conf, &pin, false, || Err("must not run".into())).unwrap();
    }

    #[test]
    fn no_download_errors_without_a_command_and_never_fetches() {
        let (_, conf, pin) = setup("nodl");
        let error = ensure_model(&conf, &pin, true, || Err("must not run".into())).unwrap_err();
        assert!(error.contains("turn the assistant on in Setup"), "{error}");
        assert!(error.contains("offline install guide"), "{error}");
        assert!(!error.contains('`'), "{error}");
    }

    #[test]
    fn another_selected_model_that_is_missing_is_not_replaced() {
        let (dir, conf, pin) = setup("other");
        fs::write(
            &conf,
            format!("OPENVIBES_LLM_MODEL={}/other.gguf\n", dir.display()),
        )
        .unwrap();
        let error = ensure_model(&conf, &pin, false, || Err("must not run".into())).unwrap_err();
        assert!(error.contains("is missing"), "{error}");
    }

    #[test]
    fn env_file_later_lines_and_comments() {
        let parsed = parse_env("# A=1\nA=2\nA=3\nB=\"x\"\n");
        assert_eq!(parsed["A"], "3");
        assert_eq!(parsed["B"], "x");
    }
}
