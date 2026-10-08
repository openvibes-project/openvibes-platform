#![forbid(unsafe_code)]

//! `openvibes-llm-check`: `ExecStartPre=` of `openvibes-llm.service` (the
//! full check), `--idle-only` for `openvibes-llm-proxy.service` (idle time
//! and ports, no model), `--wait-ready` as `openvibes-llm.service`'s
//! `ExecStartPost=` (until the model answers).

use std::{collections::BTreeMap, path::Path, process::ExitCode, time::Duration};

use openvibes_llm::{
    CheckError, MODELS_DIR, check_environment, check_model, proxy_settings, running_as_root,
    settings, wait_ready,
};

fn main() -> ExitCode {
    let mode = std::env::args().nth(1);
    if std::env::args().count() > 2
        || !matches!(mode.as_deref(), None | Some("--idle-only" | "--wait-ready"))
    {
        eprintln!("usage: openvibes-llm-check [--idle-only | --wait-ready]");
        return ExitCode::FAILURE;
    }
    let run = || -> Result<String, CheckError> {
        if running_as_root() {
            return Err(CheckError::Root);
        }
        let all: Vec<(String, String)> = std::env::vars_os()
            .map(|(name, value)| {
                (
                    name.to_string_lossy().into_owned(),
                    value.to_string_lossy().into_owned(),
                )
            })
            .collect();
        check_environment(all.iter().map(|(name, _)| name.as_str()))?;
        let env: BTreeMap<String, String> = all
            .into_iter()
            .filter(|(name, _)| name.starts_with("OPENVIBES_LLM_"))
            .collect();
        match mode.as_deref() {
            Some("--idle-only") => {
                let proxy = proxy_settings(&env)?;
                return Ok(format!(
                    "openvibes-llm-check: 127.0.0.1:{} -> 127.0.0.1:{}, idle {}",
                    proxy.port,
                    proxy.internal_port,
                    proxy
                        .idle_seconds
                        .map_or_else(|| "infinity".into(), |s| format!("{s} s"))
                ));
            }
            Some(_) => {
                let port = proxy_settings(&env)?.internal_port;
                wait_ready(port, Duration::from_millis(500), Duration::from_secs(180))?;
                return Ok(format!("openvibes-llm-check: ready on 127.0.0.1:{port}"));
            }
            None => {}
        }
        let settings = settings(&env, Path::new(MODELS_DIR))?;
        let size = check_model(&settings)?;
        Ok(format!(
            "openvibes-llm-check: model {} ({} MiB) verified; serving as {} on 127.0.0.1:{}",
            settings.model.display(),
            size >> 20,
            settings.alias,
            settings.port
        ))
    };
    match run() {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("openvibes-llm-check: {error}");
            ExitCode::FAILURE
        }
    }
}
