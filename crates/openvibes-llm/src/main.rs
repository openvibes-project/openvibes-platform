#![forbid(unsafe_code)]

//! `openvibes-llm-check`: `ExecStartPre=` of `openvibes-llm.service` (the
//! full check), `--idle-only` for `openvibes-llm-proxy.service` (the idle
//! time, no model), `--wait-ready` as `openvibes-llm.service`'s
//! `ExecStartPost=` (until the model answers).

use std::{collections::BTreeMap, path::Path, process::ExitCode, time::Duration};

use openvibes_llm::{
    CheckError, LLAMA_SOCKET, MODELS_DIR, check_environment, check_model, idle_setting,
    running_as_root, settings, wait_ready,
};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = args.first().cloned();
    let usage = !matches!(
        args.iter().map(String::as_str).collect::<Vec<_>>()[..],
        [] | ["--idle-only"] | ["--wait-ready"] | ["--wait-ready", _]
    );
    if usage {
        eprintln!("usage: openvibes-llm-check [--idle-only | --wait-ready [SOCKET]]");
        return ExitCode::FAILURE;
    }
    // The unit names the socket it gives llama-server's --host.
    let socket = args.get(1).map_or(LLAMA_SOCKET, String::as_str);
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
                let idle = idle_setting(&env)?;
                return Ok(format!(
                    "openvibes-llm-check: idle {}",
                    idle.map_or_else(|| "infinity".into(), |s| format!("{s} s"))
                ));
            }
            Some(_) => {
                wait_ready(
                    Path::new(socket),
                    Duration::from_millis(500),
                    Duration::from_secs(180),
                )?;
                return Ok(format!("openvibes-llm-check: ready on {socket}"));
            }
            None => {}
        }
        let settings = settings(&env, Path::new(MODELS_DIR))?;
        let size = check_model(&settings)?;
        Ok(format!(
            "openvibes-llm-check: model {} ({} MiB) verified; serving as {} on 127.0.0.1:{} (socket)",
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
