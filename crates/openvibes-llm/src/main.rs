#![forbid(unsafe_code)]

//! `openvibes-llm-check`: `ExecStartPre=` of `openvibes-llm.service`.

use std::{collections::BTreeMap, path::Path, process::ExitCode};

use openvibes_llm::{
    CheckError, MODELS_DIR, check_environment, check_model, running_as_root, settings,
};

fn main() -> ExitCode {
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
