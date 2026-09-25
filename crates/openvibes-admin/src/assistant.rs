//! `openvibes-admin assistant …`: check the configured model backend and
//! run the quality gate against it (assistant spec §9, §10).

use std::{path::PathBuf, sync::Arc};

use chrono::Utc;
use clap::Subcommand;
use platform_assistant::{
    AssistantConfig, BackendClient, ChatBackend, Location, ProbeReport, Settings,
    eval::{CaseSet, Fleet, evaluate, recommended_models},
    probe,
};
use serde::Deserialize;

/// Where the console reads its configuration, `[assistant]` included.
const CONSOLE_CONFIG: &str = "/etc/openvibes/console.toml";
/// Largest question-set file read.
const MAX_CASES_BYTES: u64 = 1024 * 1024;

#[derive(Subcommand)]
pub enum AssistantCommand {
    /// Connect to the configured backend and report what it supports and
    /// how fast it answers.
    Check {
        /// Configuration file holding the `[assistant]` section.
        #[arg(long, default_value = CONSOLE_CONFIG)]
        file: PathBuf,
    },
    /// Ask the evaluation questions against the evaluation fleet and apply
    /// the quality gate (non-zero exit when it fails). Uses no platform data.
    Eval {
        /// Configuration file holding the `[assistant]` section.
        #[arg(long, default_value = CONSOLE_CONFIG)]
        file: PathBuf,
        /// A question set instead of the built-in one.
        #[arg(long)]
        cases: Option<PathBuf>,
    },
}

impl AssistantCommand {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Check { .. } => "assistant check",
            Self::Eval { .. } => "assistant eval",
        }
    }
}

/// The console configuration file: only `[assistant]` is read here; other
/// sections belong to the console.
#[derive(Deserialize)]
struct ConsoleFile {
    assistant: Option<AssistantConfig>,
}

struct Loaded {
    assistant: platform_assistant::Assistant,
    backend: platform_assistant::Backend,
    client: Arc<BackendClient>,
}

fn load(file: &std::path::Path) -> Result<Loaded, String> {
    let console: ConsoleFile = platform_config::load(file).map_err(|error| error.to_string())?;
    let assistant = console
        .assistant
        .ok_or("no [assistant] section in the configuration file")?
        .validate()
        .map_err(|error| error.to_string())?;
    let backend = assistant
        .backend
        .clone()
        .ok_or("[assistant.backend] is not configured")?;
    let client = BackendClient::new(&backend).map_err(|error| error.to_string())?;
    Ok(Loaded {
        assistant,
        backend,
        client: Arc::new(client),
    })
}

fn location(location: Location) -> &'static str {
    match location {
        Location::Local => "local",
        Location::OwnNetwork => "own network",
        Location::External => "external: prompts leave the organisation",
    }
}

fn supported(result: &Result<bool, platform_assistant::BackendError>) -> String {
    match result {
        Ok(true) => "yes".into(),
        Ok(false) => "no".into(),
        Err(error) => format!("unknown ({error})"),
    }
}

fn describe(loaded: &Loaded, report: &ProbeReport) -> String {
    let backend = &loaded.backend;
    let mut out = format!(
        "backend {} ({})\nmodel {}\n",
        backend.base_url,
        location(backend.location),
        backend.model
    );
    match &report.models {
        Ok(models) => out.push_str(&format!(
            "models listed {} (configured model {})\n",
            models.len(),
            if report.model_listed == Some(true) {
                "listed"
            } else {
                "not listed"
            }
        )),
        Err(error) => out.push_str(&format!("models listed unknown ({error})\n")),
    }
    match report.first_token {
        Some(first) => out.push_str(&format!("first token {:.2} s\n", first.as_secs_f64())),
        None => out.push_str("first token none\n"),
    }
    // A backend that does not stream gives nothing to measure.
    if let Some(rate) = report
        .tokens_per_second
        .or(report.chunks_per_second)
        .filter(|rate| *rate > 0.0)
    {
        out.push_str(&format!("speed {rate:.1} tokens/s\n"));
    }
    out.push_str(&format!(
        "native tool calls {}\njson schema output {}\nlookup mode {:?}{}\nprofile {:?}\n",
        supported(&report.native),
        supported(&report.json_schema),
        report.selected,
        if report.configured_mode_failed {
            " (configured, but its probe failed)"
        } else {
            ""
        },
        loaded.assistant.profile,
    ));
    out
}

fn models_text() -> String {
    let Ok(models) = recommended_models() else {
        return String::new();
    };
    let mut out = String::from("recommended models\n");
    for m in models {
        out.push_str(&format!(
            "  {} ({}, ~{} GB, profile {}): {}; {}\n",
            m.name,
            m.file,
            m.approx_size_gb,
            m.profile,
            m.r#use,
            if m.tested.is_empty() {
                "not yet measured on OpenVIBES".to_owned()
            } else {
                format!("passed the gate {}", m.tested)
            }
        ));
    }
    out
}

async fn probe_blocking(loaded: &Loaded) -> Result<ProbeReport, String> {
    let client = loaded.client.clone();
    let mode = loaded.assistant.lookup_mode;
    tokio::task::spawn_blocking(move || probe(&client, mode))
        .await
        .map_err(|_| "the probe failed".to_owned())
}

/// Runs one assistant command; the target is the configured model.
pub async fn run(command: &AssistantCommand) -> (Result<String, String>, Option<String>) {
    let file = match command {
        AssistantCommand::Check { file } | AssistantCommand::Eval { file, .. } => file,
    };
    let loaded = match load(file) {
        Ok(loaded) => loaded,
        Err(error) => return (Err(error), None),
    };
    let target = Some(loaded.backend.model.clone());
    let report = match probe_blocking(&loaded).await {
        Ok(report) => report,
        Err(error) => return (Err(error), target),
    };
    let described = describe(&loaded, &report);
    // The speed probe is a plain question: if it failed, the backend cannot
    // answer at all.
    if report.first_token.is_none() {
        return (
            Err(format!(
                "{described}the backend did not answer a plain question"
            )),
            target,
        );
    }
    match command {
        AssistantCommand::Check { .. } => (Ok(format!("{described}{}", models_text())), target),
        AssistantCommand::Eval { cases, .. } => {
            let set = match cases {
                Some(path) => read_cases(path),
                None => CaseSet::builtin(),
            };
            let set = match set {
                Ok(set) => set,
                Err(error) => return (Err(error), target),
            };
            let now = Utc::now();
            let fleet = match Fleet::builtin(now) {
                Ok(fleet) => Arc::new(fleet),
                Err(error) => return (Err(error), target),
            };
            let settings = Settings::new(&loaded.assistant, &loaded.backend, report.selected, now);
            let backend: Arc<dyn ChatBackend> = loaded.client.clone();
            let result = evaluate(backend, settings, &set, fleet).await;
            let text = format!("{described}{result}");
            if result.passed() {
                (Ok(text), target)
            } else {
                (Err(text), target)
            }
        }
    }
}

fn read_cases(path: &std::path::Path) -> Result<CaseSet, String> {
    use std::io::Read;
    let mut text = String::new();
    std::fs::File::open(path)
        .and_then(|file| file.take(MAX_CASES_BYTES + 1).read_to_string(&mut text))
        .map_err(|_| "cannot read the question set".to_owned())?;
    if text.len() as u64 > MAX_CASES_BYTES {
        return Err("the question set exceeds 1 MiB".into());
    }
    CaseSet::parse(&text)
}
