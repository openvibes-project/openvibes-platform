//! The capability probe (spec §9): what a backend supports and how fast it
//! answers, measured with fixed prompts. `openvibes-admin assistant check`
//! prints it; with `lookup_mode = "auto"` it chooses the lookup mode.

use std::time::Duration;

use serde_json::{Value, json};

use crate::{
    client::{BackendClient, BackendError, ChatRequest, JsonSchemaFormat, Message, ToolSpec},
    config::LookupMode,
};

/// A lookup mode the orchestrator can use (never `auto`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolvedMode {
    /// The API's tool calls.
    Native,
    /// Output constrained to a JSON schema.
    JsonSchema,
    /// Instructions only, validated afterwards.
    Prompted,
}

/// What the probe found.
#[derive(Clone, Debug, PartialEq)]
pub struct ProbeReport {
    /// Models the backend lists, or why it could not list them.
    pub models: Result<Vec<String>, BackendError>,
    /// Whether the configured model is among them (`None` if not listed).
    pub model_listed: Option<bool>,
    /// Time until the first streamed text of the speed prompt.
    pub first_token: Option<Duration>,
    /// Streamed text pieces per second after the first (about one token
    /// each on most runtimes).
    pub chunks_per_second: Option<f64>,
    /// Tokens per second after the first, when the backend reports usage.
    pub tokens_per_second: Option<f64>,
    /// Whether native tool calls worked; an error means the probe could not
    /// tell.
    pub native: Result<bool, BackendError>,
    /// Whether JSON-schema output worked.
    pub json_schema: Result<bool, BackendError>,
    /// The mode the orchestrator will use.
    pub selected: ResolvedMode,
    /// Whether an explicitly configured mode failed its probe.
    pub configured_mode_failed: bool,
}

const PROBE_TOOL: &str = "lookup_probe";

fn word_schema() -> Value {
    json!({
        "type": "object",
        "properties": { "word": { "type": "string", "enum": ["alpha", "beta"] } },
        "required": ["word"],
        "additionalProperties": false,
    })
}

/// Whether `text` is exactly `{"word": "beta"}` as JSON.
fn says_beta(text: &str) -> bool {
    serde_json::from_str::<Value>(text.trim())
        .ok()
        .and_then(|value| {
            value
                .get("word")
                .and_then(Value::as_str)
                .map(|w| w == "beta")
        })
        .unwrap_or(false)
}

/// A refused request means "not supported"; anything else is an error.
fn supported(result: Result<bool, BackendError>) -> Result<bool, BackendError> {
    match result {
        Err(BackendError::Rejected) => Ok(false),
        other => other,
    }
}

/// Runs every probe against `client`, then resolves `configured` (an
/// explicit mode is kept even if its probe failed, and flagged).
pub fn probe(client: &BackendClient, configured: LookupMode) -> ProbeReport {
    let models = client.models();
    let model_listed = models
        .as_ref()
        .ok()
        .map(|names| names.iter().any(|name| name == client.model()));

    let speed = client.chat(
        &ChatRequest {
            messages: vec![
                Message::System("You answer briefly.".into()),
                Message::User("Count from 1 to 30, separated by spaces.".into()),
            ],
            tools: Vec::new(),
            response_format: None,
            max_tokens: 96,
            temperature: 0.0,
        },
        |_| {},
    );
    let (first_token, chunks_per_second, tokens_per_second) = match &speed {
        Ok(response) => {
            let writing = response
                .first_token
                .map(|first| response.elapsed.saturating_sub(first).as_secs_f64())
                .filter(|seconds| *seconds > 0.0);
            let rate = |count: f64| writing.map(|seconds| (count - 1.0).max(0.0) / seconds);
            (
                response.first_token,
                rate(f64::from(response.chunks)),
                response
                    .usage
                    .and_then(|usage| rate(usage.completion_tokens as f64)),
            )
        }
        Err(_) => (None, None, None),
    };

    let native = supported(
        client
            .chat(
                &ChatRequest {
                    messages: vec![
                        Message::System(format!("Always answer by calling the tool {PROBE_TOOL}.")),
                        Message::User(format!("Call {PROBE_TOOL} with the word beta.")),
                    ],
                    tools: vec![ToolSpec {
                        name: PROBE_TOOL.into(),
                        description: "Records one word.".into(),
                        parameters: word_schema(),
                    }],
                    response_format: None,
                    max_tokens: 96,
                    temperature: 0.0,
                },
                |_| {},
            )
            .map(|response| {
                response
                    .tool_calls
                    .first()
                    .is_some_and(|call| call.name == PROBE_TOOL && says_beta(&call.arguments))
            }),
    );

    let json_schema = supported(
        client
            .chat(
                &ChatRequest {
                    messages: vec![
                        Message::System("You answer only with JSON.".into()),
                        Message::User("Answer with the word beta.".into()),
                    ],
                    tools: Vec::new(),
                    response_format: Some(JsonSchemaFormat {
                        name: "word".into(),
                        schema: word_schema(),
                    }),
                    max_tokens: 64,
                    temperature: 0.0,
                },
                |_| {},
            )
            .map(|response| says_beta(&response.content)),
    );

    let works = |result: &Result<bool, BackendError>| matches!(result, Ok(true));
    let (selected, configured_mode_failed) = match configured {
        LookupMode::Auto => (
            if works(&native) {
                ResolvedMode::Native
            } else if works(&json_schema) {
                ResolvedMode::JsonSchema
            } else {
                ResolvedMode::Prompted
            },
            false,
        ),
        LookupMode::Native => (ResolvedMode::Native, !works(&native)),
        LookupMode::JsonSchema => (ResolvedMode::JsonSchema, !works(&json_schema)),
        LookupMode::Prompted => (ResolvedMode::Prompted, false),
    };
    ProbeReport {
        models,
        model_listed,
        first_token,
        chunks_per_second,
        tokens_per_second,
        native,
        json_schema,
        selected,
        configured_mode_failed,
    }
}
