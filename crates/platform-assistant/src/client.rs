//! A blocking client for OpenAI-compatible Chat Completions backends
//! (spec §3, §6). It sends only standard request fields, so any compatible
//! runtime can serve it (spec §10), and it treats every byte it receives as
//! untrusted: streamed answers are read line by line under fixed size
//! limits, and no error ever echoes backend content.
//!
//! Blocking by design (`ureq`, as `openvibes-vulns`); the async console
//! calls it from a blocking thread.

use std::{
    fmt,
    io::{self, BufRead, BufReader, Read},
    sync::Arc,
    time::{Duration, Instant},
};

use rustls::{SupportedCipherSuite, crypto::CryptoProvider};
use serde::Deserialize;
use serde_json::{Value, json};
use ureq::{
    Agent,
    tls::{Certificate, ClientCert, PemItem, PrivateKey, RootCerts, TlsConfig, TlsProvider},
};

use crate::config::{Backend, Location};

/// The only top-level request fields the client ever sends: all standard
/// Chat Completions fields (spec §10).
pub const STANDARD_FIELDS: &[&str] = &[
    "model",
    "messages",
    "stream",
    "stream_options",
    "max_tokens",
    "temperature",
    "tools",
    "tool_choice",
    "response_format",
];

/// Largest streamed or plain response body.
const MAX_BODY: u64 = 8 * 1024 * 1024;
/// Longest single line of a streamed response.
const MAX_LINE: u64 = 256 * 1024;
/// Largest answer text kept.
const MAX_CONTENT: usize = 256 * 1024;
/// Most tool calls in one answer.
const MAX_TOOL_CALLS: usize = 8;
/// Longest tool-call arguments string.
const MAX_ARGUMENTS: usize = 16 * 1024;
/// Longest tool name or call ID.
const MAX_NAME: usize = 128;
/// Largest `/models` response.
const MAX_MODELS_BODY: u64 = 256 * 1024;
/// Most model names read from `/models`.
const MAX_MODELS: usize = 200;

/// Fixed failure categories. None carries backend content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendError {
    /// The certificate, key, or proxy configuration could not be used.
    InvalidConfig,
    /// The backend could not be reached.
    Connect,
    /// TLS failed: untrusted certificate, protocol mismatch, or a refused
    /// client certificate.
    Tls,
    /// The request deadline passed.
    Timeout,
    /// The backend refused the credentials (401 or 403).
    Unauthorized,
    /// The backend does not know the model or route (404).
    NotFound,
    /// The backend is rate limiting (429).
    RateLimited,
    /// The backend refused the request (another 4xx, or a redirect, which is
    /// never followed). A probe treats this as "not supported".
    Rejected,
    /// The backend failed (5xx).
    Unavailable,
    /// The response exceeded a size limit.
    ResponseTooLarge,
    /// The response was malformed or ended early.
    InvalidResponse,
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfig => "assistant backend: invalid certificate, key, or proxy",
            Self::Connect => "assistant backend: connection failed",
            Self::Tls => "assistant backend: TLS failed",
            Self::Timeout => "assistant backend: deadline passed",
            Self::Unauthorized => "assistant backend: credentials refused",
            Self::NotFound => "assistant backend: model or route not found",
            Self::RateLimited => "assistant backend: rate limited",
            Self::Rejected => "assistant backend: request refused",
            Self::Unavailable => "assistant backend: server error",
            Self::ResponseTooLarge => "assistant backend: response too large",
            Self::InvalidResponse => "assistant backend: invalid response",
        })
    }
}

impl std::error::Error for BackendError {}

impl From<ureq::Error> for BackendError {
    fn from(error: ureq::Error) -> Self {
        use ureq::Error as E;
        match error {
            E::Timeout(_) => Self::Timeout,
            E::Io(error) => io_error(&error),
            E::Tls(_) | E::Rustls(_) | E::Pem(_) => Self::Tls,
            E::BodyExceedsLimit(_) | E::LargeResponseHeader(..) => Self::ResponseTooLarge,
            E::TooManyRedirects | E::RedirectFailed => Self::Rejected,
            E::InvalidProxyUrl => Self::InvalidConfig,
            _ => Self::Connect,
        }
    }
}

/// Maps an I/O error from the connection or body, looking through to the
/// `ureq` or `rustls` error inside it.
fn io_error(error: &io::Error) -> BackendError {
    if error.kind() == io::ErrorKind::TimedOut {
        return BackendError::Timeout;
    }
    match error.get_ref() {
        Some(inner) if inner.is::<rustls::Error>() => BackendError::Tls,
        Some(inner) => match inner.downcast_ref::<ureq::Error>() {
            Some(ureq::Error::BodyExceedsLimit(_)) => BackendError::ResponseTooLarge,
            Some(ureq::Error::Timeout(_)) => BackendError::Timeout,
            Some(ureq::Error::Io(inner)) => io_error(inner),
            Some(ureq::Error::Tls(_) | ureq::Error::Rustls(_)) => BackendError::Tls,
            _ => BackendError::Connect,
        },
        None => BackendError::Connect,
    }
}

/// One message of a conversation.
#[derive(Clone, Debug, PartialEq)]
pub enum Message {
    /// Instructions.
    System(String),
    /// The user's words.
    User(String),
    /// An earlier answer, possibly with the lookups it requested.
    Assistant {
        /// Its text, if any.
        content: Option<String>,
        /// Its lookup requests.
        tool_calls: Vec<ToolCall>,
    },
    /// The result of one lookup.
    Tool {
        /// The call it answers.
        call_id: String,
        /// The result, as text.
        content: String,
    },
}

/// A lookup the model may request, described by a JSON schema.
#[derive(Clone, Debug, PartialEq)]
pub struct ToolSpec {
    /// Name.
    pub name: String,
    /// What it does, for the model.
    pub description: String,
    /// JSON schema of its arguments.
    pub parameters: Value,
}

/// A JSON schema the whole answer must follow.
#[derive(Clone, Debug, PartialEq)]
pub struct JsonSchemaFormat {
    /// Schema name.
    pub name: String,
    /// The schema.
    pub schema: Value,
}

/// A request for one answer.
#[derive(Clone, Debug, PartialEq)]
pub struct ChatRequest {
    /// The conversation.
    pub messages: Vec<Message>,
    /// Lookups offered as native tools; empty for none.
    pub tools: Vec<ToolSpec>,
    /// Constrain the answer to a schema.
    pub response_format: Option<JsonSchemaFormat>,
    /// Most tokens to write.
    pub max_tokens: u32,
    /// Sampling temperature.
    pub temperature: f32,
}

/// A lookup the model requested.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolCall {
    /// Call ID, echoed in the result message.
    pub id: String,
    /// Lookup name (unchecked: the orchestrator validates it).
    pub name: String,
    /// Arguments as a JSON string (unchecked).
    pub arguments: String,
}

/// Why the backend stopped writing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FinishReason {
    /// A natural end.
    Stop,
    /// It hit `max_tokens`.
    Length,
    /// It requested lookups.
    ToolCalls,
    /// Anything else, or not reported.
    Other,
}

/// Token counts, when the backend reports them.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub struct Usage {
    /// Tokens read.
    #[serde(default)]
    pub prompt_tokens: u64,
    /// Tokens written.
    #[serde(default)]
    pub completion_tokens: u64,
}

/// One complete answer.
#[derive(Clone, Debug, PartialEq)]
pub struct ChatResponse {
    /// Answer text (untrusted).
    pub content: String,
    /// Requested lookups (untrusted).
    pub tool_calls: Vec<ToolCall>,
    /// Why it stopped.
    pub finish: FinishReason,
    /// Token counts, if reported.
    pub usage: Option<Usage>,
    /// Time from sending until the first answer text or lookup arrived.
    pub first_token: Option<Duration>,
    /// Time from sending until the answer was complete.
    pub elapsed: Duration,
    /// Streamed pieces of answer text received.
    pub chunks: u32,
}

/// A client for one configured backend.
pub struct BackendClient {
    agent: Agent,
    chat_url: String,
    models_url: String,
    model: String,
    api_key: Option<String>,
}

impl fmt::Debug for BackendClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackendClient")
            .field("chat_url", &self.chat_url)
            .field("model", &self.model)
            .finish_non_exhaustive()
    }
}

/// The `ring` provider restricted to TLS 1.3 cipher suites.
fn tls13_only() -> Arc<CryptoProvider> {
    let mut provider = rustls::crypto::ring::default_provider();
    provider
        .cipher_suites
        .retain(|suite| matches!(suite, SupportedCipherSuite::Tls13(_)));
    Arc::new(provider)
}

fn certificates(pem: &[u8]) -> Result<Vec<Certificate<'static>>, BackendError> {
    let certs = ureq::tls::parse_pem(pem)
        .filter_map(|item| match item {
            Ok(PemItem::Certificate(certificate)) => Some(Ok(certificate)),
            Ok(_) => None,
            Err(_) => Some(Err(BackendError::InvalidConfig)),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(BackendError::InvalidConfig);
    }
    Ok(certs)
}

impl BackendClient {
    /// Builds a client: TLS 1.3 only, the configured CAs (public roots only
    /// for an external backend without `ca_file`), optional mutual TLS, no
    /// redirects, no proxy but the configured one, and the deadline for
    /// the whole request.
    pub fn new(backend: &Backend) -> Result<Self, BackendError> {
        let roots = match &backend.ca_pem {
            Some(pem) => RootCerts::new_with_certs(&certificates(pem)?),
            None => RootCerts::WebPki,
        };
        let client_cert = match &backend.client_identity {
            Some((chain, key)) => Some(ClientCert::new_with_certs(
                &certificates(chain)?,
                PrivateKey::from_pem(key).map_err(|_| BackendError::InvalidConfig)?,
            )),
            None => None,
        };
        let tls = TlsConfig::builder()
            .provider(TlsProvider::Rustls)
            .unversioned_rustls_crypto_provider(tls13_only())
            .root_certs(roots)
            .client_cert(client_cert)
            .build();
        let proxy = backend
            .proxy_url
            .as_deref()
            .map(ureq::Proxy::new)
            .transpose()
            .map_err(|_| BackendError::InvalidConfig)?;
        let agent: Agent = Agent::config_builder()
            .tls_config(tls)
            .https_only(backend.location != Location::Local)
            .max_redirects(0)
            .proxy(proxy)
            .http_status_as_error(false)
            .timeout_connect(Some(backend.deadline.min(Duration::from_secs(10))))
            .timeout_global(Some(backend.deadline))
            .max_response_header_size(16 * 1024)
            .user_agent(concat!("openvibes-assistant/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        Ok(Self {
            agent,
            chat_url: format!("{}/chat/completions", backend.base_url),
            models_url: format!("{}/models", backend.base_url),
            model: backend.model.clone(),
            api_key: backend.api_key.clone(),
        })
    }

    /// The request body: only [`STANDARD_FIELDS`].
    #[must_use]
    pub fn request_body(&self, request: &ChatRequest) -> Value {
        let messages: Vec<Value> = request.messages.iter().map(message_json).collect();
        let mut body = json!({
            "model": self.model,
            "messages": messages,
            "stream": true,
            "stream_options": { "include_usage": true },
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
        });
        if !request.tools.is_empty() {
            body["tools"] = request
                .tools
                .iter()
                .map(|tool| {
                    json!({
                        "type": "function",
                        "function": {
                            "name": tool.name,
                            "description": tool.description,
                            "parameters": tool.parameters,
                        },
                    })
                })
                .collect();
            body["tool_choice"] = json!("auto");
        }
        if let Some(format) = &request.response_format {
            body["response_format"] = json!({
                "type": "json_schema",
                "json_schema": { "name": format.name, "schema": format.schema, "strict": true },
            });
        }
        body
    }

    /// Sends `request` and reads the streamed answer, calling `on_text` with
    /// each piece of answer text as it arrives. A backend that answers
    /// without streaming is accepted too.
    pub fn chat(
        &self,
        request: &ChatRequest,
        mut on_text: impl FnMut(&str),
    ) -> Result<ChatResponse, BackendError> {
        let body = serde_json::to_vec(&self.request_body(request))
            .map_err(|_| BackendError::InvalidResponse)?;
        let started = Instant::now();
        let mut call = self
            .agent
            .post(&self.chat_url)
            .header("content-type", "application/json")
            .header("accept", "text/event-stream");
        if let Some(key) = &self.api_key {
            call = call.header("authorization", &format!("Bearer {key}"));
        }
        let mut response = call.send(&body[..])?;
        check_status(response.status().as_u16())?;
        let streaming = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("text/event-stream"));
        let reader = response.body_mut().with_config().limit(MAX_BODY).reader();
        let mut answer = Accumulator::new(started);
        if streaming {
            read_stream(reader, &mut answer, &mut on_text)?;
        } else {
            let mut bytes = Vec::new();
            BufReader::new(reader)
                .read_to_end(&mut bytes)
                .map_err(|error| io_error(&error))?;
            let chunk: Chunk =
                serde_json::from_slice(&bytes).map_err(|_| BackendError::InvalidResponse)?;
            answer.apply(chunk, &mut on_text)?;
            answer.done = true;
        }
        answer.finish()
    }

    /// Model names the backend lists at `/models` (at most 200).
    pub fn models(&self) -> Result<Vec<String>, BackendError> {
        let mut call = self.agent.get(&self.models_url);
        if let Some(key) = &self.api_key {
            call = call.header("authorization", &format!("Bearer {key}"));
        }
        let mut response = call.call()?;
        check_status(response.status().as_u16())?;
        let bytes = response
            .body_mut()
            .with_config()
            .limit(MAX_MODELS_BODY)
            .read_to_vec()?;
        #[derive(Deserialize)]
        struct Models {
            data: Vec<ModelEntry>,
        }
        #[derive(Deserialize)]
        struct ModelEntry {
            id: String,
        }
        let models: Models =
            serde_json::from_slice(&bytes).map_err(|_| BackendError::InvalidResponse)?;
        Ok(models
            .data
            .into_iter()
            .map(|entry| entry.id)
            .filter(|id| !id.is_empty() && id.len() <= 256 && !id.chars().any(char::is_control))
            .take(MAX_MODELS)
            .collect())
    }

    /// The configured model name.
    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }
}

fn check_status(status: u16) -> Result<(), BackendError> {
    match status {
        200..=299 => Ok(()),
        401 | 403 => Err(BackendError::Unauthorized),
        404 => Err(BackendError::NotFound),
        429 => Err(BackendError::RateLimited),
        500..=599 => Err(BackendError::Unavailable),
        // Other 4xx, and 3xx: redirects are never followed.
        _ => Err(BackendError::Rejected),
    }
}

fn message_json(message: &Message) -> Value {
    match message {
        Message::System(text) => json!({ "role": "system", "content": text }),
        Message::User(text) => json!({ "role": "user", "content": text }),
        Message::Assistant {
            content,
            tool_calls,
        } => {
            let mut value = json!({ "role": "assistant", "content": content });
            if !tool_calls.is_empty() {
                value["tool_calls"] = tool_calls
                    .iter()
                    .map(|call| {
                        json!({
                            "id": call.id,
                            "type": "function",
                            "function": { "name": call.name, "arguments": call.arguments },
                        })
                    })
                    .collect();
            }
            value
        }
        Message::Tool { call_id, content } => {
            json!({ "role": "tool", "tool_call_id": call_id, "content": content })
        }
    }
}

/// Reads server-sent events: `data:` lines joined per event, comments and
/// other fields ignored, `[DONE]` ends the answer. Every line is bounded.
fn read_stream(
    reader: impl Read,
    answer: &mut Accumulator,
    on_text: &mut impl FnMut(&str),
) -> Result<(), BackendError> {
    let mut reader = BufReader::new(reader);
    let mut data = String::new();
    let mut line = Vec::new();
    loop {
        line.clear();
        let read = (&mut reader)
            .take(MAX_LINE + 1)
            .read_until(b'\n', &mut line)
            .map_err(|error| io_error(&error))?;
        if read as u64 > MAX_LINE {
            return Err(BackendError::ResponseTooLarge);
        }
        let end_of_body = read == 0;
        let text = std::str::from_utf8(&line).map_err(|_| BackendError::InvalidResponse)?;
        let text = text.trim_end_matches(['\r', '\n']);
        if text.is_empty() {
            // Blank line (or end of body): the event is complete.
            if !data.is_empty() {
                if data == "[DONE]" {
                    answer.done = true;
                    return Ok(());
                }
                let chunk: Chunk =
                    serde_json::from_str(&data).map_err(|_| BackendError::InvalidResponse)?;
                answer.apply(chunk, on_text)?;
                data.clear();
            }
            if end_of_body {
                return Ok(());
            }
            continue;
        }
        if let Some(value) = text.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(value.strip_prefix(' ').unwrap_or(value));
            if data.len() as u64 > MAX_LINE {
                return Err(BackendError::ResponseTooLarge);
            }
        }
        // Comments (`:`), `event:`, `id:`, and `retry:` lines are ignored.
    }
}

#[derive(Deserialize)]
struct Chunk {
    #[serde(default)]
    choices: Vec<Choice>,
    usage: Option<Usage>,
    error: Option<Value>,
}

#[derive(Deserialize)]
struct Choice {
    delta: Option<Delta>,
    message: Option<Delta>,
    finish_reason: Option<String>,
}

#[derive(Deserialize)]
struct Delta {
    content: Option<String>,
    tool_calls: Option<Vec<ToolCallDelta>>,
}

#[derive(Deserialize)]
struct ToolCallDelta {
    index: Option<usize>,
    id: Option<String>,
    function: Option<FunctionDelta>,
}

#[derive(Deserialize)]
struct FunctionDelta {
    name: Option<String>,
    arguments: Option<String>,
}

/// Builds one answer from streamed pieces, enforcing every limit.
struct Accumulator {
    started: Instant,
    content: String,
    calls: Vec<ToolCall>,
    finish: Option<FinishReason>,
    usage: Option<Usage>,
    first_token: Option<Duration>,
    chunks: u32,
    done: bool,
}

impl Accumulator {
    fn new(started: Instant) -> Self {
        Self {
            started,
            content: String::new(),
            calls: Vec::new(),
            finish: None,
            usage: None,
            first_token: None,
            chunks: 0,
            done: false,
        }
    }

    fn apply(&mut self, chunk: Chunk, on_text: &mut impl FnMut(&str)) -> Result<(), BackendError> {
        if chunk.error.is_some() {
            return Err(BackendError::InvalidResponse);
        }
        if let Some(usage) = chunk.usage {
            self.usage = Some(usage);
        }
        // One answer is requested; only the first choice counts.
        let Some(choice) = chunk.choices.into_iter().next() else {
            return Ok(());
        };
        if let Some(reason) = choice.finish_reason {
            self.finish = Some(match reason.as_str() {
                "stop" => FinishReason::Stop,
                "length" => FinishReason::Length,
                "tool_calls" | "function_call" => FinishReason::ToolCalls,
                _ => FinishReason::Other,
            });
        }
        let Some(delta) = choice.delta.or(choice.message) else {
            return Ok(());
        };
        if let Some(text) = delta.content.filter(|text| !text.is_empty()) {
            if self.content.len() + text.len() > MAX_CONTENT {
                return Err(BackendError::ResponseTooLarge);
            }
            self.mark_first();
            self.chunks = self.chunks.saturating_add(1);
            self.content.push_str(&text);
            on_text(&text);
        }
        for (position, call) in delta.tool_calls.unwrap_or_default().into_iter().enumerate() {
            self.mark_first();
            let index = call.index.unwrap_or(position);
            if index >= MAX_TOOL_CALLS {
                return Err(BackendError::InvalidResponse);
            }
            while self.calls.len() <= index {
                self.calls.push(ToolCall {
                    id: String::new(),
                    name: String::new(),
                    arguments: String::new(),
                });
            }
            let slot = &mut self.calls[index];
            if let Some(id) = call.id {
                slot.id = id;
            }
            if let Some(function) = call.function {
                if let Some(name) = function.name {
                    slot.name.push_str(&name);
                }
                if let Some(arguments) = function.arguments {
                    slot.arguments.push_str(&arguments);
                }
            }
            if slot.id.len() > MAX_NAME
                || slot.name.len() > MAX_NAME
                || slot.arguments.len() > MAX_ARGUMENTS
            {
                return Err(BackendError::ResponseTooLarge);
            }
        }
        Ok(())
    }

    fn mark_first(&mut self) {
        if self.first_token.is_none() {
            self.first_token = Some(self.started.elapsed());
        }
    }

    /// The answer, if it ended properly: `[DONE]` or a finish reason. A
    /// stream cut off mid-answer is refused, never used as a partial answer.
    fn finish(mut self) -> Result<ChatResponse, BackendError> {
        if !self.done && self.finish.is_none() {
            return Err(BackendError::InvalidResponse);
        }
        for (index, call) in self.calls.iter_mut().enumerate() {
            if call.name.is_empty() {
                return Err(BackendError::InvalidResponse);
            }
            if call.id.is_empty() {
                call.id = format!("call_{index}");
            }
        }
        Ok(ChatResponse {
            content: self.content,
            tool_calls: self.calls,
            finish: self.finish.unwrap_or(FinishReason::Other),
            usage: self.usage,
            first_token: self.first_token,
            elapsed: self.started.elapsed(),
            chunks: self.chunks,
        })
    }
}
