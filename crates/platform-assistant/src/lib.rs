#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! The console's assistant (`docs/specs/2026-09-25-assistant-design.md`):
//! configuration, a client for any OpenAI-compatible model backend, the
//! capability probe, the fixed read-only lookups, and the orchestrator that
//! answers one question with them, and the evaluation that gates models.

pub mod answer;
pub mod client;
pub mod config;
pub mod eval;
pub mod lookups;
pub mod orchestrator;
pub mod probe;

pub use answer::{Citation, Segment, plain_text, sanitize};
pub use lookups::{
    Lookup, LookupError, LookupOutput, LookupRunner, Lookups, Source, StoreLookups, StoreSource,
};
pub use orchestrator::{
    Answer, AnswerError, ChatBackend, Event, LookupRecord, Settings, Turn, answer,
};

pub use client::{
    BackendClient, BackendError, ChatRequest, ChatResponse, FinishReason, JsonSchemaFormat,
    Message, STANDARD_FIELDS, ToolCall, ToolSpec, Usage,
};
pub use config::{
    Assistant, AssistantConfig, Backend, BackendConfig, Budget, ConfigError, DataLocation,
    Location, LookupMode, Profile,
};
pub use probe::{ProbeReport, ResolvedMode, probe};
