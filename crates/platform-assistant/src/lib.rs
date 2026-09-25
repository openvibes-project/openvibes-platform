#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! The console's assistant (`docs/specs/2026-09-25-assistant-design.md`):
//! configuration, a client for any OpenAI-compatible model backend, and the
//! capability probe. Lookups and the orchestrator follow (AS2).

pub mod client;
pub mod config;
pub mod probe;

pub use client::{
    BackendClient, BackendError, ChatRequest, ChatResponse, FinishReason, JsonSchemaFormat,
    Message, STANDARD_FIELDS, ToolCall, ToolSpec, Usage,
};
pub use config::{
    Assistant, AssistantConfig, Backend, BackendConfig, Budget, ConfigError, DataLocation,
    Location, LookupMode, Profile,
};
pub use probe::{ProbeReport, ResolvedMode, probe};
