//! The assistant: the chat endpoints, its runtime and the lookups it may run
//! within the asker's permissions, and the administrator's switch for
//! internet lookups.

pub(crate) mod chat;
pub(crate) mod internet;
mod internet_types;
mod lookups;
mod runtime;
mod types;

#[cfg(test)]
mod internet_tests;
#[cfg(test)]
mod lookup_tests;

pub(crate) use lookups::{Access, ConsoleReadLookups};
pub(crate) use runtime::{AssistantRuntime, LeasedChatBackend};
pub(crate) use types::{
    AssistantInternetSource, AssistantLookup, AssistantMessageRequest, AssistantMessageResponse,
    AssistantSegment, AssistantStatusResponse, ClientTurn, encode_component, internet_sources,
};

pub use internet_types::{
    AssistantInternet, AssistantInternetTest, UpdateAssistantInternetRequest,
};
