//! The assistant: the chat endpoints, its runtime and the lookups it may run
//! within the asker's permissions, and the administrator's switch for
//! internet lookups.

use axum::{
    Router,
    routing::{get, post},
};

use crate::http::AuthHttpState;

pub(crate) mod chat;
pub(crate) mod fetch_client;
pub(crate) mod internet;
mod internet_types;
mod lookups;
mod runtime;
pub(crate) mod stored;
mod types;

#[cfg(test)]
mod internet_tests;
#[cfg(test)]
mod lookup_tests;
#[cfg(test)]
mod stored_tests;

pub(crate) use lookups::{Access, ConsoleReadLookups};
pub(crate) use runtime::{AssistantRuntime, LeasedChatBackend};
pub(crate) use types::{
    AssistantInternetSource, AssistantLookup, AssistantMessageRequest, AssistantMessageResponse,
    AssistantSegment, AssistantStatusResponse, ClientTurn, encode_component, internet_sources,
};

pub use internet_types::{
    AssistantInternet, AssistantInternetTest, UpdateAssistantInternetRequest,
};

/// The chat endpoints and the administrator's internet-lookup switch.
pub(crate) fn routes() -> Router<AuthHttpState> {
    Router::new()
        .route(
            "/v1/assistant/status",
            get(chat::authenticated_assistant_status),
        )
        .route(
            "/v1/assistant/messages",
            post(chat::authenticated_assistant_message),
        )
        .route(
            "/v1/assistant-internet",
            get(internet::get_assistant_internet).put(internet::update_assistant_internet),
        )
        .route(
            "/v1/assistant-internet/test",
            post(internet::test_assistant_internet),
        )
}
