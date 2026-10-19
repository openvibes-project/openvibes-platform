//! The demo's agent summary, list and detail.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, Query, State, rejection::QueryRejection},
    http::HeaderMap,
    response::{IntoResponse, Response},
};

use super::{
    filters::{AgentFilters, RawAgentFilters, parse_query},
    persona::context,
    repository::ConsoleRepository,
    responses::not_found,
};
use crate::Permission;

pub(super) async fn agent_summary(
    State(repository): State<Arc<dyn ConsoleRepository>>,
    headers: HeaderMap,
) -> Response {
    let (persona, mode) = match context(&headers, Permission::HostsRead) {
        Ok(context) => context,
        Err(response) => return *response,
    };
    (Json(repository.agent_summary(persona, mode))).into_response()
}

pub(super) async fn agents(
    State(repository): State<Arc<dyn ConsoleRepository>>,
    headers: HeaderMap,
    query: Result<Query<RawAgentFilters>, QueryRejection>,
) -> Response {
    let (persona, mode) = match context(&headers, Permission::HostsRead) {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let filters = match parse_query(query).and_then(AgentFilters::try_from) {
        Ok(filters) => filters,
        Err(response) => return *response,
    };
    (Json(repository.agents(&filters, persona, mode))).into_response()
}

pub(super) async fn agent(
    State(repository): State<Arc<dyn ConsoleRepository>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (persona, mode) = match context(&headers, Permission::HostsRead) {
        Ok(context) => context,
        Err(response) => return *response,
    };
    repository
        .agent(&id, persona, mode)
        .map_or_else(not_found, |agent| Json(agent).into_response())
}
