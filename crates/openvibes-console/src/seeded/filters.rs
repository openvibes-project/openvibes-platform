//! Query filters of the agent and finding lists, and their cursor paging.

use axum::extract::{Query, rejection::QueryRejection};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;

use super::{
    repository::{GENERATED_AT, MAX_AGENTS},
    responses::{SeedError, bad_request},
};
use crate::{AgentStatus, CursorPage, CursorPagination, Severity};

const DEFAULT_LIMIT: u16 = 50;
const MAX_SEARCH_LENGTH: usize = 128;

#[derive(Clone, Debug)]
pub(super) struct AgentFilters {
    pub(super) page: CursorPagination,
    pub(super) query: Option<String>,
    pub(super) status: Option<AgentStatus>,
}

#[derive(Clone, Debug)]
pub(super) struct FindingFilters {
    pub(super) page: CursorPagination,
    pub(super) query: Option<String>,
    pub(super) severity: Option<Severity>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawAgentFilters {
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default = "default_limit")]
    limit: u16,
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    status: Option<AgentStatus>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawFindingFilters {
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default = "default_limit")]
    limit: u16,
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    severity: Option<Severity>,
}

impl TryFrom<RawAgentFilters> for AgentFilters {
    type Error = SeedError;

    fn try_from(raw: RawAgentFilters) -> Result<Self, Self::Error> {
        Ok(Self {
            page: pagination(raw.cursor, raw.limit, "agents")?,
            query: bounded_query(raw.q)?,
            status: raw.status,
        })
    }
}

impl TryFrom<RawFindingFilters> for FindingFilters {
    type Error = SeedError;

    fn try_from(raw: RawFindingFilters) -> Result<Self, Self::Error> {
        Ok(Self {
            page: pagination(raw.cursor, raw.limit, "findings")?,
            query: bounded_query(raw.q)?,
            severity: raw.severity,
        })
    }
}

fn default_limit() -> u16 {
    DEFAULT_LIMIT
}

pub(super) fn page<T>(items: Vec<T>, offset: usize, limit: u16, collection: &str) -> CursorPage<T> {
    let total = items.len();
    let start = offset.min(items.len());
    let end = start.saturating_add(usize::from(limit)).min(items.len());
    CursorPage {
        items: items.into_iter().skip(start).take(end - start).collect(),
        next_cursor: (end < total).then(|| make_cursor(collection, end)),
        generated_at: GENERATED_AT.to_owned(),
    }
}

fn make_cursor(collection: &str, offset: usize) -> String {
    URL_SAFE_NO_PAD.encode(format!("{collection}:{offset}"))
}

pub(super) fn cursor_offset(cursor: Option<&str>, collection: &str) -> Option<usize> {
    let cursor = cursor?;
    let decoded = URL_SAFE_NO_PAD.decode(cursor).ok()?;
    let decoded = std::str::from_utf8(&decoded).ok()?;
    let (kind, offset) = decoded.split_once(':')?;
    (kind == collection).then(|| offset.parse().ok()).flatten()
}

fn pagination(
    cursor: Option<String>,
    limit: u16,
    collection: &'static str,
) -> Result<CursorPagination, SeedError> {
    let pagination = CursorPagination::new(cursor, limit).map_err(|_| {
        Box::new(bad_request(
            "invalid_pagination",
            "Invalid page cursor or limit",
        ))
    })?;
    let max_offset = if collection == "agents" {
        MAX_AGENTS
    } else {
        120
    };
    if pagination.cursor().is_some_and(|cursor| {
        cursor_offset(Some(cursor), collection).is_none_or(|offset| offset > max_offset)
    }) {
        return Err(Box::new(bad_request(
            "invalid_pagination",
            "Invalid page cursor or limit",
        )));
    }
    Ok(pagination)
}

fn bounded_query(query: Option<String>) -> Result<Option<String>, SeedError> {
    if query
        .as_ref()
        .is_some_and(|query| query.len() > MAX_SEARCH_LENGTH)
    {
        return Err(Box::new(bad_request(
            "invalid_filter",
            "Search filter exceeds its limit",
        )));
    }
    Ok(query.filter(|query| !query.is_empty()))
}

pub(super) fn parse_query<T: for<'de> Deserialize<'de>>(
    query: Result<Query<T>, QueryRejection>,
) -> Result<T, SeedError> {
    query
        .map(|Query(query)| query)
        .map_err(|_| Box::new(bad_request("invalid_query", "Query parameters are invalid")))
}
