//! Finding history: the list and one event.

use axum::{
    extract::{Path, Query, State, rejection::QueryRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::{SecondsFormat, Utc};
use serde::Deserialize;

use super::latest::invalid_finding_query;
use crate::{
    access::guard::{authenticated_agent_scope, unavailable_auth},
    http::{
        AuthHttpState,
        problem::{ProblemDetails, problem_response},
    },
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FindingHistoryListParams {
    since: String,
    agent_id: Option<String>,
    rule_set_id: Option<String>,
    rule_id: Option<String>,
    cursor: Option<String>,
    limit: Option<u16>,
}

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct FindingHistoryCursorToken {
    since: String,
    agent_id: Option<String>,
    rule_set_id: Option<String>,
    rule_id: Option<String>,
    scope: platform_store::console_read::AgentScope,
    observed_at: String,
    observed_day: String,
    finding_id: String,
}

#[utoipa::path(
    get,
    path = "/api/v1/compliance/history",
    tag = "compliance",
    params(
        ("since" = String, Query, description = "Required RFC 3339 lower bound for partition pruning"),
        ("agent_id" = Option<String>, Query, description = "Exact agent filter"),
        ("rule_set_id" = Option<String>, Query, description = "Exact rule-set filter; ~unknown selects legacy rows"),
        ("rule_id" = Option<String>, Query, description = "Exact rule filter"),
        ("cursor" = Option<String>, Query, description = "Opaque continuation cursor"),
        ("limit" = Option<u16>, Query, description = "Page size from 1 to 100")
    ),
    responses(
        (status = 200, description = "Scope-filtered finding history page", body = crate::FindingHistoryPage),
        (status = 400, description = "Invalid query or cursor", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Permission denied", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(crate) async fn authenticated_finding_history(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    query: Result<Query<FindingHistoryListParams>, QueryRejection>,
) -> Response {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use platform_store::console_read::{
        HistoryCursor, HistoryQuery, PageLimit, finding_history_in_scope,
    };

    let scope = match authenticated_agent_scope(&state, &headers, crate::Permission::ComplianceRead)
        .await
    {
        Ok(scope) => scope,
        Err(response) => return response,
    };
    let Query(params) = match query {
        Ok(query) => query,
        Err(_) => return invalid_finding_query(),
    };
    if [&params.agent_id, &params.rule_set_id, &params.rule_id]
        .into_iter()
        .flatten()
        .any(|value| value.is_empty() || value.len() > 128 || value.chars().any(char::is_control))
    {
        return invalid_finding_query();
    }
    let since = match chrono::DateTime::parse_from_rfc3339(&params.since) {
        Ok(value) => value.with_timezone(&Utc),
        Err(_) => return invalid_finding_query(),
    };
    if since > Utc::now() {
        return invalid_finding_query();
    }
    let Some(limit) = PageLimit::new(params.limit.unwrap_or(crate::DEFAULT_PAGE_SIZE)) else {
        return invalid_finding_query();
    };
    let after = match params.cursor.as_deref() {
        None => None,
        Some(encoded) if encoded.len() <= crate::MAX_CURSOR_LENGTH => {
            let decoded = match URL_SAFE_NO_PAD.decode(encoded) {
                Ok(decoded) => decoded,
                Err(_) => return invalid_finding_query(),
            };
            let token = match serde_json::from_slice::<FindingHistoryCursorToken>(&decoded) {
                Ok(token)
                    if token.since == params.since
                        && token.agent_id == params.agent_id
                        && token.rule_set_id == params.rule_set_id
                        && token.rule_id == params.rule_id
                        && token.scope == scope =>
                {
                    token
                }
                _ => return invalid_finding_query(),
            };
            let observed_at = match chrono::DateTime::parse_from_rfc3339(&token.observed_at) {
                Ok(value) => value.with_timezone(&Utc),
                Err(_) => return invalid_finding_query(),
            };
            let observed_day = match chrono::NaiveDate::parse_from_str(&token.observed_day, "%F") {
                Ok(value) => value,
                Err(_) => return invalid_finding_query(),
            };
            Some(HistoryCursor {
                observed_at,
                observed_day,
                finding_id: token.finding_id,
            })
        }
        Some(_) => return invalid_finding_query(),
    };
    let rule_set_id = params.rule_set_id.as_deref().map(|value| {
        if value == "~unknown" {
            "".to_owned()
        } else {
            value.to_owned()
        }
    });
    let client = match state.pool.get().await {
        Ok(client) => client,
        Err(_) => return unavailable_auth(),
    };
    let page = match finding_history_in_scope(
        &client,
        &HistoryQuery {
            since,
            agent_id: params.agent_id.clone(),
            rule_set_id,
            rule_id: params.rule_id.clone(),
            after,
            limit,
        },
        &scope,
    )
    .await
    {
        Ok(page) => page,
        Err(_) => return unavailable_auth(),
    };
    let items = page.items.into_iter().map(history_event_view).collect();
    let next_cursor = match page.next {
        None => None,
        Some(cursor) => {
            let token = FindingHistoryCursorToken {
                since: params.since,
                agent_id: params.agent_id,
                rule_set_id: params.rule_set_id,
                rule_id: params.rule_id,
                scope,
                observed_at: cursor
                    .observed_at
                    .to_rfc3339_opts(SecondsFormat::Micros, true),
                observed_day: cursor.observed_day.to_string(),
                finding_id: cursor.finding_id,
            };
            match serde_json::to_vec(&token) {
                Ok(token) => Some(URL_SAFE_NO_PAD.encode(token)),
                Err(_) => return unavailable_auth(),
            }
        }
    };
    (
        StatusCode::OK,
        axum::Json(crate::FindingHistoryPage {
            items,
            next_cursor,
            generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        }),
    )
        .into_response()
}

#[utoipa::path(
    get,
    path = "/api/v1/compliance/history/{observed_day}/{finding_id}",
    tag = "compliance",
    params(
        ("observed_day" = String, Path, description = "UTC partition date"),
        ("finding_id" = String, Path, description = "Stable finding identifier")
    ),
    responses(
        (status = 200, description = "Visible immutable finding event", body = crate::FindingHistoryEntry),
        (status = 400, description = "Invalid partition date", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Permission denied", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "Compliance finding event not found", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(crate) async fn authenticated_finding_event(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((observed_day, finding_id)): Path<(String, String)>,
) -> Response {
    let scope = match authenticated_agent_scope(&state, &headers, crate::Permission::ComplianceRead)
        .await
    {
        Ok(scope) => scope,
        Err(response) => return response,
    };
    let observed_day = match chrono::NaiveDate::parse_from_str(&observed_day, "%F") {
        Ok(value) => value,
        Err(_) => return invalid_finding_query(),
    };
    let client = match state.pool.get().await {
        Ok(client) => client,
        Err(_) => return unavailable_auth(),
    };
    match platform_store::console_read::finding_event_in_scope(
        &client,
        observed_day,
        &finding_id,
        &scope,
    )
    .await
    {
        Ok(Some(event)) => axum::Json(history_event_view(event)).into_response(),
        Ok(None) => problem_response(ProblemDetails::not_found(
            "compliance_finding_not_found",
            "Compliance finding not found",
        )),
        Err(_) => unavailable_auth(),
    }
}

fn history_event_view(
    event: platform_store::console_read::FindingEvent,
) -> crate::FindingHistoryEntry {
    use platform_store::console_read::Severity;
    crate::FindingHistoryEntry {
        id: event.finding_id,
        observed_day: event.observed_day.to_string(),
        agent_id: event.agent_id,
        rule_set_id: if event.rule_set_id.is_empty() {
            "~unknown".into()
        } else {
            event.rule_set_id
        },
        rule_id: event.rule_id,
        rule_version: event.rule_version.try_into().unwrap_or_default(),
        severity: match event.severity {
            Severity::Critical => crate::Severity::Critical,
            Severity::High => crate::Severity::High,
            Severity::Medium => crate::Severity::Medium,
            Severity::Low => crate::Severity::Low,
        },
        confidence: event.confidence.try_into().unwrap_or_default(),
        message: event.message,
        evidence: event.evidence,
        scan_id: event.scan_id,
        authenticated: event.authenticated,
        origin: match event.origin.as_str() {
            "import" => crate::FindingOrigin::Import,
            _ => crate::FindingOrigin::Online,
        },
        observed_at: event.observed_at.to_rfc3339_opts(SecondsFormat::Secs, true),
        received_at: event.received_at.to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}
