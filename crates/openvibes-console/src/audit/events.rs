//! The audit event list.

use axum::{
    extract::{Json, Query, State, rejection::QueryRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::Utc;

use super::query::{AuditEventCursorToken, AuditEventListParams};
use crate::{
    access::guard::{authenticated_permission, unavailable_auth},
    http::{
        AuthHttpState,
        problem::{ProblemDetails, problem_response},
    },
};

#[utoipa::path(
    get,
    path = "/api/v1/audit-events",
    tag = "audit",
    params(
        ("since" = String, Query, description = "Inclusive RFC3339 lower bound"),
        ("until" = Option<String>, Query, description = "Exclusive RFC3339 upper bound"),
        ("actor" = Option<String>, Query), ("action" = Option<String>, Query),
        ("result" = Option<String>, Query),
        ("action_prefix" = Option<String>, Query, description = "Actions starting with this ([a-z_.], at most 64 characters)"),
        ("cursor" = Option<String>, Query),
        ("limit" = Option<u16>, Query)
    ),
    responses((status = 200, description = "Safe audit event page", body = crate::AuditEventPage))
)]
pub(crate) async fn authenticated_audit_events(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    query: Result<Query<AuditEventListParams>, QueryRejection>,
) -> Response {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use chrono::{DateTime, SecondsFormat};
    use platform_store::{
        audit::{AuditCursor, AuditQuery, events},
        console_read::{AgentScope, PageLimit},
    };
    let (scope, user_id) =
        match authenticated_permission(&state, &headers, crate::Permission::AuditRead, false).await
        {
            Ok(context) => context,
            Err(response) => return response,
        };
    if !matches!(scope, AgentScope::Global) {
        return problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "Access is not available",
        ));
    }
    let Query(params) = match query {
        Ok(query) => query,
        Err(_) => return invalid_query(),
    };
    let since = match DateTime::parse_from_rfc3339(&params.since) {
        Ok(v) => v.with_timezone(&Utc),
        Err(_) => return invalid_query(),
    };
    let until = match params
        .until
        .as_deref()
        .map(DateTime::parse_from_rfc3339)
        .transpose()
    {
        Ok(v) => v.map(|v| v.with_timezone(&Utc)),
        Err(_) => return invalid_query(),
    };
    let now = Utc::now();
    if since > now
        || until.is_some_and(|v| v <= since || v > now)
        || [
            params.actor.as_deref(),
            params.action.as_deref(),
            params.result.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(|v| v.is_empty() || v.len() > 128 || v.chars().any(char::is_control))
        || params.action_prefix.as_deref().is_some_and(|v| {
            v.is_empty()
                || v.len() > 64
                || !v
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b == b'_' || b == b'.')
        })
    {
        return invalid_query();
    }
    let limit = match PageLimit::new(params.limit.unwrap_or(crate::DEFAULT_PAGE_SIZE)) {
        Some(v) => v,
        None => return invalid_query(),
    };
    let after = match params.cursor.as_deref() {
        None => None,
        Some(encoded) if encoded.len() <= crate::MAX_CURSOR_LENGTH => {
            let decoded = match URL_SAFE_NO_PAD.decode(encoded) {
                Ok(v) => v,
                Err(_) => return invalid_query(),
            };
            let token: AuditEventCursorToken = match serde_json::from_slice(&decoded) {
                Ok(v) => v,
                Err(_) => return invalid_query(),
            };
            let token_since = match DateTime::parse_from_rfc3339(&token.since) {
                Ok(v) => v.with_timezone(&Utc),
                Err(_) => return invalid_query(),
            };
            let token_until = match token
                .until
                .as_deref()
                .map(DateTime::parse_from_rfc3339)
                .transpose()
            {
                Ok(v) => v.map(|v| v.with_timezone(&Utc)),
                Err(_) => return invalid_query(),
            };
            if token_since != since
                || token_until != until
                || token.actor != params.actor
                || token.action != params.action
                || token.result != params.result
                || token.action_prefix != params.action_prefix
            {
                return invalid_query();
            }
            let at = match DateTime::parse_from_rfc3339(&token.at) {
                Ok(v) => v.with_timezone(&Utc),
                Err(_) => return invalid_query(),
            };
            Some(AuditCursor { at, id: token.id })
        }
        _ => return invalid_query(),
    };
    let client = match state.pool.get().await {
        Ok(v) => v,
        Err(_) => return unavailable_auth(),
    };
    let page = match events(
        &client,
        &AuditQuery {
            since,
            until,
            actor: params.actor.clone(),
            action: params.action.clone(),
            result: params.result.clone(),
            action_prefix: params.action_prefix.clone(),
            after,
            limit,
        },
    )
    .await
    {
        Ok(v) => v,
        Err(_) => return unavailable_auth(),
    };
    if platform_store::audit::record(
        &client,
        &user_id,
        "audit.accessed",
        Some("audit_events"),
        "success",
    )
    .await
    .is_err()
    {
        return unavailable_auth();
    }
    let next_cursor = page.next.and_then(|cursor| {
        let token = AuditEventCursorToken {
            since: since.to_rfc3339(),
            until: until.map(|v| v.to_rfc3339()),
            actor: params.actor,
            action: params.action,
            result: params.result,
            action_prefix: params.action_prefix,
            at: cursor.at.to_rfc3339_opts(SecondsFormat::Nanos, true),
            id: cursor.id,
        };
        serde_json::to_vec(&token)
            .map(|v| URL_SAFE_NO_PAD.encode(v))
            .ok()
    });
    Json(crate::AuditEventPage {
        items: page
            .items
            .into_iter()
            .map(|event| crate::AuditEventView {
                id: event.id.to_string(),
                at: event.at.to_rfc3339_opts(SecondsFormat::Millis, true),
                actor: event.actor,
                action: event.action,
                target: event.target,
                result: event.result,
                request_id: event.request_id,
                actor_kind: event.actor_kind,
                actor_id: event.actor_id,
                authentication_method: event.authentication_method,
                target_kind: event.target_kind,
                target_id: event.target_id,
                reason_code: event.reason_code,
            })
            .collect(),
        next_cursor,
    })
    .into_response()
}

pub(super) fn invalid_query() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::BAD_REQUEST,
        "invalid_query",
        "Audit event query parameters are invalid",
    ))
}
