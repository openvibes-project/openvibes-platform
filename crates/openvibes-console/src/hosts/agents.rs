//! The agent list, summary and detail, and revoking an agent.

use axum::{
    extract::{Json, Path, Query, State, rejection::QueryRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::{SecondsFormat, Utc};
use serde::Deserialize;

use super::certificates::certificate_view;
use crate::{
    access::guard::{authenticated_agent_scope, authenticated_permission, unavailable_auth},
    http::validate::valid_agent_id,
    http::{
        AuthHttpState,
        problem::{ProblemDetails, problem_response},
    },
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentListParams {
    state: Option<String>,
    cursor: Option<String>,
    limit: Option<u16>,
}

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct AgentCursorToken {
    state: Option<String>,
    scope: platform_store::console_read::AgentScope,
    last_seen_at: Option<String>,
    agent_id: String,
}

#[utoipa::path(
    get,
    path = "/api/v1/agents/summary",
    tag = "agents",
    responses(
        (status = 200, description = "Agent counts visible to the current user", body = crate::AgentSummary),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Permission denied", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(crate) async fn authenticated_agent_summary(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    use platform_store::console_read::agent_summary_in_scope;

    let scope =
        match authenticated_agent_scope(&state, &headers, crate::Permission::HostsRead).await {
            Ok(scope) => scope,
            Err(response) => return response,
        };
    let client = match state.pool.get().await {
        Ok(client) => client,
        Err(_) => return unavailable_auth(),
    };
    match agent_summary_in_scope(&client, Utc::now(), &scope).await {
        Ok(summary) => (
            StatusCode::OK,
            axum::Json(crate::AgentSummary {
                total: summary.total.try_into().unwrap_or_default(),
                active: summary.active.try_into().unwrap_or_default(),
                stale: summary.stale.try_into().unwrap_or_default(),
                revoked: summary.revoked.try_into().unwrap_or_default(),
                imported: summary.imported.try_into().unwrap_or_default(),
                // Agent and platform release in lockstep; if that ever
                // changes, compare against the newest published agent RPM.
                platform_version: env!("CARGO_PKG_VERSION").to_owned(),
            }),
        )
            .into_response(),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/agents",
    tag = "agents",
    params(
        ("state" = Option<String>, Query, description = "active, stale, revoked, or imported"),
        ("cursor" = Option<String>, Query, description = "Opaque continuation cursor"),
        ("limit" = Option<u16>, Query, description = "Page size from 1 to 100")
    ),
    responses(
        (status = 200, description = "Scope-filtered agent page", body = crate::AgentPage),
        (status = 400, description = "Invalid query or cursor", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Permission denied", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(crate) async fn authenticated_agents(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    query: Result<Query<AgentListParams>, QueryRejection>,
) -> Response {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use platform_store::console_read::{
        AgentCursor, AgentQuery, AgentState, PageLimit, agents_in_scope,
    };

    let scope =
        match authenticated_agent_scope(&state, &headers, crate::Permission::HostsRead).await {
            Ok(scope) => scope,
            Err(response) => return response,
        };
    let Query(params) = match query {
        Ok(query) => query,
        Err(_) => return invalid_agent_query(),
    };
    let limit = params.limit.unwrap_or(crate::DEFAULT_PAGE_SIZE);
    let Some(limit) = PageLimit::new(limit) else {
        return invalid_agent_query();
    };
    let agent_state = match params.state.as_deref() {
        None => None,
        Some("active") => Some(AgentState::Active),
        Some("stale") => Some(AgentState::Stale),
        Some("revoked") => Some(AgentState::Revoked),
        Some("imported") => Some(AgentState::Imported),
        Some(_) => return invalid_agent_query(),
    };
    let after = match params.cursor.as_deref() {
        None => None,
        Some(encoded) if encoded.len() <= crate::MAX_CURSOR_LENGTH => {
            let decoded = match URL_SAFE_NO_PAD.decode(encoded) {
                Ok(decoded) => decoded,
                Err(_) => return invalid_agent_query(),
            };
            let token: AgentCursorToken = match serde_json::from_slice::<AgentCursorToken>(&decoded)
            {
                Ok(token) if token.state == params.state && token.scope == scope => token,
                _ => return invalid_agent_query(),
            };
            let last_seen_at = match token.last_seen_at.as_deref() {
                Some(value) => match chrono::DateTime::parse_from_rfc3339(value) {
                    Ok(value) => Some(value.with_timezone(&Utc)),
                    Err(_) => return invalid_agent_query(),
                },
                None => None,
            };
            Some(AgentCursor {
                last_seen_at,
                agent_id: token.agent_id,
            })
        }
        Some(_) => return invalid_agent_query(),
    };
    let client = match state.pool.get().await {
        Ok(client) => client,
        Err(_) => return unavailable_auth(),
    };
    let page = match agents_in_scope(
        &client,
        &AgentQuery {
            state: agent_state,
            after,
            limit,
        },
        Utc::now(),
        &scope,
    )
    .await
    {
        Ok(page) => page,
        Err(_) => return unavailable_auth(),
    };
    let items = page.items.into_iter().map(agent_view).collect();
    let next_cursor = match page.next {
        None => None,
        Some(cursor) => {
            let token = AgentCursorToken {
                state: params.state,
                scope,
                last_seen_at: cursor
                    .last_seen_at
                    .map(|value| value.to_rfc3339_opts(SecondsFormat::Micros, true)),
                agent_id: cursor.agent_id,
            };
            match serde_json::to_vec(&token) {
                Ok(token) => Some(URL_SAFE_NO_PAD.encode(token)),
                Err(_) => return unavailable_auth(),
            }
        }
    };
    (
        StatusCode::OK,
        axum::Json(crate::AgentPage {
            items,
            next_cursor,
            generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        }),
    )
        .into_response()
}

pub(super) fn invalid_agent_query() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::BAD_REQUEST,
        "invalid_query",
        "Agent query parameters are invalid",
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/agents/{agent_id}",
    tag = "agents",
    params(("agent_id" = String, Path, description = "Stable agent identifier")),
    responses(
        (status = 200, description = "Visible agent detail", body = crate::AgentDetail),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Permission denied", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "Agent not found", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(crate) async fn authenticated_agent_detail(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
) -> Response {
    use platform_store::console_read::{PageLimit, agent_in_scope, certificates_in_scope};

    let scope =
        match authenticated_agent_scope(&state, &headers, crate::Permission::HostsRead).await {
            Ok(scope) => scope,
            Err(response) => return response,
        };
    let client = match state.pool.get().await {
        Ok(client) => client,
        Err(_) => return unavailable_auth(),
    };
    let agent = match agent_in_scope(&client, &agent_id, Utc::now(), &scope).await {
        Ok(Some(agent)) => agent,
        Ok(None) => {
            return problem_response(ProblemDetails::not_found(
                "agent_not_found",
                "Agent not found",
            ));
        }
        Err(_) => return unavailable_auth(),
    };
    let certificates = match certificates_in_scope(
        &client,
        &agent_id,
        None,
        PageLimit::new(100).expect("the fixed certificate detail limit is valid"),
        &scope,
    )
    .await
    {
        Ok(page) => page.items.into_iter().map(certificate_view).collect(),
        Err(_) => return unavailable_auth(),
    };
    let rfc = |at: Option<chrono::DateTime<Utc>>| {
        at.map(|at| at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
    };
    let last_test = match platform_store::rules::last_tests(&client, &agent_id).await {
        Ok((alarm, finding)) => crate::hosts::LastTest {
            alarm_at: rfc(alarm),
            finding_at: rfc(finding),
        },
        Err(_) => return unavailable_auth(),
    };
    (
        StatusCode::OK,
        axum::Json(crate::AgentDetail {
            agent: agent_view(agent),
            certificates,
            last_test,
        }),
    )
        .into_response()
}

fn agent_view(agent: platform_store::console_read::Agent) -> crate::AgentView {
    use platform_store::console_read::AgentState;
    crate::AgentView {
        id: agent.agent_id,
        hostname: agent.hostname,
        status: match agent.state {
            AgentState::Active => crate::AgentStatus::Active,
            AgentState::Stale => crate::AgentStatus::Stale,
            AgentState::Revoked => crate::AgentStatus::Revoked,
            AgentState::Imported => crate::AgentStatus::Imported,
        },
        enrolled_at: agent.enrolled_at.to_rfc3339_opts(SecondsFormat::Secs, true),
        revoked_at: agent
            .revoked_at
            .map(|value| value.to_rfc3339_opts(SecondsFormat::Secs, true)),
        last_seen_at: agent
            .last_seen_at
            .map(|value| value.to_rfc3339_opts(SecondsFormat::Secs, true)),
        scanner_version: agent.scanner_version,
        capabilities: agent.capabilities,
        os_id: agent.os_id,
        os_version: agent.os_version,
        running_kernel: agent.running_kernel,
        inventory_at: agent
            .inventory_at
            .map(|value| value.to_rfc3339_opts(SecondsFormat::Secs, true)),
        rule_sets: agent
            .rule_sets
            .into_iter()
            .map(|set| crate::AgentRuleSetView {
                id: set.id,
                version: set.version,
                expires_at_ms: set.expires_at_ms,
                refused: set.refused,
                state: set.state,
            })
            .collect(),
        rule_sets_at: agent
            .rule_sets_at
            .map(|value| value.to_rfc3339_opts(SecondsFormat::Secs, true)),
        alarms: agent.alarms.map(alarms_view),
    }
}

pub(super) fn alarms_view(
    status: platform_store::alarms_status::AlarmsStatus,
) -> crate::AgentAlarmsView {
    use platform_store::alarms_status::AlarmsStatus;
    match status {
        AlarmsStatus::On { source } => crate::AgentAlarmsView {
            state: "on".to_owned(),
            source: Some(source.to_owned()),
            reason: None,
            text: None,
            fix: None,
            command: None,
            fault: false,
        },
        AlarmsStatus::Off {
            reason,
            text,
            fix,
            command,
            fault,
        } => crate::AgentAlarmsView {
            state: "off".to_owned(),
            source: None,
            reason: Some(reason.to_owned()),
            text: Some(text),
            fix: Some(fix),
            command: command.map(str::to_owned),
            fault,
        },
    }
}

/// Revokes one visible agent and records an operator reason.
#[utoipa::path(post,path="/api/v1/agents/{agent_id}/revoke",tag="agents",params(("agent_id"=String,Path)),request_body=crate::RevokeAgentRequest,responses((status=204,description="Agent revoked"),(status=404,description="Agent not found in the current scope",body=ProblemDetails),(status=400,description="Invalid reason",body=ProblemDetails)))]
pub(crate) async fn revoke_authenticated_agent(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
    Json(request): Json<crate::RevokeAgentRequest>,
) -> Response {
    if !valid_agent_id(&agent_id)
        || request.reason.trim().is_empty()
        || request.reason.chars().count() > 500
        || request.reason.chars().any(char::is_control)
    {
        return problem_response(ProblemDetails::new(
            StatusCode::BAD_REQUEST,
            "invalid_revoke_reason",
            "Provide a non-empty reason up to 500 characters",
        ));
    }
    let (scope, actor) = match authenticated_permission(
        &state,
        &headers,
        crate::Permission::HostsRevoke,
        true,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let mut client = match state.pool.get().await {
        Ok(value) => value,
        Err(_) => return unavailable_auth(),
    };
    match platform_store::console_auth::revoke_agent_in_scope(
        &mut client,
        &agent_id,
        &scope,
        &actor,
        request.reason.trim(),
        Utc::now(),
    )
    .await
    {
        Ok(
            platform_store::agents::Revoke::Revoked
            | platform_store::agents::Revoke::AlreadyRevoked,
        ) => StatusCode::NO_CONTENT.into_response(),
        Ok(platform_store::agents::Revoke::Unknown) => problem_response(ProblemDetails::not_found(
            "agent_not_found",
            "Agent not found",
        )),
        Ok(platform_store::agents::Revoke::Imported) => problem_response(ProblemDetails::new(
            StatusCode::CONFLICT,
            "imported_host_cannot_be_revoked",
            "Imported hosts cannot be revoked",
        )),
        Err(_) => unavailable_auth(),
    }
}
