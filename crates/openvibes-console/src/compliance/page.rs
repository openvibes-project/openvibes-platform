//! `GET /v1/compliance/checks/{rule_set_id}/{rule_id}/summary` and
//! `/hosts`: a check's page (step 5c rulings 8, 11–17) over its failing and
//! inferred passing hosts in the viewer's `compliance.read` reach. A check
//! the Compliance list would not show in reach answers 404
//! `check_not_found`.

use axum::{
    extract::{Path, Query, State, rejection::QueryRejection},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use platform_store::{
    check_summary::{CheckHostSegment, Lookup, check_hosts, check_summary},
    console_read::AgentScope,
    vuln_summary::reaches_any,
};
use serde::Deserialize;
use utoipa::IntoParams;

use super::{
    list_page::invalid_query,
    page_types::{CheckActionsView, CheckHostsPageView, CheckSummaryView},
};
use crate::{
    Permission,
    access::guard::{authenticated_capabilities, permission_denied, scope_of, unavailable_auth},
    alarms::list::{number, pick},
    http::{
        AuthHttpState,
        problem::{ProblemDetails, problem_response},
    },
};

fn not_found() -> Response {
    problem_response(ProblemDetails::not_found(
        "check_not_found",
        "Compliance check not found",
    ))
}

/// A rule set or rule id the page can have: 1 to 256 characters, no
/// control character.
fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.chars().count() <= 256 && !id.chars().any(char::is_control)
}

/// Whether `scope` is held and reaches one of `agents`.
async fn holds(
    client: &platform_store::Client,
    agents: &[String],
    scope: Option<AgentScope>,
) -> Result<bool, platform_store::StoreError> {
    match scope {
        Some(scope) => reaches_any(client, agents, &scope).await,
        None => Ok(false),
    }
}

/// A check's page above the Hosts table.
#[utoipa::path(get, path = "/api/v1/compliance/checks/{rule_set_id}/{rule_id}/summary", tag = "compliance",
    params(("rule_set_id" = String, Path, description = "Rule set id"), ("rule_id" = String, Path, description = "Rule id")),
    responses((status = 200, description = "The page in the caller's reach", body = CheckSummaryView),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Needs compliance.read", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "check_not_found: missing or outside reach", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn check_summary_page(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((rule_set_id, rule_id)): Path<(String, String)>,
) -> Response {
    let (capabilities, _) = match authenticated_capabilities(&state, &headers, false).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let Some(read) = scope_of(&capabilities, Permission::ComplianceRead) else {
        return permission_denied();
    };
    if !valid_id(&rule_set_id) || !valid_id(&rule_id) {
        return not_found();
    }
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let s = match check_summary(&client, &rule_set_id, &rule_id, &read, Utc::now()).await {
        Ok(Lookup::Found(s)) => s,
        Ok(Lookup::Missing | Lookup::SeveralCves(_)) => return not_found(),
        Err(_) => return unavailable_auth(),
    };
    let scope = |p| scope_of(&capabilities, p);
    let holds = |p| holds(&client, &s.agents, scope(p));
    let (Ok(triage), Ok(case_write), Ok(case_read), Ok(assistant), Ok(export)) = (
        holds(Permission::ComplianceTriage).await,
        holds(Permission::CasesWrite).await,
        holds(Permission::CasesRead).await,
        holds(Permission::AssistantUse).await,
        holds(Permission::ComplianceExport).await,
    ) else {
        return unavailable_auth();
    };
    let can = CheckActionsView {
        triage,
        assign: triage,
        // As the bulk route's add to case: cases.write and cases.read.
        add_to_case: case_write && case_read,
        // Capabilities here are not filtered like /session's; the assistant may be off.
        ask: state.assistant.is_some() && assistant,
        export,
    };
    axum::Json(CheckSummaryView::new(s, can)).into_response()
}

/// Segment and page. Empty values count as absent.
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub(crate) struct CheckHostsParams {
    /// all (default), failing or passing.
    segment: Option<String>,
    /// Rows to skip, 0 to 100000.
    offset: Option<String>,
    /// Page size, 1 to 100 (default 50).
    limit: Option<String>,
}

/// A check's Hosts table: its failing hosts in any triage state and its
/// passing hosts.
#[utoipa::path(get, path = "/api/v1/compliance/checks/{rule_set_id}/{rule_id}/hosts", tag = "compliance",
    params(("rule_set_id" = String, Path, description = "Rule set id"), ("rule_id" = String, Path, description = "Rule id"), CheckHostsParams),
    responses((status = 200, description = "A page of the hosts in the caller's reach", body = CheckHostsPageView),
        (status = 400, description = "invalid_query, naming the parameter", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Needs compliance.read", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "check_not_found: missing or outside reach", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn check_hosts_page(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((rule_set_id, rule_id)): Path<(String, String)>,
    query: Result<Query<CheckHostsParams>, QueryRejection>,
) -> Response {
    let (capabilities, _) = match authenticated_capabilities(&state, &headers, false).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let Some(read) = scope_of(&capabilities, Permission::ComplianceRead) else {
        return permission_denied();
    };
    let Ok(Query(p)) = query else {
        return invalid_query("query");
    };
    let present = |v: &Option<String>| v.clone().filter(|v| !v.is_empty());
    let (segment, offset, limit) = (present(&p.segment), present(&p.offset), present(&p.limit));
    let parsed = (|| {
        Ok((
            pick(segment.as_deref(), "segment", CheckHostSegment::parse)?
                .unwrap_or(CheckHostSegment::All),
            number(offset.as_deref(), 0, 100_000, "offset")?,
            number(limit.as_deref(), 50, 100, "limit")?,
        ))
    })();
    let (segment, offset, limit) = match parsed {
        Ok(v) => v,
        Err(field) => return invalid_query(field),
    };
    if !valid_id(&rule_set_id) || !valid_id(&rule_id) {
        return not_found();
    }
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match check_hosts(
        &client,
        &rule_set_id,
        &rule_id,
        &read,
        segment,
        offset,
        limit,
        Utc::now(),
    )
    .await
    {
        Ok(Lookup::Found(page)) => axum::Json(CheckHostsPageView::from(page)).into_response(),
        Ok(Lookup::Missing | Lookup::SeveralCves(_)) => not_found(),
        Err(_) => unavailable_auth(),
    }
}
