//! `GET /v1/vulnerabilities/{key}/summary` and `/{key}/hosts`: a
//! vulnerability's page (step 5b rulings 2, 7, 9–12), one CVE or a CVE-less
//! advisory over its pairs in the viewer's `vulnerabilities.read` reach.
//! An advisory with one CVE answers as that CVE; one with several answers
//! 409 `advisory_has_several_cves`; a key out of reach answers 404.

use axum::{
    extract::{Path, Query, State, rejection::QueryRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use platform_store::{
    console_read::AgentScope,
    vuln_summary::{HostSegment, Lookup, PageScopes, reaches_any, vuln_hosts, vuln_summary},
};
use serde::Deserialize;
use utoipa::IntoParams;

use super::{
    list_page::invalid_query,
    page_types::{VulnActionsView, VulnerabilityHostsPage, VulnerabilitySummaryView},
};
use crate::{
    Permission,
    access::guard::{authenticated_capabilities, permission_denied, scope_of, unavailable_auth},
    alarms::list::{number, pick},
    http::{
        AuthHttpState,
        problem::{FieldError, ProblemDetails, problem_response},
    },
};

fn not_found() -> Response {
    problem_response(ProblemDetails::not_found(
        "vulnerability_not_found",
        "Vulnerability not found",
    ))
}

fn several(cves: Vec<String>) -> Response {
    let mut p = ProblemDetails::new(
        StatusCode::CONFLICT,
        "advisory_has_several_cves",
        "The advisory names several CVEs; open the list filtered by it",
    );
    p.field_errors = Some(
        cves.into_iter()
            .map(|cve| FieldError {
                field: "key".into(),
                code: "cve".into(),
                message: cve,
            })
            .collect(),
    );
    problem_response(p)
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

/// A key the page can have: at most 256 characters, no control character.
fn valid_key(key: &str) -> bool {
    !key.is_empty() && key.chars().count() <= 256 && !key.chars().any(char::is_control)
}

/// A vulnerability's page above the Hosts table.
#[utoipa::path(get, path = "/api/v1/vulnerabilities/{key}/summary", tag = "vulnerabilities",
    params(("key" = String, Path, description = "A CVE id, or an advisory id")),
    responses((status = 200, description = "The page in the caller's reach", body = VulnerabilitySummaryView),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Needs vulnerabilities.read", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "vulnerability_not_found: missing or outside reach", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "advisory_has_several_cves, listing them in field_errors (field `key`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn vulnerability_summary_page(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Response {
    let (capabilities, _) = match authenticated_capabilities(&state, &headers, false).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let Some(read) = scope_of(&capabilities, Permission::VulnerabilitiesRead) else {
        return permission_denied();
    };
    if !valid_key(&key) {
        return not_found();
    }
    let scope = |p| scope_of(&capabilities, p);
    let (alarms, cases) = (scope(Permission::AlarmsRead), scope(Permission::CasesRead));
    let scopes = PageScopes {
        read: &read,
        alarms: alarms.as_ref(),
        cases: cases.as_ref(),
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let s = match vuln_summary(&client, &key, &scopes, Utc::now().date_naive()).await {
        Ok(Lookup::Found(s)) => s,
        Ok(Lookup::Missing) => return not_found(),
        Ok(Lookup::SeveralCves(cves)) => return several(cves),
        Err(_) => return unavailable_auth(),
    };
    let holds = |p| holds(&client, &s.agents, scope(p));
    let (Ok(triage), Ok(case_write), Ok(case_read), Ok(assistant), Ok(export)) = (
        holds(Permission::VulnerabilitiesTriage).await,
        holds(Permission::CasesWrite).await,
        holds(Permission::CasesRead).await,
        holds(Permission::AssistantUse).await,
        holds(Permission::VulnerabilitiesExport).await,
    ) else {
        return unavailable_auth();
    };
    let can = VulnActionsView {
        triage,
        assign: triage,
        // As the bulk route's add to case: cases.write and cases.read.
        add_to_case: case_write && case_read,
        // Capabilities here are not filtered like /session's; the assistant may be off.
        ask: state.assistant.is_some() && assistant,
        export,
    };
    axum::Json(VulnerabilitySummaryView::new(s, can)).into_response()
}

/// Segment and page. Empty values count as absent.
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub(crate) struct VulnHostsParams {
    /// all (default), open, mitigated or resolved.
    segment: Option<String>,
    /// Rows to skip, 0 to 100000.
    offset: Option<String>,
    /// Page size, 1 to 100 (default 50).
    limit: Option<String>,
}

/// A vulnerability's Hosts table: one row per host and covering advisory.
#[utoipa::path(get, path = "/api/v1/vulnerabilities/{key}/hosts", tag = "vulnerabilities",
    params(("key" = String, Path, description = "A CVE id, or an advisory id"), VulnHostsParams),
    responses((status = 200, description = "A page of the hosts in the caller's reach", body = VulnerabilityHostsPage),
        (status = 400, description = "invalid_query, naming the parameter", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Needs vulnerabilities.read", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "vulnerability_not_found: missing or outside reach", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "advisory_has_several_cves, listing them in field_errors (field `key`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn vulnerability_hosts_page(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(key): Path<String>,
    query: Result<Query<VulnHostsParams>, QueryRejection>,
) -> Response {
    let (capabilities, _) = match authenticated_capabilities(&state, &headers, false).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let Some(read): Option<AgentScope> = scope_of(&capabilities, Permission::VulnerabilitiesRead)
    else {
        return permission_denied();
    };
    let Ok(Query(p)) = query else {
        return invalid_query("query");
    };
    let present = |v: &Option<String>| v.clone().filter(|v| !v.is_empty());
    let (segment, offset, limit) = (present(&p.segment), present(&p.offset), present(&p.limit));
    let parsed = (|| {
        Ok((
            pick(segment.as_deref(), "segment", HostSegment::parse)?.unwrap_or(HostSegment::All),
            number(offset.as_deref(), 0, 100_000, "offset")?,
            number(limit.as_deref(), 50, 100, "limit")?,
        ))
    })();
    let (segment, offset, limit) = match parsed {
        Ok(v) => v,
        Err(field) => return invalid_query(field),
    };
    if !valid_key(&key) {
        return not_found();
    }
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match vuln_hosts(
        &client,
        &key,
        &read,
        segment,
        offset,
        limit,
        Utc::now().date_naive(),
    )
    .await
    {
        Ok(Lookup::Found(page)) => axum::Json(VulnerabilityHostsPage::from(page)).into_response(),
        Ok(Lookup::Missing) => not_found(),
        Ok(Lookup::SeveralCves(cves)) => several(cves),
        Err(_) => unavailable_auth(),
    }
}
