//! `GET /v1/services/{unit}/summary` and `/hosts`: a service's page (step
//! 5f rulings 2, 11–13) over the hosts in the viewer's `hosts.read` reach.
//! A service no host in reach runs and nothing in reach changed in 90 days
//! answers 404 `service_not_found`; an empty or over-long unit answers 400
//! `invalid_unit`.

use axum::{
    extract::{Path, Query, State, rejection::QueryRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use platform_store::{
    port_related::RelatedReach,
    service_summary::{ServiceSegment, service_hosts_page, service_summary},
    vuln_summary::reaches_any,
};
use serde::Deserialize;
use utoipa::IntoParams;

use super::{
    list_page::invalid_query,
    page_types::{ServiceActionsView, ServicePageHostsView, ServicePageSummaryView},
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
        "service_not_found",
        "No host in reach runs this service",
    ))
}

fn invalid_unit() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::BAD_REQUEST,
        "invalid_unit",
        "A service is 1 to 200 characters without control characters",
    ))
}

/// A unit the store can look up.
fn valid(unit: &str) -> bool {
    !unit.is_empty() && unit.chars().count() <= 200 && !unit.chars().any(char::is_control)
}

fn reach_of(capabilities: &[crate::EffectiveCapability]) -> RelatedReach {
    let scope = |p| scope_of(capabilities, p);
    RelatedReach {
        compliance: scope(Permission::ComplianceRead),
        vulnerabilities: scope(Permission::VulnerabilitiesRead),
        alarms: scope(Permission::AlarmsRead),
    }
}

/// A service's page above the Hosts table.
#[utoipa::path(get, path = "/api/v1/services/{unit}/summary", tag = "assets",
    params(("unit" = String, Path, description = "The unit, e.g. sshd.service")),
    responses((status = 200, description = "The page in the caller's reach", body = ServicePageSummaryView),
        (status = 400, description = "invalid_unit", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Needs hosts.read", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "service_not_found: no host in reach runs it", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn service_summary_page(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(unit): Path<String>,
) -> Response {
    let (capabilities, _) = match authenticated_capabilities(&state, &headers, false).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let Some(read) = scope_of(&capabilities, Permission::HostsRead) else {
        return permission_denied();
    };
    if !valid(&unit) {
        return invalid_unit();
    }
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let reach = reach_of(&capabilities);
    let s = match service_summary(&client, &read, &reach, &unit, Utc::now()).await {
        Ok(Some(s)) => s,
        Ok(None) => return not_found(),
        Err(_) => return unavailable_auth(),
    };
    let holds = async |p| match scope_of(&capabilities, p) {
        Some(scope) => reaches_any(&client, &s.hosts, &scope).await,
        None => Ok(false),
    };
    let (Ok(export), Ok(case_write), Ok(case_read)) = (
        holds(Permission::HostsExport).await,
        holds(Permission::CasesWrite).await,
        holds(Permission::CasesRead).await,
    ) else {
        return unavailable_auth();
    };
    let can = ServiceActionsView {
        export,
        // Adding takes a host in reach running it and shows the case after.
        add_to_case: case_write && case_read && !s.hosts.is_empty(),
    };
    axum::Json(ServicePageSummaryView::new(s, can)).into_response()
}

/// Segment and page. Empty values count as absent.
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServiceHostsParams {
    /// all (default), exposed or root.
    segment: Option<String>,
    /// Rows to skip, 0 to 100000.
    offset: Option<String>,
    /// Page size, 1 to 100 (default 50).
    limit: Option<String>,
}

/// A service's Hosts table.
#[utoipa::path(get, path = "/api/v1/services/{unit}/hosts", tag = "assets",
    params(("unit" = String, Path, description = "The unit, e.g. sshd.service"), ServiceHostsParams),
    responses((status = 200, description = "A page of the hosts in the caller's reach running it", body = ServicePageHostsView),
        (status = 400, description = "invalid_unit or invalid_query, naming the parameter", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Needs hosts.read", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn service_hosts_page_route(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(unit): Path<String>,
    query: Result<Query<ServiceHostsParams>, QueryRejection>,
) -> Response {
    let (capabilities, _) = match authenticated_capabilities(&state, &headers, false).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let Some(read) = scope_of(&capabilities, Permission::HostsRead) else {
        return permission_denied();
    };
    if !valid(&unit) {
        return invalid_unit();
    }
    let Ok(Query(p)) = query else {
        return invalid_query("query");
    };
    let present = |v: &Option<String>| v.clone().filter(|v| !v.is_empty());
    let (segment, offset, limit) = (present(&p.segment), present(&p.offset), present(&p.limit));
    let parsed = (|| {
        Ok((
            pick(segment.as_deref(), "segment", ServiceSegment::parse)?
                .unwrap_or(ServiceSegment::All),
            number(offset.as_deref(), 0, 100_000, "offset")?,
            number(limit.as_deref(), 50, 100, "limit")?,
        ))
    })();
    let (segment, offset, limit) = match parsed {
        Ok(v) => v,
        Err(field) => return invalid_query(field),
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let reach = reach_of(&capabilities);
    match service_hosts_page(&client, &read, &reach, &unit, segment, offset, limit).await {
        Ok(page) => axum::Json(ServicePageHostsView::from(page)).into_response(),
        Err(_) => unavailable_auth(),
    }
}
