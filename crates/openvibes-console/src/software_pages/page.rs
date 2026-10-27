//! `GET /v1/software-pages/{name}/summary` and `/hosts`: a package's page
//! (step 5g rulings 2, 9–13) over the hosts in the viewer's `hosts.read`
//! reach. A package no host in reach has and nothing in reach changed in
//! 90 days answers 404 `package_not_found`; an empty or over-long name
//! answers 400 `invalid_package`.

use axum::{
    extract::{Path, Query, State, rejection::QueryRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use platform_store::software_summary::{SoftwareSegment, software_hosts_page, software_summary};
use serde::Deserialize;
use utoipa::IntoParams;

use super::{
    list_page::invalid_query,
    page_types::{SoftwareActionsView, SoftwarePageHostsView, SoftwarePageSummaryView},
};
use crate::{
    Permission,
    access::guard::{authenticated_capabilities, permission_denied, scope_of, unavailable_auth},
    host_pages::{holds, hosts_query},
    http::{
        AuthHttpState,
        problem::{ProblemDetails, problem_response},
    },
};

fn not_found() -> Response {
    problem_response(ProblemDetails::not_found(
        "package_not_found",
        "No host in reach has this package",
    ))
}

fn invalid_package() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::BAD_REQUEST,
        "invalid_package",
        "A package is 1 to 200 characters without control characters",
    ))
}

/// A name the store can look up.
fn valid(name: &str) -> bool {
    !name.is_empty() && name.chars().count() <= 200 && !name.chars().any(char::is_control)
}

/// A package's page above the Hosts table.
#[utoipa::path(get, path = "/api/v1/software-pages/{name}/summary", tag = "software",
    params(("name" = String, Path, description = "The package name, e.g. openssl")),
    responses((status = 200, description = "The page in the caller's reach", body = SoftwarePageSummaryView),
        (status = 400, description = "invalid_package", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Needs hosts.read", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "package_not_found: no host in reach has it", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn software_summary_page(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    let (capabilities, _) = match authenticated_capabilities(&state, &headers, false).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let Some(read) = scope_of(&capabilities, Permission::HostsRead) else {
        return permission_denied();
    };
    if !valid(&name) {
        return invalid_package();
    }
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let s = match software_summary(&client, &read, &name, Utc::now()).await {
        Ok(Some(s)) => s,
        Ok(None) => return not_found(),
        Err(_) => return unavailable_auth(),
    };
    let holds = |p| holds(&client, &capabilities, &s.host_ids, p);
    let (Ok(export), Ok(case_write), Ok(case_read)) = (
        holds(Permission::HostsExport).await,
        holds(Permission::CasesWrite).await,
        holds(Permission::CasesRead).await,
    ) else {
        return unavailable_auth();
    };
    let can = SoftwareActionsView {
        export,
        // Adding takes a host in reach that has it and shows the case after.
        add_to_case: case_write && case_read && !s.host_ids.is_empty(),
    };
    axum::Json(SoftwarePageSummaryView::new(s, can)).into_response()
}

/// Segment and page. Empty values count as absent.
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub(crate) struct SoftwareHostsParams {
    /// all (default), update or current.
    segment: Option<String>,
    /// Rows to skip, 0 to 100000.
    offset: Option<String>,
    /// Page size, 1 to 100 (default 50).
    limit: Option<String>,
}

/// A package's Hosts table.
#[utoipa::path(get, path = "/api/v1/software-pages/{name}/hosts", tag = "software",
    params(("name" = String, Path, description = "The package name, e.g. openssl"), SoftwareHostsParams),
    responses((status = 200, description = "A page of the hosts in the caller's reach that have it", body = SoftwarePageHostsView),
        (status = 400, description = "invalid_package or invalid_query, naming the parameter", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Needs hosts.read", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn software_hosts_page_route(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    query: Result<Query<SoftwareHostsParams>, QueryRejection>,
) -> Response {
    let (capabilities, _) = match authenticated_capabilities(&state, &headers, false).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let Some(read) = scope_of(&capabilities, Permission::HostsRead) else {
        return permission_denied();
    };
    if !valid(&name) {
        return invalid_package();
    }
    let Ok(Query(p)) = query else {
        return invalid_query("query");
    };
    let parsed = hosts_query(
        (&p.segment, &p.offset, &p.limit),
        SoftwareSegment::parse,
        SoftwareSegment::All,
    );
    let (segment, offset, limit) = match parsed {
        Ok(v) => v,
        Err(field) => return invalid_query(field),
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match software_hosts_page(&client, &read, &name, segment, offset, limit, Utc::now()).await {
        Ok(page) => axum::Json(SoftwarePageHostsView::from(page)).into_response(),
        Err(_) => unavailable_auth(),
    }
}
