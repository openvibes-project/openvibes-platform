//! `GET /v1/ports/{protocol}/{port}/summary` and `/hosts`: a port's page
//! (step 5e rulings 18, 20–22) over the hosts in the viewer's `hosts.read`
//! reach. A port with no listening host in reach and no change there in 90
//! days answers 404 `port_not_found`; a bad protocol or port answers 400
//! `invalid_port`.

use axum::{
    extract::{Path, Query, State, rejection::QueryRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use platform_store::port_summary::{PortSegment, port_hosts_page, port_summary};
use serde::Deserialize;
use utoipa::IntoParams;

use super::{
    list_page::invalid_query,
    page_types::{PortActionsView, PortPageHostsView, PortPageSummaryView},
};
use crate::{
    Permission,
    access::guard::{authenticated_capabilities, permission_denied, scope_of, unavailable_auth},
    host_pages::{holds, hosts_query, related_reach},
    http::{
        AuthHttpState,
        problem::{ProblemDetails, problem_response},
    },
};

fn not_found() -> Response {
    problem_response(ProblemDetails::not_found(
        "port_not_found",
        "No host in reach listens on this port",
    ))
}

fn invalid_port() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::BAD_REQUEST,
        "invalid_port",
        "The protocol must be tcp or udp and the port 1 to 65535",
    ))
}

/// `tcp` or `udp`, and a port from 1 to 65535.
fn valid(protocol: &str, port: &str) -> Option<(&'static str, u16)> {
    let protocol = match protocol {
        "tcp" => "tcp",
        "udp" => "udp",
        _ => return None,
    };
    let number: u16 = port.parse().ok().filter(|p| *p > 0)?;
    // `+22` and `022` parse but are not the port's spelling.
    (number.to_string() == port).then_some((protocol, number))
}

/// A port's page above the Hosts table.
#[utoipa::path(get, path = "/api/v1/ports/{protocol}/{port}/summary", tag = "assets",
    params(("protocol" = String, Path, description = "tcp or udp"), ("port" = String, Path, description = "1 to 65535")),
    responses((status = 200, description = "The page in the caller's reach", body = PortPageSummaryView),
        (status = 400, description = "invalid_port", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Needs hosts.read", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "port_not_found: nothing listens in reach", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn port_summary_page(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((protocol, port)): Path<(String, String)>,
) -> Response {
    let (capabilities, _) = match authenticated_capabilities(&state, &headers, false).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let Some(read) = scope_of(&capabilities, Permission::HostsRead) else {
        return permission_denied();
    };
    let Some((protocol, port)) = valid(&protocol, &port) else {
        return invalid_port();
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let reach = related_reach(&capabilities);
    let s = match port_summary(&client, &read, &reach, protocol, port, Utc::now()).await {
        Ok(Some(s)) => s,
        Ok(None) => return not_found(),
        Err(_) => return unavailable_auth(),
    };
    let holds = |p| holds(&client, &capabilities, &s.hosts, p);
    let (Ok(export), Ok(case_write), Ok(case_read), Ok(assistant)) = (
        holds(Permission::HostsExport).await,
        holds(Permission::CasesWrite).await,
        holds(Permission::CasesRead).await,
        holds(Permission::AssistantUse).await,
    ) else {
        return unavailable_auth();
    };
    let can = PortActionsView {
        export,
        // Adding takes a listening host in reach and shows the case after.
        add_to_case: case_write && case_read && !s.hosts.is_empty(),
        // Capabilities here are not filtered like /session's; the assistant may be off.
        ask: state.assistant.is_some() && assistant,
    };
    axum::Json(PortPageSummaryView::new(s, can)).into_response()
}

/// Segment and page. Empty values count as absent.
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub(crate) struct PortHostsParams {
    /// all (default), exposed or local.
    segment: Option<String>,
    /// Rows to skip, 0 to 100000.
    offset: Option<String>,
    /// Page size, 1 to 100 (default 50).
    limit: Option<String>,
}

/// A port's Hosts table.
#[utoipa::path(get, path = "/api/v1/ports/{protocol}/{port}/hosts", tag = "assets",
    params(("protocol" = String, Path, description = "tcp or udp"), ("port" = String, Path, description = "1 to 65535"), PortHostsParams),
    responses((status = 200, description = "A page of the listening hosts in the caller's reach", body = PortPageHostsView),
        (status = 400, description = "invalid_port or invalid_query, naming the parameter", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Needs hosts.read", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn port_hosts_page_route(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((protocol, port)): Path<(String, String)>,
    query: Result<Query<PortHostsParams>, QueryRejection>,
) -> Response {
    let (capabilities, _) = match authenticated_capabilities(&state, &headers, false).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let Some(read) = scope_of(&capabilities, Permission::HostsRead) else {
        return permission_denied();
    };
    let Some((protocol, port)) = valid(&protocol, &port) else {
        return invalid_port();
    };
    let Ok(Query(p)) = query else {
        return invalid_query("query");
    };
    let parsed = hosts_query(
        (&p.segment, &p.offset, &p.limit),
        PortSegment::parse,
        PortSegment::All,
    );
    let (segment, offset, limit) = match parsed {
        Ok(v) => v,
        Err(field) => return invalid_query(field),
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match port_hosts_page(&client, &read, protocol, port, segment, offset, limit).await {
        Ok(page) => axum::Json(PortPageHostsView::from(page)).into_response(),
        Err(_) => unavailable_auth(),
    }
}
