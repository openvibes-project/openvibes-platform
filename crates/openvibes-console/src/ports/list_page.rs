//! `GET /v1/port-list`: the Ports list (one row per port) with filters,
//! per-value counts and a summary line, inside the caller's `hosts.read`
//! reach. `GET /v1/ports` stays as it is.

use axum::{
    extract::{Query, State, rejection::QueryRejection},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use platform_store::port_list::{
    Changes, Exposure, PortQuery, PortSort, ProtocolFilter, ServiceFilter, port_list,
};
use serde::Deserialize;
use utoipa::IntoParams;

use super::list_page_types::PortListView;
use crate::{
    Permission,
    access::guard::{authenticated_permission, unavailable_auth},
    alarms::list::{blank_to_none, check_text, group_and_dir, invalid_query_of, number, pick},
    http::{AuthHttpState, problem::ProblemDetails},
};

/// Filters, sort and page. Empty values count as absent.
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub(crate) struct PortListParams {
    /// Port number, `22/tcp`, usual name or owner unit (contains).
    q: Option<String>,
    /// exposed (exposed on some host) or local (on none).
    exposure: Option<String>,
    /// tcp or udp.
    protocol: Option<String>,
    /// A host group id.
    group: Option<String>,
    /// An owner unit, or `~none` for an owner not collected.
    service: Option<String>,
    /// new (a host started listening this week) or look (needs a look).
    changes: Option<String>,
    /// An agent id.
    host: Option<String>,
    /// port (default), hosts, exposed or week.
    sort: Option<String>,
    /// asc (default) or desc.
    dir: Option<String>,
    /// Rows to skip, 0 to 100000.
    offset: Option<String>,
    /// Page size, 1 to 100 (default 50).
    limit: Option<String>,
}

pub(crate) fn invalid_query(field: &str) -> Response {
    invalid_query_of("Port query parameters are invalid", field)
}

/// The Ports list.
#[utoipa::path(get, path = "/api/v1/port-list", tag = "assets", params(PortListParams),
    responses((status = 200, description = "A page of ports on the caller's hosts", body = PortListView),
        (status = 400, description = "invalid_query, naming the parameter", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Needs hosts.read", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn list_port_page(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    query: Result<Query<PortListParams>, QueryRejection>,
) -> Response {
    let (scope, _) =
        match authenticated_permission(&state, &headers, Permission::HostsRead, false).await {
            Ok(caller) => caller,
            Err(response) => return response,
        };
    let Ok(Query(mut p)) = query else {
        return invalid_query("query");
    };
    blank_to_none(&mut [
        &mut p.q,
        &mut p.exposure,
        &mut p.protocol,
        &mut p.group,
        &mut p.service,
        &mut p.changes,
        &mut p.host,
        &mut p.sort,
        &mut p.dir,
        &mut p.offset,
        &mut p.limit,
    ]);
    let parsed = (|| {
        check_text(&[
            ("q", &p.q, 200),
            ("service", &p.service, 200),
            ("host", &p.host, 100),
        ])?;
        let (group, descending) = group_and_dir(p.group.as_deref(), p.dir.as_deref())?;
        Ok((
            group,
            descending,
            pick(p.exposure.as_deref(), "exposure", Exposure::parse)?,
            pick(p.protocol.as_deref(), "protocol", ProtocolFilter::parse)?,
            pick(p.changes.as_deref(), "changes", Changes::parse)?,
            pick(p.sort.as_deref(), "sort", PortSort::parse)?.unwrap_or(PortSort::Port),
            number(p.offset.as_deref(), 0, 100_000, "offset")?,
            number(p.limit.as_deref(), 50, 100, "limit")?,
        ))
    })();
    let (group, descending, exposure, protocol, changes, sort, offset, limit) = match parsed {
        Ok(v) => v,
        Err(field) => return invalid_query(field),
    };
    let port_query = PortQuery {
        q: p.q.as_deref(),
        exposure,
        protocol,
        group: group.as_deref(),
        service: p.service.as_deref().map(ServiceFilter::parse),
        changes,
        host: p.host.as_deref(),
        sort,
        descending,
        offset,
        limit,
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let now = Utc::now();
    match port_list(&client, &port_query, &scope, now).await {
        Ok(page) => axum::Json(PortListView::new(page, now)).into_response(),
        Err(_) => unavailable_auth(),
    }
}
