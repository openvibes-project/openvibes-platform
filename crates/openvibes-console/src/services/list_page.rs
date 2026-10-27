//! `GET /v1/service-list`: the Services list (one row per unit) with filters,
//! per-value counts and a summary line, inside the caller's `hosts.read`
//! reach. `GET /v1/services` stays as it is.

use axum::{
    extract::{Query, State, rejection::QueryRejection},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use platform_store::service_list::{
    Changes, Listens, Packaged, RunsAs, ServiceQuery, ServiceSort, service_list,
};
use serde::Deserialize;
use utoipa::IntoParams;

use super::list_page_types::ServiceListView;
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
pub(crate) struct ServiceListParams {
    /// Unit, usual name, program, package or owned port (contains).
    q: Option<String>,
    /// root (root or SYSTEM on some host) or other (on none).
    runs_as: Option<String>,
    /// exposed (owns an exposed port on some host), local or none.
    listens: Option<String>,
    /// yes (from a package on every host) or no (not on some host).
    packaged: Option<String>,
    /// A host group id.
    group: Option<String>,
    /// new (a host started running it this week) or look (needs a look).
    changes: Option<String>,
    /// An agent id.
    host: Option<String>,
    /// service (default), hosts or week.
    sort: Option<String>,
    /// asc (default) or desc.
    dir: Option<String>,
    /// Rows to skip, 0 to 100000.
    offset: Option<String>,
    /// Page size, 1 to 100 (default 50).
    limit: Option<String>,
}

pub(crate) fn invalid_query(field: &str) -> Response {
    invalid_query_of("Service query parameters are invalid", field)
}

/// The Services list.
#[utoipa::path(get, path = "/api/v1/service-list", tag = "assets", params(ServiceListParams),
    responses((status = 200, description = "A page of services on the caller's hosts", body = ServiceListView),
        (status = 400, description = "invalid_query, naming the parameter", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Needs hosts.read", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn list_service_page(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    query: Result<Query<ServiceListParams>, QueryRejection>,
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
        &mut p.runs_as,
        &mut p.listens,
        &mut p.packaged,
        &mut p.group,
        &mut p.changes,
        &mut p.host,
        &mut p.sort,
        &mut p.dir,
        &mut p.offset,
        &mut p.limit,
    ]);
    let parsed = (|| {
        check_text(&[("q", &p.q, 200), ("host", &p.host, 100)])?;
        let (group, descending) = group_and_dir(p.group.as_deref(), p.dir.as_deref())?;
        Ok((
            group,
            descending,
            pick(p.runs_as.as_deref(), "runs_as", RunsAs::parse)?,
            pick(p.listens.as_deref(), "listens", Listens::parse)?,
            pick(p.packaged.as_deref(), "packaged", Packaged::parse)?,
            pick(p.changes.as_deref(), "changes", Changes::parse)?,
            pick(p.sort.as_deref(), "sort", ServiceSort::parse)?.unwrap_or(ServiceSort::Service),
            number(p.offset.as_deref(), 0, 100_000, "offset")?,
            number(p.limit.as_deref(), 50, 100, "limit")?,
        ))
    })();
    let (group, descending, runs_as, listens, packaged, changes, sort, offset, limit) = match parsed
    {
        Ok(v) => v,
        Err(field) => return invalid_query(field),
    };
    let service_query = ServiceQuery {
        q: p.q.as_deref(),
        runs_as,
        listens,
        packaged,
        group: group.as_deref(),
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
    match service_list(&client, &service_query, &scope, now).await {
        Ok(page) => axum::Json(ServiceListView::new(page, now)).into_response(),
        Err(_) => unavailable_auth(),
    }
}
