//! `GET /v1/software-list`: the Software list (one row per package name) with
//! filters, per-value counts and a summary line, inside the caller's
//! `hosts.read` reach. `GET /v1/software` stays as it is.

use axum::{
    extract::{Query, State, rejection::QueryRejection},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use platform_store::software_list::{
    Changes, Fix, PackageType, SoftwareQuery, SoftwareSort, Versions, Vulns, software_list,
};
use serde::Deserialize;
use utoipa::IntoParams;

use super::list_page_types::SoftwareListView;
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
pub(crate) struct SoftwareListParams {
    /// Package name or a service using it (contains).
    q: Option<String>,
    /// exploited, critical_high, any or none: by the package's open advisories.
    vulns: Option<String>,
    /// available (an update fixes an open advisory somewhere) or none (an
    /// open advisory has no fix yet).
    fix: Option<String>,
    /// one or several versions in use.
    versions: Option<String>,
    /// dpkg or rpm.
    #[serde(rename = "type")]
    kind: Option<String>,
    /// A host group id.
    group: Option<String>,
    /// new, updated or removed this week.
    changes: Option<String>,
    /// An agent id.
    host: Option<String>,
    /// package (default), hosts, vulnerabilities, versions or week.
    sort: Option<String>,
    /// asc (default) or desc.
    dir: Option<String>,
    /// Rows to skip, 0 to 100000.
    offset: Option<String>,
    /// Page size, 1 to 100 (default 50).
    limit: Option<String>,
}

pub(crate) fn invalid_query(field: &str) -> Response {
    invalid_query_of("Software query parameters are invalid", field)
}

/// The Software list.
#[utoipa::path(get, path = "/api/v1/software-list", tag = "software", params(SoftwareListParams),
    responses((status = 200, description = "A page of packages on the caller's hosts", body = SoftwareListView),
        (status = 400, description = "invalid_query, naming the parameter", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Needs hosts.read", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn list_software_page(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    query: Result<Query<SoftwareListParams>, QueryRejection>,
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
        &mut p.vulns,
        &mut p.fix,
        &mut p.versions,
        &mut p.kind,
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
            pick(p.vulns.as_deref(), "vulns", Vulns::parse)?,
            pick(p.fix.as_deref(), "fix", Fix::parse)?,
            pick(p.versions.as_deref(), "versions", Versions::parse)?,
            pick(p.kind.as_deref(), "type", PackageType::parse)?,
            pick(p.changes.as_deref(), "changes", Changes::parse)?,
            pick(p.sort.as_deref(), "sort", SoftwareSort::parse)?.unwrap_or(SoftwareSort::Package),
            number(p.offset.as_deref(), 0, 100_000, "offset")?,
            number(p.limit.as_deref(), 50, 100, "limit")?,
        ))
    })();
    let (group, descending, vulns, fix, versions, kind, changes, sort, offset, limit) = match parsed
    {
        Ok(v) => v,
        Err(field) => return invalid_query(field),
    };
    let software_query = SoftwareQuery {
        q: p.q.as_deref(),
        vulns,
        fix,
        versions,
        kind,
        group: group.as_deref(),
        changes,
        host: p.host.as_deref(),
        sort,
        descending,
        offset,
        limit,
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let now = Utc::now();
    match software_list(&mut client, &software_query, &scope, now).await {
        Ok(page) => axum::Json(SoftwareListView::new(page, now)).into_response(),
        Err(_) => unavailable_auth(),
    }
}
