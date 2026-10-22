//! `GET /v1/vulnerability-list`: the Vulnerabilities list (one row per CVE)
//! with filters, per-value counts and a summary line, inside the caller's
//! `vulnerabilities.read` reach. `GET /v1/vulnerabilities` stays as it is.

use axum::{
    extract::{Query, State, rejection::QueryRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use platform_store::{
    alarm_list::Assignee,
    vuln_list::{Signal, VulnQuery, VulnSeverity, VulnSort, VulnState, vuln_list},
};
use serde::Deserialize;
use utoipa::IntoParams;

use super::list_page_types::VulnListView;
use crate::{
    Permission,
    access::guard::{authenticated_capabilities, permission_denied, scope_of, unavailable_auth},
    alarms::list::{is_uuid, number, pick},
    http::{
        AuthHttpState,
        problem::{FieldError, ProblemDetails, problem_response},
    },
};

/// Filters, sort and page. Empty values count as absent.
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub(crate) struct VulnListParams {
    /// CVE id, advisory id, title or package name (contains).
    q: Option<String>,
    /// open (default), mitigated, accepted_risk, false_positive, resolved or all.
    state: Option<String>,
    /// critical, important, moderate, low or unrated.
    severity: Option<String>,
    /// exploited, due30, nofix, reboot or lowconf.
    signal: Option<String>,
    /// A package name.
    package: Option<String>,
    /// A host group id.
    group: Option<String>,
    /// An agent id.
    host: Option<String>,
    /// An advisory id: the CVEs it names.
    advisory: Option<String>,
    /// me, unassigned or a user id.
    assignee: Option<String>,
    /// priority (default), severity, cvss, epss, open or due.
    sort: Option<String>,
    /// asc or desc (default).
    dir: Option<String>,
    /// Rows to skip, 0 to 100000.
    offset: Option<String>,
    /// Page size, 1 to 100 (default 50).
    limit: Option<String>,
}

fn invalid_query(field: &str) -> Response {
    let mut p = ProblemDetails::new(
        StatusCode::BAD_REQUEST,
        "invalid_query",
        "Vulnerability query parameters are invalid",
    );
    p.field_errors = Some(vec![FieldError {
        field: field.into(),
        code: "invalid".into(),
        message: format!("The {field} parameter is invalid"),
    }]);
    problem_response(p)
}

/// The Vulnerabilities list.
#[utoipa::path(get, path = "/api/v1/vulnerability-list", tag = "vulnerabilities", params(VulnListParams),
    responses((status = 200, description = "A page of vulnerabilities (CVEs) in the caller's reach", body = VulnListView),
        (status = 400, description = "invalid_query, naming the parameter", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Needs vulnerabilities.read", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn list_vulnerability_page(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    query: Result<Query<VulnListParams>, QueryRejection>,
) -> Response {
    let (capabilities, actor_id) = match authenticated_capabilities(&state, &headers, false).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let Some(scope) = scope_of(&capabilities, Permission::VulnerabilitiesRead) else {
        return permission_denied();
    };
    let Ok(Query(mut p)) = query else {
        return invalid_query("query");
    };
    for v in [
        &mut p.q,
        &mut p.state,
        &mut p.severity,
        &mut p.signal,
        &mut p.package,
        &mut p.group,
        &mut p.host,
        &mut p.advisory,
        &mut p.assignee,
        &mut p.sort,
        &mut p.dir,
        &mut p.offset,
        &mut p.limit,
    ] {
        if v.as_deref().is_some_and(str::is_empty) {
            *v = None;
        }
    }
    let parsed = (|| {
        for (field, v, max) in [
            ("q", &p.q, 200),
            ("package", &p.package, 200),
            ("host", &p.host, 100),
            ("advisory", &p.advisory, 200),
        ] {
            if v.as_deref()
                .is_some_and(|v| v.chars().count() > max || v.chars().any(char::is_control))
            {
                return Err(field);
            }
        }
        let lowercase_uuid = |v: &Option<String>, field| match v.as_deref() {
            Some(g) if !is_uuid(g) => Err(field),
            g => Ok(g.map(str::to_ascii_lowercase)),
        };
        let group = lowercase_uuid(&p.group, "group")?;
        let assignee_id = match p.assignee.as_deref() {
            Some("me" | "unassigned") | None => None,
            Some(_) => lowercase_uuid(&p.assignee, "assignee")?,
        };
        let descending = match p.dir.as_deref() {
            None | Some("desc") => true,
            Some("asc") => false,
            Some(_) => return Err("dir"),
        };
        Ok((
            group,
            assignee_id,
            descending,
            pick(p.state.as_deref(), "state", VulnState::parse)?.unwrap_or(VulnState::Open),
            pick(p.severity.as_deref(), "severity", VulnSeverity::parse)?,
            pick(p.signal.as_deref(), "signal", Signal::parse)?,
            pick(p.sort.as_deref(), "sort", VulnSort::parse)?.unwrap_or(VulnSort::Priority),
            number(p.offset.as_deref(), 0, 100_000, "offset")?,
            number(p.limit.as_deref(), 50, 100, "limit")?,
        ))
    })();
    let (group, assignee_id, descending, state_filter, severity, signal, sort, offset, limit) =
        match parsed {
            Ok(v) => v,
            Err(field) => return invalid_query(field),
        };
    let assignee = match p.assignee.as_deref() {
        None => None,
        Some("me") => Some(Assignee::Me),
        Some("unassigned") => Some(Assignee::Unassigned),
        Some(_) => assignee_id.as_deref().map(Assignee::User),
    };
    let vuln_query = VulnQuery {
        q: p.q.as_deref(),
        state: state_filter,
        severity,
        signal,
        package: p.package.as_deref(),
        group: group.as_deref(),
        host: p.host.as_deref(),
        advisory: p.advisory.as_deref(),
        assignee,
        sort,
        descending,
        offset,
        limit,
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let now = Utc::now();
    match vuln_list(&client, &vuln_query, &scope, &actor_id, now.date_naive()).await {
        Ok(page) => axum::Json(VulnListView::new(page, now)).into_response(),
        Err(_) => unavailable_auth(),
    }
}
