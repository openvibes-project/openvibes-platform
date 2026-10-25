//! `GET /v1/case-list`: the Cases list page (one row per case the caller
//! sees) with filters, per-value counts and the summary line (roles plan
//! 2026-10-25 step 5d, rulings 5–10). `GET /v1/cases` stays for Add to
//! case, the palette and the badges.

use axum::{
    extract::{Query, State, rejection::QueryRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use platform_store::{
    alarm_list::Assignee,
    case_list::{
        CaseContains, CaseQuery, CaseSeverity, CaseSort, CaseStatus, CaseUpdated, case_list,
    },
    console_cases as store,
};
use serde::Deserialize;
use utoipa::IntoParams;

use super::{list_page_types::CaseListView, permissions::reader};
use crate::{
    access::guard::unavailable_auth,
    alarms::list::{is_uuid, number, pick},
    http::problem::{FieldError, ProblemDetails, problem_response},
};

/// Filters, sort and page. Empty values count as absent.
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub(crate) struct CaseListPageParams {
    /// Title, `C-<number>`, the number, or the opener's name (contains).
    q: Option<String>,
    /// active (default: not closed), open, investigating, closed or all.
    status: Option<String>,
    /// critical, high, medium or low.
    severity: Option<String>,
    /// me, unassigned or a user id.
    assignee: Option<String>,
    /// alarms, vulnerabilities or findings: holds a visible item of that kind.
    contains: Option<String>,
    /// An agent id: a visible item on that host.
    host: Option<String>,
    /// A host group id: a visible item on a host in it.
    group: Option<String>,
    /// today, week (the last 7 days) or quiet (not for 7 days or more).
    updated: Option<String>,
    /// updated (default), severity, number or opened.
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
        "Case query parameters are invalid",
    );
    p.field_errors = Some(vec![FieldError {
        field: field.into(),
        code: "invalid".into(),
        message: format!("The {field} parameter is invalid"),
    }]);
    problem_response(p)
}

/// The Cases list.
#[utoipa::path(get, path = "/api/v1/case-list", tag = "cases", params(CaseListPageParams),
    responses((status = 200, description = "A page of the cases the caller can see", body = CaseListView),
        (status = 400, description = "invalid_query, naming the parameter", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Bearer tokens and callers without cases.read are refused", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn list_case_page(
    State(state): State<crate::http::AuthHttpState>,
    headers: HeaderMap,
    query: Result<Query<CaseListPageParams>, QueryRejection>,
) -> Response {
    let (scope, user_id) = match reader(&state, &headers).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let Ok(Query(mut p)) = query else {
        return invalid_query("query");
    };
    for v in [
        &mut p.q,
        &mut p.status,
        &mut p.severity,
        &mut p.assignee,
        &mut p.contains,
        &mut p.host,
        &mut p.group,
        &mut p.updated,
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
        for (field, v, max) in [("q", &p.q, 200), ("host", &p.host, 100)] {
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
            pick(p.status.as_deref(), "status", CaseStatus::parse)?.unwrap_or(CaseStatus::Active),
            pick(p.severity.as_deref(), "severity", CaseSeverity::parse)?,
            pick(p.contains.as_deref(), "contains", CaseContains::parse)?,
            pick(p.updated.as_deref(), "updated", CaseUpdated::parse)?,
            pick(p.sort.as_deref(), "sort", CaseSort::parse)?.unwrap_or(CaseSort::Updated),
            number(p.offset.as_deref(), 0, 100_000, "offset")?,
            number(p.limit.as_deref(), 50, 100, "limit")?,
        ))
    })();
    let (group, assignee_id, descending, status, severity, contains, updated, sort, offset, limit) =
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
    let case_query = CaseQuery {
        q: p.q.as_deref(),
        status,
        severity,
        assignee,
        contains,
        host: p.host.as_deref(),
        group: group.as_deref(),
        updated,
        sort,
        descending,
        offset,
        limit,
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let now = Utc::now();
    // Accepted risk that has run out, and resolved evidence that has come
    // back, reopen or unready their case before anyone looks.
    if store::reopen_due(&mut client, now).await.is_err() {
        return unavailable_auth();
    }
    match case_list(&client, &case_query, &scope, &user_id, now).await {
        Ok(page) => axum::Json(CaseListView::new(page, now)).into_response(),
        Err(_) => unavailable_auth(),
    }
}
