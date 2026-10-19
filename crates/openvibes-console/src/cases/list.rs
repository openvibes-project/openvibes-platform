use axum::{
    Json,
    extract::{Path, Query, State, rejection::JsonRejection, rejection::QueryRejection},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use chrono::Utc;
use platform_store::console_cases::{
    self as store, AssigneeFilter, CaseChange, CaseFilters, NewCase, Refusal,
};

use super::permissions::{manager, reader};
use super::request::{
    blank_is_absent, decode_cursor, encode_cursor, parse_time, precondition, title,
};
use super::responses::{answer, bad_request, detail_answer, invalid, refused};
use super::types::{CaseListParams, CasePage, CreateCaseRequest, UpdateCaseRequest};
use super::views::summary_view;
use crate::{
    ProblemDetails, access::guard::unavailable_auth, http::AuthHttpState,
    http::problem::problem_response,
};

#[utoipa::path(get, path = "/api/v1/cases", tag = "cases", params(CaseListParams),
    responses((status = 200, description = "The cases the caller can see, newest change first", body = crate::cases::CasePage),
        (status = 400, description = "Invalid query or cursor", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Bearer tokens and missing permissions are refused", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn list_cases(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    query: Result<Query<CaseListParams>, QueryRejection>,
) -> Response {
    let (scope, user_id) = match reader(&state, &headers).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let Ok(Query(params)) = query else {
        return bad_request("invalid_query", "Case query is invalid");
    };
    let limit = params.limit.unwrap_or(50);
    if !(1..=100).contains(&limit) {
        return bad_request("invalid_query", "limit must be 1 to 100");
    }
    if params
        .status
        .as_deref()
        .is_some_and(|status| !matches!(status, "open" | "investigating" | "closed" | "all"))
    {
        return bad_request(
            "invalid_query",
            "status must be open, investigating, closed or all",
        );
    }
    if params
        .severity
        .as_deref()
        .is_some_and(|severity| !matches!(severity, "critical" | "high" | "medium" | "low"))
    {
        return bad_request(
            "invalid_query",
            "severity must be critical, high, medium or low",
        );
    }
    if params.q.as_deref().is_some_and(|q| q.chars().count() > 120) {
        return bad_request("invalid_query", "q is at most 120 characters");
    }
    let assignee = match params.assignee.as_deref() {
        None => AssigneeFilter::Anyone,
        Some("none") => AssigneeFilter::Nobody,
        Some("me") => AssigneeFilter::User(user_id.clone()),
        Some(id) => AssigneeFilter::User(id.to_ascii_lowercase()),
    };
    let after = match params.cursor.as_deref().map(decode_cursor) {
        Some(None) => return bad_request("invalid_cursor", "cursor is invalid"),
        Some(cursor) => cursor,
        None => None,
    };
    let filters = CaseFilters {
        status: params.status,
        severity: params.severity,
        assignee,
        q: params.q,
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    // Accepted risk that has run out, and resolved evidence that has come
    // back, reopen their case before anyone looks.
    if store::reopen_due(&mut client, Utc::now()).await.is_err() {
        return unavailable_auth();
    }
    // One extra row says whether another page follows.
    let Ok(mut rows) = store::list(
        &client,
        &scope,
        &user_id,
        &filters,
        after.as_ref(),
        i64::from(limit) + 1,
    )
    .await
    else {
        return unavailable_auth();
    };
    let more = rows.len() > usize::from(limit);
    rows.truncate(usize::from(limit));
    let next_cursor = more.then(|| rows.last().map(encode_cursor)).flatten();
    answer(
        StatusCode::OK,
        None,
        CasePage {
            items: rows.into_iter().map(summary_view).collect(),
            next_cursor,
        },
    )
}

#[utoipa::path(post, path = "/api/v1/cases", tag = "cases", request_body = crate::cases::CreateCaseRequest,
    responses((status = 201, description = "Opened", body = crate::cases::CaseDetailView, headers(("ETag" = String, description = "Case version"))),
        (status = 400, description = "Invalid body", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "An item does not exist or is outside the caller's scope", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "An item is already in another open case", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "Invalid field", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Bearer tokens and missing permissions are refused", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn create_case(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    payload: Result<Json<CreateCaseRequest>, JsonRejection>,
) -> Response {
    let (scope, user_id) = match manager(&state, &headers).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let Ok(Json(request)) = payload else {
        return bad_request("invalid_request", "The request body is invalid");
    };
    let items: Vec<(&str, &str)> = request
        .items
        .iter()
        .map(|item| (item.kind.as_str(), item.reference.as_str()))
        .collect();
    let assignee = request.assignee_user_id.map(|id| id.to_ascii_lowercase());
    let new = NewCase {
        title: title(&request.title),
        severity: request.severity.as_deref(),
        assignee_user_id: assignee.as_deref(),
        items: &items,
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::create(&mut client, &scope, &user_id, &new, Utc::now()).await {
        Ok(Ok(created)) => detail_answer(StatusCode::CREATED, created),
        Ok(Err(refusal)) => refused(refusal),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(get, path = "/api/v1/cases/{case_id}", tag = "cases", params(("case_id" = String, Path)),
    responses((status = 200, description = "The case, its visible items and timeline", body = crate::cases::CaseDetailView, headers(("ETag" = String, description = "Case version"))),
        (status = 404, description = "Absent or not visible", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Bearer tokens and missing permissions are refused", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn get_case(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (scope, user_id) = match reader(&state, &headers).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    if store::reopen_due(&mut client, Utc::now()).await.is_err() {
        return unavailable_auth();
    }
    match store::get(&client, &scope, &user_id, &id).await {
        Ok(Some(detail)) => detail_answer(StatusCode::OK, detail),
        Ok(None) => refused(Refusal::NotFound),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(put, path = "/api/v1/cases/{case_id}", tag = "cases", params(("case_id" = String, Path), ("If-Match" = String, Header, description = "Quoted version from ETag")),
    request_body = crate::cases::UpdateCaseRequest,
    responses((status = 200, description = "Saved", body = crate::cases::CaseDetailView, headers(("ETag" = String, description = "New case version"))),
        (status = 400, description = "Invalid body or If-Match", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "Absent or not visible", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "Items still need an outcome, an item is in another open case, or the case is closed", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "Stale version", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "Invalid field", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 428, description = "If-Match is required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Bearer tokens and missing permissions are refused", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn update_case(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    payload: Result<Json<UpdateCaseRequest>, JsonRejection>,
) -> Response {
    let (scope, user_id) = match manager(&state, &headers).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let expected = match precondition(&headers) {
        Ok(version) => version,
        Err(problem) => return problem_response(problem),
    };
    let Ok(Json(request)) = payload else {
        return bad_request("invalid_request", "The request body is invalid");
    };
    let accepted_until = match request.accepted_until.as_deref().map(parse_time) {
        Some(Some(at)) => Some(at),
        Some(None) => {
            return invalid(
                "accepted_until",
                "invalid_timestamp",
                "Use an RFC 3339 time",
            );
        }
        None => None,
    };
    let assignee = request.assignee_user_id.map(|id| id.to_ascii_lowercase());
    let note = blank_is_absent(request.resolution_note.as_deref());
    let change = CaseChange {
        expected_version: expected,
        title: title(&request.title),
        severity: &request.severity,
        status: &request.status,
        assignee_user_id: assignee.as_deref(),
        resolution: request.resolution.as_deref(),
        resolution_note: note,
        accepted_until,
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::update(&mut client, &scope, &user_id, &id, &change, Utc::now()).await {
        Ok(Ok(saved)) => detail_answer(StatusCode::OK, saved),
        Ok(Err(refusal)) => refused(refusal),
        Err(_) => unavailable_auth(),
    }
}
