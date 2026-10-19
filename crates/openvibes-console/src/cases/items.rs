use axum::{
    Json,
    extract::{Path, Query, State, rejection::JsonRejection, rejection::QueryRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use platform_store::console_cases::{self as store, OutcomeChange};

use super::permissions::{manager, reader};
use super::request::blank_is_absent;
use super::responses::{answer, bad_request, refused};
use super::types::{
    AddCaseNoteRequest, CaseItemRef, ForItemParams, ItemCasesView, SetCaseItemOutcomeRequest,
};
use super::views::{event_view, item_case_view, item_view};
use crate::{ProblemDetails, access::guard::unavailable_auth, http::AuthHttpState};

#[utoipa::path(post, path = "/api/v1/cases/{case_id}/notes", tag = "cases", params(("case_id" = String, Path)), request_body = crate::cases::AddCaseNoteRequest,
    responses((status = 201, description = "Added to the timeline", body = crate::cases::CaseEventView),
        (status = 400, description = "Invalid body", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "Absent or not visible", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "Invalid note, or the timeline is full", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Bearer tokens and missing permissions are refused", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn add_note(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    payload: Result<Json<AddCaseNoteRequest>, JsonRejection>,
) -> Response {
    let (scope, user_id) = match manager(&state, &headers).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let Ok(Json(request)) = payload else {
        return bad_request("invalid_request", "The request body is invalid");
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::add_note(
        &mut client,
        &scope,
        &user_id,
        &id,
        &request.body,
        Utc::now(),
    )
    .await
    {
        Ok(Ok(event)) => answer(StatusCode::CREATED, None, event_view(event)),
        Ok(Err(refusal)) => refused(refusal),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(post, path = "/api/v1/cases/{case_id}/items", tag = "cases", params(("case_id" = String, Path)), request_body = crate::cases::CaseItemRef,
    responses((status = 201, description = "Added", body = crate::cases::CaseItemView),
        (status = 400, description = "Invalid body", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "The case or the item does not exist or is outside the caller's scope", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "In another open case, already in this one, or the case is closed", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "Invalid kind or ref, or the case is full", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Bearer tokens and missing permissions are refused", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn add_item(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    payload: Result<Json<CaseItemRef>, JsonRejection>,
) -> Response {
    let (scope, user_id) = match manager(&state, &headers).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let Ok(Json(request)) = payload else {
        return bad_request("invalid_request", "The request body is invalid");
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::add_item(
        &mut client,
        &scope,
        &user_id,
        &id,
        &request.kind,
        &request.reference,
        Utc::now(),
    )
    .await
    {
        Ok(Ok(item)) => answer(StatusCode::CREATED, None, item_view(item)),
        Ok(Err(refusal)) => refused(refusal),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(delete, path = "/api/v1/cases/{case_id}/items/{item_id}", tag = "cases", params(("case_id" = String, Path), ("item_id" = String, Path)),
    responses((status = 204, description = "Removed"),
        (status = 404, description = "The case or the item is absent or not visible", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The case is closed", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Bearer tokens and missing permissions are refused", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn remove_item(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((id, item_id)): Path<(String, String)>,
) -> Response {
    let (scope, user_id) = match manager(&state, &headers).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::remove_item(&mut client, &scope, &user_id, &id, &item_id, Utc::now()).await {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(refusal)) => refused(refusal),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(put, path = "/api/v1/cases/{case_id}/items/{item_id}/outcome", tag = "cases", params(("case_id" = String, Path), ("item_id" = String, Path)), request_body = crate::cases::SetCaseItemOutcomeRequest,
    responses((status = 200, description = "Set or cleared", body = crate::cases::CaseItemView),
        (status = 400, description = "Invalid body", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "The case or the item is absent or not visible", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The case is closed, or resolved was asked for while the evidence is still there", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "Invalid outcome or note, or a kind that takes no outcome", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Bearer tokens and missing permissions are refused", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn set_item_outcome(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((id, item_id)): Path<(String, String)>,
    payload: Result<Json<SetCaseItemOutcomeRequest>, JsonRejection>,
) -> Response {
    let (scope, user_id) = match manager(&state, &headers).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let Ok(Json(request)) = payload else {
        return bad_request("invalid_request", "The request body is invalid");
    };
    let note = blank_is_absent(request.note.as_deref());
    let change = request
        .outcome
        .as_deref()
        .map(|outcome| OutcomeChange { outcome, note });
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::set_outcome(
        &mut client,
        &scope,
        &user_id,
        &id,
        &item_id,
        change.as_ref(),
        Utc::now(),
    )
    .await
    {
        Ok(Ok(item)) => answer(StatusCode::OK, None, item_view(item)),
        Ok(Err(refusal)) => refused(refusal),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(get, path = "/api/v1/cases/for-item", tag = "cases", params(ForItemParams),
    responses((status = 200, description = "The visible cases that hold the item", body = crate::cases::ItemCasesView),
        (status = 400, description = "Invalid query", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "Invalid kind or ref", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Bearer tokens and missing permissions are refused", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn cases_for_item(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    query: Result<Query<ForItemParams>, QueryRejection>,
) -> Response {
    let (scope, user_id) = match reader(&state, &headers).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let Ok(Query(params)) = query else {
        return bad_request("invalid_query", "kind and ref are required");
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::for_item(&client, &scope, &user_id, &params.kind, &params.reference).await {
        Ok(Ok(found)) => answer(
            StatusCode::OK,
            None,
            ItemCasesView {
                items: found.into_iter().map(item_case_view).collect(),
            },
        ),
        Ok(Err(refusal)) => refused(refusal),
        Err(_) => unavailable_auth(),
    }
}
