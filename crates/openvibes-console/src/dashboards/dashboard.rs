//! Dashboards over `/api/v1`: list, create, read, update, delete and share.

use axum::{
    Json,
    extract::{Path, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use platform_store::dashboards::{self as store, Refusal};

use super::answers::{bad_request, checked, invalid, refused, view, with_etag};
use crate::{
    DashboardPage, Permission, PermissionScope, ProblemDetails, SaveDashboardRequest,
    ShareDashboardRequest,
    access::guard::{session_user, unavailable_auth},
    http::AuthHttpState,
    http::headers::parse_if_match_version,
    http::problem::problem_response,
};

#[utoipa::path(get, path = "/api/v1/dashboards", tag = "dashboards",
    responses((status = 200, description = "Own and shared dashboards", body = crate::DashboardPage), (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"), (status = 403, description = "Bearer tokens and missing permissions are refused", body = ProblemDetails, content_type = "application/problem+json"), (status = 503, description = "Unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn list_dashboards(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    let user = match session_user(&state, &headers, false).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::list_visible(&client, &user.user_id).await {
        Ok(items) => Json(DashboardPage {
            items: items.into_iter().map(|d| view(d, &user.user_id)).collect(),
        })
        .into_response(),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(post, path = "/api/v1/dashboards", tag = "dashboards", request_body = crate::SaveDashboardRequest,
    responses((status = 201, description = "Created", body = crate::DashboardView), (status = 400, description = "Invalid body", body = ProblemDetails, content_type = "application/problem+json"), (status = 422, description = "Invalid name or layout, or 100 dashboards already", body = ProblemDetails, content_type = "application/problem+json"), (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"), (status = 403, description = "Bearer tokens and missing permissions are refused", body = ProblemDetails, content_type = "application/problem+json"), (status = 503, description = "Unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn create_dashboard(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    payload: Result<Json<SaveDashboardRequest>, JsonRejection>,
) -> Response {
    let user = match session_user(&state, &headers, true).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Ok(Json(request)) = payload else {
        return bad_request();
    };
    let name = match checked(&request) {
        Ok(name) => name,
        Err(errors) => return invalid(errors),
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::create(
        &mut client,
        &user.user_id,
        &name,
        &request.layout,
        Utc::now(),
    )
    .await
    {
        Ok(Ok(dashboard)) => with_etag(StatusCode::CREATED, view(dashboard, &user.user_id)),
        Ok(Err(refusal)) => refused(refusal),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(get, path = "/api/v1/dashboards/{dashboard_id}", tag = "dashboards", params(("dashboard_id" = String, Path)),
    responses((status = 200, description = "The dashboard", body = crate::DashboardView), (status = 404, description = "Not found or not visible", body = ProblemDetails, content_type = "application/problem+json"), (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"), (status = 403, description = "Bearer tokens and missing permissions are refused", body = ProblemDetails, content_type = "application/problem+json"), (status = 503, description = "Unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn get_dashboard(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let user = match session_user(&state, &headers, false).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::get_visible(&client, &user.user_id, &id).await {
        Ok(Some(dashboard)) => with_etag(StatusCode::OK, view(dashboard, &user.user_id)),
        Ok(None) => refused(Refusal::NotFound),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(put, path = "/api/v1/dashboards/{dashboard_id}", tag = "dashboards", params(("dashboard_id" = String, Path), ("If-Match" = String, Header, description = "Quoted version from ETag")), request_body = crate::SaveDashboardRequest,
    responses((status = 200, description = "Saved", body = crate::DashboardView), (status = 400, description = "Invalid body or If-Match", body = ProblemDetails, content_type = "application/problem+json"), (status = 404, description = "Not found or not visible", body = ProblemDetails, content_type = "application/problem+json"), (status = 412, description = "Stale version", body = ProblemDetails, content_type = "application/problem+json"), (status = 422, description = "Invalid name or layout", body = ProblemDetails, content_type = "application/problem+json"), (status = 428, description = "If-Match is required", body = ProblemDetails, content_type = "application/problem+json"), (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"), (status = 403, description = "Bearer tokens and missing permissions are refused", body = ProblemDetails, content_type = "application/problem+json"), (status = 503, description = "Unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn update_dashboard(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    payload: Result<Json<SaveDashboardRequest>, JsonRejection>,
) -> Response {
    let user = match session_user(&state, &headers, true).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let expected = match parse_if_match_version(&headers) {
        Ok(Some(version)) => version,
        Ok(None) => {
            return problem_response(ProblemDetails::new(
                StatusCode::PRECONDITION_REQUIRED,
                "precondition_required",
                "If-Match is required",
            ));
        }
        Err(()) => {
            return problem_response(ProblemDetails::new(
                StatusCode::BAD_REQUEST,
                "invalid_precondition",
                "If-Match must contain one quoted version",
            ));
        }
    };
    let Ok(Json(request)) = payload else {
        return bad_request();
    };
    let name = match checked(&request) {
        Ok(name) => name,
        Err(errors) => return invalid(errors),
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::update(
        &mut client,
        &user.user_id,
        &id,
        &name,
        &request.layout,
        expected,
        Utc::now(),
    )
    .await
    {
        Ok(Ok(dashboard)) => with_etag(StatusCode::OK, view(dashboard, &user.user_id)),
        Ok(Err(refusal)) => refused(refusal),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(delete, path = "/api/v1/dashboards/{dashboard_id}", tag = "dashboards", params(("dashboard_id" = String, Path)),
    responses((status = 204, description = "Deleted"), (status = 404, description = "Not found or not visible", body = ProblemDetails, content_type = "application/problem+json"), (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"), (status = 403, description = "Bearer tokens and missing permissions are refused", body = ProblemDetails, content_type = "application/problem+json"), (status = 503, description = "Unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn delete_dashboard(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let user = match session_user(&state, &headers, true).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::delete(&mut client, &user.user_id, &id).await {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(refusal)) => refused(refusal),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(put, path = "/api/v1/dashboards/{dashboard_id}/sharing", tag = "dashboards", params(("dashboard_id" = String, Path)), request_body = crate::ShareDashboardRequest,
    responses((status = 200, description = "Sharing changed", body = crate::DashboardView), (status = 404, description = "Not found or not visible", body = ProblemDetails, content_type = "application/problem+json"), (status = 422, description = "Unknown role", body = ProblemDetails, content_type = "application/problem+json"), (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"), (status = 403, description = "Bearer tokens and missing permissions are refused", body = ProblemDetails, content_type = "application/problem+json"), (status = 503, description = "Unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn share_dashboard(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    payload: Result<Json<ShareDashboardRequest>, JsonRejection>,
) -> Response {
    let user = match session_user(&state, &headers, true).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let may_share = user
        .capabilities
        .iter()
        .any(|c| c.permission == Permission::DashboardsShare && c.scope == PermissionScope::Global);
    if !may_share {
        return problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "Access is not available",
        ));
    }
    let Ok(Json(request)) = payload else {
        return bad_request();
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::set_sharing(
        &mut client,
        &user.user_id,
        &id,
        request.role_id.as_deref(),
        Utc::now(),
    )
    .await
    {
        Ok(Ok(dashboard)) => with_etag(StatusCode::OK, view(dashboard, &user.user_id)),
        Ok(Err(refusal)) => refused(refusal),
        Err(_) => unavailable_auth(),
    }
}
