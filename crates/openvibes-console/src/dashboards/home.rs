//! The dashboard that opens first for the signed-in user.

use axum::{
    Json,
    extract::{State, rejection::JsonRejection},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use platform_store::dashboards as store;

use super::responses::{bad_request, refused};
use crate::{
    HomeDashboard, ProblemDetails,
    access::guard::{session_user, unavailable_auth},
    http::AuthHttpState,
};

#[utoipa::path(get, path = "/api/v1/me/home", tag = "dashboards",
    responses((status = 200, description = "Home dashboard, or null for the built-in", body = crate::HomeDashboard), (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"), (status = 403, description = "Bearer tokens and missing permissions are refused", body = ProblemDetails, content_type = "application/problem+json"), (status = 503, description = "Unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn get_home(State(state): State<AuthHttpState>, headers: HeaderMap) -> Response {
    let user = match session_user(&state, &headers, false).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::home(&client, &user.user_id).await {
        Ok(dashboard_id) => Json(HomeDashboard { dashboard_id }).into_response(),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(put, path = "/api/v1/me/home", tag = "dashboards", request_body = crate::HomeDashboard,
    responses((status = 200, description = "Home changed", body = crate::HomeDashboard), (status = 404, description = "Dashboard not visible", body = ProblemDetails, content_type = "application/problem+json"), (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"), (status = 403, description = "Bearer tokens and missing permissions are refused", body = ProblemDetails, content_type = "application/problem+json"), (status = 503, description = "Unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn set_home(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    payload: Result<Json<HomeDashboard>, JsonRejection>,
) -> Response {
    let user = match session_user(&state, &headers, true).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Ok(Json(request)) = payload else {
        return bad_request();
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::set_home(&mut client, &user.user_id, request.dashboard_id.as_deref()).await {
        Ok(Ok(())) => Json(request).into_response(),
        Ok(Err(refusal)) => refused(refusal),
        Err(_) => unavailable_auth(),
    }
}
