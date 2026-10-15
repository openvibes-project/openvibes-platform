use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::SecondsFormat;
use platform_store::dashboards::{Dashboard, Refusal};

use super::layout::{validate_layout, validate_name};
use crate::{DashboardView, ProblemDetails, SaveDashboardRequest, http::problem::problem_response};

pub(super) fn view(dashboard: Dashboard, user_id: &str) -> DashboardView {
    DashboardView {
        mine: dashboard.owner_user_id == user_id,
        dashboard_id: dashboard.dashboard_id,
        name: dashboard.name,
        owner_display_name: dashboard.owner_display_name,
        shared_role_id: dashboard.shared_role_id,
        version: dashboard.version.try_into().unwrap_or_default(),
        layout: dashboard.layout,
        created_at: dashboard
            .created_at
            .to_rfc3339_opts(SecondsFormat::Secs, true),
        updated_at: dashboard
            .updated_at
            .to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub(super) fn with_etag(status: StatusCode, dashboard: DashboardView) -> Response {
    let etag = format!("\"{}\"", dashboard.version);
    let mut response = (status, Json(dashboard)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(value) = HeaderValue::from_str(&etag) {
        response.headers_mut().insert(header::ETAG, value);
    }
    response
}

pub(super) fn refused(refusal: Refusal) -> Response {
    problem_response(match refusal {
        Refusal::NotFound => {
            ProblemDetails::not_found("dashboard_not_found", "Dashboard not found")
        }
        Refusal::NotOwner => ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "not_dashboard_owner",
            "Only the owner can change this dashboard; duplicate it instead",
        ),
        Refusal::Stale => ProblemDetails::new(
            StatusCode::PRECONDITION_FAILED,
            "stale_dashboard",
            "The dashboard changed since you loaded it",
        ),
        Refusal::TooMany => ProblemDetails::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "too_many_dashboards",
            "You already have 100 dashboards",
        ),
        Refusal::UnknownRole => ProblemDetails::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "unknown_role",
            "No such role",
        ),
    })
}

pub(super) fn invalid(errors: Vec<crate::FieldError>) -> Response {
    let mut problem = ProblemDetails::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "invalid_dashboard",
        "The dashboard is invalid",
    );
    problem.field_errors = Some(errors);
    problem_response(problem)
}

pub(super) fn bad_request() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "The request body is invalid",
    ))
}

/// Validates name and layout; the trimmed name, or every field problem.
pub(super) fn checked(request: &SaveDashboardRequest) -> Result<String, Vec<crate::FieldError>> {
    let name = validate_name(&request.name);
    let layout = validate_layout(&request.layout);
    match (name, layout) {
        (Ok(name), Ok(())) => Ok(name),
        (name, layout) => {
            let mut errors: Vec<_> = name.err().into_iter().collect();
            errors.extend(layout.err().unwrap_or_default());
            errors.truncate(32);
            Err(errors)
        }
    }
}
