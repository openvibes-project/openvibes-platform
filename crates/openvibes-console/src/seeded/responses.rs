//! The demo's problem answers and its no-store header.

use axum::{http::StatusCode, response::Response};

use crate::http::problem::{ProblemDetails, problem_response};

pub(super) type SeedError = Box<Response>;

pub(super) fn invalid_header(name: &'static str) -> SeedError {
    Box::new(bad_request("invalid_demo_selection", name))
}

pub(super) fn bad_request(code: &'static str, title: &'static str) -> Response {
    problem_response(ProblemDetails::new(StatusCode::BAD_REQUEST, code, title))
}

pub(super) fn denied() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::FORBIDDEN,
        "permission_denied",
        "Access is not available",
    ))
}

pub(super) fn not_found() -> Response {
    problem_response(ProblemDetails::not_found(
        "resource_not_found",
        "Resource not found",
    ))
}

pub(super) fn unavailable() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "seeded_read_unavailable",
        "Synthetic read source is unavailable",
    ))
}

pub(super) fn expired() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::UNAUTHORIZED,
        "session_expired",
        "The demonstration session has expired",
    ))
}

pub(super) async fn no_store(mut response: Response) -> Response {
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}
