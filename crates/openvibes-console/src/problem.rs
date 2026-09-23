use std::sync::atomic::{AtomicU64, Ordering};

use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;

static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

/// Stable RFC Problem Details-style error response used by the console API.
#[derive(Debug, Serialize)]
pub struct ProblemDetails {
    /// Stable machine-readable error code.
    pub code: &'static str,
    /// Short human-readable error title.
    pub title: &'static str,
    /// HTTP status code.
    pub status: u16,
    /// Process-local correlation identifier.
    pub request_id: String,
}

impl ProblemDetails {
    pub(crate) fn not_found(code: &'static str, title: &'static str) -> Self {
        let sequence = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
        Self {
            code,
            title,
            status: StatusCode::NOT_FOUND.as_u16(),
            request_id: format!("c0-{sequence:016x}"),
        }
    }
}

pub(crate) fn problem_response(problem: ProblemDetails) -> Response {
    let status = StatusCode::from_u16(problem.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut response = (status, Json(problem)).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
