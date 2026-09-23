use std::sync::atomic::{AtomicU64, Ordering};

use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use utoipa::ToSchema;

static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

/// Stable RFC Problem Details-style error response used by the console API.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct ProblemDetails {
    /// Stable machine-readable error code.
    pub code: String,
    /// Short human-readable error title.
    pub title: String,
    /// HTTP status code.
    #[schema(minimum = 400, maximum = 599)]
    pub status: u16,
    /// Process-local correlation identifier.
    pub request_id: String,
    /// Bounded request-field errors when validation can safely identify them.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(max_items = 32)]
    pub field_errors: Option<Vec<FieldError>>,
}

/// Safe validation detail for one request field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct FieldError {
    /// Stable JSON field name or dotted field path.
    pub field: String,
    /// Stable machine-readable validation code.
    pub code: String,
    /// Bounded operator-facing explanation.
    pub message: String,
}

impl ProblemDetails {
    pub(crate) fn not_found(code: &'static str, title: &'static str) -> Self {
        let sequence = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
        Self {
            code: code.to_owned(),
            title: title.to_owned(),
            status: StatusCode::NOT_FOUND.as_u16(),
            request_id: format!("c0-{sequence:016x}"),
            field_errors: None,
        }
    }

    pub(crate) fn authentication_unavailable() -> Self {
        let sequence = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
        Self {
            code: "authentication_unavailable".to_owned(),
            title: "Authentication is not available".to_owned(),
            status: StatusCode::SERVICE_UNAVAILABLE.as_u16(),
            request_id: format!("c0-{sequence:016x}"),
            field_errors: None,
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
