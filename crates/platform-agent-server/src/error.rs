use std::fmt;

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use openvibes_core::{PlatformError, PlatformErrorCode, SchemaVersion};

/// Startup failures; messages never include file contents or secrets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerError {
    /// The settings are invalid or out of range.
    Config,
    /// A certificate or key file is unreadable or invalid.
    Tls,
    /// The database is unreachable at startup.
    Database,
    /// A listener could not be bound.
    Listen,
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Config => "invalid configuration",
            Self::Tls => "invalid TLS or CA certificate or key file",
            Self::Database => "database unavailable",
            Self::Listen => "cannot bind a listener",
        })
    }
}

impl std::error::Error for ServerError {}

/// Request outcomes other than success. Bodies are fixed and never echo
/// the request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApiError {
    /// Malformed, invalid, or oversized request (400).
    BadRequest,
    /// No, unknown, or expired client certificate (401).
    Unauthorized,
    /// The agent is revoked (403 `identity_revoked`).
    Revoked,
    /// The requested resource does not exist (404).
    NotFound,
    /// The database is unreachable or a query failed (503).
    Unavailable,
    /// More than `max_in_flight` requests at once (503).
    Busy,
    /// The request missed its deadline (408).
    Timeout,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            Self::Revoked => (
                StatusCode::FORBIDDEN,
                Json(PlatformError {
                    schema_version: SchemaVersion::V1,
                    code: PlatformErrorCode::IdentityRevoked,
                }),
            )
                .into_response(),
            Self::BadRequest => (StatusCode::BAD_REQUEST, "bad request").into_response(),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized").into_response(),
            Self::NotFound => (StatusCode::NOT_FOUND, "not found").into_response(),
            Self::Unavailable => {
                // Logged inside the request span, so the line carries the
                // endpoint (and agent_id once authenticated).
                tracing::warn!("database unavailable or query failed");
                (StatusCode::SERVICE_UNAVAILABLE, "unavailable").into_response()
            }
            Self::Busy => (StatusCode::SERVICE_UNAVAILABLE, "busy").into_response(),
            Self::Timeout => (StatusCode::REQUEST_TIMEOUT, "request timeout").into_response(),
        }
    }
}

impl From<platform_store::StoreError> for ApiError {
    fn from(_: platform_store::StoreError) -> Self {
        Self::Unavailable
    }
}
