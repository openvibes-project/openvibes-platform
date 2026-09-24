use std::fmt;

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use openvibes_core::{PlatformError, PlatformErrorCode, SchemaVersion};

/// Startup failures; messages never include file contents or secrets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngestError {
    /// The configuration is missing, invalid, or out of range.
    Config,
    /// A certificate or key file is unreadable or invalid.
    Tls,
    /// The database is unreachable at startup.
    Database,
    /// A listener could not be bound.
    Listen,
}

impl fmt::Display for IngestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Config => "invalid ingest configuration",
            Self::Tls => "invalid TLS or CA certificate or key file",
            Self::Database => "database unavailable",
            Self::Listen => "cannot bind a listener",
        })
    }
}

impl std::error::Error for IngestError {}

/// Request outcomes other than success. Bodies are fixed and never echo
/// the request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ApiError {
    BadRequest,
    Unauthorized,
    Revoked,
    /// The database is unreachable or a query failed.
    Unavailable,
    /// More than `max_in_flight` requests at once.
    Busy,
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
