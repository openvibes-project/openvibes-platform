//! Audit trail: the event list, its CSV export and the retention policy.

use axum::{Router, routing::get};

use crate::http::AuthHttpState;

pub(crate) mod events;
pub(crate) mod export;
mod query;
pub(crate) mod retention;
mod types;

pub use types::{
    AuditEventPage, AuditEventView, AuditRetentionPolicy, UpdateAuditRetentionRequest,
};

/// The audit event list, its CSV export and the retention policy.
pub(crate) fn routes() -> Router<AuthHttpState> {
    Router::new()
        .route(
            "/v1/audit-retention",
            get(retention::authenticated_audit_retention)
                .put(retention::update_authenticated_audit_retention),
        )
        .route("/v1/audit-events", get(events::authenticated_audit_events))
        .route(
            "/v1/audit-export.csv",
            get(export::authenticated_audit_export),
        )
}
