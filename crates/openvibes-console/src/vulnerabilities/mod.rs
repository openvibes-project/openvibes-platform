//! Vulnerabilities: the summary, the list and advisory detail.

use axum::{Router, routing::get};

use crate::http::AuthHttpState;

pub(crate) mod advisory;
mod cpe;
pub(crate) mod list;
pub(crate) mod summary;
mod types;

pub use types::{
    CveDetailView, VulnerabilityAdvisoryDetail, VulnerabilityPage, VulnerabilitySeverity,
    VulnerabilitySeverityCount, VulnerabilitySummary, VulnerabilityTopHost, VulnerabilityView,
};

/// The vulnerability summary, list and advisory detail.
pub(crate) fn routes() -> Router<AuthHttpState> {
    Router::new()
        .route(
            "/v1/vulnerabilities/summary",
            get(summary::authenticated_vulnerability_summary),
        )
        .route(
            "/v1/vulnerabilities",
            get(list::authenticated_vulnerabilities),
        )
        .route(
            "/v1/vulnerabilities/advisories/{advisory_id}",
            get(advisory::authenticated_vulnerability_advisory),
        )
}
