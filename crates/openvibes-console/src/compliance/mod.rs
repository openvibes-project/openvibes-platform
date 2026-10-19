//! Compliance: the latest findings and finding groups, history, triage, bulk
//! triage and triage detail.

use axum::{
    Router,
    routing::{get, post, put},
};

use crate::http::AuthHttpState;

pub(crate) mod bulk;
pub(crate) mod group_triage;
pub(crate) mod groups;
pub(crate) mod history;
pub(crate) mod latest;
pub(crate) mod triage;
pub(crate) mod triage_detail;
mod types;

pub use types::{
    BulkFindingTriageChange, BulkFindingTriageRequest, BulkFindingTriageResponse,
    FindingGroupEndpointPage, FindingGroupEndpointView, FindingGroupPage, FindingGroupView,
    FindingHistoryEntry, FindingHistoryPage, FindingOrigin, FindingPage, FindingSummary,
    FindingTriageCounts, FindingTriageView, FindingView, Severity, UpdateFindingTriageRequest,
};

/// Findings, finding groups, history and triage, triage history and bulk
/// triage (alarms and vulnerabilities included), and per-host vulnerability
/// triage.
pub(crate) fn routes() -> Router<AuthHttpState> {
    Router::new()
        .route(
            "/v1/compliance/summary",
            get(latest::authenticated_finding_summary),
        )
        .route(
            "/v1/compliance/groups",
            get(groups::authenticated_finding_groups),
        )
        .route(
            "/v1/compliance/groups/{rule_set_id}/{rule_id}/endpoints",
            get(groups::authenticated_finding_group_endpoints),
        )
        .route(
            "/v1/compliance/groups/{rule_set_id}/{rule_id}/triage",
            post(group_triage::update_authenticated_finding_group_triage),
        )
        .route(
            "/v1/compliance/latest",
            get(latest::authenticated_latest_findings),
        )
        .route(
            "/v1/compliance/latest/{agent_id}/{rule_set_id}/{rule_id}",
            get(latest::authenticated_latest_finding),
        )
        .route(
            "/v1/compliance/latest/{agent_id}/{rule_set_id}/{rule_id}/triage",
            get(triage::authenticated_finding_triage)
                .put(triage::update_authenticated_finding_triage),
        )
        .route(
            "/v1/compliance/history",
            get(history::authenticated_finding_history),
        )
        .route(
            "/v1/compliance/history/{observed_day}/{finding_id}",
            get(history::authenticated_finding_event),
        )
        .route("/v1/triage-history", get(triage_detail::triage_history))
        .route("/v1/alarms/bulk", post(bulk::bulk_alarms))
        .route("/v1/compliance/bulk", post(bulk::bulk_compliance))
        .route("/v1/vulnerabilities/bulk", post(bulk::bulk_vulnerabilities))
        .route(
            "/v1/vulnerabilities/advisories/{advisory_id}/hosts/{agent_id}/triage",
            put(triage_detail::update_vulnerability_triage),
        )
}
