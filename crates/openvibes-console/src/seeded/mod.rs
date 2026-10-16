//! Deterministic, permission-aware C1 read models for the loopback demo.

use std::sync::Arc;

use axum::{Router, middleware, routing::get};

mod access;
mod audit;
mod compliance;
mod filters;
mod hosts;
mod persona;
mod repository;
mod responses;
mod vulnerabilities;

pub(crate) fn router() -> Router {
    let repository: Arc<dyn repository::ConsoleRepository> =
        Arc::new(repository::SeededRepository::default());
    Router::new()
        .route("/api/v1/agents/summary", get(hosts::agent_summary))
        .route("/api/v1/agents", get(hosts::agents))
        .route("/api/v1/agents/{id}", get(hosts::agent))
        .route(
            "/api/v1/compliance/summary",
            get(compliance::finding_summary),
        )
        .route("/api/v1/audit-events", get(audit::audit_events))
        .route("/api/v1/audit-export.csv", get(audit::audit_export))
        .route("/api/v1/access-control", get(access::access_inventory))
        .route("/api/v1/compliance/latest", get(compliance::findings))
        .route("/api/v1/compliance/groups", get(compliance::finding_groups))
        .route(
            "/api/v1/compliance/groups/{rule_set}/{rule}/endpoints",
            get(compliance::finding_group_endpoints),
        )
        .route(
            "/api/v1/vulnerabilities/summary",
            get(vulnerabilities::vulnerability_summary),
        )
        .route(
            "/api/v1/vulnerabilities",
            get(vulnerabilities::vulnerabilities),
        )
        .route(
            "/api/v1/vulnerabilities/advisories/{advisory_id}",
            get(vulnerabilities::vulnerability_advisory),
        )
        .route(
            "/api/v1/compliance/latest/{agent}/{rule_set}/{rule}",
            get(compliance::finding),
        )
        .with_state(repository)
        .layer(middleware::map_response(responses::no_store))
}
