//! The vulnerability summary.

use axum::{
    extract::{Json, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use chrono::SecondsFormat;

use crate::{
    access::guard::{authenticated_agent_scope, unavailable_auth},
    http::AuthHttpState,
};

#[utoipa::path(get, path="/api/v1/vulnerabilities/summary", tag="vulnerabilities", responses((status=200, description="Scoped vulnerability summary", body=crate::VulnerabilitySummary)))]
pub(crate) async fn authenticated_vulnerability_summary(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    let scope =
        match authenticated_agent_scope(&state, &headers, crate::Permission::VulnerabilitiesRead)
            .await
        {
            Ok(scope) => scope,
            Err(response) => return response,
        };
    let client = match state.pool.get().await {
        Ok(client) => client,
        Err(_) => return unavailable_auth(),
    };
    let summary = match platform_store::vulns::summary_in_scope(&client, &scope).await {
        Ok(summary) => summary,
        Err(_) => return unavailable_auth(),
    };
    let by_severity = summary
        .by_severity
        .into_iter()
        .map(|(severity, count)| crate::VulnerabilitySeverityCount {
            severity: match severity.as_str() {
                "critical" => crate::VulnerabilitySeverity::Critical,
                "important" => crate::VulnerabilitySeverity::Important,
                "moderate" => crate::VulnerabilitySeverity::Moderate,
                "low" => crate::VulnerabilitySeverity::Low,
                _ => crate::VulnerabilitySeverity::Unrated,
            },
            count: count.max(0) as u64,
        })
        .collect();
    let top_hosts = summary
        .top_hosts
        .into_iter()
        .map(
            |(agent_id, hostname, open, serious)| crate::VulnerabilityTopHost {
                agent_id,
                hostname,
                open: open.max(0) as u64,
                serious: serious.max(0) as u64,
            },
        )
        .collect();
    Json(crate::VulnerabilitySummary {
        by_severity,
        hosts: summary.hosts.max(0) as u64,
        top_hosts,
        reboot_hosts: summary.reboot_hosts.max(0) as u64,
        no_fix: summary.no_fix.max(0) as u64,
        exploited: summary.exploited.max(0) as u64,
        feed_last_imported_at: summary
            .feed_last_imported_at
            .map(|at| at.to_rfc3339_opts(SecondsFormat::Secs, true)),
    })
    .into_response()
}
