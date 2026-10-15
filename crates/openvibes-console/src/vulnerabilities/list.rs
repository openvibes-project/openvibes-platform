//! The vulnerability list and the views its rows are built from.

use axum::{
    extract::{Json, Query, State, rejection::QueryRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::{SecondsFormat, Utc};
use serde::Deserialize;

use super::cpe::{CPE_MAX_CONFIDENCE, CPE_PAGE, cpe_findings, cpe_view};
use crate::compliance::latest::invalid_finding_query;
use crate::{
    access::guard::{authenticated_agent_scope, unavailable_auth},
    http::{
        AuthHttpState,
        problem::{ProblemDetails, problem_response},
    },
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VulnerabilityListParams {
    pub(super) host: Option<String>,
    pub(super) advisory: Option<String>,
    pub(super) severity: Option<String>,
    pub(super) cve: Option<String>,
    pub(super) fixed: Option<bool>,
    pub(super) exploited: Option<bool>,
    pub(super) reboot_needed: Option<bool>,
    pub(super) min_confidence: Option<u8>,
}

#[utoipa::path(get, path="/api/v1/vulnerabilities", tag="vulnerabilities", params(("host"=Option<String>, Query), ("advisory"=Option<String>, Query), ("severity"=Option<String>, Query), ("cve"=Option<String>, Query), ("fixed"=Option<bool>, Query), ("exploited"=Option<bool>, Query), ("reboot_needed"=Option<bool>, Query), ("min_confidence"=Option<u8>, Query)), responses((status=200, description="Prioritised, scope-filtered vulnerabilities", body=crate::VulnerabilityPage), (status=400, description="Invalid filters", body=crate::ProblemDetails)))]
pub(crate) async fn authenticated_vulnerabilities(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    query: Result<Query<VulnerabilityListParams>, QueryRejection>,
) -> Response {
    let scope =
        match authenticated_agent_scope(&state, &headers, crate::Permission::VulnerabilitiesRead)
            .await
        {
            Ok(scope) => scope,
            Err(response) => return response,
        };
    let Query(params) = match query {
        Ok(value) => value,
        Err(_) => return invalid_finding_query(),
    };
    for value in [
        &params.host,
        &params.advisory,
        &params.severity,
        &params.cve,
    ]
    .into_iter()
    .flatten()
    {
        if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
            return invalid_finding_query();
        }
    }
    if params
        .severity
        .as_deref()
        .is_some_and(|s| !matches!(s, "critical" | "important" | "moderate" | "low" | "unrated"))
    {
        return invalid_finding_query();
    }
    let client = match state.pool.get().await {
        Ok(client) => client,
        Err(_) => return unavailable_auth(),
    };
    if let Some(host) = params.host.as_deref() {
        let matches = match platform_store::vulns::hosts_named_in_scope(&client, host, &scope).await
        {
            Ok(ids) => ids,
            Err(_) => return unavailable_auth(),
        };
        if matches.len() > 1 {
            let mut problem = ProblemDetails::new(
                StatusCode::BAD_REQUEST,
                "ambiguous_host",
                "Host name matches multiple visible hosts; use an agent ID",
            );
            problem.field_errors = Some(vec![crate::FieldError {
                field: "host".into(),
                code: "ambiguous_host".into(),
                message: matches.join(", "),
            }]);
            return problem_response(problem);
        }
    }
    let rows = match platform_store::vulns::list_in_scope(
        &client,
        &platform_store::vulns::ListFilter {
            host: params.host.as_deref(),
            advisory: params.advisory.as_deref(),
            severity: params.severity.as_deref(),
            cve: params.cve.as_deref(),
            fixed: params.fixed.unwrap_or(false),
            exploited: params.exploited,
            reboot_needed: params.reboot_needed,
            min_confidence: params.min_confidence,
        },
        &scope,
    )
    .await
    {
        Ok(rows) => rows,
        Err(_) => return unavailable_auth(),
    };
    let mut rows = rows;
    let mut more_available = rows.len() > 100;
    rows.truncate(100);
    let mut items: Vec<crate::VulnerabilityView> =
        rows.into_iter().map(vulnerability_view).collect();
    // Lower-confidence findings from NVD CPE ranges, only when asked for
    // (a minimum confidence at or below theirs) and never mixed into the
    // lists of fixed or reboot-pending vulnerabilities.
    let wants_cpe = params
        .min_confidence
        .is_some_and(|min| min <= CPE_MAX_CONFIDENCE)
        && !params.fixed.unwrap_or(false)
        && params.reboot_needed != Some(true)
        && params
            .advisory
            .as_deref()
            .is_none_or(|a| a.starts_with("CPE:"));
    if wants_cpe {
        let found = match cpe_findings(&client, &scope, &params).await {
            Ok(found) => found,
            Err(_) => return unavailable_auth(),
        };
        more_available |= found.len() > CPE_PAGE;
        items.extend(found.into_iter().take(CPE_PAGE).map(cpe_view));
    }
    if attach_triage(&client, &mut items).await.is_err() {
        return unavailable_auth();
    }
    Json(crate::VulnerabilityPage {
        items,
        more_available,
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    })
    .into_response()
}

/// Each row's triage (triage v2), in one lookup; untriaged rows stay open.
pub(super) async fn attach_triage(
    client: &platform_store::Client,
    items: &mut [crate::VulnerabilityView],
) -> Result<(), platform_store::StoreError> {
    let pairs: Vec<(String, String)> = items
        .iter()
        .map(|v| (v.agent_id.clone(), v.advisory_id.clone()))
        .collect();
    let triage = platform_store::vulnerability_triage::states(client, &pairs).await?;
    for item in items {
        if let Some(t) = triage.get(&(item.agent_id.clone(), item.advisory_id.clone())) {
            item.triage_state.clone_from(&t.state);
            item.triage_version = t.version;
            item.assigned_to.clone_from(&t.assigned_to);
        }
    }
    Ok(())
}

pub(super) fn vulnerability_view(row: platform_store::vulns::VulnRow) -> crate::VulnerabilityView {
    crate::VulnerabilityView {
        agent_id: row.agent_id,
        hostname: row.hostname,
        advisory_id: row.advisory_id,
        severity: match row.severity.as_str() {
            "critical" => crate::VulnerabilitySeverity::Critical,
            "important" => crate::VulnerabilitySeverity::Important,
            "moderate" => crate::VulnerabilitySeverity::Moderate,
            "low" => crate::VulnerabilitySeverity::Low,
            _ => crate::VulnerabilitySeverity::Unrated,
        },
        title: row.title,
        url: row.url,
        cves: row.cves,
        packages: row.packages,
        first_seen_at: row.first_seen_at.to_rfc3339_opts(SecondsFormat::Secs, true),
        fixed_at: row
            .fixed_at
            .map(|v| v.to_rfc3339_opts(SecondsFormat::Secs, true)),
        reboot_needed: row.reboot_needed,
        exploited: row.exploited,
        kev: row.kev,
        euvd: row.euvd,
        kev_due: row.kev_due.map(|v| v.to_string()),
        ransomware: row.ransomware,
        epss: row.epss,
        epss_percentile: row.epss_percentile,
        cvss: row.cvss,
        source: row.source,
        match_method: row.match_method,
        confidence: row.confidence,
        match_basis: row.match_basis,
        triage_state: "open".into(),
        triage_version: 0,
        assigned_to: None,
    }
}
