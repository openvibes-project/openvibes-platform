//! One advisory: its CVE enrichment and the hosts it affects.

use axum::{
    extract::{Json, Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use chrono::{SecondsFormat, Utc};

use super::cpe::{CPE_PREFIX, cpe_findings, cpe_view};
use super::list::{VulnerabilityListParams, attach_triage, vulnerability_view};
use crate::compliance::latest::invalid_finding_query;
use crate::{
    access::guard::{authenticated_agent_scope, unavailable_auth},
    http::{
        AuthHttpState,
        problem::{ProblemDetails, problem_response},
    },
};

/// Most hosts an advisory's detail lists.
const ADVISORY_HOSTS: usize = 2_000;

#[utoipa::path(get, path="/api/v1/vulnerabilities/advisories/{advisory_id}", tag="vulnerabilities", params(("advisory_id"=String, Path)), responses((status=200, description="Scoped advisory and CVE enrichment", body=crate::VulnerabilityAdvisoryDetail), (status=404, description="Advisory not visible", body=crate::ProblemDetails)))]
pub(crate) async fn authenticated_vulnerability_advisory(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(advisory_id): Path<String>,
) -> Response {
    let scope =
        match authenticated_agent_scope(&state, &headers, crate::Permission::VulnerabilitiesRead)
            .await
        {
            Ok(scope) => scope,
            Err(response) => return response,
        };
    if advisory_id.is_empty()
        || advisory_id.len() > 128
        || advisory_id.chars().any(char::is_control)
    {
        return invalid_finding_query();
    }
    let client = match state.pool.get().await {
        Ok(client) => client,
        Err(_) => return unavailable_auth(),
    };
    if advisory_id.starts_with(CPE_PREFIX) {
        let params = VulnerabilityListParams {
            host: None,
            advisory: Some(advisory_id.clone()),
            severity: None,
            cve: None,
            fixed: None,
            exploited: None,
            reboot_needed: None,
            min_confidence: Some(0),
        };
        let found = match cpe_findings(&client, &scope, &params).await {
            Ok(found) if !found.is_empty() => found,
            Ok(_) => {
                return problem_response(ProblemDetails::not_found(
                    "advisory_not_found",
                    "Advisory not found",
                ));
            }
            Err(_) => return unavailable_auth(),
        };
        let first = &found[0];
        let cves = vec![crate::CveDetailView {
            cve_id: first.cve_id.clone(),
            cvss_score: first.cvss,
            cvss_version: None,
            cwe: Vec::new(),
            description: first.description.clone(),
            kev: first.kev,
            euvd_exploited: first.euvd.then(|| "listed".to_owned()),
            epss: first.epss,
        }];
        let more_available = found.len() > 100;
        let items = found.into_iter().take(100).map(cpe_view).collect();
        return Json(crate::VulnerabilityAdvisoryDetail {
            hosts: crate::VulnerabilityPage {
                items,
                more_available,
                generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            },
            cves,
        })
        .into_response();
    }
    let cves =
        match platform_store::vulns::cve_details_in_scope(&client, &advisory_id, &scope).await {
            Ok(Some(cves)) => cves,
            Ok(None) => {
                return problem_response(ProblemDetails::not_found(
                    "advisory_not_found",
                    "Advisory not found",
                ));
            }
            Err(_) => return unavailable_auth(),
        };
    let rows = match platform_store::vulns::list_in_scope(
        &client,
        &platform_store::vulns::ListFilter {
            advisory: Some(&advisory_id),
            ..Default::default()
        },
        &scope,
    )
    .await
    {
        Ok(rows) => rows,
        Err(_) => return unavailable_auth(),
    };
    // The detail's Hosts tab: as many hosts as a finding's (2,000), so
    // it is not cut off at the list's page (#239).
    // ponytail: one response; page it if advisories reach that many hosts.
    let mut rows = rows;
    let more_available = rows.len() > ADVISORY_HOSTS;
    rows.truncate(ADVISORY_HOSTS);
    let mut items: Vec<crate::VulnerabilityView> =
        rows.into_iter().map(vulnerability_view).collect();
    if attach_triage(&client, &mut items).await.is_err() {
        return unavailable_auth();
    }
    let hosts = crate::VulnerabilityPage {
        items,
        more_available,
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    };
    let cves = cves
        .into_iter()
        .map(|c| crate::CveDetailView {
            cve_id: c.cve_id,
            cvss_score: c.cvss_score,
            cvss_version: c.cvss_version,
            cwe: c.cwe,
            description: c.description,
            kev: c.kev,
            euvd_exploited: c.euvd_exploited,
            epss: c.epss,
        })
        .collect();
    Json(crate::VulnerabilityAdvisoryDetail { hosts, cves }).into_response()
}
