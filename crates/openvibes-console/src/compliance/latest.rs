//! The latest findings: summary, list and one finding.

use axum::{
    extract::{Path, Query, State, rejection::QueryRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::{SecondsFormat, Utc};
use serde::Deserialize;

use crate::{
    access::guard::{authenticated_agent_scope, unavailable_auth},
    http::{
        AuthHttpState,
        problem::{ProblemDetails, problem_response},
    },
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LatestFindingListParams {
    severity: Option<String>,
    /// One host's findings only.
    agent_id: Option<String>,
    cursor: Option<String>,
    limit: Option<u16>,
}

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct LatestFindingCursorToken {
    severity: Option<String>,
    scope: platform_store::console_read::AgentScope,
    last_observed_at: String,
    agent_id: String,
    rule_set_id: String,
    rule_id: String,
}

#[utoipa::path(
    get,
    path = "/api/v1/compliance/summary",
    tag = "compliance",
    responses(
        (status = 200, description = "Scope-filtered latest compliance finding counts", body = crate::FindingSummary),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Permission denied", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(crate) async fn authenticated_finding_summary(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    let scope = match authenticated_agent_scope(&state, &headers, crate::Permission::ComplianceRead)
        .await
    {
        Ok(scope) => scope,
        Err(response) => return response,
    };
    let client = match state.pool.get().await {
        Ok(client) => client,
        Err(_) => return unavailable_auth(),
    };
    match platform_store::console_read::finding_summary_in_scope(&client, &scope).await {
        Ok(summary) => (
            StatusCode::OK,
            axum::Json(crate::FindingSummary {
                total: summary.total.try_into().unwrap_or_default(),
                impacted_agents: summary.impacted_agents.try_into().unwrap_or_default(),
                critical: summary.critical.try_into().unwrap_or_default(),
                high: summary.high.try_into().unwrap_or_default(),
                medium: summary.medium.try_into().unwrap_or_default(),
                low: summary.low.try_into().unwrap_or_default(),
            }),
        )
            .into_response(),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/compliance/latest",
    tag = "compliance",
    params(
        ("severity" = Option<String>, Query, description = "critical, high, medium, or low"),
        ("agent_id" = Option<String>, Query, description = "One host's findings only"),
        ("cursor" = Option<String>, Query, description = "Opaque continuation cursor"),
        ("limit" = Option<u16>, Query, description = "Page size from 1 to 100")
    ),
    responses(
        (status = 200, description = "Scope-filtered latest finding page", body = crate::FindingPage),
        (status = 400, description = "Invalid query or cursor", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Permission denied", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(crate) async fn authenticated_latest_findings(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    query: Result<Query<LatestFindingListParams>, QueryRejection>,
) -> Response {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use platform_store::console_read::{
        LatestCursor, LatestQuery, PageLimit, Severity, latest_findings_in_scope,
    };

    let scope = match authenticated_agent_scope(&state, &headers, crate::Permission::ComplianceRead)
        .await
    {
        Ok(scope) => scope,
        Err(response) => return response,
    };
    let Query(params) = match query {
        Ok(query) => query,
        Err(_) => return invalid_finding_query(),
    };
    let Some(limit) = PageLimit::new(params.limit.unwrap_or(crate::DEFAULT_PAGE_SIZE)) else {
        return invalid_finding_query();
    };
    let severity = match params.severity.as_deref() {
        None => None,
        Some("critical") => Some(Severity::Critical),
        Some("high") => Some(Severity::High),
        Some("medium") => Some(Severity::Medium),
        Some("low") => Some(Severity::Low),
        Some(_) => return invalid_finding_query(),
    };
    let after = match params.cursor.as_deref() {
        None => None,
        Some(encoded) if encoded.len() <= crate::MAX_CURSOR_LENGTH => {
            let decoded = match URL_SAFE_NO_PAD.decode(encoded) {
                Ok(decoded) => decoded,
                Err(_) => return invalid_finding_query(),
            };
            let token = match serde_json::from_slice::<LatestFindingCursorToken>(&decoded) {
                Ok(token) if token.severity == params.severity && token.scope == scope => token,
                _ => return invalid_finding_query(),
            };
            let last_observed_at =
                match chrono::DateTime::parse_from_rfc3339(&token.last_observed_at) {
                    Ok(value) => value.with_timezone(&Utc),
                    Err(_) => return invalid_finding_query(),
                };
            Some(LatestCursor {
                last_observed_at,
                agent_id: token.agent_id,
                rule_set_id: token.rule_set_id,
                rule_id: token.rule_id,
            })
        }
        Some(_) => return invalid_finding_query(),
    };
    let client = match state.pool.get().await {
        Ok(client) => client,
        Err(_) => return unavailable_auth(),
    };
    let page = match latest_findings_in_scope(
        &client,
        &LatestQuery {
            severity,
            // ponytail: the cursor isn't bound to agent_id (it is to
            // severity and scope); a client changing hosts mid-paging
            // just reads another page. Scope still applies.
            agent_id: params.agent_id.filter(|id| !id.is_empty()),
            after,
            limit,
        },
        &scope,
    )
    .await
    {
        Ok(page) => page,
        Err(_) => return unavailable_auth(),
    };
    let items = page.items.into_iter().map(latest_finding_view).collect();
    let next_cursor = match page.next {
        None => None,
        Some(cursor) => {
            let token = LatestFindingCursorToken {
                severity: params.severity,
                scope,
                last_observed_at: cursor
                    .last_observed_at
                    .to_rfc3339_opts(SecondsFormat::Micros, true),
                agent_id: cursor.agent_id,
                rule_set_id: cursor.rule_set_id,
                rule_id: cursor.rule_id,
            };
            match serde_json::to_vec(&token) {
                Ok(token) => Some(URL_SAFE_NO_PAD.encode(token)),
                Err(_) => return unavailable_auth(),
            }
        }
    };
    (
        StatusCode::OK,
        axum::Json(crate::FindingPage {
            items,
            next_cursor,
            generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        }),
    )
        .into_response()
}

pub(crate) fn invalid_finding_query() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::BAD_REQUEST,
        "invalid_query",
        "Finding query parameters are invalid",
    ))
}

pub(super) fn latest_finding_view(
    finding: platform_store::console_read::LatestFinding,
) -> crate::FindingView {
    use platform_store::console_read::Severity;
    crate::FindingView {
        detection: finding.detection,
        id: finding.finding_id,
        agent_id: finding.agent_id,
        hostname: finding.hostname,
        rule_set_id: if finding.rule_set_id.is_empty() {
            "~unknown".into()
        } else {
            finding.rule_set_id
        },
        rule_id: finding.rule_id,
        rule_version: finding.rule_version.try_into().unwrap_or_default(),
        severity: match finding.severity {
            Severity::Critical => crate::Severity::Critical,
            Severity::High => crate::Severity::High,
            Severity::Medium => crate::Severity::Medium,
            Severity::Low => crate::Severity::Low,
        },
        confidence: finding.confidence.try_into().unwrap_or_default(),
        message: finding.message,
        evidence: finding.evidence,
        scan_id: finding.scan_id,
        authenticated: finding.authenticated,
        origin: match finding.origin.as_str() {
            "import" => crate::FindingOrigin::Import,
            _ => crate::FindingOrigin::Online,
        },
        first_observed_at: finding
            .first_observed_at
            .to_rfc3339_opts(SecondsFormat::Secs, true),
        last_observed_at: finding
            .last_observed_at
            .to_rfc3339_opts(SecondsFormat::Secs, true),
        received_at: finding
            .received_at
            .to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/compliance/latest/{agent_id}/{rule_set_id}/{rule_id}",
    tag = "compliance",
    params(
        ("agent_id" = String, Path, description = "Stable agent identifier"),
        ("rule_set_id" = String, Path, description = "Rule set id or reserved ~unknown"),
        ("rule_id" = String, Path, description = "Rule identifier")
    ),
    responses(
        (status = 200, description = "Visible latest observation", body = crate::FindingView),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Permission denied", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "Compliance finding not found", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(crate) async fn authenticated_latest_finding(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((agent_id, rule_set_id, rule_id)): Path<(String, String, String)>,
) -> Response {
    let scope = match authenticated_agent_scope(&state, &headers, crate::Permission::ComplianceRead)
        .await
    {
        Ok(scope) => scope,
        Err(response) => return response,
    };
    let client = match state.pool.get().await {
        Ok(client) => client,
        Err(_) => return unavailable_auth(),
    };
    let rule_set_id = if rule_set_id == "~unknown" {
        ""
    } else {
        &rule_set_id
    };
    match platform_store::console_read::latest_finding_in_scope(
        &client,
        &agent_id,
        rule_set_id,
        &rule_id,
        &scope,
    )
    .await
    {
        Ok(Some(finding)) => axum::Json(latest_finding_view(finding)).into_response(),
        Ok(None) => problem_response(ProblemDetails::not_found(
            "compliance_finding_not_found",
            "Compliance finding not found",
        )),
        Err(_) => unavailable_auth(),
    }
}
