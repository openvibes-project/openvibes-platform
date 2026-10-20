//! Findings grouped by rule, and the endpoints of one group.

use axum::{
    extract::{Json, Path, Query, State, rejection::QueryRejection},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use chrono::{Duration, SecondsFormat, Utc};
use serde::Deserialize;

use crate::http::validate::invalid_finding_query;
use crate::{
    access::guard::{authenticated_agent_scope, unavailable_auth},
    http::{
        AuthHttpState,
        problem::{ProblemDetails, problem_response},
    },
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FindingGroupsParams {
    since: Option<String>,
    /// One host's findings only.
    agent_id: Option<String>,
    cursor: Option<String>,
    limit: Option<u16>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FindingGroupEndpointsParams {
    since: Option<String>,
    include_older: Option<bool>,
    cursor: Option<String>,
    limit: Option<u16>,
}

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct FindingGroupCursorToken {
    since: String,
    scope: platform_store::console_read::AgentScope,
    /// The host filter the page was read with; a cursor never crosses filters.
    #[serde(default)]
    agent_id: Option<String>,
    last_observed_at: String,
    rule_set_id: String,
    rule_id: String,
}

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct FindingGroupEndpointCursorToken {
    since: String,
    include_older: bool,
    scope: platform_store::console_read::AgentScope,
    rule_set_id: String,
    rule_id: String,
    last_observed_at: String,
    agent_id: String,
}

#[utoipa::path(get, path="/api/v1/compliance/groups", tag = "compliance", params(("since"=Option<String>, Query), ("agent_id"=Option<String>, Query, description="One host's findings only"), ("cursor"=Option<String>, Query), ("limit"=Option<u16>, Query)), responses((status=200, description="Recent scope-filtered findings grouped by rule", body=crate::FindingGroupPage)))]
pub(crate) async fn authenticated_finding_groups(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    query: Result<Query<FindingGroupsParams>, QueryRejection>,
) -> Response {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use platform_store::console_read::{
        FindingGroupCursor, FindingGroupQuery, finding_groups_in_scope,
    };
    let scope = match authenticated_agent_scope(&state, &headers, crate::Permission::ComplianceRead)
        .await
    {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Query(params) = match query {
        Ok(v) => v,
        Err(_) => return invalid_finding_query(),
    };
    let agent_id = params.agent_id.filter(|id| !id.is_empty());
    if agent_id
        .as_deref()
        .is_some_and(|id| !crate::http::validate::valid_agent_id(id))
    {
        return invalid_finding_query();
    }
    let cursor_token = match params.cursor.as_deref() {
        None => None,
        Some(encoded) if encoded.len() <= crate::MAX_CURSOR_LENGTH => {
            let bytes = match URL_SAFE_NO_PAD.decode(encoded) {
                Ok(v) => v,
                Err(_) => return invalid_finding_query(),
            };
            match serde_json::from_slice::<FindingGroupCursorToken>(&bytes) {
                Ok(token) => Some(token),
                Err(_) => return invalid_finding_query(),
            }
        }
        Some(_) => return invalid_finding_query(),
    };
    let since_text = params
        .since
        .or_else(|| cursor_token.as_ref().map(|v| v.since.clone()))
        .unwrap_or_else(|| {
            (Utc::now() - Duration::hours(24)).to_rfc3339_opts(SecondsFormat::Secs, true)
        });
    let since = match chrono::DateTime::parse_from_rfc3339(&since_text) {
        Ok(v) => v.with_timezone(&Utc),
        Err(_) => return invalid_finding_query(),
    };
    if since > Utc::now() || since < Utc::now() - Duration::days(90) {
        return invalid_finding_query();
    }
    let limit = match platform_store::console_read::PageLimit::new(
        params.limit.unwrap_or(crate::DEFAULT_PAGE_SIZE),
    ) {
        Some(v) => v,
        None => return invalid_finding_query(),
    };
    let after = match cursor_token {
        None => None,
        Some(token)
            if token.since == since_text && token.scope == scope && token.agent_id == agent_id =>
        {
            let timestamp = match chrono::DateTime::parse_from_rfc3339(&token.last_observed_at) {
                Ok(v) => v.with_timezone(&Utc),
                Err(_) => return invalid_finding_query(),
            };
            Some(FindingGroupCursor {
                last_observed_at: timestamp,
                rule_set_id: token.rule_set_id,
                rule_id: token.rule_id,
            })
        }
        Some(_) => return invalid_finding_query(),
    };
    let client = match state.pool.get().await {
        Ok(v) => v,
        Err(_) => return unavailable_auth(),
    };
    let page = match finding_groups_in_scope(
        &client,
        &FindingGroupQuery {
            since,
            after,
            limit,
            agent_id: agent_id.clone(),
        },
        &scope,
    )
    .await
    {
        Ok(v) => v,
        Err(_) => return unavailable_auth(),
    };
    let items = page
        .items
        .into_iter()
        .map(|g| crate::FindingGroupView {
            rule_set_id: if g.rule_set_id.is_empty() {
                "~unknown".into()
            } else {
                g.rule_set_id
            },
            rule_id: g.rule_id,
            endpoint_count: g.endpoint_count.max(0) as u64,
            severity: match g.severity {
                platform_store::console_read::Severity::Critical => crate::Severity::Critical,
                platform_store::console_read::Severity::High => crate::Severity::High,
                platform_store::console_read::Severity::Medium => crate::Severity::Medium,
                platform_store::console_read::Severity::Low => crate::Severity::Low,
            },
            latest_message: g.latest_message,
            rule_versions: g
                .rule_versions
                .into_iter()
                .map(|v| v.max(0) as u64)
                .collect(),
            first_observed_at: g
                .first_observed_at
                .to_rfc3339_opts(SecondsFormat::Secs, true),
            last_observed_at: g
                .last_observed_at
                .to_rfc3339_opts(SecondsFormat::Secs, true),
            older_endpoint_count: g.older_endpoint_count.max(0) as u64,
            triage_counts: crate::FindingTriageCounts {
                open: g.open.max(0) as u64,
                mitigated: g.mitigated.max(0) as u64,
                accepted_risk: g.accepted_risk.max(0) as u64,
                false_positive: g.false_positive.max(0) as u64,
            },
        })
        .collect();
    let next_cursor = match page.next {
        None => None,
        Some(c) => match serde_json::to_vec(&FindingGroupCursorToken {
            since: since_text.clone(),
            scope,
            agent_id,
            last_observed_at: c
                .last_observed_at
                .to_rfc3339_opts(SecondsFormat::Micros, true),
            rule_set_id: c.rule_set_id,
            rule_id: c.rule_id,
        }) {
            Ok(v) => Some(URL_SAFE_NO_PAD.encode(v)),
            Err(_) => return unavailable_auth(),
        },
    };
    Json(crate::FindingGroupPage {
        items,
        next_cursor,
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        since: since_text,
    })
    .into_response()
}

#[utoipa::path(get, path="/api/v1/compliance/groups/{rule_set_id}/{rule_id}/endpoints", tag = "compliance", params(("rule_set_id"=String,Path),("rule_id"=String,Path),("since"=Option<String>,Query),("include_older"=Option<bool>,Query),("cursor"=Option<String>,Query),("limit"=Option<u16>,Query)), responses((status=200,description="Scoped endpoints reporting one recent rule group",body=crate::FindingGroupEndpointPage),(status=404,description="Compliance finding group not found",body=crate::ProblemDetails)))]
pub(crate) async fn authenticated_finding_group_endpoints(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((rule_set_id, rule_id)): Path<(String, String)>,
    query: Result<Query<FindingGroupEndpointsParams>, QueryRejection>,
) -> Response {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use platform_store::console_read::{
        FindingGroupEndpointCursor, FindingGroupEndpointQuery, finding_group_endpoints_in_scope,
    };
    let scope = match authenticated_agent_scope(&state, &headers, crate::Permission::ComplianceRead)
        .await
    {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Query(params) = match query {
        Ok(v) => v,
        Err(_) => return invalid_finding_query(),
    };
    let cursor_token = match params.cursor.as_deref() {
        None => None,
        Some(encoded) if encoded.len() <= crate::MAX_CURSOR_LENGTH => {
            let bytes = match URL_SAFE_NO_PAD.decode(encoded) {
                Ok(v) => v,
                Err(_) => return invalid_finding_query(),
            };
            match serde_json::from_slice::<FindingGroupEndpointCursorToken>(&bytes) {
                Ok(token) => Some(token),
                Err(_) => return invalid_finding_query(),
            }
        }
        Some(_) => return invalid_finding_query(),
    };
    let since_text = params
        .since
        .or_else(|| cursor_token.as_ref().map(|v| v.since.clone()))
        .unwrap_or_else(|| {
            (Utc::now() - Duration::hours(24)).to_rfc3339_opts(SecondsFormat::Secs, true)
        });
    let since = match chrono::DateTime::parse_from_rfc3339(&since_text) {
        Ok(v) => v.with_timezone(&Utc),
        Err(_) => return invalid_finding_query(),
    };
    if since > Utc::now() || since < Utc::now() - Duration::days(90) {
        return invalid_finding_query();
    }
    let include_older = params.include_older.unwrap_or(false);
    let limit = match platform_store::console_read::PageLimit::new(
        params.limit.unwrap_or(crate::DEFAULT_PAGE_SIZE),
    ) {
        Some(v) => v,
        None => return invalid_finding_query(),
    };
    let actual_rule_set = if rule_set_id == "~unknown" {
        ""
    } else {
        &rule_set_id
    };
    let after = match cursor_token {
        None => None,
        Some(token)
            if token.since == since_text
                && token.include_older == include_older
                && token.scope == scope
                && token.rule_set_id == rule_set_id
                && token.rule_id == rule_id =>
        {
            let ts = match chrono::DateTime::parse_from_rfc3339(&token.last_observed_at) {
                Ok(v) => v.with_timezone(&Utc),
                Err(_) => return invalid_finding_query(),
            };
            Some(FindingGroupEndpointCursor {
                last_observed_at: ts,
                agent_id: token.agent_id,
            })
        }
        Some(_) => return invalid_finding_query(),
    };
    let client = match state.pool.get().await {
        Ok(v) => v,
        Err(_) => return unavailable_auth(),
    };
    let page = match finding_group_endpoints_in_scope(
        &client,
        actual_rule_set,
        &rule_id,
        &FindingGroupEndpointQuery {
            since,
            include_older,
            after,
            limit,
        },
        &scope,
    )
    .await
    {
        Ok(Some(v)) => v,
        Ok(None) => {
            return problem_response(ProblemDetails::not_found(
                "compliance_finding_not_found",
                "Compliance finding group not found",
            ));
        }
        Err(_) => return unavailable_auth(),
    };
    let items = page
        .items
        .into_iter()
        .map(|e| crate::FindingGroupEndpointView {
            agent_id: e.agent_id,
            hostname: e.hostname,
            first_observed_at: e
                .first_observed_at
                .to_rfc3339_opts(SecondsFormat::Secs, true),
            last_observed_at: e
                .last_observed_at
                .to_rfc3339_opts(SecondsFormat::Secs, true),
            rule_version: e.rule_version.max(0) as u64,
            triage_state: e.triage_state,
            triage_version: e.triage_version,
            assigned_to: e.assigned_to,
            accepted_until: e.accepted_until.map(|value| value.to_rfc3339()),
            ended_at: e.ended_at.map(|value| value.to_rfc3339()),
            end_approximate: e.end_approximate,
            outside_window: e.outside_window,
            origin: if e.origin == "import" {
                crate::FindingOrigin::Import
            } else {
                crate::FindingOrigin::Online
            },
            authenticated: e.authenticated,
        })
        .collect();
    let next_cursor = match page.next {
        None => None,
        Some(c) => match serde_json::to_vec(&FindingGroupEndpointCursorToken {
            since: since_text.clone(),
            include_older,
            scope,
            rule_set_id,
            rule_id,
            last_observed_at: c
                .last_observed_at
                .to_rfc3339_opts(SecondsFormat::Micros, true),
            agent_id: c.agent_id,
        }) {
            Ok(v) => Some(URL_SAFE_NO_PAD.encode(v)),
            Err(_) => return unavailable_auth(),
        },
    };
    Json(crate::FindingGroupEndpointPage {
        items,
        next_cursor,
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        since: since_text,
    })
    .into_response()
}
