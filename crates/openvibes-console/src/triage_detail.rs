//! The detail view's triage over `/api/v1` (triage v2, spec
//! `2026-10-10-bulk-triage-design.md` §2, §5): one host's vulnerability
//! triage, and the History tab of an alarm, a compliance finding or a
//! vulnerability across the hosts in the caller's scope.

use axum::{
    Json,
    extract::{Query, State, rejection::JsonRejection, rejection::QueryRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use platform_store::triage_history::{self, Subject};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::{
    Permission, ProblemDetails,
    cases::authorize,
    problem::problem_response,
    router::{AuthHttpState, unavailable_auth},
};

fn bad(code: &'static str, title: &'static str) -> Response {
    problem_response(ProblemDetails::new(StatusCode::BAD_REQUEST, code, title))
}

/// One triage change.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct TriageEventView {
    /// The host.
    pub agent_id: String,
    /// Its name, when known.
    pub hostname: Option<String>,
    /// The state before; absent for the first triage.
    pub from_state: Option<String>,
    /// The state after.
    pub to_state: String,
    /// The note given.
    pub note: Option<String>,
    /// When (RFC 3339).
    pub changed_at: String,
    /// Who: a user id, or `migration` or `system`.
    pub changed_by: String,
}

/// The newest triage changes, at most 200.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct TriageHistoryView {
    /// Newest first.
    pub items: Vec<TriageEventView>,
}

/// Whose history: `kind=alarm&id=`, `kind=compliance&rule_set_id=&rule_id=`
/// or `kind=vulnerability&advisory_id=`.
#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
pub(crate) struct HistoryParams {
    kind: String,
    id: Option<String>,
    rule_set_id: Option<String>,
    rule_id: Option<String>,
    advisory_id: Option<String>,
}

#[utoipa::path(get, path = "/api/v1/triage-history", tag = "triage", params(HistoryParams),
    responses((status = 200, description = "Triage changes on hosts in scope, newest first", body = crate::triage_detail::TriageHistoryView),
        (status = 400, description = "Invalid kind or subject", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Missing the kind's read permission", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn triage_history(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    query: Result<Query<HistoryParams>, QueryRejection>,
) -> Response {
    let Ok(Query(params)) = query else {
        return bad("invalid_query", "kind and its subject are required");
    };
    let (permission, subject) = match (
        params.kind.as_str(),
        params.id.as_deref(),
        params.rule_set_id.as_deref(),
        params.rule_id.as_deref(),
        params.advisory_id.as_deref(),
    ) {
        ("alarm", Some(id), None, None, None) => match id.parse::<i64>() {
            Ok(id) if id > 0 => (Permission::AlarmsRead, Subject::Alarm(id)),
            _ => return bad("invalid_query", "id must be an alarm id"),
        },
        ("compliance", None, Some(rule_set_id), Some(rule_id), None) => (
            Permission::ComplianceRead,
            Subject::Finding {
                // `~unknown`: findings from before rule sets (stored empty).
                rule_set_id: if rule_set_id == "~unknown" {
                    ""
                } else {
                    rule_set_id
                },
                rule_id,
            },
        ),
        ("vulnerability", None, None, None, Some(advisory)) => (
            Permission::VulnerabilitiesRead,
            Subject::Vulnerability(advisory),
        ),
        _ => return bad("invalid_query", "kind and its subject are required"),
    };
    let (scope, _) = match authorize(&state, &headers, &[permission], false).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match triage_history::events(&client, &scope, subject).await {
        Ok(events) => Json(TriageHistoryView {
            items: events
                .into_iter()
                .map(|e| TriageEventView {
                    agent_id: e.agent_id,
                    hostname: e.hostname,
                    from_state: e.from_state,
                    to_state: e.to_state,
                    note: e.note,
                    changed_at: e.changed_at.to_rfc3339(),
                    changed_by: e.changed_by,
                })
                .collect(),
        })
        .into_response(),
        Err(_) => unavailable_auth(),
    }
}

/// One host's triage of one advisory (triage v2).
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct VulnerabilityTriageView {
    /// `open`, `mitigated`, `accepted_risk` or `false_positive`.
    pub state: String,
    /// Assigned analyst's username.
    pub assigned_to: Option<String>,
    /// Operator note.
    pub note: Option<String>,
    /// Accepted-risk expiry (RFC 3339).
    pub accepted_until: Option<String>,
    /// Write version, also the ETag.
    pub version: i64,
}

#[utoipa::path(put, path = "/api/v1/vulnerabilities/advisories/{advisory_id}/hosts/{agent_id}/triage",
    tag = "vulnerabilities", params(("advisory_id" = String, Path), ("agent_id" = String, Path)),
    request_body = crate::alarms::UpdateAlarmTriageRequest,
    responses((status = 200, description = "Updated triage", body = crate::triage_detail::VulnerabilityTriageView),
        (status = 400, description = "Invalid state, note, expiry or assignee", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No open vulnerability in scope", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "Stale triage version", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 428, description = "If-Match is required", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn update_vulnerability_triage(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    axum::extract::Path((advisory_id, agent_id)): axum::extract::Path<(String, String)>,
    payload: Result<Json<crate::alarms::UpdateAlarmTriageRequest>, JsonRejection>,
) -> Response {
    use platform_store::vulnerability_triage::{self as triage, VulnerabilityTriageUpdate as U};
    let (scope, user_id) =
        match authorize(&state, &headers, &[Permission::VulnerabilitiesTriage], true).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    // An untriaged vulnerability is version 0, as findings are.
    let expected = match crate::router::parse_if_match_zero_version(&headers) {
        Ok(Some(version)) => version,
        Ok(None) => {
            return problem_response(ProblemDetails::new(
                StatusCode::PRECONDITION_REQUIRED,
                "precondition_required",
                "If-Match is required",
            ));
        }
        Err(()) => {
            return bad(
                "invalid_precondition",
                "If-Match must be one quoted version",
            );
        }
    };
    let Ok(Json(payload)) = payload else {
        return bad("invalid_request", "Triage request is invalid");
    };
    let accepted_until = match payload
        .accepted_until
        .as_deref()
        .map(DateTime::parse_from_rfc3339)
    {
        Some(Ok(at)) => Some(at.with_timezone(&Utc)),
        Some(Err(_)) => return bad("invalid_expiry", "accepted_until must be RFC 3339"),
        None => None,
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let outcome = triage::update(
        &mut client,
        &scope,
        &agent_id,
        &advisory_id,
        Some(expected),
        &payload.state,
        payload.assigned_to.as_deref(),
        payload.note.as_deref(),
        accepted_until,
        &user_id,
        Utc::now(),
    )
    .await;
    match outcome {
        Ok(U::Updated(t)) => {
            let version = t.version;
            let mut response = Json(VulnerabilityTriageView {
                state: t.state,
                assigned_to: t.assigned_to,
                note: t.note,
                accepted_until: t.accepted_until.map(|at| at.to_rfc3339()),
                version,
            })
            .into_response();
            if let Ok(value) = axum::http::HeaderValue::from_str(&format!("\"{version}\"")) {
                response
                    .headers_mut()
                    .insert(axum::http::header::ETAG, value);
            }
            response
        }
        Ok(U::NotFound) => problem_response(ProblemDetails::not_found(
            "vulnerability_not_found",
            "No open vulnerability for this host and advisory",
        )),
        Ok(U::Stale(_)) => problem_response(ProblemDetails::new(
            StatusCode::PRECONDITION_FAILED,
            "stale_triage",
            "The triage changed; reload it",
        )),
        Ok(U::InvalidFields) => bad(
            "invalid_triage",
            "Triage state, note, or expiry is invalid (closing needs a note)",
        ),
        Ok(U::AssigneeUnavailable) => bad("assignee_unavailable", "That person cannot be assigned"),
        Err(_) => unavailable_auth(),
    }
}
