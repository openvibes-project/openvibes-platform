//! A finding's triage: read and update.

use axum::{
    extract::{Json, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::Utc;

use crate::{
    access::guard::{authenticated_agent_scope, authenticated_permission, unavailable_auth},
    http::{
        AuthHttpState,
        problem::{ProblemDetails, problem_response},
    },
    router::parse_if_match_zero_version,
};

pub(super) fn triage_view(
    record: platform_store::console_triage::TriageRecord,
) -> crate::FindingTriageView {
    crate::FindingTriageView {
        state: record.state,
        rule_version: record.rule_version,
        assigned_to: record.assigned_to_username,
        note: record.note,
        accepted_until: record.accepted_until.map(|value| value.to_rfc3339()),
        version: record.version,
    }
}

pub(super) fn triage_response(record: platform_store::console_triage::TriageRecord) -> Response {
    let view = triage_view(record);
    let mut response = (StatusCode::OK, Json(view.clone())).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(value) = HeaderValue::from_str(&format!("\"{}\"", view.version)) {
        response.headers_mut().insert(header::ETAG, value);
    }
    response
}

#[utoipa::path(get, path = "/api/v1/compliance/latest/{agent_id}/{rule_set_id}/{rule_id}/triage", tag = "compliance", params(("agent_id" = String, Path), ("rule_set_id" = String, Path), ("rule_id" = String, Path)), responses((status = 200, description = "Current finding triage", body = crate::FindingTriageView, headers(("ETag" = String, description = "Triage version"))), (status = 404, description = "Compliance finding not found", body = crate::ProblemDetails), (status = 403, description = "Permission denied", body = crate::ProblemDetails)))]
pub(crate) async fn authenticated_finding_triage(
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
        Ok(Some(_)) => {
            match platform_store::console_triage::get(&client, &agent_id, rule_set_id, &rule_id)
                .await
            {
                Ok(Some(record)) => triage_response(record),
                Ok(None) => problem_response(ProblemDetails::not_found(
                    "compliance_finding_not_found",
                    "Compliance finding not found",
                )),
                Err(_) => unavailable_auth(),
            }
        }
        Ok(None) => problem_response(ProblemDetails::not_found(
            "compliance_finding_not_found",
            "Compliance finding not found",
        )),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(put, path = "/api/v1/compliance/latest/{agent_id}/{rule_set_id}/{rule_id}/triage", tag = "compliance", params(("agent_id" = String, Path), ("rule_set_id" = String, Path), ("rule_id" = String, Path), ("If-Match" = String, Header)), request_body = crate::UpdateFindingTriageRequest, responses((status = 200, description = "Updated finding triage", body = crate::FindingTriageView, headers(("ETag" = String, description = "New triage version"))), (status = 412, description = "Stale triage version", body = crate::ProblemDetails), (status = 428, description = "If-Match is required", body = crate::ProblemDetails)))]
pub(crate) async fn update_authenticated_finding_triage(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((agent_id, rule_set_id, rule_id)): Path<(String, String, String)>,
    payload: Result<
        Json<crate::UpdateFindingTriageRequest>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Response {
    let (scope, user_id) =
        match authenticated_permission(&state, &headers, crate::Permission::ComplianceTriage, true)
            .await
        {
            Ok(context) => context,
            Err(response) => return response,
        };
    let expected = match parse_if_match_zero_version(&headers) {
        Ok(Some(version)) => version,
        Ok(None) => {
            return problem_response(ProblemDetails::new(
                StatusCode::PRECONDITION_REQUIRED,
                "precondition_required",
                "If-Match is required",
            ));
        }
        Err(()) => {
            return problem_response(ProblemDetails::new(
                StatusCode::BAD_REQUEST,
                "invalid_precondition",
                "If-Match must contain one quoted triage version",
            ));
        }
    };
    let Json(payload) = match payload {
        Ok(payload) => payload,
        Err(_) => {
            return problem_response(ProblemDetails::new(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Triage request is invalid",
            ));
        }
    };
    let accepted_until = match payload
        .accepted_until
        .as_deref()
        .map(chrono::DateTime::parse_from_rfc3339)
        .transpose()
    {
        Ok(value) => value.map(|value| value.with_timezone(&Utc)),
        Err(_) => {
            return problem_response(ProblemDetails::new(
                StatusCode::BAD_REQUEST,
                "invalid_expiry",
                "accepted_until must be an RFC 3339 timestamp",
            ));
        }
    };
    let client = match state.pool.get().await {
        Ok(client) => client,
        Err(_) => return unavailable_auth(),
    };
    let actual_rule_set_id = if rule_set_id == "~unknown" {
        ""
    } else {
        &rule_set_id
    };
    match platform_store::console_read::latest_finding_in_scope(
        &client,
        &agent_id,
        actual_rule_set_id,
        &rule_id,
        &scope,
    )
    .await
    {
        Ok(Some(_)) => {}
        Ok(None) => {
            return problem_response(ProblemDetails::not_found(
                "compliance_finding_not_found",
                "Compliance finding not found",
            ));
        }
        Err(_) => return unavailable_auth(),
    }
    let mut client = match state.pool.get().await {
        Ok(client) => client,
        Err(_) => return unavailable_auth(),
    };
    match platform_store::console_triage::update(
        &mut client,
        &agent_id,
        actual_rule_set_id,
        &rule_id,
        expected,
        &payload.state,
        payload.assigned_to.as_deref(),
        payload.note.as_deref(),
        accepted_until,
        &user_id,
        Utc::now(),
    )
    .await
    {
        Ok(platform_store::console_triage::TriageUpdate::Updated(record)) => {
            triage_response(record)
        }
        Ok(platform_store::console_triage::TriageUpdate::Stale(_record)) => {
            problem_response(ProblemDetails::new(
                StatusCode::PRECONDITION_FAILED,
                "stale_triage",
                "Triage changed; reload before saving",
            ))
        }
        Ok(platform_store::console_triage::TriageUpdate::InvalidTransition(_)) => {
            problem_response(ProblemDetails::new(
                StatusCode::CONFLICT,
                "invalid_transition",
                "Requested triage transition is not allowed",
            ))
        }
        Ok(platform_store::console_triage::TriageUpdate::InvalidFields) => {
            problem_response(ProblemDetails::new(
                StatusCode::BAD_REQUEST,
                "invalid_triage",
                "Triage state, note, or expiry is invalid",
            ))
        }
        Ok(platform_store::console_triage::TriageUpdate::AssigneeUnavailable) => {
            problem_response(ProblemDetails::new(
                StatusCode::BAD_REQUEST,
                "invalid_assignee",
                "Assignee must be an enabled analyst or admin",
            ))
        }
        Ok(platform_store::console_triage::TriageUpdate::NotFound) => {
            problem_response(ProblemDetails::not_found(
                "compliance_finding_not_found",
                "Compliance finding not found",
            ))
        }
        Err(_) => unavailable_auth(),
    }
}
