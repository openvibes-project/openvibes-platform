//! Triage of every endpoint in one finding group, in one transaction.

use axum::{
    extract::{Json, Path, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::Utc;

use super::triage::triage_view;
use crate::{
    access::guard::{authenticated_permission, unavailable_auth},
    http::{
        AuthHttpState,
        problem::{ProblemDetails, next_request_id, problem_response},
    },
};

#[utoipa::path(post,path="/api/v1/compliance/groups/{rule_set_id}/{rule_id}/triage",tag = "compliance",params(("rule_set_id"=String,Path),("rule_id"=String,Path)),request_body=crate::BulkFindingTriageRequest,responses((status=200,description="Atomic endpoint triage update",body=crate::BulkFindingTriageResponse),(status=412,description="At least one triage version is stale",body=crate::ProblemDetails),(status=404,description="Group or endpoint is not visible",body=crate::ProblemDetails)))]
pub(crate) async fn update_authenticated_finding_group_triage(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((rule_set_id, rule_id)): Path<(String, String)>,
    payload: Result<Json<crate::BulkFindingTriageRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let (scope, user_id) =
        match authenticated_permission(&state, &headers, crate::Permission::ComplianceTriage, true)
            .await
        {
            Ok(v) => v,
            Err(r) => return r,
        };
    let Json(payload) = match payload {
        Ok(v) => v,
        Err(_) => {
            return problem_response(ProblemDetails::new(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Triage request is invalid",
            ));
        }
    };
    if payload.changes.is_empty()
        || payload.changes.len() > 100
        || payload.changes.iter().any(|x| {
            x.agent_id.is_empty()
                || x.agent_id.len() > 128
                || x.agent_id.chars().any(char::is_control)
        })
    {
        return problem_response(ProblemDetails::new(
            StatusCode::BAD_REQUEST,
            "invalid_triage",
            "Select between 1 and 100 endpoints",
        ));
    }
    let expiry = match payload
        .accepted_until
        .as_deref()
        .map(chrono::DateTime::parse_from_rfc3339)
        .transpose()
    {
        Ok(v) => v.map(|v| v.with_timezone(&Utc)),
        Err(_) => {
            return problem_response(ProblemDetails::new(
                StatusCode::BAD_REQUEST,
                "invalid_expiry",
                "accepted_until must be an RFC 3339 timestamp",
            ));
        }
    };
    let actual_rule_set = if rule_set_id == "~unknown" {
        ""
    } else {
        &rule_set_id
    };
    let changes: Vec<_> = payload
        .changes
        .iter()
        .map(|v| (v.agent_id.clone(), v.version))
        .collect();
    let mut client = match state.pool.get().await {
        Ok(v) => v,
        Err(_) => return unavailable_auth(),
    };
    let request_id = next_request_id();
    match platform_store::console_triage::update_many_with_request_id(
        &mut client,
        actual_rule_set,
        &rule_id,
        &changes,
        &scope,
        &payload.state,
        payload.assigned_to.as_deref(),
        payload.note.as_deref(),
        expiry,
        &user_id,
        Some(&request_id),
        Utc::now(),
    )
    .await
    {
        Ok(platform_store::console_triage::BulkTriageUpdate::Updated(records)) => {
            let updated = changes
                .iter()
                .zip(records)
                .map(|((id, _), record)| (id.clone(), triage_view(record)))
                .collect();
            let mut response = Json(crate::BulkFindingTriageResponse { updated }).into_response();
            response.headers_mut().insert(
                HeaderName::from_static("x-request-id"),
                HeaderValue::from_str(&request_id)
                    .expect("generated request IDs are valid headers"),
            );
            response
        }
        Ok(platform_store::console_triage::BulkTriageUpdate::Stale(items)) => {
            let mut p = ProblemDetails::new(
                StatusCode::PRECONDITION_FAILED,
                "stale_triage",
                "One or more selected endpoints changed; reload before saving",
            );
            p.field_errors = Some(
                items
                    .into_iter()
                    .map(|item| crate::FieldError {
                        field: "changes".into(),
                        code: "stale_version".into(),
                        message: format!(
                            "{} now has triage version {}",
                            item.agent_id, item.actual_version
                        ),
                    })
                    .collect(),
            );
            problem_response(p)
        }
        Ok(platform_store::console_triage::BulkTriageUpdate::NotFound) => {
            problem_response(ProblemDetails::not_found(
                "compliance_finding_not_found",
                "Compliance finding group or endpoint not found",
            ))
        }
        Ok(platform_store::console_triage::BulkTriageUpdate::InvalidTransition) => {
            problem_response(ProblemDetails::new(
                StatusCode::CONFLICT,
                "invalid_transition",
                "Requested triage transition is not allowed",
            ))
        }
        Ok(platform_store::console_triage::BulkTriageUpdate::InvalidFields) => {
            problem_response(ProblemDetails::new(
                StatusCode::BAD_REQUEST,
                "invalid_triage",
                "Triage state, note, expiry, or selection is invalid",
            ))
        }
        Ok(platform_store::console_triage::BulkTriageUpdate::AssigneeUnavailable) => {
            problem_response(ProblemDetails::new(
                StatusCode::BAD_REQUEST,
                "invalid_assignee",
                "Assignee must be an enabled analyst or admin",
            ))
        }
        Err(_) => unavailable_auth(),
    }
}
