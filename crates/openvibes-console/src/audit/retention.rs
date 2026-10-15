//! The audit retention policy: read and update.

use axum::{
    extract::{Json, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::{SecondsFormat, Utc};

use crate::{
    access::guard::{authenticated_permission, unavailable_auth},
    http::{
        AuthHttpState,
        problem::{ProblemDetails, problem_response},
    },
    router::parse_if_match_version,
};

#[utoipa::path(
    get,
    path = "/api/v1/audit-retention",
    tag = "audit",
    responses(
        (status = 200, description = "Current audit retention policy", body = crate::AuditRetentionPolicy, headers(("ETag" = String, description = "Policy version"))),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Permission denied", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(crate) async fn authenticated_audit_retention(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    let (scope, user_id) =
        match authenticated_permission(&state, &headers, crate::Permission::AuditRead, false).await
        {
            Ok(context) => context,
            Err(response) => return response,
        };
    if !matches!(scope, platform_store::console_read::AgentScope::Global) {
        return problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "Access is not available",
        ));
    }
    let client = match state.pool.get().await {
        Ok(client) => client,
        Err(_) => return unavailable_auth(),
    };
    match platform_store::audit::retention_policy(&client).await {
        Ok(policy) => {
            if platform_store::audit::record(
                &client,
                &user_id,
                "audit.accessed",
                Some("audit_retention"),
                "success",
            )
            .await
            .is_err()
            {
                return unavailable_auth();
            }
            retention_policy_response(policy)
        }
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(
    put,
    path = "/api/v1/audit-retention",
    tag = "audit",
    request_body = crate::UpdateAuditRetentionRequest,
    params(
        ("If-Match" = String, Header, description = "Quoted policy version from ETag"),
        ("Origin" = String, Header, description = "Must exactly match configured origin"),
        ("X-CSRF-Token" = String, Header, description = "Session synchronizer token")
    ),
    responses(
        (status = 200, description = "Updated retention policy", body = crate::AuditRetentionPolicy, headers(("ETag" = String, description = "New policy version"))),
        (status = 400, description = "Invalid retention value or request", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Origin, CSRF, or permission check failed", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "Policy version is stale", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 428, description = "If-Match is required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Update unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(crate) async fn update_authenticated_audit_retention(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    payload: Result<
        Json<crate::UpdateAuditRetentionRequest>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Response {
    let (scope, user_id) = match authenticated_permission(
        &state,
        &headers,
        crate::Permission::AuditRetentionManage,
        true,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    if !matches!(scope, platform_store::console_read::AgentScope::Global) {
        return problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "Access is not available",
        ));
    }
    let expected_version = match parse_if_match_version(&headers) {
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
                "If-Match must contain one quoted policy version",
            ));
        }
    };
    let Json(payload) = match payload {
        Ok(payload) => payload,
        Err(_) => {
            return problem_response(ProblemDetails::new(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Retention request is invalid",
            ));
        }
    };
    if !(1..=36_500).contains(&payload.retention_days) {
        return problem_response(ProblemDetails::new(
            StatusCode::BAD_REQUEST,
            "invalid_retention",
            "Retention must be between 1 and 36500 days",
        ));
    }
    let mut client = match state.pool.get().await {
        Ok(client) => client,
        Err(_) => return unavailable_auth(),
    };
    match platform_store::audit::update_retention_policy(
        &mut client,
        payload.retention_days as i32,
        expected_version,
        &user_id,
        Utc::now(),
    )
    .await
    {
        Ok(Some(policy)) => retention_policy_response(policy),
        Ok(None) => problem_response(ProblemDetails::new(
            StatusCode::PRECONDITION_FAILED,
            "stale_policy",
            "Audit retention policy changed; reload before saving",
        )),
        Err(_) => unavailable_auth(),
    }
}

fn retention_policy_response(policy: platform_store::audit::RetentionPolicy) -> Response {
    let etag = format!("\"{}\"", policy.version);
    let mut response = (
        StatusCode::OK,
        Json(crate::AuditRetentionPolicy {
            retention_days: policy.retention_days.try_into().unwrap_or_default(),
            version: policy.version.try_into().unwrap_or_default(),
            updated_at: policy.updated_at.to_rfc3339_opts(SecondsFormat::Secs, true),
            updated_by: policy.updated_by,
        }),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(value) = HeaderValue::from_str(&etag) {
        response.headers_mut().insert(header::ETAG, value);
    }
    response
}
