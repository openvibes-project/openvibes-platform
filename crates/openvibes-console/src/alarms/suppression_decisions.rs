//! Deciding on suppressions (roles spec §8): approve and reject need
//! `alarms.suppressions.approve` on the row's where, and never by the
//! requester; withdraw is the requester's own waiting request; remove
//! needs `alarms.suppress` on the row's where (ruling 6). Every one is a
//! browser write: bearer tokens are refused. A row outside the caller's
//! reach answers the same 404 as a missing one.

use axum::{
    Json,
    extract::{Path, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use chrono::Utc;
use platform_store::alarm_suppressions::{self as store, Change};

use super::suppression_types::{RejectAlarmSuppressionRequest, answer};
use crate::{
    Permission,
    access::guard::{authenticated_permission, unavailable_auth},
    http::AuthHttpState,
};

const MISSING: &str = "suppression_not_found";

/// What a decision route does.
#[derive(Clone, Copy)]
enum Act<'a> {
    Approve,
    Reject(Option<&'a str>),
    Withdraw,
    Remove,
}

async fn act(state: &AuthHttpState, headers: &HeaderMap, id: &str, act: Act<'_>) -> Response {
    let permission = match act {
        Act::Approve | Act::Reject(_) => Permission::AlarmsSuppressionsApprove,
        Act::Withdraw | Act::Remove => Permission::AlarmsSuppress,
    };
    let (scope, me) = match authenticated_permission(state, headers, permission, true).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let (change, done) = match id.parse::<i64>().ok().filter(|id| *id > 0) {
        None => (Ok(Change::NotFound), StatusCode::OK),
        Some(id) => {
            let now = Utc::now();
            let client = &mut client;
            match act {
                Act::Approve => (
                    store::decide(client, &scope, id, true, None, &me, now).await,
                    StatusCode::OK,
                ),
                Act::Reject(reason) => (
                    store::decide(client, &scope, id, false, reason, &me, now).await,
                    StatusCode::OK,
                ),
                Act::Withdraw => (store::withdraw(client, id, &me, now).await, StatusCode::OK),
                Act::Remove => (
                    store::remove(client, &scope, id, &me, now).await,
                    StatusCode::NO_CONTENT,
                ),
            }
        }
    };
    answer(&client, headers, &me, change, done, MISSING).await
}

#[utoipa::path(post, path = "/api/v1/alarm-suppressions/{suppression_id}/approve", tag = "alarms", params(("suppression_id" = String, Path)),
    responses((status = 200, description = "Approved: active from now, its source alarm closed", body = crate::alarms::AlarmSuppressionView),
        (status = 404, description = "Absent or outside the caller's approve reach", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The caller's own request (own_request), or not waiting (suppression_not_waiting)", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "Its group no longer exists", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn approve_suppression(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    act(&state, &headers, &id, Act::Approve).await
}

#[utoipa::path(post, path = "/api/v1/alarm-suppressions/{suppression_id}/reject", tag = "alarms", params(("suppression_id" = String, Path)),
    request_body = crate::alarms::RejectAlarmSuppressionRequest,
    responses((status = 200, description = "Rejected", body = crate::alarms::AlarmSuppressionView),
        (status = 404, description = "Absent or outside the caller's approve reach", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The caller's own request (own_request), or not waiting (suppression_not_waiting)", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "A reason of 1 to 4,000 characters is required", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn reject_suppression(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    payload: Result<Json<RejectAlarmSuppressionRequest>, JsonRejection>,
) -> Response {
    // A missing or malformed body is a missing reason.
    let body = payload.map(|Json(body)| body).unwrap_or_default();
    act(&state, &headers, &id, Act::Reject(body.reason.as_deref())).await
}

#[utoipa::path(post, path = "/api/v1/alarm-suppressions/{suppression_id}/withdraw", tag = "alarms", params(("suppression_id" = String, Path)),
    responses((status = 200, description = "Withdrawn (it leaves the list)", body = crate::alarms::AlarmSuppressionView),
        (status = 404, description = "Absent or not the caller's request", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "No longer waiting", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn withdraw_suppression(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    act(&state, &headers, &id, Act::Withdraw).await
}

#[utoipa::path(delete, path = "/api/v1/alarm-suppressions/{suppression_id}", tag = "alarms", params(("suppression_id" = String, Path)),
    responses((status = 204, description = "Removed (kept as history in the audit log)"),
        (status = 404, description = "Absent, not active, or outside the caller's suppress reach", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn remove_suppression(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    act(&state, &headers, &id, Act::Remove).await
}
