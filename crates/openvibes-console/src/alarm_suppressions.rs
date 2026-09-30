//! Alarm suppressions over `/api/v1` (P14). Listing needs `alarms.read`;
//! creating and removing need `alarms.suppress`. A suppression is derived
//! from an alarm the caller can see; `program` and `command` apply on every
//! host, so they need global scope. It applies to alarms stored from then
//! on; past alarms keep their triage.

use axum::{
    Json,
    extract::{Path, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::{SecondsFormat, Utc};
use platform_store::alarm_suppressions::{self as store, Change, Suppression};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    Permission, ProblemDetails,
    problem::problem_response,
    router::{AuthHttpState, authenticated_permission, unavailable_auth},
};

/// One active suppression.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct AlarmSuppressionView {
    /// Its id; closed alarms say "suppressed by #id".
    pub id: String,
    /// Rule set of the rule.
    pub rule_set_id: String,
    /// Rule it quiets.
    pub rule_id: String,
    /// `host`, `program` or `command`.
    pub scope: String,
    /// The agent, for `host`.
    pub agent_id: Option<String>,
    /// The program, for `program` and `command`.
    pub exe: Option<String>,
    /// SHA-256 of the masked args' JSON array, for `command`.
    pub args_sha256: Option<String>,
    /// Why.
    pub note: String,
    /// Who created it.
    pub created_by: String,
    /// When (RFC 3339).
    pub created_at: String,
}

/// Active suppressions the caller may see.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct AlarmSuppressionList {
    /// Newest first.
    pub items: Vec<AlarmSuppressionView>,
}

/// "Don't alarm on this again", derived from one alarm.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateAlarmSuppressionRequest {
    /// The platform's id of the alarm to derive it from.
    pub alarm_id: String,
    /// `host` (this alarm's host), `program` (this program on any host) or
    /// `command` (this exact command line on any host).
    pub scope: String,
    /// Why, 1 to 4,000 characters.
    pub note: String,
}

fn view(suppression: Suppression) -> AlarmSuppressionView {
    AlarmSuppressionView {
        id: suppression.id.to_string(),
        rule_set_id: suppression.rule_set_id,
        rule_id: suppression.rule_id,
        scope: suppression.scope,
        agent_id: suppression.agent_id,
        exe: suppression.exe,
        args_sha256: suppression.args_sha256,
        note: suppression.note,
        created_by: suppression.created_by,
        created_at: suppression
            .created_at
            .to_rfc3339_opts(SecondsFormat::Millis, true),
    }
}

fn answer(change: Change, done: StatusCode) -> Response {
    match change {
        Change::Done(suppression) => (done, Json(view(suppression))).into_response(),
        Change::NotFound => problem_response(ProblemDetails::not_found(
            "alarm_not_found",
            "Alarm or suppression not found",
        )),
        Change::NeedsGlobalScope => problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "global_scope_required",
            "Only a user with access to every host may suppress on every host",
        )),
        Change::Invalid => problem_response(ProblemDetails::new(
            StatusCode::BAD_REQUEST,
            "invalid_suppression",
            "Scope must be host, program or command, with a note",
        )),
    }
}

#[utoipa::path(get, path = "/api/v1/alarm-suppressions", tag = "alarms",
    responses((status = 200, description = "Active suppressions the caller may see", body = crate::alarm_suppressions::AlarmSuppressionList)))]
pub(crate) async fn list_suppressions(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    let (scope, _) =
        match authenticated_permission(&state, &headers, Permission::AlarmsRead, false).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::list(&client, &scope).await {
        Ok(items) => Json(AlarmSuppressionList {
            items: items.into_iter().map(view).collect(),
        })
        .into_response(),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(post, path = "/api/v1/alarm-suppressions", tag = "alarms",
    request_body = crate::alarm_suppressions::CreateAlarmSuppressionRequest,
    responses((status = 201, description = "Created; applies to alarms stored from now on", body = crate::alarm_suppressions::AlarmSuppressionView),
        (status = 400, description = "Invalid scope or note", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Permission denied, or program/command without global scope", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "Alarm absent or outside the caller's scope", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn create_suppression(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    payload: Result<Json<CreateAlarmSuppressionRequest>, JsonRejection>,
) -> Response {
    let (scope, user_id) =
        match authenticated_permission(&state, &headers, Permission::AlarmsSuppress, true).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    let Ok(Json(request)) = payload else {
        return answer(Change::Invalid, StatusCode::CREATED);
    };
    let Some(alarm_id) = request.alarm_id.parse::<i64>().ok().filter(|id| *id > 0) else {
        return answer(Change::NotFound, StatusCode::CREATED);
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::create(
        &mut client,
        &scope,
        alarm_id,
        &request.scope,
        &request.note,
        &user_id,
        Utc::now(),
    )
    .await
    {
        Ok(change) => answer(change, StatusCode::CREATED),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(delete, path = "/api/v1/alarm-suppressions/{suppression_id}", tag = "alarms", params(("suppression_id" = String, Path)),
    responses((status = 200, description = "Removed (kept as history)", body = crate::alarm_suppressions::AlarmSuppressionView),
        (status = 404, description = "Absent, already removed, or outside the caller's scope", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn remove_suppression(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (scope, user_id) =
        match authenticated_permission(&state, &headers, Permission::AlarmsSuppress, true).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    let Some(id) = id.parse::<i64>().ok().filter(|id| *id > 0) else {
        return answer(Change::NotFound, StatusCode::OK);
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::remove(&mut client, &scope, id, &user_id, Utc::now()).await {
        Ok(change) => answer(change, StatusCode::OK),
        Err(_) => unavailable_auth(),
    }
}
