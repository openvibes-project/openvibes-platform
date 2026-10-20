//! Alarm suppressions over `/api/v1` (roles spec §8): the list (needs
//! `alarms.suppressions.read`), the suppress form's options and a new
//! request (need `alarms.suppress`). A suppression is derived from an alarm
//! the caller can see, on its host, a group or all hosts within the
//! caller's suppress reach; with approval on it waits for someone else.
//! Deciding, withdrawing and removing live in `suppression_decisions.rs`.

use axum::{
    Json,
    extract::{Query, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use platform_store::{
    alarm_suppressions::{
        self as store, Change, ListFilter, Request, State as SuppressionState, What, Where,
    },
    console_read::AgentScope,
    console_settings,
};
use serde::Deserialize;
use utoipa::IntoParams;

use super::suppression_types::{
    AlarmSuppressionGroup, AlarmSuppressionList, AlarmSuppressionOptions,
    CreateAlarmSuppressionRequest, SuppressWhat, SuppressWhere, answer, invalid, views,
};
use crate::{
    Permission,
    access::guard::{authenticated_permission, unavailable_auth},
    http::AuthHttpState,
};

/// Filters of the list.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct SuppressionQuery {
    /// `waiting`, `active` (with expired) or `rejected`; all three when absent.
    state: Option<String>,
    /// Only those made from this alarm.
    alarm_id: Option<String>,
}

#[utoipa::path(get, path = "/api/v1/alarm-suppressions", tag = "alarms", params(SuppressionQuery),
    responses((status = 200, description = "Suppressions the caller may read", body = crate::alarms::AlarmSuppressionList),
        (status = 422, description = "Unknown state or alarm id", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn list_suppressions(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Query(query): Query<SuppressionQuery>,
) -> Response {
    let (scope, me) =
        match authenticated_permission(&state, &headers, Permission::AlarmsSuppressionsRead, false)
            .await
        {
            Ok(context) => context,
            Err(response) => return response,
        };
    let state_filter = match query.state.as_deref() {
        None => None,
        Some("waiting") => Some(SuppressionState::Waiting),
        Some("active") => Some(SuppressionState::Active),
        Some("rejected") => Some(SuppressionState::Rejected),
        Some(_) => return invalid("state"),
    };
    let alarm_id = match query.alarm_id.as_deref().map(str::parse::<i64>) {
        None => None,
        Some(Ok(id)) => Some(id),
        Some(Err(_)) => return invalid("alarm_id"),
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let filter = ListFilter {
        state: state_filter,
        alarm_id,
    };
    let rows = match store::list(&client, &scope, &filter, Utc::now()).await {
        Ok(rows) => rows,
        Err(_) => return unavailable_auth(),
    };
    match views(&client, &headers, &me, rows).await {
        Ok(items) => Json(AlarmSuppressionList { items }).into_response(),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(get, path = "/api/v1/alarm-suppressions/options", tag = "alarms",
    responses((status = 200, description = "What the suppress form may offer the caller", body = crate::alarms::AlarmSuppressionOptions)))]
pub(crate) async fn suppression_options(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    let (scope, _) =
        match authenticated_permission(&state, &headers, Permission::AlarmsSuppress, false).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    let (all_hosts, groups) = match scope {
        AgentScope::Global => (true, Vec::new()),
        AgentScope::AssetGroups(groups) => (false, groups),
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let (Ok(require_approval), Ok(rows)) = (
        console_settings::require_approval(&client).await,
        client
            .query(
                "SELECT asset_group_id::text, name FROM console_asset_groups
                 WHERE $1 OR asset_group_id::text = ANY($2) ORDER BY lower(name), name",
                &[&all_hosts, &groups],
            )
            .await,
    ) else {
        return unavailable_auth();
    };
    Json(AlarmSuppressionOptions {
        require_approval,
        all_hosts,
        groups: rows
            .iter()
            .map(|row| AlarmSuppressionGroup {
                id: row.get(0),
                name: row.get(1),
            })
            .collect(),
    })
    .into_response()
}

#[utoipa::path(post, path = "/api/v1/alarm-suppressions", tag = "alarms",
    request_body = crate::alarms::CreateAlarmSuppressionRequest,
    responses((status = 201, description = "Created: active at once, or waiting when approval is on", body = crate::alarms::AlarmSuppressionView),
        (status = 403, description = "Permission denied, a group outside reach, or all hosts without global scope (global_scope_required)", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "Alarm absent or outside the caller's reach", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "Invalid field (reason, for, group, command or body)", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn create_suppression(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    payload: Result<Json<CreateAlarmSuppressionRequest>, JsonRejection>,
) -> Response {
    let (scope, me) =
        match authenticated_permission(&state, &headers, Permission::AlarmsSuppress, true).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    let Ok(Json(body)) = payload else {
        return invalid("body");
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let change = match body.alarm_id.parse::<i64>().ok().filter(|id| *id > 0) {
        None => Ok(Change::NotFound),
        Some(alarm_row_id) => {
            let request = Request {
                alarm_row_id,
                what: match body.what {
                    SuppressWhat::Program => What::Program,
                    SuppressWhat::Command => What::Command,
                },
                place: match body.place {
                    SuppressWhere::Host => Where::Host,
                    SuppressWhere::Group { group_id } => Where::Group(group_id),
                    SuppressWhere::All => Where::All,
                },
                for_days: body.for_days,
                reason: &body.reason,
            };
            store::request(&mut client, &scope, &request, &me, Utc::now()).await
        }
    };
    let code = StatusCode::CREATED;
    answer(&client, &headers, &me, change, code, "alarm_not_found").await
}
