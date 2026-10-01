//! Threat alarms over `/api/v1` (P14): the list, one alarm with its
//! process tree, and its triage. Reads need `alarms.read`, triage
//! `alarms.triage`; both are scoped to the caller's agents. Alarms are not
//! offered to the assistant in P14.

use axum::{
    Json,
    extract::{Path, Query, State, rejection::JsonRejection, rejection::QueryRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, SecondsFormat, Utc};
use platform_store::console_alarms::{
    self as store, AlarmDetail, AlarmFilters, AlarmSummary, AlarmTriage, TriageChange,
    TriageOutcome,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::{
    Permission, ProblemDetails,
    problem::problem_response,
    router::{AuthHttpState, authenticated_permission, parse_if_match_version, unavailable_auth},
};

/// One alarm in the list.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct AlarmSummaryView {
    /// The platform's alarm id.
    pub id: String,
    /// Agent that raised it.
    pub agent_id: String,
    /// The agent's hostname, when known.
    pub hostname: Option<String>,
    /// Rule set of the rule.
    pub rule_set_id: String,
    /// Rule that raised it.
    pub rule_id: String,
    /// `critical`, `high`, `medium`, `low` or `info`.
    pub severity: String,
    /// The rule's message.
    pub message: String,
    /// The process's program.
    pub exe: String,
    /// Its parent's program, when known.
    pub parent_exe: Option<String>,
    /// How many starts matched.
    pub count: i64,
    /// First match (RFC 3339).
    pub first_seen: String,
    /// Latest match (RFC 3339).
    pub last_seen: String,
    /// Triage state.
    pub state: String,
    /// The suppression that closed it, if any.
    pub suppressed_by: Option<String>,
}

/// A page of alarms, newest first.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct AlarmPage {
    /// The alarms.
    pub items: Vec<AlarmSummaryView>,
    /// Pass as `cursor` for the next page; absent on the last page.
    pub next_cursor: Option<String>,
}

/// An alarm's triage.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct AlarmTriageView {
    /// Workflow state.
    pub state: String,
    /// Assignee's username.
    pub assigned_to: Option<String>,
    /// Operator note.
    pub note: Option<String>,
    /// Accepted-risk expiry (RFC 3339).
    pub accepted_until: Option<String>,
    /// Version for If-Match (also the ETag).
    pub version: i64,
    /// Last change (RFC 3339).
    pub updated_at: Option<String>,
    /// Who changed it; `ingest` for a suppression or a recurrence.
    pub updated_by: Option<String>,
}

/// One alarm with its process tree and triage.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct AlarmDetailView {
    /// The list fields.
    #[serde(flatten)]
    pub summary: AlarmSummaryView,
    /// Rule set version.
    pub rule_set_version: i64,
    /// Rule version.
    pub rule_version: i64,
    /// 0 to 100.
    pub confidence: i16,
    /// The process (masked args) as the agent sent it.
    #[schema(value_type = Object)]
    pub process: serde_json::Value,
    /// Its ancestors, nearest first, as sent.
    #[schema(value_type = Vec<Object>)]
    pub ancestors: serde_json::Value,
    /// When ingest stored it (RFC 3339).
    pub received_at: String,
    /// Current triage.
    pub triage: AlarmTriageView,
}

/// A triage change; the same rules as findings triage.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateAlarmTriageRequest {
    /// New state.
    pub state: String,
    /// Assignee's username.
    pub assigned_to: Option<String>,
    /// Note, required for completed states.
    pub note: Option<String>,
    /// Accepted-risk expiry (RFC 3339), required for `accepted_risk`.
    pub accepted_until: Option<String>,
}

/// Filters and paging for the alarm list.
#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
pub(crate) struct AlarmListParams {
    /// Exact agent.
    agent_id: Option<String>,
    /// Exact rule.
    rule_id: Option<String>,
    /// Exact severity.
    severity: Option<String>,
    /// Exact triage state, or `active` (open or investigating).
    state: Option<String>,
    /// Include alarms closed by a suppression (default false).
    suppressed: Option<bool>,
    /// Opaque continuation cursor.
    cursor: Option<String>,
    /// Page size from 1 to 100 (default 50).
    limit: Option<u16>,
}

fn time(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn summary_view(alarm: AlarmSummary) -> AlarmSummaryView {
    AlarmSummaryView {
        id: alarm.id.to_string(),
        agent_id: alarm.agent_id,
        hostname: alarm.hostname,
        rule_set_id: alarm.rule_set_id,
        rule_id: alarm.rule_id,
        severity: alarm.severity,
        message: alarm.message,
        exe: alarm.exe,
        parent_exe: alarm.parent_exe,
        count: alarm.count,
        first_seen: time(alarm.first_seen),
        last_seen: time(alarm.last_seen),
        state: alarm.state,
        suppressed_by: alarm.suppressed_by.map(|id| id.to_string()),
    }
}

fn triage_view(triage: AlarmTriage) -> AlarmTriageView {
    AlarmTriageView {
        state: triage.state,
        assigned_to: triage.assigned_to_username,
        note: triage.note,
        accepted_until: triage.accepted_until.map(time),
        version: triage.version,
        updated_at: triage.updated_at.map(time),
        updated_by: triage.updated_by,
    }
}

fn detail_view(alarm: AlarmDetail) -> AlarmDetailView {
    AlarmDetailView {
        summary: summary_view(alarm.summary),
        rule_set_version: alarm.rule_set_version,
        rule_version: alarm.rule_version,
        confidence: alarm.confidence,
        process: alarm.process,
        ancestors: alarm.ancestors,
        received_at: time(alarm.received_at),
        triage: triage_view(alarm.triage),
    }
}

fn with_etag(status: StatusCode, version: i64, body: impl Serialize) -> Response {
    let mut response = (status, Json(body)).into_response();
    if let Ok(value) = HeaderValue::from_str(&format!("\"{version}\"")) {
        response.headers_mut().insert(header::ETAG, value);
    }
    response
}

fn bad(code: &'static str, title: &'static str) -> Response {
    problem_response(ProblemDetails::new(StatusCode::BAD_REQUEST, code, title))
}

fn not_found() -> Response {
    problem_response(ProblemDetails::not_found(
        "alarm_not_found",
        "Alarm not found",
    ))
}

fn encode_cursor(alarm: &AlarmSummary) -> String {
    URL_SAFE_NO_PAD.encode(format!(
        "{}.{}",
        alarm.last_seen.timestamp_millis(),
        alarm.id
    ))
}

fn decode_cursor(text: &str) -> Option<store::AlarmCursor> {
    let bytes = URL_SAFE_NO_PAD.decode(text).ok()?;
    let (ms, id) = std::str::from_utf8(&bytes).ok()?.split_once('.')?;
    Some((
        DateTime::from_timestamp_millis(ms.parse().ok()?)?,
        id.parse().ok()?,
    ))
}

fn alarm_id(text: &str) -> Option<i64> {
    text.parse().ok().filter(|id| *id > 0)
}

#[utoipa::path(get, path = "/api/v1/alarms", tag = "alarms", params(AlarmListParams),
    responses((status = 200, description = "Scoped alarms, newest first", body = crate::alarms::AlarmPage),
        (status = 400, description = "Invalid query or cursor", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Permission denied", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn list_alarms(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    query: Result<Query<AlarmListParams>, QueryRejection>,
) -> Response {
    let (scope, _) =
        match authenticated_permission(&state, &headers, Permission::AlarmsRead, false).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    let Ok(Query(params)) = query else {
        return bad("invalid_query", "Alarm query is invalid");
    };
    let limit = params.limit.unwrap_or(50);
    if !(1..=100).contains(&limit) {
        return bad("invalid_query", "limit must be 1 to 100");
    }
    let after = match params.cursor.as_deref().map(decode_cursor) {
        Some(None) => return bad("invalid_cursor", "cursor is invalid"),
        Some(cursor) => cursor,
        None => None,
    };
    let filters = AlarmFilters {
        agent_id: params.agent_id,
        rule_id: params.rule_id,
        severity: params.severity,
        state: params.state,
        suppressed: params.suppressed.unwrap_or(false),
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    // One extra row says whether another page follows.
    let Ok(mut rows) = store::list(&client, &scope, &filters, after, i64::from(limit) + 1).await
    else {
        return unavailable_auth();
    };
    let more = rows.len() > usize::from(limit);
    rows.truncate(usize::from(limit));
    let next_cursor = more.then(|| rows.last().map(encode_cursor)).flatten();
    Json(AlarmPage {
        items: rows.into_iter().map(summary_view).collect(),
        next_cursor,
    })
    .into_response()
}

#[utoipa::path(get, path = "/api/v1/alarms/{alarm_id}", tag = "alarms", params(("alarm_id" = String, Path)),
    responses((status = 200, description = "The alarm, its process tree and triage", body = crate::alarms::AlarmDetailView, headers(("ETag" = String, description = "Triage version"))),
        (status = 404, description = "Absent or outside the caller's scope", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn get_alarm(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (scope, _) =
        match authenticated_permission(&state, &headers, Permission::AlarmsRead, false).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    let Some(id) = alarm_id(&id) else {
        return not_found();
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::detail(&client, &scope, id).await {
        Ok(Some(alarm)) => {
            let version = alarm.triage.version;
            with_etag(StatusCode::OK, version, detail_view(alarm))
        }
        Ok(None) => not_found(),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(put, path = "/api/v1/alarms/{alarm_id}/triage", tag = "alarms", params(("alarm_id" = String, Path), ("If-Match" = String, Header, description = "Quoted triage version")),
    request_body = crate::alarms::UpdateAlarmTriageRequest,
    responses((status = 200, description = "Updated triage", body = crate::alarms::AlarmTriageView, headers(("ETag" = String, description = "New triage version"))),
        (status = 400, description = "Invalid state, note, expiry or assignee", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "Absent or outside the caller's scope", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The workflow does not allow this step", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "Stale triage version", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 428, description = "If-Match is required", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn update_alarm_triage(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    payload: Result<Json<UpdateAlarmTriageRequest>, JsonRejection>,
) -> Response {
    let (scope, user_id) =
        match authenticated_permission(&state, &headers, Permission::AlarmsTriage, true).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    let expected = match parse_if_match_version(&headers) {
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
    let Some(id) = alarm_id(&id) else {
        return not_found();
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
    let change = TriageChange {
        expected_version: expected,
        state: &payload.state,
        assigned_to_username: payload.assigned_to.as_deref(),
        note: payload.note.as_deref(),
        accepted_until,
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::update_triage(&mut client, &scope, id, &change, &user_id, Utc::now()).await {
        Ok(TriageOutcome::Updated(triage)) => {
            let version = triage.version;
            with_etag(StatusCode::OK, version, triage_view(triage))
        }
        Ok(TriageOutcome::NotFound) => not_found(),
        Ok(TriageOutcome::Stale) => problem_response(ProblemDetails::new(
            StatusCode::PRECONDITION_FAILED,
            "stale_triage",
            "Triage changed; reload before saving",
        )),
        Ok(TriageOutcome::InvalidTransition) => problem_response(ProblemDetails::new(
            StatusCode::CONFLICT,
            "invalid_transition",
            "Requested triage transition is not allowed",
        )),
        Ok(TriageOutcome::InvalidFields) => {
            bad("invalid_triage", "Triage state, note, or expiry is invalid")
        }
        Ok(TriageOutcome::AssigneeUnavailable) => bad(
            "invalid_assignee",
            "Assignee must be an enabled analyst or admin",
        ),
        Err(_) => unavailable_auth(),
    }
}
