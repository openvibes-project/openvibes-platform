//! `GET /v1/alarm-list`: the Alarms list with filters, per-value counts and a
//! summary line, inside the caller's `alarms.read` reach.

use axum::{
    extract::{Query, State, rejection::QueryRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use platform_store::alarm_list::{
    AlarmQuery, AlarmSeverity, AlarmSort, AlarmState, Assignee, alarm_list,
};
use serde::Deserialize;
use utoipa::IntoParams;

use super::list_types::AlarmListView;
use crate::{
    Permission,
    access::guard::{authenticated_capabilities, permission_denied, scope_of, unavailable_auth},
    http::{
        AuthHttpState,
        problem::{FieldError, ProblemDetails, problem_response},
    },
};

/// Filters, sort and page. Empty values count as absent.
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub(crate) struct AlarmListParams {
    /// Message, rule id, host name or program (contains).
    q: Option<String>,
    /// open (default), mitigated, accepted_risk, false_positive or all.
    state: Option<String>,
    /// critical, high, medium, low or info.
    severity: Option<String>,
    /// hidden (default) or shown.
    suppressed: Option<String>,
    /// An agent id.
    host: Option<String>,
    /// A host group id.
    group: Option<String>,
    /// An ATT&CK technique id, such as T1059.004.
    technique: Option<String>,
    /// yes (in an open case) or no.
    case: Option<String>,
    /// me, unassigned or a user id.
    assignee: Option<String>,
    /// last_seen (default), first_seen, count or severity.
    sort: Option<String>,
    /// asc or desc (default).
    dir: Option<String>,
    /// Rows to skip, 0 to 100000.
    offset: Option<String>,
    /// Page size, 1 to 100 (default 50).
    limit: Option<String>,
}

fn invalid_query(field: &str) -> Response {
    let mut p = ProblemDetails::new(
        StatusCode::BAD_REQUEST,
        "invalid_query",
        "Alarm query parameters are invalid",
    );
    p.field_errors = Some(vec![FieldError {
        field: field.into(),
        code: "invalid".into(),
        message: format!("The {field} parameter is invalid"),
    }]);
    problem_response(p)
}

fn is_uuid(s: &str) -> bool {
    s.len() == 36
        && s.char_indices().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        })
}

fn number(
    value: Option<&str>,
    default: i64,
    max: i64,
    field: &'static str,
) -> Result<i64, &'static str> {
    let min = i64::from(field == "limit");
    value.map_or(Ok(default), |v| {
        v.parse::<i64>()
            .ok()
            .filter(|n| (min..=max).contains(n))
            .ok_or(field)
    })
}

/// A pick from a closed list.
fn pick<T>(
    value: Option<&str>,
    field: &'static str,
    parse: impl Fn(&str) -> Option<T>,
) -> Result<Option<T>, &'static str> {
    value.map_or(Ok(None), |v| parse(v).map(Some).ok_or(field))
}

/// The Alarms list.
#[utoipa::path(get, path = "/api/v1/alarm-list", tag = "alarms", params(AlarmListParams),
    responses((status = 200, description = "A page of alarms in the caller's reach", body = AlarmListView),
        (status = 400, description = "invalid_query, naming the parameter", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Needs alarms.read", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn list_alarm_page(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    query: Result<Query<AlarmListParams>, QueryRejection>,
) -> Response {
    let (capabilities, actor_id) = match authenticated_capabilities(&state, &headers, false).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let Some(scope) = scope_of(&capabilities, Permission::AlarmsRead) else {
        return permission_denied();
    };
    let Ok(Query(mut p)) = query else {
        return invalid_query("query");
    };
    for v in [
        &mut p.q,
        &mut p.state,
        &mut p.severity,
        &mut p.suppressed,
        &mut p.host,
        &mut p.group,
        &mut p.technique,
        &mut p.case,
        &mut p.assignee,
        &mut p.sort,
        &mut p.dir,
        &mut p.offset,
        &mut p.limit,
    ] {
        if v.as_deref().is_some_and(str::is_empty) {
            *v = None;
        }
    }
    let parsed = (|| {
        for (field, v, max) in [
            ("q", &p.q, 200),
            ("host", &p.host, 100),
            ("technique", &p.technique, 16),
        ] {
            if v.as_deref()
                .is_some_and(|v| v.chars().count() > max || v.chars().any(char::is_control))
            {
                return Err(field);
            }
        }
        let lowercase_uuid = |v: &Option<String>, field| match v.as_deref() {
            Some(g) if !is_uuid(g) => Err(field),
            g => Ok(g.map(str::to_ascii_lowercase)),
        };
        let group = lowercase_uuid(&p.group, "group")?;
        let assignee_id = match p.assignee.as_deref() {
            Some("me" | "unassigned") | None => None,
            Some(_) => lowercase_uuid(&p.assignee, "assignee")?,
        };
        let state = match p.state.as_deref() {
            None => Some(AlarmState::Open),
            Some("all") => None,
            Some(v) => Some(AlarmState::parse(v).ok_or("state")?),
        };
        let suppressed = match p.suppressed.as_deref() {
            None | Some("hidden") => false,
            Some("shown") => true,
            Some(_) => return Err("suppressed"),
        };
        let case = match p.case.as_deref() {
            None => None,
            Some("yes") => Some(true),
            Some("no") => Some(false),
            Some(_) => return Err("case"),
        };
        let descending = match p.dir.as_deref() {
            None | Some("desc") => true,
            Some("asc") => false,
            Some(_) => return Err("dir"),
        };
        Ok((
            group,
            assignee_id,
            state,
            suppressed,
            case,
            descending,
            pick(p.severity.as_deref(), "severity", AlarmSeverity::parse)?,
            pick(p.sort.as_deref(), "sort", AlarmSort::parse)?.unwrap_or(AlarmSort::LastSeen),
            number(p.offset.as_deref(), 0, 100_000, "offset")?,
            number(p.limit.as_deref(), 50, 100, "limit")?,
        ))
    })();
    let (
        group,
        assignee_id,
        state_filter,
        suppressed,
        case,
        descending,
        severity,
        sort,
        offset,
        limit,
    ) = match parsed {
        Ok(v) => v,
        Err(field) => return invalid_query(field),
    };
    let assignee = match p.assignee.as_deref() {
        None => None,
        Some("me") => Some(Assignee::Me),
        Some("unassigned") => Some(Assignee::Unassigned),
        Some(_) => assignee_id.as_deref().map(Assignee::User),
    };
    let alarm_query = AlarmQuery {
        q: p.q.as_deref(),
        state: state_filter,
        severity,
        suppressed,
        host: p.host.as_deref(),
        group: group.as_deref(),
        technique: p.technique.as_deref(),
        case,
        assignee,
        sort,
        descending,
        offset,
        limit,
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let now = Utc::now();
    let hosts_read = scope_of(&capabilities, Permission::HostsRead);
    match alarm_list(
        &client,
        &alarm_query,
        &scope,
        hosts_read.as_ref(),
        &actor_id,
        now,
    )
    .await
    {
        Ok(page) => axum::Json(AlarmListView::new(page, hosts_read.is_some(), now)).into_response(),
        Err(_) => unavailable_auth(),
    }
}
