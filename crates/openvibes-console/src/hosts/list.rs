//! `GET /v1/hosts`: the Hosts list with filters, per-value counts and a
//! summary line, inside the caller's reach.

use axum::{
    extract::{Query, State, rejection::QueryRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use platform_store::host_list::{
    AgentAge, HostQuery, HostScopes, HostSort, HostStatus, Problems, hosts,
};
use serde::Deserialize;
use utoipa::IntoParams;

use super::list_types::{HostListView, problems_value};
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
pub(crate) struct HostListParams {
    /// Host name (contains), agent id or address prefix, or CIDR range.
    q: Option<String>,
    /// online, offline, revoked or imported.
    status: Option<String>,
    /// linux or windows.
    os: Option<String>,
    /// A host group id.
    group: Option<String>,
    /// A label.
    label: Option<String>,
    /// critical, alarms or none.
    problems: Option<String>,
    /// older or latest.
    agent: Option<String>,
    /// host, heartbeat, version or problems.
    sort: Option<String>,
    /// asc or desc.
    dir: Option<String>,
    /// Rows to skip, 0 to 100000.
    offset: Option<String>,
    /// Page size, 1 to 100 (default 50).
    limit: Option<String>,
}

fn invalid_query(field: &str) -> Response {
    let message = format!("The {field} parameter is invalid");
    let mut p = ProblemDetails::new(
        StatusCode::BAD_REQUEST,
        "invalid_query",
        "Host query parameters are invalid",
    );
    p.field_errors = Some(vec![FieldError {
        field: field.into(),
        code: "invalid".into(),
        message,
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

/// The Hosts list.
#[utoipa::path(get, path = "/api/v1/hosts", tag = "hosts", params(HostListParams),
    responses((status = 200, description = "A page of hosts in the caller's reach", body = HostListView),
        (status = 400, description = "invalid_query, naming the parameter", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Needs hosts.read", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn list_hosts(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    query: Result<Query<HostListParams>, QueryRejection>,
) -> Response {
    let (capabilities, _) = match authenticated_capabilities(&state, &headers, false).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let Some(hosts_scope) = scope_of(&capabilities, Permission::HostsRead) else {
        return permission_denied();
    };
    let Ok(Query(mut p)) = query else {
        return invalid_query("query");
    };
    for v in [
        &mut p.q,
        &mut p.status,
        &mut p.os,
        &mut p.group,
        &mut p.label,
        &mut p.problems,
        &mut p.agent,
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
        for (field, v, max) in [("q", &p.q, 200), ("label", &p.label, 64)] {
            if v.as_deref()
                .is_some_and(|v| v.chars().count() > max || v.chars().any(char::is_control))
            {
                return Err(field);
            }
        }
        let group = match p.group.as_deref() {
            Some(g) if !is_uuid(g) => return Err("group"),
            g => g.map(str::to_ascii_lowercase),
        };
        let os = match p.os.as_deref() {
            None => None,
            Some(o @ ("linux" | "windows")) => Some(o),
            Some(_) => return Err("os"),
        };
        let descending = match p.dir.as_deref() {
            None | Some("asc") => false,
            Some("desc") => true,
            Some(_) => return Err("dir"),
        };
        Ok((
            group,
            os,
            descending,
            pick(p.status.as_deref(), "status", HostStatus::parse)?,
            pick(p.problems.as_deref(), "problems", |v| {
                Problems::ALL
                    .iter()
                    .copied()
                    .find(|p| problems_value(*p) == v)
            })?,
            pick(p.agent.as_deref(), "agent", AgentAge::parse)?,
            pick(p.sort.as_deref(), "sort", HostSort::parse)?.unwrap_or(HostSort::Host),
            number(p.offset.as_deref(), 0, 100_000, "offset")?,
            number(p.limit.as_deref(), 50, 100, "limit")?,
        ))
    })();
    let (group, os, descending, status, problems, agent, sort, offset, limit) = match parsed {
        Ok(v) => v,
        Err(field) => return invalid_query(field),
    };
    let (alarms, vulns, compliance) = (
        scope_of(&capabilities, Permission::AlarmsRead),
        scope_of(&capabilities, Permission::VulnerabilitiesRead),
        scope_of(&capabilities, Permission::ComplianceRead),
    );
    let scopes = HostScopes {
        hosts: &hosts_scope,
        alarms: alarms.as_ref(),
        vulnerabilities: vulns.as_ref(),
        compliance: compliance.as_ref(),
    };
    let host_query = HostQuery {
        q: p.q.as_deref(),
        status,
        os_family: os,
        group: group.as_deref(),
        label: p.label.as_deref(),
        problems,
        agent,
        sort,
        descending,
        offset,
        limit,
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let latest = crate::about::latest_agent_version(&state);
    let now = Utc::now();
    match hosts(&client, &host_query, &scopes, latest.as_deref(), now).await {
        Ok(page) => axum::Json(HostListView::new(page, latest, now)).into_response(),
        Err(_) => unavailable_auth(),
    }
}
