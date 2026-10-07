//! Count history over `/api/v1/metrics/history` (spec
//! 2026-10-07-overview-clarity-design §5): one catalogued count per day,
//! summed over the hosts the caller may see. Stored days come from
//! `host_daily_counts`; today is always the live value.

use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::{Duration, Utc};
use platform_store::{
    console_read::{AgentScope, agent_ids_in_scope},
    history::{self, Expr},
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::{
    FieldError, Permission, ProblemDetails,
    problem::problem_response,
    router::{AuthHttpState, authenticated_agent_scope, unavailable_auth},
};

use Permission::{
    AgentsRead as AG, AlarmsRead as AL, ComplianceRead as CO, VulnerabilitiesRead as VU,
};

/// One countable thing: who may read it and how to compute it.
pub struct Metric {
    pub id: &'static str,
    // ponytail: read by the metric picker (a later task); API ignores it.
    #[allow(dead_code)]
    pub label: &'static str,
    pub permissions: &'static [Permission],
    pub expr: Expr,
}

macro_rules! m {
    ($id:expr, $label:expr, $perms:expr, $expr:expr) => {
        Metric {
            id: $id,
            label: $label,
            permissions: $perms,
            expr: $expr,
        }
    };
}

/// Every metric the endpoint serves. `Expr`s live only here, never built
/// from request input.
pub static CATALOGUE: [Metric; 21] = [
    m!(
        "all.open.critical",
        "Critical problems",
        &[AL, VU, CO],
        Expr::Sum(&["alarms_critical", "vulns_critical", "compliance_critical"])
    ),
    m!(
        "all.open.high",
        "High problems",
        &[AL, VU, CO],
        Expr::Sum(&["alarms_high", "vulns_high", "compliance_high"])
    ),
    m!(
        "alarms.active",
        "Active alarms",
        &[AL],
        Expr::Sum(&[
            "alarms_critical",
            "alarms_high",
            "alarms_medium",
            "alarms_low",
            "alarms_info"
        ])
    ),
    m!(
        "alarms.active.critical",
        "Critical alarms",
        &[AL],
        Expr::Sum(&["alarms_critical"])
    ),
    m!(
        "alarms.active.high",
        "High alarms",
        &[AL],
        Expr::Sum(&["alarms_high"])
    ),
    m!(
        "alarms.active.medium",
        "Medium alarms",
        &[AL],
        Expr::Sum(&["alarms_medium"])
    ),
    m!(
        "alarms.active.low",
        "Low alarms",
        &[AL],
        Expr::Sum(&["alarms_low"])
    ),
    m!(
        "vulns.open.critical",
        "Critical vulnerabilities",
        &[VU],
        Expr::Sum(&["vulns_critical"])
    ),
    m!(
        "vulns.open.high",
        "High vulnerabilities",
        &[VU],
        Expr::Sum(&["vulns_high"])
    ),
    m!(
        "vulns.open.medium",
        "Medium vulnerabilities",
        &[VU],
        Expr::Sum(&["vulns_medium"])
    ),
    m!(
        "vulns.open.low",
        "Low vulnerabilities",
        &[VU],
        Expr::Sum(&["vulns_low"])
    ),
    m!(
        "vulns.exploited",
        "Exploited vulnerabilities",
        &[VU],
        Expr::Sum(&["vulns_exploited"])
    ),
    m!(
        "vulns.no_fix",
        "Vulnerabilities without a fix",
        &[VU],
        Expr::Sum(&["vulns_no_fix"])
    ),
    m!(
        "vulns.reboot_hosts",
        "Hosts needing a reboot",
        &[VU],
        Expr::HostsWhere("needs_reboot")
    ),
    m!(
        "compliance.open.critical",
        "Critical compliance findings",
        &[CO],
        Expr::Sum(&["compliance_critical"])
    ),
    m!(
        "compliance.open.high",
        "High compliance findings",
        &[CO],
        Expr::Sum(&["compliance_high"])
    ),
    m!(
        "compliance.open.medium",
        "Medium compliance findings",
        &[CO],
        Expr::Sum(&["compliance_medium"])
    ),
    m!(
        "compliance.open.low",
        "Low compliance findings",
        &[CO],
        Expr::Sum(&["compliance_low"])
    ),
    m!(
        "agents.active",
        "Active agents",
        &[AG],
        Expr::HostsWhere("status = 'active'")
    ),
    m!(
        "agents.stale",
        "Stale agents",
        &[AG],
        Expr::HostsWhere("status = 'stale'")
    ),
    m!(
        "agents.revoked",
        "Revoked agents",
        &[AG],
        Expr::HostsWhere("status = 'revoked'")
    ),
];

/// Query of `GET /api/v1/metrics/history`.
#[derive(Debug, Deserialize, IntoParams)]
pub struct HistoryParams {
    /// Catalogue id, for example `vulns.open.critical`.
    metric: Option<String>,
    /// Window in days: 7, 30, 90 or 365 (default 30).
    days: Option<String>,
}

/// One day's value.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct MetricPoint {
    /// UTC day, `YYYY-MM-DD`.
    pub day: String,
    /// The count that day.
    pub value: u64,
}

/// A metric's daily values, oldest first; days with no data are absent.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct MetricHistory {
    /// The requested catalogue id.
    pub metric: String,
    /// Stored days, then today's live value.
    pub points: Vec<MetricPoint>,
}

fn invalid(field: &str, code: &str, message: &str) -> Response {
    let mut problem = ProblemDetails::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "invalid_metric_query",
        "The metric query is invalid",
    );
    problem.field_errors = Some(vec![FieldError {
        field: field.into(),
        code: code.into(),
        message: message.into(),
    }]);
    problem_response(problem)
}

/// The one scope all of `scopes` agree on, if they do.
fn common_scope(scopes: Vec<AgentScope>) -> Option<AgentScope> {
    let norm = |s: AgentScope| match s {
        AgentScope::AssetGroups(mut g) => {
            g.sort();
            AgentScope::AssetGroups(g)
        }
        global => global,
    };
    let mut scopes = scopes.into_iter().map(norm);
    let first = scopes.next()?;
    scopes.all(|s| s == first).then_some(first)
}

#[utoipa::path(
    get,
    path = "/api/v1/metrics/history",
    tag = "metrics",
    params(HistoryParams),
    responses(
        (status = 200, description = "Daily values of one count, ending with today's live value", body = MetricHistory),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Missing permission, or the metric spans kinds with different scopes", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "Unknown metric or unsupported window", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Unavailable", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(crate) async fn history(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Query(params): Query<HistoryParams>,
) -> Response {
    let Some(metric) = CATALOGUE
        .iter()
        .find(|m| Some(m.id) == params.metric.as_deref())
    else {
        return invalid("metric", "unknown_metric", "Unknown metric");
    };
    let days: i64 = match params.days.as_deref().unwrap_or("30") {
        "7" => 7,
        "30" => 30,
        "90" => 90,
        "365" => 365,
        _ => return invalid("days", "invalid_days", "days must be 7, 30, 90 or 365"),
    };
    let mut scopes = Vec::new();
    for permission in metric.permissions {
        match authenticated_agent_scope(&state, &headers, *permission).await {
            Ok(scope) => scopes.push(scope),
            Err(response) => return response,
        }
    }
    let Some(scope) = common_scope(scopes) else {
        return problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "Counts across kinds need the same scope for alarms, vulnerabilities and compliance",
        ));
    };
    let client = match state.pool.get().await {
        Ok(client) => client,
        Err(_) => return unavailable_auth(),
    };
    let ids = match &scope {
        AgentScope::Global => None,
        scoped => match agent_ids_in_scope(&client, scoped).await {
            Ok(ids) => Some(ids),
            Err(_) => return unavailable_auth(),
        },
    };
    let now = Utc::now();
    let today = now.date_naive();
    let stored = history::series(
        &client,
        &metric.expr,
        today - Duration::days(days - 1),
        ids.as_deref(),
    );
    let live = history::current(&client, &metric.expr, now, ids.as_deref());
    let (Ok(stored), Ok(live)) = (stored.await, live.await) else {
        return unavailable_auth();
    };
    let mut points: Vec<MetricPoint> = stored
        .into_iter()
        .filter(|(day, _)| *day < today)
        .map(|(day, value)| MetricPoint {
            day: day.to_string(),
            value: value.max(0) as u64,
        })
        .collect();
    points.push(MetricPoint {
        day: today.to_string(),
        value: live.max(0) as u64,
    });
    Json(MetricHistory {
        metric: metric.id.to_owned(),
        points,
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogue_uses_only_known_columns_and_conditions() {
        let conditions = [
            "needs_reboot",
            "status = 'active'",
            "status = 'stale'",
            "status = 'revoked'",
        ];
        let mut ids = std::collections::HashSet::new();
        for m in &CATALOGUE {
            assert!(ids.insert(m.id), "duplicate {}", m.id);
            match &m.expr {
                Expr::Sum(cols) => {
                    for c in *cols {
                        assert!(
                            history::COLUMNS[..16].contains(c) && *c != "needs_reboot",
                            "{c}"
                        );
                    }
                }
                Expr::HostsWhere(c) => assert!(conditions.contains(c), "{c}"),
            }
        }
    }

    #[test]
    fn scopes_must_agree() {
        let a = AgentScope::AssetGroups(vec!["a".into()]);
        let b = AgentScope::AssetGroups(vec!["b".into()]);
        assert_eq!(
            common_scope(vec![AgentScope::Global; 3]),
            Some(AgentScope::Global)
        );
        assert_eq!(common_scope(vec![a.clone(), a.clone()]), Some(a.clone()));
        assert_eq!(common_scope(vec![a.clone(), b]), None);
        assert_eq!(common_scope(vec![a, AgentScope::Global]), None);
    }
}
