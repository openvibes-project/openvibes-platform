//! `GET /v1/alarms/{id}/summary`: everything above the fold on an alarm's
//! page (roles 5a): the alarm, tiles, rule text, commands seen, the last 24
//! hours and the Related card, inside the viewer's `alarms.read` reach,
//! with each action by its permission on the alarm's host.

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use platform_store::{
    alarm_summary::{AlarmPageSummary, alarm_summary},
    console_read::AgentScope,
};

use super::{
    alarm::triage_view,
    list_types::{AlarmListCaseView, AlarmListRowView},
    summary_types::{
        AlarmActionsView, AlarmCommandView, AlarmPageAlarmView, AlarmRelatedView,
        AlarmRuleTextView, AlarmSummaryPageView, AlarmTilesView, SameRuleElsewhereView,
    },
};
use crate::{
    Permission,
    access::guard::{authenticated_capabilities, permission_denied, scope_of, unavailable_auth},
    hosts::summary::{top_alarms_view, top_vulnerabilities_view},
    http::{
        AuthHttpState,
        problem::{ProblemDetails, problem_response},
    },
};

fn alarm_not_found() -> Response {
    problem_response(ProblemDetails::not_found(
        "alarm_not_found",
        "Alarm not found",
    ))
}

/// An alarm's page.
#[utoipa::path(get, path = "/api/v1/alarms/{id}/summary", tag = "alarms",
    params(("id" = String, Path, description = "Alarm id")),
    responses((status = 200, description = "The alarm page above the fold", body = AlarmSummaryPageView),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Needs alarms.read", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "alarm_not_found: missing or outside reach", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn alarm_summary_page(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (capabilities, _) = match authenticated_capabilities(&state, &headers, false).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let Some(alarms) = scope_of(&capabilities, Permission::AlarmsRead) else {
        return permission_denied();
    };
    let Some(id) = id.parse::<i64>().ok().filter(|id| *id > 0) else {
        return alarm_not_found();
    };
    let scope = |p| scope_of(&capabilities, p);
    let vulns = scope(Permission::VulnerabilitiesRead);
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let s = match alarm_summary(&client, id, &alarms, vulns.as_ref(), Utc::now()).await {
        Ok(Some(s)) => s,
        Ok(None) => return alarm_not_found(),
        Err(_) => return unavailable_auth(),
    };
    let here = |p| scope(p).is_some_and(|sc: AgentScope| s.reaches(&sc));
    let triage = here(Permission::AlarmsTriage);
    let can = AlarmActionsView {
        triage,
        // Assigning is a triage change; the people to pick need cases.assign.
        assign: triage && here(Permission::CasesAssign),
        suppress: here(Permission::AlarmsSuppress),
        add_to_case: here(Permission::CasesWrite),
        // The session drops assistant.use when the assistant is off.
        ask: state.assistant.is_some() && here(Permission::AssistantUse),
        export: here(Permission::AlarmsExport),
    };
    axum::Json(view(s, can)).into_response()
}

fn view(s: AlarmPageSummary, can: AlarmActionsView) -> AlarmSummaryPageView {
    let starts = s.commands.iter().map(|c| c.count).sum();
    let first_seen = s
        .commands
        .iter()
        .map(|c| c.first_seen)
        .min()
        .unwrap_or(s.alarm.first_seen);
    AlarmSummaryPageView {
        tiles: AlarmTilesView {
            starts,
            different_commands: i64::try_from(s.commands.len()).unwrap_or(i64::MAX),
            first_seen: first_seen.to_rfc3339(),
            confidence: s.confidence,
        },
        rule: AlarmRuleTextView {
            title: s.rule.title,
            message: s.rule.message,
            explain: s.rule.explain,
            check: s.rule.check,
            techniques: s.rule.techniques,
        },
        commands: s
            .commands
            .into_iter()
            .map(|c| AlarmCommandView {
                id: c.id,
                args: c.args,
                count: c.count,
                first_seen: c.first_seen.to_rfc3339(),
                last_seen: c.last_seen.to_rfc3339(),
                state: c.state,
                suppressed_by: c.suppressed_by,
                case: c.case.map(|(id, number)| AlarmListCaseView { id, number }),
            })
            .collect(),
        hourly: s.hourly,
        related: AlarmRelatedView {
            host_alarms: top_alarms_view(s.host_alarms),
            host_vulnerabilities: s.host_vulnerabilities.map(top_vulnerabilities_view),
            same_rule_elsewhere: SameRuleElsewhereView {
                hosts: s.elsewhere.hosts,
                open: s.elsewhere.open,
            },
        },
        alarm: AlarmPageAlarmView {
            row: AlarmListRowView::from(s.alarm),
            confidence: s.confidence,
            rule_set_version: s.rule_set_version,
            rule_version: s.rule_version,
            process: s.process,
            ancestors: s.ancestors,
            received_at: s.received_at.to_rfc3339(),
            triage: triage_view(s.triage),
        },
        can,
    }
}
