//! `GET /v1/hosts/{agent_id}/summary`: everything above the fold on the
//! host page (plan ruling 10), each section present only with its
//! permission on this host.

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, SecondsFormat, Utc};
use platform_store::{
    console_read::AgentScope,
    host_list::{HostScopes, HostStatus},
    host_summary::{HostSummary, Top, TopAlarm, summary},
    vulns::VulnRow,
};

use super::LastTest;
use super::{
    agents::alarms_view,
    certificates::certificate_view,
    list_types::{HostListGroupView, HostOsView},
    summary_types::{
        HostActionsView, HostFactsView, HostInventoryView, HostProtectionView, HostSummaryView,
        HostTilesView, TopAlarmView, TopAlarmsView, TopFailingListView, TopFailingView,
        TopVulnerabilitiesView, TopVulnerabilityView,
    },
};
use crate::{
    Permission,
    access::guard::{authenticated_capabilities, permission_denied, scope_of, unavailable_auth},
    http::{
        AuthHttpState,
        problem::{ProblemDetails, problem_response},
        validate::valid_agent_id,
    },
};

fn rfc(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn host_not_found() -> Response {
    problem_response(ProblemDetails::not_found("host_not_found", "No such host"))
}

/// The host page's summary.
#[utoipa::path(get, path = "/api/v1/hosts/{agent_id}/summary", tag = "hosts",
    params(("agent_id" = String, Path, description = "Agent id")),
    responses((status = 200, description = "The host page above the fold", body = HostSummaryView),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Needs hosts.read", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "host_not_found: missing or outside reach", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn host_summary(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
) -> Response {
    let (capabilities, _) = match authenticated_capabilities(&state, &headers, false).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let Some(hosts) = scope_of(&capabilities, Permission::HostsRead) else {
        return permission_denied();
    };
    if !valid_agent_id(&agent_id) {
        return host_not_found();
    }
    let scope = |p| scope_of(&capabilities, p);
    let (alarms, vulns, compliance) = (
        scope(Permission::AlarmsRead),
        scope(Permission::VulnerabilitiesRead),
        scope(Permission::ComplianceRead),
    );
    let scopes = HostScopes {
        hosts: &hosts,
        alarms: alarms.as_ref(),
        vulnerabilities: vulns.as_ref(),
        compliance: compliance.as_ref(),
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let latest = crate::about::latest_agent_version(&state);
    let s = match summary(&client, &agent_id, &scopes, latest.as_deref(), Utc::now()).await {
        Ok(Some(s)) => s,
        Ok(None) => return host_not_found(),
        Err(_) => return unavailable_auth(),
    };
    let here = |p| scope(p).is_some_and(|sc: AgentScope| s.reaches(&sc));
    let changeable = matches!(s.status, HostStatus::Online | HostStatus::Offline);
    let can = HostActionsView {
        label: changeable && here(Permission::HostsLabel),
        revoke: changeable && here(Permission::HostsRevoke),
        export: here(Permission::HostsExport),
        add_to_case: here(Permission::CasesWrite),
        ask: state.assistant.is_some() && here(Permission::AssistantUse),
    };
    axum::Json(view(s, can)).into_response()
}

fn total<T>(top: Option<&Top<T>>) -> Option<i64> {
    top.map(|t| t.total)
}

/// Open alarms as the host page and an alarm's Related card show them.
pub(crate) fn top_alarms_view(t: Top<TopAlarm>) -> TopAlarmsView {
    TopAlarmsView {
        total: t.total,
        items: t
            .items
            .into_iter()
            .map(|i| TopAlarmView {
                id: i.id,
                rule_id: i.rule_id,
                message: i.message,
                severity: i.severity,
                last_seen: rfc(i.last_seen),
            })
            .collect(),
    }
}

/// Open vulnerabilities as the host page and an alarm's Related card show them.
pub(crate) fn top_vulnerabilities_view(t: Top<VulnRow>) -> TopVulnerabilitiesView {
    TopVulnerabilitiesView {
        total: t.total,
        items: t
            .items
            .into_iter()
            .map(|v| TopVulnerabilityView {
                advisory: v.advisory_id,
                severity: v.severity,
                kev: v.kev,
                exploited: v.exploited,
                title: v.title,
            })
            .collect(),
    }
}

fn view(s: HostSummary, can: HostActionsView) -> HostSummaryView {
    let a = s.agent;
    HostSummaryView {
        tiles: HostTilesView {
            open_alarms: total(s.top_alarms.as_ref()),
            compliance_failing: total(s.top_failing.as_ref()),
            compliance_stale: s.compliance_stale,
            vulnerabilities: total(s.top_vulnerabilities.as_ref()),
            software: Some(s.packages),
        },
        host: HostFactsView {
            id: a.agent_id,
            hostname: a.hostname,
            status: s.status.as_str().into(),
            address: s.address,
            os: HostOsView {
                id: a.os_id,
                version: a.os_version,
                distribution: s.distribution,
                family: s.os_family,
            },
            running_kernel: a.running_kernel,
            scanner_version: a.scanner_version,
            agent_older: s.agent_older,
            enrolled_at: rfc(a.enrolled_at),
            revoked_at: a.revoked_at.map(rfc),
            last_seen_at: a.last_seen_at.map(rfc),
            inventory_at: a.inventory_at.map(rfc),
            capabilities: a.capabilities,
        },
        protection: HostProtectionView {
            threat_alarms: a.alarms.map(alarms_view),
            last_test: LastTest {
                alarm_at: s.last_test.0.map(rfc),
                finding_at: s.last_test.1.map(rfc),
            },
        },
        groups: s
            .groups
            .into_iter()
            .map(|(id, name, kind)| HostListGroupView {
                id,
                name,
                kind: kind.into(),
            })
            .collect(),
        labels: s.labels,
        certificates: s.certificates.into_iter().map(certificate_view).collect(),
        certificate_count: s.certificate_count,
        top_alarms: s.top_alarms.map(top_alarms_view),
        top_vulnerabilities: s.top_vulnerabilities.map(top_vulnerabilities_view),
        top_failing: s.top_failing.map(|t| TopFailingListView {
            total: t.total,
            items: t
                .items
                .into_iter()
                .map(|f| TopFailingView {
                    rule_set_id: f.rule_set_id,
                    rule_id: f.rule_id,
                    severity: f.severity,
                    message: f.message,
                })
                .collect(),
        }),
        inventory: HostInventoryView {
            packages: s.packages,
            listening_ports: s.listening_ports,
            exposed_ports: s.exposed_ports,
            services: s.services,
        },
        can,
    }
}
