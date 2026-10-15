//! The route table: every API and auth path, with the handler serving it.

use axum::{Router, http::StatusCode, response::Response, routing::get};

use super::{
    AuthHttpState,
    problem::{ProblemDetails, problem_response},
};
use crate::access::{
    asset_groups::*, bindings::*, inventory::*, login::*, service_accounts::*, service_tokens::*,
    session::*, tags::*,
};
use crate::audit::{events::*, export::*, retention::*};
use crate::hosts::{agents::*, certificates::*, enrollment::*, install::*};
use crate::router::*;

pub(super) fn api_router() -> Router {
    Router::new()
        .route("/v1/session", get(session))
        .method_not_allowed_fallback(api_method_not_allowed)
        .fallback(api_not_found)
}

pub(super) fn authenticated_api_router() -> Router<AuthHttpState> {
    Router::new()
        .route("/v1/session", get(authenticated_session))
        .route(
            "/v1/session/password",
            axum::routing::post(crate::access::users::change_password),
        )
        .route("/v1/assistant/status", get(authenticated_assistant_status))
        .route(
            "/v1/assistant/messages",
            axum::routing::post(authenticated_assistant_message),
        )
        .route("/v1/about", get(crate::about::about))
        .route("/v1/about/update", get(crate::about::about_update))
        .route("/v1/agent-package", get(authenticated_agent_package))
        .route("/v1/agent-command", get(authenticated_agent_command))
        .route("/v1/agents/summary", get(authenticated_agent_summary))
        .route(
            "/v1/agents/events",
            get(crate::hosts::presence::agent_events),
        )
        .route("/v1/agents", get(authenticated_agents))
        .route("/v1/agents/{agent_id}", get(authenticated_agent_detail))
        .route(
            "/v1/agents/{agent_id}/tags/preview",
            axum::routing::post(preview_authenticated_agent_tags),
        )
        .route(
            "/v1/agents/{agent_id}/tags",
            axum::routing::put(apply_authenticated_agent_tags),
        )
        .route(
            "/v1/agents/{agent_id}/revoke",
            axum::routing::post(revoke_authenticated_agent),
        )
        .route(
            "/v1/agents/{agent_id}/certificates",
            get(authenticated_agent_certificates),
        )
        .route("/v1/compliance/summary", get(authenticated_finding_summary))
        .route("/v1/compliance/groups", get(authenticated_finding_groups))
        .route(
            "/v1/compliance/groups/{rule_set_id}/{rule_id}/endpoints",
            get(authenticated_finding_group_endpoints),
        )
        .route(
            "/v1/compliance/groups/{rule_set_id}/{rule_id}/triage",
            axum::routing::post(update_authenticated_finding_group_triage),
        )
        .route("/v1/compliance/latest", get(authenticated_latest_findings))
        .route(
            "/v1/compliance/latest/{agent_id}/{rule_set_id}/{rule_id}/rule/{finding_id}",
            get(crate::detection::finding_rule),
        )
        .route("/v1/alarms/{id}/rule", get(crate::detection::alarm_rule))
        .route(
            "/v1/compliance/latest/{agent_id}/{rule_set_id}/{rule_id}",
            get(authenticated_latest_finding),
        )
        .route(
            "/v1/compliance/latest/{agent_id}/{rule_set_id}/{rule_id}/triage",
            get(authenticated_finding_triage).put(update_authenticated_finding_triage),
        )
        .route("/v1/compliance/history", get(authenticated_finding_history))
        .route(
            "/v1/vulnerabilities/summary",
            get(authenticated_vulnerability_summary),
        )
        .route("/v1/vulnerabilities", get(authenticated_vulnerabilities))
        .route(
            "/v1/vulnerabilities/advisories/{advisory_id}",
            get(authenticated_vulnerability_advisory),
        )
        .route(
            "/v1/compliance/history/{observed_day}/{finding_id}",
            get(authenticated_finding_event),
        )
        .route(
            "/v1/audit-retention",
            get(authenticated_audit_retention).put(update_authenticated_audit_retention),
        )
        .route(
            "/v1/assistant-internet",
            get(crate::assistant_internet::get_assistant_internet)
                .put(crate::assistant_internet::update_assistant_internet),
        )
        .route(
            "/v1/assistant-internet/test",
            axum::routing::post(crate::assistant_internet::test_assistant_internet),
        )
        .route("/v1/audit-events", get(authenticated_audit_events))
        .route("/v1/audit-export.csv", get(authenticated_audit_export))
        .route("/v1/access-control", get(authenticated_access_inventory))
        .route(
            "/v1/enrollment-tokens",
            get(authenticated_enrollment_tokens).post(create_authenticated_enrollment_token),
        )
        .route(
            "/v1/enrollment-tokens/{token_id}",
            get(authenticated_enrollment_token),
        )
        .route(
            "/v1/enrollment-tokens/{token_id}/revoke",
            axum::routing::post(revoke_authenticated_enrollment_token),
        )
        .route(
            "/v1/service-accounts",
            get(authenticated_service_accounts).post(create_authenticated_service_account),
        )
        .route(
            "/v1/service-accounts/{service_account_id}/disable",
            axum::routing::post(disable_authenticated_service_account),
        )
        .route(
            "/v1/service-accounts/{service_account_id}/tokens",
            get(authenticated_service_tokens).post(create_authenticated_service_token),
        )
        .route(
            "/v1/service-accounts/{service_account_id}/tokens/{token_id}/revoke",
            axum::routing::post(revoke_authenticated_service_token),
        )
        .route("/v1/rule-sets", get(authenticated_rule_sets))
        .route(
            "/v1/rule-sets/{rule_set_id}/bundles",
            get(authenticated_rule_bundles),
        )
        .route(
            "/v1/rule-set-assignments",
            get(crate::rule_assignment::list_assignments),
        )
        .route(
            "/v1/rule-set-assignments/{rule_set_id}",
            axum::routing::put(crate::rule_assignment::set_default),
        )
        .route(
            "/v1/rule-set-assignments/{rule_set_id}/groups/{asset_group_id}",
            axum::routing::put(crate::rule_assignment::set_group)
                .delete(crate::rule_assignment::clear_group),
        )
        .route(
            "/v1/agents/{agent_id}/rule-set-assignments",
            get(crate::rule_assignment::host_assignments),
        )
        .route(
            "/v1/rule-bundles/preview",
            axum::routing::post(preview_authenticated_rule_bundle),
        )
        .route(
            "/v1/rule-bundles/publish",
            axum::routing::post(publish_authenticated_rule_bundle),
        )
        .route(
            "/v1/access-control/asset-groups",
            axum::routing::post(create_authenticated_asset_group),
        )
        .route(
            "/v1/access-control/asset-groups/{group_id}",
            axum::routing::put(update_authenticated_asset_group),
        )
        .route(
            "/v1/access-control/bindings",
            axum::routing::post(create_authenticated_access_binding),
        )
        .route(
            "/v1/access-control/users",
            axum::routing::post(crate::access::users::create_user),
        )
        .route(
            "/v1/access-control/bindings/{binding_id}",
            axum::routing::delete(revoke_authenticated_access_binding),
        )
        .route(
            "/v1/dashboards",
            get(crate::dashboards::list_dashboards).post(crate::dashboards::create_dashboard),
        )
        .route(
            "/v1/dashboards/{dashboard_id}",
            get(crate::dashboards::get_dashboard)
                .put(crate::dashboards::update_dashboard)
                .delete(crate::dashboards::delete_dashboard),
        )
        .route(
            "/v1/dashboards/{dashboard_id}/sharing",
            axum::routing::put(crate::dashboards::share_dashboard),
        )
        .route(
            "/v1/me/home",
            get(crate::dashboards::get_home).put(crate::dashboards::set_home),
        )
        .route(
            "/v1/agents/{agent_id}/packages",
            get(crate::hosts::software::list_host_packages),
        )
        .route("/v1/metrics/history", get(crate::metrics::history))
        .route("/v1/metrics/top-hosts", get(crate::metrics::top_hosts))
        .route("/v1/software", get(crate::hosts::software::list_software))
        .route(
            "/v1/software/{manager}/{name}",
            get(crate::hosts::software::get_software),
        )
        .route(
            "/v1/agents/{agent_id}/services",
            get(crate::hosts::ports::get_host_services),
        )
        .route("/v1/ports", get(crate::hosts::ports::list_ports))
        .route(
            "/v1/ports/{protocol}/{port}",
            get(crate::hosts::ports::get_port),
        )
        .route("/v1/services", get(crate::hosts::ports::list_services))
        .route("/v1/services/{unit}", get(crate::hosts::ports::get_unit))
        .route(
            "/v1/cases",
            get(crate::cases::list_cases).post(crate::cases::create_case),
        )
        .route("/v1/cases/for-item", get(crate::cases::cases_for_item))
        .route("/v1/cases/assignees", get(crate::cases::list_assignees))
        .route("/v1/cases/active-items", get(crate::cases::active_items))
        .route(
            "/v1/cases/{case_id}",
            get(crate::cases::get_case).put(crate::cases::update_case),
        )
        .route(
            "/v1/cases/{case_id}/notes",
            axum::routing::post(crate::cases::add_note),
        )
        .route(
            "/v1/cases/{case_id}/items",
            axum::routing::post(crate::cases::add_item),
        )
        .route(
            "/v1/cases/{case_id}/items/{item_id}",
            axum::routing::delete(crate::cases::remove_item),
        )
        .route(
            "/v1/cases/{case_id}/items/{item_id}/outcome",
            axum::routing::put(crate::cases::set_item_outcome),
        )
        .route("/v1/alarms", get(crate::alarms::list_alarms))
        .route("/v1/alarms/{alarm_id}", get(crate::alarms::get_alarm))
        .route(
            "/v1/alarms/{alarm_id}/triage",
            axum::routing::put(crate::alarms::update_alarm_triage),
        )
        .route(
            "/v1/alarm-suppressions",
            get(crate::alarm_suppressions::list_suppressions)
                .post(crate::alarm_suppressions::create_suppression),
        )
        .route(
            "/v1/alarm-suppressions/{suppression_id}",
            axum::routing::delete(crate::alarm_suppressions::remove_suppression),
        )
        .route(
            "/v1/triage-history",
            get(crate::triage_detail::triage_history),
        )
        .route(
            "/v1/alarms/bulk",
            axum::routing::post(crate::bulk::bulk_alarms),
        )
        .route(
            "/v1/compliance/bulk",
            axum::routing::post(crate::bulk::bulk_compliance),
        )
        .route(
            "/v1/vulnerabilities/bulk",
            axum::routing::post(crate::bulk::bulk_vulnerabilities),
        )
        .route(
            "/v1/vulnerabilities/advisories/{advisory_id}/hosts/{agent_id}/triage",
            axum::routing::put(crate::triage_detail::update_vulnerability_triage),
        )
        .route("/v1/rules/coverage", get(crate::coverage::rule_coverage))
        .route("/v1/attack", get(crate::coverage::attack_catalog))
        .route(
            "/v1/rule-drafts/{rule_set_id}",
            get(crate::rule_drafts::list_drafts),
        )
        .route(
            "/v1/rule-drafts/{rule_set_id}/{rule_id}",
            axum::routing::put(crate::rule_drafts::save_draft)
                .delete(crate::rule_drafts::delete_draft),
        )
        .route(
            "/v1/rule-drafts/{rule_set_id}/changes",
            get(crate::rule_drafts::draft_changes),
        )
        .route(
            "/v1/rule-drafts/{rule_set_id}/publish",
            axum::routing::post(crate::rule_drafts::publish_drafts),
        )
        .route(
            "/v1/rule-drafts/{rule_set_id}/{rule_id}/check",
            axum::routing::post(crate::rule_drafts::check_draft),
        )
        .route(
            "/v1/site-rules/fleet",
            axum::routing::get(crate::hosts::site_fleet::site_fleet),
        )
        .route(
            "/v1/rule-drafts/{rule_set_id}/{rule_id}/test",
            axum::routing::post(crate::rule_test::test_rule),
        )
        .method_not_allowed_fallback(api_method_not_allowed)
        .fallback(api_not_found)
}

pub(super) fn authenticated_auth_router() -> Router<AuthHttpState> {
    Router::new()
        .route("/v1/preauth", get(preauth))
        .route("/v1/login", axum::routing::post(login))
        .route("/v1/logout", axum::routing::post(logout))
        .fallback(auth_not_found)
}

async fn api_not_found() -> Response {
    problem_response(ProblemDetails::not_found(
        "api_not_found",
        "API resource not found",
    ))
}

async fn api_method_not_allowed() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        "Method not allowed for this API resource",
    ))
}

pub(super) async fn auth_not_found() -> Response {
    problem_response(ProblemDetails::not_found(
        "auth_not_found",
        "Authentication resource not found",
    ))
}
