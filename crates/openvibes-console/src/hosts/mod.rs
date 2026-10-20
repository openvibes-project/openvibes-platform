//! Hosts: the agent list, summary, detail and certificates, revoking an
//! agent, enrollment tokens, the agent install package and command, software,
//! ports and services, live presence, the site rule-set fleet, host groups
//! and host labels.

use axum::{
    Router,
    routing::{get, post, put},
};

use crate::http::AuthHttpState;

pub(crate) mod agent_package;
pub(crate) mod agents;
pub(crate) mod certificates;
pub(crate) mod enrollment;
mod group_checks;
pub mod group_words;
pub(crate) mod groups;
pub(crate) mod groups_types;
pub(crate) mod install;
pub(crate) mod labels;
pub(crate) mod list;
pub(crate) mod list_types;
pub(crate) mod ports;
pub(crate) mod presence;
pub(crate) mod site_fleet;
pub(crate) mod software;
mod software_types;
mod types;

pub use types::{
    AgentAlarmsView, AgentCommandView, AgentDetail, AgentPage, AgentRuleSetView, AgentStatus,
    AgentSummary, AgentView, CertificatePage, CertificateView, CreateEnrollmentTokenRequest,
    CreatedEnrollmentToken, EnrollmentTokenPage, EnrollmentTokenView, LastTest, RevokeAgentRequest,
};

/// Hosts and their certificates, enrollment tokens, the agent package and
/// install command, live presence, software, ports and services, and the
/// site rule-set fleet, host groups and host labels.
pub(crate) fn routes() -> Router<AuthHttpState> {
    Router::new()
        .route(
            "/v1/agent-package",
            get(install::authenticated_agent_package),
        )
        .route(
            "/v1/agent-command",
            get(install::authenticated_agent_command),
        )
        .route(
            "/v1/agents/summary",
            get(agents::authenticated_agent_summary),
        )
        .route("/v1/hosts", get(list::list_hosts))
        .route("/v1/agents/events", get(presence::agent_events))
        .route("/v1/agents", get(agents::authenticated_agents))
        .route(
            "/v1/agents/{agent_id}",
            get(agents::authenticated_agent_detail),
        )
        .route(
            "/v1/agents/{agent_id}/revoke",
            post(agents::revoke_authenticated_agent),
        )
        .route(
            "/v1/agents/{agent_id}/certificates",
            get(certificates::authenticated_agent_certificates),
        )
        .route(
            "/v1/enrollment-tokens",
            get(enrollment::authenticated_enrollment_tokens)
                .post(enrollment::create_authenticated_enrollment_token),
        )
        .route(
            "/v1/enrollment-tokens/{token_id}",
            get(enrollment::authenticated_enrollment_token),
        )
        .route(
            "/v1/enrollment-tokens/{token_id}/revoke",
            post(enrollment::revoke_authenticated_enrollment_token),
        )
        .route(
            "/v1/agents/{agent_id}/packages",
            get(software::list_host_packages),
        )
        .route("/v1/software", get(software::list_software))
        .route("/v1/software/{manager}/{name}", get(software::get_software))
        .route(
            "/v1/agents/{agent_id}/services",
            get(ports::get_host_services),
        )
        .route("/v1/ports", get(ports::list_ports))
        .route("/v1/ports/{protocol}/{port}", get(ports::get_port))
        .route("/v1/services", get(ports::list_services))
        .route("/v1/services/{unit}", get(ports::get_unit))
        .route("/v1/site-rules/fleet", get(site_fleet::site_fleet))
        .route(
            "/v1/host-groups",
            get(groups::list_groups).post(groups::create_group),
        )
        .route("/v1/host-groups/preview", post(groups::preview_new_group))
        .route(
            "/v1/host-groups/{group_id}",
            get(groups::get_group)
                .patch(groups::update_group)
                .delete(groups::delete_group),
        )
        .route("/v1/host-groups/{group_id}/hosts", get(groups::group_hosts))
        .route(
            "/v1/host-groups/{group_id}/preview",
            post(groups::preview_group),
        )
        .route("/v1/hosts/{agent_id}/labels", get(labels::host_labels))
        .route(
            "/v1/hosts/{agent_id}/labels/{label}",
            put(labels::add_label).delete(labels::remove_label),
        )
}
