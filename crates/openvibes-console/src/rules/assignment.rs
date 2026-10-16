//! `/api/v1/rule-set-assignments`: the per-group switches of the project's
//! assignable rule sets (spec 2026-10-14). Reading needs
//! `rules.assignment.read`, changing `rules.assignment.write`, both global
//! (`rules_reader` also serves the rule-set list, bundle history, coverage
//! and ATT&CK catalog with their own permission); one host's state needs
//! `hosts.read` within the caller's scope.

use axum::{
    Json,
    extract::{Path, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use platform_store::{console_read::AgentScope, rule_assignment as store};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    Permission, ProblemDetails,
    access::guard::{authenticated_permission, unavailable_auth},
    http::AuthHttpState,
    http::headers::no_store,
    http::problem::problem_response,
};

/// One asset group's override.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct RuleSetGroupOverrideView {
    /// The group.
    pub asset_group_id: String,
    /// Its name.
    pub name: String,
    /// On or off for its hosts.
    pub enabled: bool,
}

/// One assignable rule set.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct RuleSetAssignmentView {
    /// Rule set id.
    pub rule_set_id: String,
    /// On or off for hosts no override covers.
    pub default_enabled: bool,
    /// False until a live bundle is published ("not available yet").
    pub published: bool,
    /// Linux hosts that run it now (an active agent that reported
    /// os-release).
    pub hosts_on: i64,
    /// Linux hosts that do not.
    pub hosts_off: i64,
    /// Overrides, by group name.
    pub groups: Vec<RuleSetGroupOverrideView>,
}

/// An asset group an override can name.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct AssignableGroupView {
    /// The group.
    pub asset_group_id: String,
    /// Its name.
    pub name: String,
    /// Its selectors, `key=value`.
    pub selectors: Vec<String>,
    /// Linux hosts it matches.
    pub hosts: i64,
}

/// Every assignable set, and the groups an override can name.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct RuleSetAssignmentsView {
    /// The sets.
    pub items: Vec<RuleSetAssignmentView>,
    /// Every asset group, by name.
    pub asset_groups: Vec<AssignableGroupView>,
}

/// A set's new default.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SetRuleSetDefaultRequest {
    /// On or off for hosts no override covers.
    pub default_enabled: bool,
}

/// A group's override.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SetRuleSetGroupRequest {
    /// On or off for the group's hosts.
    pub enabled: bool,
}

/// One assignable set's state on a host, as the platform decides it.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct HostRuleSetAssignmentView {
    /// Rule set id.
    pub rule_set_id: String,
    /// Whether the host runs it.
    pub enabled: bool,
    /// `default` or `group`.
    pub source: String,
    /// The group that decided it (the first by name when several agree);
    /// null when the default did.
    pub group: Option<String>,
    /// False until a live bundle is published ("waits until published").
    pub published: bool,
}

/// Every assignable set's state on one host.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct HostRuleSetAssignmentsView {
    /// The sets, by id.
    pub items: Vec<HostRuleSetAssignmentView>,
    /// The hardening collector's outcome in the host's latest health report:
    /// `ok`, or an error code such as `not_found` (the root-facts helper's
    /// file is stale or malformed); null without one.
    pub hardening_facts: Option<String>,
    /// RFC 3339 time of the last stored report whose hardening outcome was
    /// `ok`; null when none was since enrollment.
    pub hardening_facts_ok_at: Option<String>,
}

fn forbidden() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::FORBIDDEN,
        "permission_denied",
        "Access is not available",
    ))
}

fn view(assignment: store::Assignment) -> RuleSetAssignmentView {
    RuleSetAssignmentView {
        rule_set_id: assignment.rule_set_id,
        default_enabled: assignment.default_enabled,
        published: assignment.published,
        hosts_on: assignment.hosts_on,
        hosts_off: assignment.hosts_off,
        groups: assignment
            .groups
            .into_iter()
            .map(|g| RuleSetGroupOverrideView {
                asset_group_id: g.asset_group_id,
                name: g.name,
                enabled: g.enabled,
            })
            .collect(),
    }
}

/// The caller's user id when they may change switches.
async fn writer(state: &AuthHttpState, headers: &HeaderMap) -> Result<String, Response> {
    match authenticated_permission(state, headers, Permission::RulesAssignmentWrite, true).await {
        Ok((AgentScope::Global, actor)) => Ok(actor),
        Ok(_) => Err(forbidden()),
        Err(response) => Err(response),
    }
}

/// The caller's user id when they hold `permission` globally: one of the
/// rule-set views (`rules.read`, `rules.assignment.read`,
/// `rules.coverage.read`), all platform-wide.
pub(super) async fn rules_reader(
    state: &AuthHttpState,
    headers: &HeaderMap,
    permission: Permission,
) -> Result<String, Response> {
    match authenticated_permission(state, headers, permission, false).await {
        Ok((AgentScope::Global, actor)) => Ok(actor),
        Ok(_) => Err(forbidden()),
        Err(response) => Err(response),
    }
}

fn change_response(result: Result<store::Change, platform_store::StoreError>) -> Response {
    match result {
        Ok(store::Change::Done(assignment)) => no_store(Json(view(assignment)).into_response()),
        Ok(store::Change::UnknownSet) => problem_response(ProblemDetails::not_found(
            "rule_set_not_assignable",
            "Rule set is not assignable",
        )),
        Ok(store::Change::UnknownGroup) => problem_response(ProblemDetails::not_found(
            "asset_group_not_found",
            "Asset group not found",
        )),
        Err(_) => unavailable_auth(),
    }
}

fn invalid() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "The request body is not valid",
    ))
}

#[utoipa::path(get, path = "/api/v1/rule-set-assignments", tag = "rules",
    responses(
        (status = 200, description = "Assignable rule sets and asset groups", body = RuleSetAssignmentsView),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "No global rules.assignment.read", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn list_assignments(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = rules_reader(&state, &headers, Permission::RulesAssignmentRead).await {
        return response;
    }
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::overview(&client).await {
        Ok(overview) => no_store(
            Json(RuleSetAssignmentsView {
                items: overview.sets.into_iter().map(view).collect(),
                asset_groups: overview
                    .groups
                    .into_iter()
                    .map(|g| AssignableGroupView {
                        asset_group_id: g.asset_group_id,
                        name: g.name,
                        selectors: g.selectors,
                        hosts: g.hosts,
                    })
                    .collect(),
            })
            .into_response(),
        ),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(put, path = "/api/v1/rule-set-assignments/{rule_set_id}", tag = "rules",
    params(("rule_set_id" = String, Path),
        ("Origin" = String, Header, description = "Must exactly match configured origin"),
        ("X-CSRF-Token" = String, Header, description = "Session synchronizer token")),
    request_body = SetRuleSetDefaultRequest,
    responses(
        (status = 200, description = "The set after the change", body = RuleSetAssignmentView),
        (status = 400, description = "Invalid body", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Origin, CSRF, or permission check failed", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "Not an assignable set", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Update unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn set_default(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(rule_set_id): Path<String>,
    payload: Result<Json<SetRuleSetDefaultRequest>, JsonRejection>,
) -> Response {
    let actor = match writer(&state, &headers).await {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    let Ok(Json(request)) = payload else {
        return invalid();
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    change_response(
        store::set_default(&mut client, &actor, &rule_set_id, request.default_enabled).await,
    )
}

#[utoipa::path(put, path = "/api/v1/rule-set-assignments/{rule_set_id}/groups/{asset_group_id}", tag = "rules",
    params(("rule_set_id" = String, Path), ("asset_group_id" = String, Path),
        ("Origin" = String, Header, description = "Must exactly match configured origin"),
        ("X-CSRF-Token" = String, Header, description = "Session synchronizer token")),
    request_body = SetRuleSetGroupRequest,
    responses(
        (status = 200, description = "The set after the change", body = RuleSetAssignmentView),
        (status = 400, description = "Invalid body", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Origin, CSRF, or permission check failed", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "Not an assignable set, or no such group", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Update unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn set_group(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((rule_set_id, asset_group_id)): Path<(String, String)>,
    payload: Result<Json<SetRuleSetGroupRequest>, JsonRejection>,
) -> Response {
    let actor = match writer(&state, &headers).await {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    let Ok(Json(request)) = payload else {
        return invalid();
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    change_response(
        store::set_group(
            &mut client,
            &actor,
            &rule_set_id,
            &asset_group_id,
            Some(request.enabled),
        )
        .await,
    )
}

#[utoipa::path(delete, path = "/api/v1/rule-set-assignments/{rule_set_id}/groups/{asset_group_id}", tag = "rules",
    params(("rule_set_id" = String, Path), ("asset_group_id" = String, Path),
        ("Origin" = String, Header, description = "Must exactly match configured origin"),
        ("X-CSRF-Token" = String, Header, description = "Session synchronizer token")),
    responses(
        (status = 200, description = "The set without that override (also when it had none)", body = RuleSetAssignmentView),
        (status = 403, description = "Origin, CSRF, or permission check failed", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "Not an assignable set, or no such group", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Update unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn clear_group(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((rule_set_id, asset_group_id)): Path<(String, String)>,
) -> Response {
    let actor = match writer(&state, &headers).await {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    change_response(
        store::set_group(&mut client, &actor, &rule_set_id, &asset_group_id, None).await,
    )
}

#[utoipa::path(get, path = "/api/v1/agents/{agent_id}/rule-set-assignments", tag = "agents",
    params(("agent_id" = String, Path)),
    responses(
        (status = 200, description = "Each assignable set's state on the host", body = HostRuleSetAssignmentsView),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "Agent not found", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn host_assignments(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
) -> Response {
    let (scope, _) =
        match authenticated_permission(&state, &headers, Permission::HostsRead, false).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let sets = match store::for_agent(&client, &scope, &agent_id).await {
        Ok(Some(sets)) => sets,
        Ok(None) => {
            return problem_response(ProblemDetails::not_found(
                "agent_not_found",
                "Agent not found",
            ));
        }
        Err(_) => return unavailable_auth(),
    };
    let Ok((hardening_facts, ok_at)) = store::hardening_facts(&client, &agent_id).await else {
        return unavailable_auth();
    };
    no_store(
        Json(HostRuleSetAssignmentsView {
            items: sets
                .into_iter()
                .map(|set| HostRuleSetAssignmentView {
                    rule_set_id: set.rule_set_id,
                    enabled: set.enabled,
                    source: match set.source {
                        store::Source::Default => "default",
                        store::Source::Group => "group",
                    }
                    .to_owned(),
                    group: set.group,
                    published: set.published,
                })
                .collect(),
            hardening_facts,
            hardening_facts_ok_at: ok_at
                .map(|at| at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
        })
        .into_response(),
    )
}
