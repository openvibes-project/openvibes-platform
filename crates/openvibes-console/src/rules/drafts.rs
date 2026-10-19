//! Draft rules for the site's own rule sets over `/api/v1`. Listing needs
//! `site_rules.read`; checking, saving and deleting `site_rules.write`.
//! Publishing is separate (`site_rules.publish`). A draft never reaches
//! an agent: only a signed, published set does.
//!
//! Every draft is checked with the agent's own loader code before it is
//! saved, so a saved draft is one the agent would accept; the console
//! applies the same restricted-set `programs` caps the agent and the rule
//! signer enforce.

use axum::{
    Json,
    extract::{Path, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::{SecondsFormat, Utc};
use openvibes_core::Rule;
use platform_store::rule_drafts::{self as store, Draft};
use serde_json::Value;

use super::draft_check::{check, known_set, other_programs, rule_json};
use super::draft_types::{RuleCheck, RuleDraftInput, RuleDraftList, RuleDraftView};
use crate::{
    Permission, ProblemDetails,
    access::guard::{authenticated_permission, unavailable_auth},
    http::AuthHttpState,
    http::problem::problem_response,
};

/// Most drafts one set keeps.
const MAX_DRAFTS: usize = 512;

fn view(draft: Draft) -> Option<RuleDraftView> {
    let rule: Rule = serde_json::from_value(draft.rule).ok()?;
    let severity = serde_json::to_value(rule.severity)
        .ok()?
        .as_str()?
        .to_owned();
    Some(RuleDraftView {
        rule_set_id: draft.rule_set_id,
        rule_id: draft.rule_id,
        version: rule.version,
        title: rule.title,
        severity,
        confidence: rule.confidence.value(),
        expression: rule.expression,
        finding_message: rule.finding_message,
        attack: super::coverage::pair_views(rule.attack.as_deref()),
        programs: rule.programs,
        updated_by: draft.updated_by,
        updated_at: draft
            .updated_at
            .to_rfc3339_opts(SecondsFormat::Millis, true),
    })
}

pub(super) fn unknown_set() -> Response {
    problem_response(ProblemDetails::not_found(
        "rule_set_not_found",
        "Only the site's own rule sets, site and site-alarms, have drafts",
    ))
}

pub(super) fn global_only() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::FORBIDDEN,
        "permission_denied",
        "Access is not available",
    ))
}

#[utoipa::path(get, path = "/api/v1/rule-drafts/{rule_set_id}", tag = "rules", params(("rule_set_id" = String, Path)),
    responses((status = 200, description = "The set's draft rules", body = crate::rules::RuleDraftList),
        (status = 404, description = "Not a site rule set", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn list_drafts(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(rule_set_id): Path<String>,
) -> Response {
    let (scope, _) =
        match authenticated_permission(&state, &headers, Permission::SiteRulesRead, false).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    if !matches!(scope, platform_store::console_read::AgentScope::Global) {
        return global_only();
    }
    if !known_set(&rule_set_id) {
        return unknown_set();
    }
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::list(&client, &rule_set_id).await {
        Ok(drafts) => Json(RuleDraftList {
            items: drafts.into_iter().filter_map(view).collect(),
        })
        .into_response(),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(post, path = "/api/v1/rule-drafts/{rule_set_id}/{rule_id}/check", tag = "rules",
    params(("rule_set_id" = String, Path), ("rule_id" = String, Path)),
    request_body = crate::rules::RuleDraftInput,
    responses((status = 200, description = "Whether the agent would accept the rule, and why not", body = crate::rules::RuleCheck),
        (status = 404, description = "Not a site rule set", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn check_draft(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((rule_set_id, rule_id)): Path<(String, String)>,
    payload: Result<Json<RuleDraftInput>, JsonRejection>,
) -> Response {
    let (scope, _) =
        match authenticated_permission(&state, &headers, Permission::SiteRulesWrite, true).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    if !matches!(scope, platform_store::console_read::AgentScope::Global) {
        return global_only();
    }
    if !known_set(&rule_set_id) {
        return unknown_set();
    }
    let Ok(Json(input)) = payload else {
        return invalid_body();
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let Ok(drafts) = store::list(&client, &rule_set_id).await else {
        return unavailable_auth();
    };
    let problems = check(
        &rule_set_id,
        &rule_id,
        &input,
        &other_programs(&drafts, &rule_id),
    );
    Json(RuleCheck {
        ok: problems.is_empty(),
        problems,
    })
    .into_response()
}

fn invalid_body() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::BAD_REQUEST,
        "invalid_rule",
        "The request is not a rule: title, severity, confidence, expression, finding_message and, for alarms, programs",
    ))
}

#[utoipa::path(put, path = "/api/v1/rule-drafts/{rule_set_id}/{rule_id}", tag = "rules",
    params(("rule_set_id" = String, Path), ("rule_id" = String, Path)),
    request_body = crate::rules::RuleDraftInput,
    responses((status = 200, description = "Saved", body = crate::rules::RuleDraftView),
        (status = 404, description = "Not a site rule set", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The agent would refuse the rule", body = crate::rules::RuleCheck)))]
pub(crate) async fn save_draft(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((rule_set_id, rule_id)): Path<(String, String)>,
    payload: Result<Json<RuleDraftInput>, JsonRejection>,
) -> Response {
    let (scope, actor) =
        match authenticated_permission(&state, &headers, Permission::SiteRulesWrite, true).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    if !matches!(scope, platform_store::console_read::AgentScope::Global) {
        return global_only();
    }
    if !known_set(&rule_set_id) {
        return unknown_set();
    }
    let Ok(Json(input)) = payload else {
        return invalid_body();
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let Ok(drafts) = store::list(&client, &rule_set_id).await else {
        return unavailable_auth();
    };
    let problems = check(
        &rule_set_id,
        &rule_id,
        &input,
        &other_programs(&drafts, &rule_id),
    );
    if !problems.is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(RuleCheck {
                ok: false,
                problems,
            }),
        )
            .into_response();
    }
    let earlier = drafts.iter().find(|draft| draft.rule_id == rule_id);
    if earlier.is_none() && drafts.len() >= MAX_DRAFTS {
        return problem_response(ProblemDetails::new(
            StatusCode::CONFLICT,
            "too_many_rules",
            "A rule set keeps at most 512 rules",
        ));
    }
    let version = next_version(&rule_set_id, &rule_id, &input, earlier);
    let rule = rule_json(&rule_set_id, &rule_id, version, &input);
    let saved = match store::put(&client, &rule_set_id, &rule_id, &rule, &actor, Utc::now()).await {
        Ok(saved) => saved,
        Err(_) => return unavailable_auth(),
    };
    if platform_store::audit::record(
        &client,
        &actor,
        "rule_draft.saved",
        Some(&format!("{rule_set_id}/{rule_id} v{version}")),
        "success",
    )
    .await
    .is_err()
    {
        return unavailable_auth();
    }
    match view(saved) {
        Some(saved) => Json(saved).into_response(),
        None => unavailable_auth(),
    }
}

/// 1 for a new rule; the earlier version when nothing changed; else one more.
fn next_version(
    rule_set_id: &str,
    rule_id: &str,
    input: &RuleDraftInput,
    earlier: Option<&Draft>,
) -> u64 {
    let Some(earlier) = earlier else {
        return 1;
    };
    let before = earlier
        .rule
        .get("version")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if rule_json(rule_set_id, rule_id, before, input) == earlier.rule {
        before
    } else {
        before + 1
    }
}

#[utoipa::path(delete, path = "/api/v1/rule-drafts/{rule_set_id}/{rule_id}", tag = "rules",
    params(("rule_set_id" = String, Path), ("rule_id" = String, Path)),
    responses((status = 204, description = "Deleted"),
        (status = 404, description = "No such draft", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn delete_draft(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((rule_set_id, rule_id)): Path<(String, String)>,
) -> Response {
    let (scope, actor) =
        match authenticated_permission(&state, &headers, Permission::SiteRulesWrite, true).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    if !matches!(scope, platform_store::console_read::AgentScope::Global) {
        return global_only();
    }
    if !known_set(&rule_set_id) {
        return unknown_set();
    }
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::delete(&client, &rule_set_id, &rule_id).await {
        Ok(true) => {
            if platform_store::audit::record(
                &client,
                &actor,
                "rule_draft.deleted",
                Some(&format!("{rule_set_id}/{rule_id}")),
                "success",
            )
            .await
            .is_err()
            {
                return unavailable_auth();
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => problem_response(ProblemDetails::not_found(
            "draft_not_found",
            "No such draft",
        )),
        Err(_) => unavailable_auth(),
    }
}
