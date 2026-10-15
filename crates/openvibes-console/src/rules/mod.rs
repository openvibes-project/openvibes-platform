//! Rules: rule sets and their signed bundles, which asset groups run each
//! set, the site's draft rules and their publishing, testing a rule on one
//! host, and ATT&CK coverage.

use axum::{
    Router,
    routing::{get, post, put},
};

use crate::http::AuthHttpState;

pub(crate) mod assignment;
mod bundle_types;
pub(crate) mod bundles;
pub(crate) mod coverage;
mod draft_check;
pub(crate) mod draft_publish;
mod draft_types;
pub(crate) mod drafts;
mod envelope;
pub(crate) mod test_on_host;

pub(crate) use draft_types::{
    DraftChanges, PublishDraftsRequest, PublishedDrafts, RuleCheck, RuleDraftInput, RuleDraftList,
    RuleDraftView, RuleProblem,
};

pub use bundle_types::{
    RuleBundlePage, RuleBundlePreview, RuleBundleView, RuleSetPage, RuleSetView,
    SignedRuleEnvelopeRequest,
};

/// Rule sets and bundles, rule-set assignment, ATT&CK coverage, draft rules
/// and their publishing, and testing a rule on one host.
pub(crate) fn routes() -> Router<AuthHttpState> {
    Router::new()
        .route("/v1/rule-sets", get(bundles::authenticated_rule_sets))
        .route(
            "/v1/rule-sets/{rule_set_id}/bundles",
            get(bundles::authenticated_rule_bundles),
        )
        .route(
            "/v1/rule-set-assignments",
            get(assignment::list_assignments),
        )
        .route(
            "/v1/rule-set-assignments/{rule_set_id}",
            put(assignment::set_default),
        )
        .route(
            "/v1/rule-set-assignments/{rule_set_id}/groups/{asset_group_id}",
            put(assignment::set_group).delete(assignment::clear_group),
        )
        .route(
            "/v1/agents/{agent_id}/rule-set-assignments",
            get(assignment::host_assignments),
        )
        .route(
            "/v1/rule-bundles/preview",
            post(bundles::preview_authenticated_rule_bundle),
        )
        .route(
            "/v1/rule-bundles/publish",
            post(bundles::publish_authenticated_rule_bundle),
        )
        .route("/v1/rules/coverage", get(coverage::rule_coverage))
        .route("/v1/attack", get(coverage::attack_catalog))
        .route("/v1/rule-drafts/{rule_set_id}", get(drafts::list_drafts))
        .route(
            "/v1/rule-drafts/{rule_set_id}/{rule_id}",
            put(drafts::save_draft).delete(drafts::delete_draft),
        )
        .route(
            "/v1/rule-drafts/{rule_set_id}/changes",
            get(draft_publish::draft_changes),
        )
        .route(
            "/v1/rule-drafts/{rule_set_id}/publish",
            post(draft_publish::publish_drafts),
        )
        .route(
            "/v1/rule-drafts/{rule_set_id}/{rule_id}/check",
            post(drafts::check_draft),
        )
        .route(
            "/v1/rule-drafts/{rule_set_id}/{rule_id}/test",
            post(test_on_host::test_rule),
        )
}
