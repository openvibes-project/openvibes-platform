use axum::{
    extract::{Json, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

use super::envelope::{digest_hex, verify_console_rule_envelope};
use crate::{
    access::guard::{authenticated_permission, unavailable_auth},
    http::headers::no_store,
    http::{
        AuthHttpState,
        problem::{ProblemDetails, problem_response},
    },
};

/// Lists rule sets and safe current-version metadata.
#[utoipa::path(get,path="/api/v1/rule-sets",tag="rules",responses((status=200,description="Rule-set summaries",body=crate::RuleSetPage)))]
pub(crate) async fn authenticated_rule_sets(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    let actor =
        match super::assignment::rules_reader(&state, &headers, crate::Permission::RulesRead).await
        {
            Ok(actor) => actor,
            Err(response) => return response,
        };
    let client = match state.pool.get().await {
        Ok(value) => value,
        Err(_) => return unavailable_auth(),
    };
    let sets = match platform_store::rules::list(&client).await {
        Ok(value) => value,
        Err(_) => return unavailable_auth(),
    };
    if platform_store::audit::record(
        &client,
        &actor,
        "rule_sets.viewed",
        Some("rule_sets"),
        "success",
    )
    .await
    .is_err()
    {
        return unavailable_auth();
    }
    no_store(
        Json(crate::RuleSetPage {
            items: sets
                .into_iter()
                .map(|set| crate::RuleSetView {
                    rule_set_id: set.rule_set_id,
                    current_version: set.current_version,
                    current_expires_at_ms: set.current_expires_at_ms,
                    current_issuer_key_id: set.current_issuer_key_id,
                    current_signer_removed: set.current_signer_removed,
                    trusted_keys: set.trusted_keys,
                    retired: set.retired_at.is_some(),
                })
                .collect(),
        })
        .into_response(),
    )
}

/// Lists a rule set's published bundle metadata.
#[utoipa::path(get,path="/api/v1/rule-sets/{rule_set_id}/bundles",tag="rules",params(("rule_set_id"=String,Path)),responses((status=200,description="Bundle history",body=crate::RuleBundlePage),(status=404,description="Rule set not found",body=ProblemDetails)))]
pub(crate) async fn authenticated_rule_bundles(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(rule_set_id): Path<String>,
) -> Response {
    use chrono::SecondsFormat;
    let actor =
        match super::assignment::rules_reader(&state, &headers, crate::Permission::RulesRead).await
        {
            Ok(actor) => actor,
            Err(response) => return response,
        };
    let client = match state.pool.get().await {
        Ok(value) => value,
        Err(_) => return unavailable_auth(),
    };
    let sets = match platform_store::rules::list(&client).await {
        Ok(value) => value,
        Err(_) => return unavailable_auth(),
    };
    if !sets.iter().any(|set| set.rule_set_id == rule_set_id) {
        return problem_response(ProblemDetails::new(
            StatusCode::NOT_FOUND,
            "rule_set_not_found",
            "Rule set not found",
        ));
    }
    let bundles = match platform_store::rules::bundles(&client, &rule_set_id).await {
        Ok(value) => value,
        Err(_) => return unavailable_auth(),
    };
    if platform_store::audit::record(
        &client,
        &actor,
        "rule_bundles.viewed",
        Some(&rule_set_id),
        "success",
    )
    .await
    .is_err()
    {
        return unavailable_auth();
    }
    no_store(
        Json(crate::RuleBundlePage {
            items: bundles
                .into_iter()
                .map(|bundle| crate::RuleBundleView {
                    version: bundle.version,
                    envelope_sha256: digest_hex(&bundle.envelope_sha256),
                    issuer_key_id: bundle.issuer_key_id,
                    created_at_ms: bundle.created_at_ms,
                    expires_at_ms: bundle.expires_at_ms,
                    published_at: bundle
                        .published_at
                        .to_rfc3339_opts(SecondsFormat::Millis, true),
                    published_by: bundle.published_by,
                    bytes: bundle.bytes,
                })
                .collect(),
        })
        .into_response(),
    )
}

/// Verifies an uploaded signed bundle and returns an exact-bytes confirmation token.
#[utoipa::path(post,path="/api/v1/rule-bundles/preview",tag="rules",request_body=crate::SignedRuleEnvelopeRequest,responses((status=200,description="Verified bundle preview",body=crate::RuleBundlePreview),(status=422,description="Envelope signature or trust validation failed",body=ProblemDetails)))]
pub(crate) async fn preview_authenticated_rule_bundle(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let (scope, actor) =
        match authenticated_permission(&state, &headers, crate::Permission::RulesPublish, false)
            .await
        {
            Ok(value) => value,
            Err(response) => return response,
        };
    if !matches!(scope, platform_store::console_read::AgentScope::Global) {
        return problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "Access is not available",
        ));
    }
    let client = match state.pool.get().await {
        Ok(value) => value,
        Err(_) => return unavailable_auth(),
    };
    let (envelope, hash) = match verify_console_rule_envelope(&client, &body).await {
        Ok(value) => value,
        Err(()) => {
            return problem_response(ProblemDetails::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_signed_envelope",
                "The envelope is invalid, expired, or not signed by a currently trusted key",
            ));
        }
    };
    let set = envelope.rule_set_id.as_str().to_owned();
    let version = match i64::try_from(envelope.rule_set_version) {
        Ok(value) => value,
        Err(_) => {
            return problem_response(ProblemDetails::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_signed_envelope",
                "The envelope version is out of range",
            ));
        }
    };
    let current_version = match platform_store::rules::list(&client).await {
        Ok(sets) => sets
            .into_iter()
            .find(|row| row.rule_set_id == set)
            .and_then(|row| row.current_version),
        Err(_) => return unavailable_auth(),
    };
    let preview_token = digest_hex(&hash);
    if platform_store::audit::record(
        &client,
        &actor,
        "rule_bundle.previewed",
        Some(&format!("{set} v{}", envelope.rule_set_version)),
        "success",
    )
    .await
    .is_err()
    {
        return unavailable_auth();
    }
    no_store(
        Json(crate::RuleBundlePreview {
            rule_set_id: set,
            version,
            issuer_key_id: envelope.issuer_key_id.as_str().to_owned(),
            expires_at_ms: envelope.expires_at_unix_ms,
            envelope_sha256: preview_token.clone(),
            preview_token,
            current_version,
        })
        .into_response(),
    )
}

/// Re-verifies a previewed envelope before publishing its exact signed bytes.
#[utoipa::path(post,path="/api/v1/rule-bundles/publish",tag="rules",params(("X-Rule-Preview-Token"=String,Header,description="SHA-256 confirmation token returned by preview")),request_body=crate::SignedRuleEnvelopeRequest,responses((status=201,description="Bundle stored"),(status=204,description="Identical bundle already stored"),(status=409,description="Stale version, retired set, or issuer no longer trusted",body=ProblemDetails)))]
pub(crate) async fn publish_authenticated_rule_bundle(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let (scope, actor) =
        match authenticated_permission(&state, &headers, crate::Permission::RulesPublish, true)
            .await
        {
            Ok(value) => value,
            Err(response) => return response,
        };
    if !matches!(scope, platform_store::console_read::AgentScope::Global) {
        return problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "Access is not available",
        ));
    }
    let Some(preview) = headers
        .get("x-rule-preview-token")
        .and_then(|value| value.to_str().ok())
    else {
        return problem_response(ProblemDetails::new(
            StatusCode::BAD_REQUEST,
            "preview_token_required",
            "Confirm the exact signed bytes returned by preview",
        ));
    };
    let mut client = match state.pool.get().await {
        Ok(value) => value,
        Err(_) => return unavailable_auth(),
    };
    let (envelope, hash) = match verify_console_rule_envelope(&client, &body).await {
        Ok(value) => value,
        Err(()) => {
            return problem_response(ProblemDetails::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_signed_envelope",
                "The envelope is invalid, expired, or not signed by a currently trusted key",
            ));
        }
    };
    let expected = digest_hex(&hash);
    if preview != expected {
        return problem_response(ProblemDetails::new(
            StatusCode::CONFLICT,
            "stale_preview",
            "The uploaded bytes differ from the verified preview",
        ));
    }
    let set = envelope.rule_set_id.as_str().to_owned();
    let version = match i64::try_from(envelope.rule_set_version) {
        Ok(value) => value,
        Err(_) => {
            return problem_response(ProblemDetails::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_signed_envelope",
                "The envelope version is out of range",
            ));
        }
    };
    let bundle = platform_store::rules::NewBundle {
        rule_set_id: &set,
        version,
        envelope: &body,
        envelope_sha256: hash,
        issuer_key_id: envelope.issuer_key_id.as_str(),
        created_at_ms: envelope.created_at_unix_ms,
        expires_at_ms: envelope.expires_at_unix_ms,
        published_by: &actor,
    };
    let published =
        match platform_store::rules::publish_and_audit(&mut client, &bundle, &actor).await {
            Ok(value) => value,
            Err(_) => return unavailable_auth(),
        };
    let status = match published {
        platform_store::rules::Published::Stored => StatusCode::CREATED,
        platform_store::rules::Published::Unchanged => StatusCode::NO_CONTENT,
        _ => {
            return problem_response(ProblemDetails::new(
                StatusCode::CONFLICT,
                "rule_bundle_conflict",
                "The version, set lifecycle, or signer changed after preview",
            ));
        }
    };
    super::meta::index_published(&client, &set, version).await;
    no_store(status.into_response())
}
