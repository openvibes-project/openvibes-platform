use std::sync::Arc;

use axum::{
    extract::{Json, Path, Query, State, rejection::QueryRejection},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::{Duration, SecondsFormat, Utc};
use serde::Deserialize;

use crate::{
    access::guard::{authenticated_agent_scope, authenticated_permission, unavailable_auth},
    http::{
        AuthHttpState,
        middleware::assistant_answer_timeout,
        problem::{ProblemDetails, next_request_id, problem_response},
    },
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LatestFindingListParams {
    severity: Option<String>,
    /// One host's findings only.
    agent_id: Option<String>,
    cursor: Option<String>,
    limit: Option<u16>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VulnerabilityListParams {
    host: Option<String>,
    advisory: Option<String>,
    severity: Option<String>,
    cve: Option<String>,
    fixed: Option<bool>,
    exploited: Option<bool>,
    reboot_needed: Option<bool>,
    min_confidence: Option<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FindingGroupsParams {
    since: Option<String>,
    cursor: Option<String>,
    limit: Option<u16>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FindingGroupEndpointsParams {
    since: Option<String>,
    include_older: Option<bool>,
    cursor: Option<String>,
    limit: Option<u16>,
}

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct FindingGroupCursorToken {
    since: String,
    scope: platform_store::console_read::AgentScope,
    last_observed_at: String,
    rule_set_id: String,
    rule_id: String,
}

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct FindingGroupEndpointCursorToken {
    since: String,
    include_older: bool,
    scope: platform_store::console_read::AgentScope,
    rule_set_id: String,
    rule_id: String,
    last_observed_at: String,
    agent_id: String,
}

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct LatestFindingCursorToken {
    severity: Option<String>,
    scope: platform_store::console_read::AgentScope,
    last_observed_at: String,
    agent_id: String,
    rule_set_id: String,
    rule_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FindingHistoryListParams {
    since: String,
    agent_id: Option<String>,
    rule_set_id: Option<String>,
    rule_id: Option<String>,
    cursor: Option<String>,
    limit: Option<u16>,
}

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct FindingHistoryCursorToken {
    since: String,
    agent_id: Option<String>,
    rule_set_id: Option<String>,
    rule_id: Option<String>,
    scope: platform_store::console_read::AgentScope,
    observed_at: String,
    observed_day: String,
    finding_id: String,
}

pub(crate) fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Shared signature verifier for exact signed-envelope request bytes.
pub(crate) async fn verify_console_rule_envelope(
    client: &platform_store::Client,
    bytes: &[u8],
) -> Result<(openvibes_core::SignedRuleEnvelope, [u8; 32]), ()> {
    use openvibes_core::{Identifier, ResourceLimits, SignedRuleEnvelope};
    use openvibes_rules::{RuleLoader, TrustedRuleKey};
    use ring::digest;
    if bytes.is_empty() || bytes.len() > 1_048_576 {
        return Err(());
    }
    let envelope: SignedRuleEnvelope = serde_json::from_slice(bytes).map_err(|_| ())?;
    let set = envelope.rule_set_id.as_str();
    let trusted = platform_store::rules::active_trust_keys(client, set)
        .await
        .map_err(|_| ())?
        .into_iter()
        .map(|(key, issuer)| {
            let issuer = Identifier::new(&issuer).map_err(|_| ())?;
            TrustedRuleKey::new(envelope.rule_set_id.clone(), issuer, key).map_err(|_| ())
        })
        .collect::<Result<Vec<_>, ()>>()?;
    let loader = RuleLoader::new(trusted, ResourceLimits::V1).map_err(|_| ())?;
    loader
        .load_json(
            bytes,
            openvibes_rules::LoadContext {
                expected_rule_set_id: &envelope.rule_set_id,
                now_unix_ms: Utc::now().timestamp_millis(),
                last_accepted: None,
            },
        )
        .map_err(|_| ())?;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(digest::digest(&digest::SHA256, bytes).as_ref());
    Ok((envelope, hash))
}

fn digest_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Lists rule sets and safe current-version metadata.
#[utoipa::path(get,path="/api/v1/rule-sets",tag="rules",responses((status=200,description="Rule-set summaries",body=crate::RuleSetPage)))]
pub(crate) async fn authenticated_rule_sets(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    let actor = match crate::rule_assignment::rules_reader(&state, &headers).await {
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
    let actor = match crate::rule_assignment::rules_reader(&state, &headers).await {
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
        match authenticated_permission(&state, &headers, crate::Permission::RulesUpload, false)
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
    let (scope, actor) = match authenticated_permission(
        &state,
        &headers,
        crate::Permission::RulesUpload,
        true,
    )
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
    no_store(status.into_response())
}

pub(crate) fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

pub(crate) fn valid_agent_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

#[utoipa::path(get, path="/api/v1/assistant/status", tag="assistant", responses((status=200,description="Local assistant status",body=crate::assistant::AssistantStatusResponse),(status=404,description="Assistant is disabled",body=ProblemDetails)))]
pub(crate) async fn authenticated_assistant_status(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    let Some(runtime) = state.assistant.as_ref() else {
        return problem_response(ProblemDetails::not_found(
            "assistant_disabled",
            "Assistant is disabled",
        ));
    };
    if let Err(response) =
        authenticated_permission(&state, &headers, crate::Permission::AssistantUse, false).await
    {
        return response;
    }
    let backend = runtime
        .assistant
        .backend
        .as_ref()
        .expect("enabled assistant has a backend");
    let location = match backend.location {
        platform_assistant::Location::Local => "local",
        platform_assistant::Location::OwnNetwork => "own_network",
        platform_assistant::Location::External => "external",
    };
    let body = crate::assistant::AssistantStatusResponse {
        available: *runtime.available.read().await,
        location,
        model: backend.model.clone(),
    };
    let mut response = (StatusCode::OK, Json(body)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[utoipa::path(post, path="/api/v1/assistant/messages", tag="assistant", request_body=crate::assistant::AssistantMessageRequest, responses((status=200,description="Answer with verified citations",body=crate::assistant::AssistantMessageResponse),(status=403,description="Permission denied",body=ProblemDetails),(status=503,description="Local model is unavailable",body=ProblemDetails)))]
pub(crate) async fn authenticated_assistant_message(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Json(request): Json<crate::assistant::AssistantMessageRequest>,
) -> Response {
    use platform_assistant::{Settings, Turn};
    use platform_store::console_read::AgentScope as ConsoleScope;
    use std::time::Instant;

    let Some(runtime) = state.assistant.as_ref() else {
        return problem_response(ProblemDetails::not_found(
            "assistant_disabled",
            "Assistant is disabled",
        ));
    };
    let (assistant_scope, actor) =
        match authenticated_permission(&state, &headers, crate::Permission::AssistantUse, true)
            .await
        {
            Ok(value) => value,
            Err(response) => return response,
        };
    let (agent_scope, agent_actor) = match authenticated_permission(
        &state,
        &headers,
        crate::Permission::AgentsRead,
        false,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let (finding_scope, finding_actor) =
        match authenticated_permission(&state, &headers, crate::Permission::ComplianceRead, false)
            .await
        {
            Ok(value) => value,
            Err(response) => return response,
        };
    if actor != agent_actor || actor != finding_actor || assistant_scope != ConsoleScope::Global {
        return problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "Access is not available",
        ));
    }
    if request.question.len() > 4_000
        || request.history.len() >= 20
        || request
            .history
            .iter()
            .any(|turn| turn.question.len() > 4_000 || turn.answer.len() > 8_000)
        || request
            .history
            .iter()
            .map(|turn| turn.question.len().saturating_add(turn.answer.len()))
            .sum::<usize>()
            .saturating_add(request.question.len())
            > 164_000
    {
        return problem_response(ProblemDetails::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "assistant_input_too_large",
            "The question or conversation is too long",
        ));
    }
    if agent_scope != finding_scope {
        return problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "Assistant access requires matching agent and finding scopes",
        ));
    }
    // Lookups the user may not run are still offered and answer "no
    // access" (ConsoleReadLookups); only a refusal means that here.
    let vulnerabilities = match authenticated_permission(
        &state,
        &headers,
        crate::Permission::VulnerabilitiesRead,
        false,
    )
    .await
    {
        Ok((scope, _)) => Some(scope),
        Err(response) if response.status() == StatusCode::FORBIDDEN => None,
        Err(response) => return response,
    };
    // The Rules page is global only.
    let rules =
        match authenticated_permission(&state, &headers, crate::Permission::RulesRead, false).await
        {
            Ok((scope, _)) => scope == ConsoleScope::Global,
            Err(response) if response.status() == StatusCode::FORBIDDEN => false,
            Err(response) => return response,
        };
    let user_slot = runtime.principal_slot(&actor).await;
    let Ok(user_permit) = user_slot.try_acquire_owned() else {
        return problem_response(ProblemDetails::new(
            StatusCode::CONFLICT,
            "assistant_busy",
            "An assistant answer is already running for your account",
        ));
    };
    let Ok(capacity_permit) = runtime.concurrency.clone().try_acquire_owned() else {
        return problem_response(ProblemDetails::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "assistant_busy",
            "The assistant is busy. Try again shortly",
        ));
    };
    if !*runtime.available.read().await {
        return problem_response(ProblemDetails::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "assistant_unavailable",
            "The local model is unavailable",
        ));
    }
    let Some(mode) = *runtime.mode.read().await else {
        return problem_response(ProblemDetails::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "assistant_unavailable",
            "The local model is unavailable",
        ));
    };
    let backend = runtime
        .assistant
        .backend
        .as_ref()
        .expect("enabled assistant has a backend");
    let settings = Settings::new(&runtime.assistant, backend, mode, Utc::now());
    let history = request
        .history
        .into_iter()
        .map(|turn| Turn {
            question: turn.question,
            answer: turn.answer,
        })
        .collect::<Vec<_>>();
    // One ID for the question's audit row and every internet lookup it makes.
    let request_id = next_request_id();
    let access = crate::assistant::Access {
        agents: agent_scope,
        vulnerabilities,
        rules,
        // The handler requires assistant.use (analysts, administrators).
        internet: Some(crate::fetch_client::Internet {
            user: actor.clone(),
            request_id: request_id.clone(),
            socket: state.fetch_socket.clone(),
            limits: state.internet_limits.clone(),
            sent: std::sync::Mutex::default(),
        }),
    };
    let lookups = match crate::assistant::ConsoleReadLookups::for_user(
        state.pool.clone(),
        access,
        settings.now,
    )
    .await
    {
        Ok(lookups) => lookups,
        Err(_) => return unavailable_auth(),
    };
    let backend: Arc<dyn platform_assistant::ChatBackend> =
        Arc::new(crate::assistant::LeasedChatBackend::new(
            runtime.backend.clone(),
            user_permit,
            capacity_permit,
        ));
    // The same level decides the offered tools and the mitigation prefetch
    // (the orchestrator reads it from the tools).
    let extra_tools = platform_assistant::lookups::internet_specs(
        crate::assistant_internet::current_level(&state.pool).await,
    );
    let started = Instant::now();
    let answer = tokio::time::timeout(
        assistant_answer_timeout(settings.longest()),
        platform_assistant::answer(
            backend,
            &lookups,
            settings,
            &history,
            &request.question,
            None,
            &extra_tools,
        ),
    )
    .await
    .unwrap_or(Err(platform_assistant::AnswerError::Deadline));
    let result_code = match &answer {
        Ok(_) => "success",
        Err(platform_assistant::AnswerError::EmptyQuestion) => "empty_question",
        Err(platform_assistant::AnswerError::QuestionTooLong) => "question_too_long",
        Err(platform_assistant::AnswerError::Backend(_)) => "backend_error",
        Err(platform_assistant::AnswerError::Deadline) => "deadline",
        Err(platform_assistant::AnswerError::NoAnswer) => "no_answer",
        Err(platform_assistant::AnswerError::Truncated) => "truncated",
    };
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let location = match runtime
        .assistant
        .backend
        .as_ref()
        .map(|backend| backend.location)
    {
        Some(platform_assistant::Location::Local) => "local",
        Some(platform_assistant::Location::OwnNetwork) => "own_network",
        Some(platform_assistant::Location::External) | None => "external",
    };
    let detail = serde_json::json!({
        "model": runtime.assistant.backend.as_ref().map(|backend| backend.model.as_str()),
        "location": location,
        "elapsed_ms": elapsed_ms,
    });
    let audit_succeeded = match state.pool.get().await {
        Ok(client) => platform_store::audit::record_with_detail(
            &client,
            &actor,
            "assistant.question",
            "assistant",
            result_code,
            &request_id,
            &detail,
        )
        .await
        .is_ok(),
        Err(_) => false,
    };
    if !audit_succeeded {
        let mut problem = ProblemDetails::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "assistant_audit_unavailable",
            "The assistant answer could not be recorded",
        );
        problem.request_id = request_id;
        return problem_response(problem);
    }
    tracing::info!(request_id = %request_id, actor_id = %actor, elapsed_ms, outcome = result_code, "assistant question completed");
    let answer = match answer {
        Ok(answer) => answer,
        Err(error) => {
            let (status, code, message) = match error {
                platform_assistant::AnswerError::EmptyQuestion => (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "empty_question",
                    "Enter a question",
                ),
                platform_assistant::AnswerError::QuestionTooLong => (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "question_too_long",
                    "The question is too long for the local model",
                ),
                platform_assistant::AnswerError::Backend(_) => (
                    StatusCode::BAD_GATEWAY,
                    "assistant_backend_error",
                    "The local model could not answer this question",
                ),
                platform_assistant::AnswerError::Deadline => (
                    StatusCode::GATEWAY_TIMEOUT,
                    "assistant_timeout",
                    "The local model took too long to answer",
                ),
                platform_assistant::AnswerError::NoAnswer => (
                    StatusCode::BAD_GATEWAY,
                    "assistant_no_answer",
                    "The local model returned no usable answer",
                ),
                platform_assistant::AnswerError::Truncated => (
                    StatusCode::BAD_GATEWAY,
                    "assistant_truncated",
                    "The local model ran out of answer space before replying; if it is a thinking model, run it with --reasoning off",
                ),
            };
            let mut problem = ProblemDetails::new(status, code, message);
            problem.request_id = request_id;
            return problem_response(problem);
        }
    };
    let response = crate::assistant::AssistantMessageResponse {
        segments: answer.segments.iter().map(Into::into).collect(),
        lookups: answer
            .lookups
            .iter()
            .map(|lookup| crate::assistant::AssistantLookup {
                name: lookup.name.map(str::to_owned),
                objects: lookup.objects,
                error: lookup.error.map(|error| error.message().to_owned()),
            })
            .collect(),
        internet: crate::assistant::internet_sources(
            lookups.internet_failed(),
            &lookups.internet_sent(),
        ),
    };
    let mut response = (StatusCode::OK, Json(response)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        HeaderName::from_static("x-request-id"),
        HeaderValue::from_str(&request_id).expect("generated request IDs are valid headers"),
    );
    response
}

#[utoipa::path(
    get,
    path = "/api/v1/compliance/summary",
    tag = "compliance",
    responses(
        (status = 200, description = "Scope-filtered latest compliance finding counts", body = crate::FindingSummary),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Permission denied", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(crate) async fn authenticated_finding_summary(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    let scope = match authenticated_agent_scope(&state, &headers, crate::Permission::ComplianceRead)
        .await
    {
        Ok(scope) => scope,
        Err(response) => return response,
    };
    let client = match state.pool.get().await {
        Ok(client) => client,
        Err(_) => return unavailable_auth(),
    };
    match platform_store::console_read::finding_summary_in_scope(&client, &scope).await {
        Ok(summary) => (
            StatusCode::OK,
            axum::Json(crate::FindingSummary {
                total: summary.total.try_into().unwrap_or_default(),
                impacted_agents: summary.impacted_agents.try_into().unwrap_or_default(),
                critical: summary.critical.try_into().unwrap_or_default(),
                high: summary.high.try_into().unwrap_or_default(),
                medium: summary.medium.try_into().unwrap_or_default(),
                low: summary.low.try_into().unwrap_or_default(),
            }),
        )
            .into_response(),
        Err(_) => unavailable_auth(),
    }
}

pub(crate) fn parse_if_match_version(headers: &HeaderMap) -> Result<Option<i64>, ()> {
    let values = headers.get_all(header::IF_MATCH);
    let mut iter = values.iter();
    let Some(value) = iter.next() else {
        return Ok(None);
    };
    if iter.next().is_some() {
        return Err(());
    }
    let value = value.to_str().map_err(|_| ())?;
    let version = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or(())?;
    if version.is_empty() || !version.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(());
    }
    let version = version.parse::<i64>().map_err(|_| ())?;
    (version > 0).then_some(Some(version)).ok_or(())
}

pub(crate) fn parse_if_match_zero_version(headers: &HeaderMap) -> Result<Option<i64>, ()> {
    let values = headers.get_all(header::IF_MATCH);
    let mut iter = values.iter();
    let Some(value) = iter.next() else {
        return Ok(None);
    };
    if iter.next().is_some() {
        return Err(());
    }
    let value = value.to_str().map_err(|_| ())?;
    let version = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or(())?;
    if version.is_empty() || !version.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(());
    }
    Ok(Some(version.parse::<i64>().map_err(|_| ())?))
}

#[utoipa::path(
    get,
    path = "/api/v1/compliance/latest",
    tag = "compliance",
    params(
        ("severity" = Option<String>, Query, description = "critical, high, medium, or low"),
        ("agent_id" = Option<String>, Query, description = "One host's findings only"),
        ("cursor" = Option<String>, Query, description = "Opaque continuation cursor"),
        ("limit" = Option<u16>, Query, description = "Page size from 1 to 100")
    ),
    responses(
        (status = 200, description = "Scope-filtered latest finding page", body = crate::FindingPage),
        (status = 400, description = "Invalid query or cursor", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Permission denied", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(crate) async fn authenticated_latest_findings(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    query: Result<Query<LatestFindingListParams>, QueryRejection>,
) -> Response {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use platform_store::console_read::{
        LatestCursor, LatestQuery, PageLimit, Severity, latest_findings_in_scope,
    };

    let scope = match authenticated_agent_scope(&state, &headers, crate::Permission::ComplianceRead)
        .await
    {
        Ok(scope) => scope,
        Err(response) => return response,
    };
    let Query(params) = match query {
        Ok(query) => query,
        Err(_) => return invalid_finding_query(),
    };
    let Some(limit) = PageLimit::new(params.limit.unwrap_or(crate::DEFAULT_PAGE_SIZE)) else {
        return invalid_finding_query();
    };
    let severity = match params.severity.as_deref() {
        None => None,
        Some("critical") => Some(Severity::Critical),
        Some("high") => Some(Severity::High),
        Some("medium") => Some(Severity::Medium),
        Some("low") => Some(Severity::Low),
        Some(_) => return invalid_finding_query(),
    };
    let after = match params.cursor.as_deref() {
        None => None,
        Some(encoded) if encoded.len() <= crate::MAX_CURSOR_LENGTH => {
            let decoded = match URL_SAFE_NO_PAD.decode(encoded) {
                Ok(decoded) => decoded,
                Err(_) => return invalid_finding_query(),
            };
            let token = match serde_json::from_slice::<LatestFindingCursorToken>(&decoded) {
                Ok(token) if token.severity == params.severity && token.scope == scope => token,
                _ => return invalid_finding_query(),
            };
            let last_observed_at =
                match chrono::DateTime::parse_from_rfc3339(&token.last_observed_at) {
                    Ok(value) => value.with_timezone(&Utc),
                    Err(_) => return invalid_finding_query(),
                };
            Some(LatestCursor {
                last_observed_at,
                agent_id: token.agent_id,
                rule_set_id: token.rule_set_id,
                rule_id: token.rule_id,
            })
        }
        Some(_) => return invalid_finding_query(),
    };
    let client = match state.pool.get().await {
        Ok(client) => client,
        Err(_) => return unavailable_auth(),
    };
    let page = match latest_findings_in_scope(
        &client,
        &LatestQuery {
            severity,
            // ponytail: the cursor isn't bound to agent_id (it is to
            // severity and scope); a client changing hosts mid-paging
            // just reads another page. Scope still applies.
            agent_id: params.agent_id.filter(|id| !id.is_empty()),
            after,
            limit,
        },
        &scope,
    )
    .await
    {
        Ok(page) => page,
        Err(_) => return unavailable_auth(),
    };
    let items = page.items.into_iter().map(latest_finding_view).collect();
    let next_cursor = match page.next {
        None => None,
        Some(cursor) => {
            let token = LatestFindingCursorToken {
                severity: params.severity,
                scope,
                last_observed_at: cursor
                    .last_observed_at
                    .to_rfc3339_opts(SecondsFormat::Micros, true),
                agent_id: cursor.agent_id,
                rule_set_id: cursor.rule_set_id,
                rule_id: cursor.rule_id,
            };
            match serde_json::to_vec(&token) {
                Ok(token) => Some(URL_SAFE_NO_PAD.encode(token)),
                Err(_) => return unavailable_auth(),
            }
        }
    };
    (
        StatusCode::OK,
        axum::Json(crate::FindingPage {
            items,
            next_cursor,
            generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        }),
    )
        .into_response()
}

fn invalid_finding_query() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::BAD_REQUEST,
        "invalid_query",
        "Finding query parameters are invalid",
    ))
}

fn latest_finding_view(finding: platform_store::console_read::LatestFinding) -> crate::FindingView {
    use platform_store::console_read::Severity;
    crate::FindingView {
        detection: finding.detection,
        id: finding.finding_id,
        agent_id: finding.agent_id,
        hostname: finding.hostname,
        rule_set_id: if finding.rule_set_id.is_empty() {
            "~unknown".into()
        } else {
            finding.rule_set_id
        },
        rule_id: finding.rule_id,
        rule_version: finding.rule_version.try_into().unwrap_or_default(),
        severity: match finding.severity {
            Severity::Critical => crate::Severity::Critical,
            Severity::High => crate::Severity::High,
            Severity::Medium => crate::Severity::Medium,
            Severity::Low => crate::Severity::Low,
        },
        confidence: finding.confidence.try_into().unwrap_or_default(),
        message: finding.message,
        evidence: finding.evidence,
        scan_id: finding.scan_id,
        authenticated: finding.authenticated,
        origin: match finding.origin.as_str() {
            "import" => crate::FindingOrigin::Import,
            _ => crate::FindingOrigin::Online,
        },
        first_observed_at: finding
            .first_observed_at
            .to_rfc3339_opts(SecondsFormat::Secs, true),
        last_observed_at: finding
            .last_observed_at
            .to_rfc3339_opts(SecondsFormat::Secs, true),
        received_at: finding
            .received_at
            .to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/compliance/latest/{agent_id}/{rule_set_id}/{rule_id}",
    tag = "compliance",
    params(
        ("agent_id" = String, Path, description = "Stable agent identifier"),
        ("rule_set_id" = String, Path, description = "Rule set id or reserved ~unknown"),
        ("rule_id" = String, Path, description = "Rule identifier")
    ),
    responses(
        (status = 200, description = "Visible latest observation", body = crate::FindingView),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Permission denied", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "Compliance finding not found", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(crate) async fn authenticated_latest_finding(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((agent_id, rule_set_id, rule_id)): Path<(String, String, String)>,
) -> Response {
    let scope = match authenticated_agent_scope(&state, &headers, crate::Permission::ComplianceRead)
        .await
    {
        Ok(scope) => scope,
        Err(response) => return response,
    };
    let client = match state.pool.get().await {
        Ok(client) => client,
        Err(_) => return unavailable_auth(),
    };
    let rule_set_id = if rule_set_id == "~unknown" {
        ""
    } else {
        &rule_set_id
    };
    match platform_store::console_read::latest_finding_in_scope(
        &client,
        &agent_id,
        rule_set_id,
        &rule_id,
        &scope,
    )
    .await
    {
        Ok(Some(finding)) => axum::Json(latest_finding_view(finding)).into_response(),
        Ok(None) => problem_response(ProblemDetails::not_found(
            "compliance_finding_not_found",
            "Compliance finding not found",
        )),
        Err(_) => unavailable_auth(),
    }
}

fn triage_view(record: platform_store::console_triage::TriageRecord) -> crate::FindingTriageView {
    crate::FindingTriageView {
        state: record.state,
        rule_version: record.rule_version,
        assigned_to: record.assigned_to_username,
        note: record.note,
        accepted_until: record.accepted_until.map(|value| value.to_rfc3339()),
        version: record.version,
    }
}

fn triage_response(record: platform_store::console_triage::TriageRecord) -> Response {
    let view = triage_view(record);
    let mut response = (StatusCode::OK, Json(view.clone())).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(value) = HeaderValue::from_str(&format!("\"{}\"", view.version)) {
        response.headers_mut().insert(header::ETAG, value);
    }
    response
}

#[utoipa::path(get, path = "/api/v1/compliance/latest/{agent_id}/{rule_set_id}/{rule_id}/triage", tag = "compliance", params(("agent_id" = String, Path), ("rule_set_id" = String, Path), ("rule_id" = String, Path)), responses((status = 200, description = "Current finding triage", body = crate::FindingTriageView, headers(("ETag" = String, description = "Triage version"))), (status = 404, description = "Compliance finding not found", body = crate::ProblemDetails), (status = 403, description = "Permission denied", body = crate::ProblemDetails)))]
pub(crate) async fn authenticated_finding_triage(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((agent_id, rule_set_id, rule_id)): Path<(String, String, String)>,
) -> Response {
    let scope = match authenticated_agent_scope(&state, &headers, crate::Permission::ComplianceRead)
        .await
    {
        Ok(scope) => scope,
        Err(response) => return response,
    };
    let client = match state.pool.get().await {
        Ok(client) => client,
        Err(_) => return unavailable_auth(),
    };
    let rule_set_id = if rule_set_id == "~unknown" {
        ""
    } else {
        &rule_set_id
    };
    match platform_store::console_read::latest_finding_in_scope(
        &client,
        &agent_id,
        rule_set_id,
        &rule_id,
        &scope,
    )
    .await
    {
        Ok(Some(_)) => {
            match platform_store::console_triage::get(&client, &agent_id, rule_set_id, &rule_id)
                .await
            {
                Ok(Some(record)) => triage_response(record),
                Ok(None) => problem_response(ProblemDetails::not_found(
                    "compliance_finding_not_found",
                    "Compliance finding not found",
                )),
                Err(_) => unavailable_auth(),
            }
        }
        Ok(None) => problem_response(ProblemDetails::not_found(
            "compliance_finding_not_found",
            "Compliance finding not found",
        )),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(put, path = "/api/v1/compliance/latest/{agent_id}/{rule_set_id}/{rule_id}/triage", tag = "compliance", params(("agent_id" = String, Path), ("rule_set_id" = String, Path), ("rule_id" = String, Path), ("If-Match" = String, Header)), request_body = crate::UpdateFindingTriageRequest, responses((status = 200, description = "Updated finding triage", body = crate::FindingTriageView, headers(("ETag" = String, description = "New triage version"))), (status = 412, description = "Stale triage version", body = crate::ProblemDetails), (status = 428, description = "If-Match is required", body = crate::ProblemDetails)))]
pub(crate) async fn update_authenticated_finding_triage(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((agent_id, rule_set_id, rule_id)): Path<(String, String, String)>,
    payload: Result<
        Json<crate::UpdateFindingTriageRequest>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Response {
    let (scope, user_id) =
        match authenticated_permission(&state, &headers, crate::Permission::ComplianceTriage, true)
            .await
        {
            Ok(context) => context,
            Err(response) => return response,
        };
    let expected = match parse_if_match_zero_version(&headers) {
        Ok(Some(version)) => version,
        Ok(None) => {
            return problem_response(ProblemDetails::new(
                StatusCode::PRECONDITION_REQUIRED,
                "precondition_required",
                "If-Match is required",
            ));
        }
        Err(()) => {
            return problem_response(ProblemDetails::new(
                StatusCode::BAD_REQUEST,
                "invalid_precondition",
                "If-Match must contain one quoted triage version",
            ));
        }
    };
    let Json(payload) = match payload {
        Ok(payload) => payload,
        Err(_) => {
            return problem_response(ProblemDetails::new(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Triage request is invalid",
            ));
        }
    };
    let accepted_until = match payload
        .accepted_until
        .as_deref()
        .map(chrono::DateTime::parse_from_rfc3339)
        .transpose()
    {
        Ok(value) => value.map(|value| value.with_timezone(&Utc)),
        Err(_) => {
            return problem_response(ProblemDetails::new(
                StatusCode::BAD_REQUEST,
                "invalid_expiry",
                "accepted_until must be an RFC 3339 timestamp",
            ));
        }
    };
    let client = match state.pool.get().await {
        Ok(client) => client,
        Err(_) => return unavailable_auth(),
    };
    let actual_rule_set_id = if rule_set_id == "~unknown" {
        ""
    } else {
        &rule_set_id
    };
    match platform_store::console_read::latest_finding_in_scope(
        &client,
        &agent_id,
        actual_rule_set_id,
        &rule_id,
        &scope,
    )
    .await
    {
        Ok(Some(_)) => {}
        Ok(None) => {
            return problem_response(ProblemDetails::not_found(
                "compliance_finding_not_found",
                "Compliance finding not found",
            ));
        }
        Err(_) => return unavailable_auth(),
    }
    let mut client = match state.pool.get().await {
        Ok(client) => client,
        Err(_) => return unavailable_auth(),
    };
    match platform_store::console_triage::update(
        &mut client,
        &agent_id,
        actual_rule_set_id,
        &rule_id,
        expected,
        &payload.state,
        payload.assigned_to.as_deref(),
        payload.note.as_deref(),
        accepted_until,
        &user_id,
        Utc::now(),
    )
    .await
    {
        Ok(platform_store::console_triage::TriageUpdate::Updated(record)) => {
            triage_response(record)
        }
        Ok(platform_store::console_triage::TriageUpdate::Stale(_record)) => {
            problem_response(ProblemDetails::new(
                StatusCode::PRECONDITION_FAILED,
                "stale_triage",
                "Triage changed; reload before saving",
            ))
        }
        Ok(platform_store::console_triage::TriageUpdate::InvalidTransition(_)) => {
            problem_response(ProblemDetails::new(
                StatusCode::CONFLICT,
                "invalid_transition",
                "Requested triage transition is not allowed",
            ))
        }
        Ok(platform_store::console_triage::TriageUpdate::InvalidFields) => {
            problem_response(ProblemDetails::new(
                StatusCode::BAD_REQUEST,
                "invalid_triage",
                "Triage state, note, or expiry is invalid",
            ))
        }
        Ok(platform_store::console_triage::TriageUpdate::AssigneeUnavailable) => {
            problem_response(ProblemDetails::new(
                StatusCode::BAD_REQUEST,
                "invalid_assignee",
                "Assignee must be an enabled analyst or admin",
            ))
        }
        Ok(platform_store::console_triage::TriageUpdate::NotFound) => {
            problem_response(ProblemDetails::not_found(
                "compliance_finding_not_found",
                "Compliance finding not found",
            ))
        }
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/compliance/history",
    tag = "compliance",
    params(
        ("since" = String, Query, description = "Required RFC 3339 lower bound for partition pruning"),
        ("agent_id" = Option<String>, Query, description = "Exact agent filter"),
        ("rule_set_id" = Option<String>, Query, description = "Exact rule-set filter; ~unknown selects legacy rows"),
        ("rule_id" = Option<String>, Query, description = "Exact rule filter"),
        ("cursor" = Option<String>, Query, description = "Opaque continuation cursor"),
        ("limit" = Option<u16>, Query, description = "Page size from 1 to 100")
    ),
    responses(
        (status = 200, description = "Scope-filtered finding history page", body = crate::FindingHistoryPage),
        (status = 400, description = "Invalid query or cursor", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Permission denied", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(crate) async fn authenticated_finding_history(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    query: Result<Query<FindingHistoryListParams>, QueryRejection>,
) -> Response {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use platform_store::console_read::{
        HistoryCursor, HistoryQuery, PageLimit, finding_history_in_scope,
    };

    let scope = match authenticated_agent_scope(&state, &headers, crate::Permission::ComplianceRead)
        .await
    {
        Ok(scope) => scope,
        Err(response) => return response,
    };
    let Query(params) = match query {
        Ok(query) => query,
        Err(_) => return invalid_finding_query(),
    };
    if [&params.agent_id, &params.rule_set_id, &params.rule_id]
        .into_iter()
        .flatten()
        .any(|value| value.is_empty() || value.len() > 128 || value.chars().any(char::is_control))
    {
        return invalid_finding_query();
    }
    let since = match chrono::DateTime::parse_from_rfc3339(&params.since) {
        Ok(value) => value.with_timezone(&Utc),
        Err(_) => return invalid_finding_query(),
    };
    if since > Utc::now() {
        return invalid_finding_query();
    }
    let Some(limit) = PageLimit::new(params.limit.unwrap_or(crate::DEFAULT_PAGE_SIZE)) else {
        return invalid_finding_query();
    };
    let after = match params.cursor.as_deref() {
        None => None,
        Some(encoded) if encoded.len() <= crate::MAX_CURSOR_LENGTH => {
            let decoded = match URL_SAFE_NO_PAD.decode(encoded) {
                Ok(decoded) => decoded,
                Err(_) => return invalid_finding_query(),
            };
            let token = match serde_json::from_slice::<FindingHistoryCursorToken>(&decoded) {
                Ok(token)
                    if token.since == params.since
                        && token.agent_id == params.agent_id
                        && token.rule_set_id == params.rule_set_id
                        && token.rule_id == params.rule_id
                        && token.scope == scope =>
                {
                    token
                }
                _ => return invalid_finding_query(),
            };
            let observed_at = match chrono::DateTime::parse_from_rfc3339(&token.observed_at) {
                Ok(value) => value.with_timezone(&Utc),
                Err(_) => return invalid_finding_query(),
            };
            let observed_day = match chrono::NaiveDate::parse_from_str(&token.observed_day, "%F") {
                Ok(value) => value,
                Err(_) => return invalid_finding_query(),
            };
            Some(HistoryCursor {
                observed_at,
                observed_day,
                finding_id: token.finding_id,
            })
        }
        Some(_) => return invalid_finding_query(),
    };
    let rule_set_id = params.rule_set_id.as_deref().map(|value| {
        if value == "~unknown" {
            "".to_owned()
        } else {
            value.to_owned()
        }
    });
    let client = match state.pool.get().await {
        Ok(client) => client,
        Err(_) => return unavailable_auth(),
    };
    let page = match finding_history_in_scope(
        &client,
        &HistoryQuery {
            since,
            agent_id: params.agent_id.clone(),
            rule_set_id,
            rule_id: params.rule_id.clone(),
            after,
            limit,
        },
        &scope,
    )
    .await
    {
        Ok(page) => page,
        Err(_) => return unavailable_auth(),
    };
    let items = page.items.into_iter().map(history_event_view).collect();
    let next_cursor = match page.next {
        None => None,
        Some(cursor) => {
            let token = FindingHistoryCursorToken {
                since: params.since,
                agent_id: params.agent_id,
                rule_set_id: params.rule_set_id,
                rule_id: params.rule_id,
                scope,
                observed_at: cursor
                    .observed_at
                    .to_rfc3339_opts(SecondsFormat::Micros, true),
                observed_day: cursor.observed_day.to_string(),
                finding_id: cursor.finding_id,
            };
            match serde_json::to_vec(&token) {
                Ok(token) => Some(URL_SAFE_NO_PAD.encode(token)),
                Err(_) => return unavailable_auth(),
            }
        }
    };
    (
        StatusCode::OK,
        axum::Json(crate::FindingHistoryPage {
            items,
            next_cursor,
            generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        }),
    )
        .into_response()
}

#[utoipa::path(
    get,
    path = "/api/v1/compliance/history/{observed_day}/{finding_id}",
    tag = "compliance",
    params(
        ("observed_day" = String, Path, description = "UTC partition date"),
        ("finding_id" = String, Path, description = "Stable finding identifier")
    ),
    responses(
        (status = 200, description = "Visible immutable finding event", body = crate::FindingHistoryEntry),
        (status = 400, description = "Invalid partition date", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Permission denied", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "Compliance finding event not found", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(crate) async fn authenticated_finding_event(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((observed_day, finding_id)): Path<(String, String)>,
) -> Response {
    let scope = match authenticated_agent_scope(&state, &headers, crate::Permission::ComplianceRead)
        .await
    {
        Ok(scope) => scope,
        Err(response) => return response,
    };
    let observed_day = match chrono::NaiveDate::parse_from_str(&observed_day, "%F") {
        Ok(value) => value,
        Err(_) => return invalid_finding_query(),
    };
    let client = match state.pool.get().await {
        Ok(client) => client,
        Err(_) => return unavailable_auth(),
    };
    match platform_store::console_read::finding_event_in_scope(
        &client,
        observed_day,
        &finding_id,
        &scope,
    )
    .await
    {
        Ok(Some(event)) => axum::Json(history_event_view(event)).into_response(),
        Ok(None) => problem_response(ProblemDetails::not_found(
            "compliance_finding_not_found",
            "Compliance finding not found",
        )),
        Err(_) => unavailable_auth(),
    }
}

fn history_event_view(
    event: platform_store::console_read::FindingEvent,
) -> crate::FindingHistoryEntry {
    use platform_store::console_read::Severity;
    crate::FindingHistoryEntry {
        id: event.finding_id,
        observed_day: event.observed_day.to_string(),
        agent_id: event.agent_id,
        rule_set_id: if event.rule_set_id.is_empty() {
            "~unknown".into()
        } else {
            event.rule_set_id
        },
        rule_id: event.rule_id,
        rule_version: event.rule_version.try_into().unwrap_or_default(),
        severity: match event.severity {
            Severity::Critical => crate::Severity::Critical,
            Severity::High => crate::Severity::High,
            Severity::Medium => crate::Severity::Medium,
            Severity::Low => crate::Severity::Low,
        },
        confidence: event.confidence.try_into().unwrap_or_default(),
        message: event.message,
        evidence: event.evidence,
        scan_id: event.scan_id,
        authenticated: event.authenticated,
        origin: match event.origin.as_str() {
            "import" => crate::FindingOrigin::Import,
            _ => crate::FindingOrigin::Online,
        },
        observed_at: event.observed_at.to_rfc3339_opts(SecondsFormat::Secs, true),
        received_at: event.received_at.to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

#[utoipa::path(get, path="/api/v1/vulnerabilities/summary", tag="vulnerabilities", responses((status=200, description="Scoped vulnerability summary", body=crate::VulnerabilitySummary)))]
pub(crate) async fn authenticated_vulnerability_summary(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    let scope =
        match authenticated_agent_scope(&state, &headers, crate::Permission::VulnerabilitiesRead)
            .await
        {
            Ok(scope) => scope,
            Err(response) => return response,
        };
    let client = match state.pool.get().await {
        Ok(client) => client,
        Err(_) => return unavailable_auth(),
    };
    let summary = match platform_store::vulns::summary_in_scope(&client, &scope).await {
        Ok(summary) => summary,
        Err(_) => return unavailable_auth(),
    };
    let by_severity = summary
        .by_severity
        .into_iter()
        .map(|(severity, count)| crate::VulnerabilitySeverityCount {
            severity: match severity.as_str() {
                "critical" => crate::VulnerabilitySeverity::Critical,
                "important" => crate::VulnerabilitySeverity::Important,
                "moderate" => crate::VulnerabilitySeverity::Moderate,
                "low" => crate::VulnerabilitySeverity::Low,
                _ => crate::VulnerabilitySeverity::Unrated,
            },
            count: count.max(0) as u64,
        })
        .collect();
    let top_hosts = summary
        .top_hosts
        .into_iter()
        .map(
            |(agent_id, hostname, open, serious)| crate::VulnerabilityTopHost {
                agent_id,
                hostname,
                open: open.max(0) as u64,
                serious: serious.max(0) as u64,
            },
        )
        .collect();
    Json(crate::VulnerabilitySummary {
        by_severity,
        hosts: summary.hosts.max(0) as u64,
        top_hosts,
        reboot_hosts: summary.reboot_hosts.max(0) as u64,
        no_fix: summary.no_fix.max(0) as u64,
        exploited: summary.exploited.max(0) as u64,
        feed_last_imported_at: summary
            .feed_last_imported_at
            .map(|at| at.to_rfc3339_opts(SecondsFormat::Secs, true)),
    })
    .into_response()
}

#[utoipa::path(get, path="/api/v1/vulnerabilities", tag="vulnerabilities", params(("host"=Option<String>, Query), ("advisory"=Option<String>, Query), ("severity"=Option<String>, Query), ("cve"=Option<String>, Query), ("fixed"=Option<bool>, Query), ("exploited"=Option<bool>, Query), ("reboot_needed"=Option<bool>, Query), ("min_confidence"=Option<u8>, Query)), responses((status=200, description="Prioritised, scope-filtered vulnerabilities", body=crate::VulnerabilityPage), (status=400, description="Invalid filters", body=crate::ProblemDetails)))]
pub(crate) async fn authenticated_vulnerabilities(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    query: Result<Query<VulnerabilityListParams>, QueryRejection>,
) -> Response {
    let scope =
        match authenticated_agent_scope(&state, &headers, crate::Permission::VulnerabilitiesRead)
            .await
        {
            Ok(scope) => scope,
            Err(response) => return response,
        };
    let Query(params) = match query {
        Ok(value) => value,
        Err(_) => return invalid_finding_query(),
    };
    for value in [
        &params.host,
        &params.advisory,
        &params.severity,
        &params.cve,
    ]
    .into_iter()
    .flatten()
    {
        if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
            return invalid_finding_query();
        }
    }
    if params
        .severity
        .as_deref()
        .is_some_and(|s| !matches!(s, "critical" | "important" | "moderate" | "low" | "unrated"))
    {
        return invalid_finding_query();
    }
    let client = match state.pool.get().await {
        Ok(client) => client,
        Err(_) => return unavailable_auth(),
    };
    if let Some(host) = params.host.as_deref() {
        let matches = match platform_store::vulns::hosts_named_in_scope(&client, host, &scope).await
        {
            Ok(ids) => ids,
            Err(_) => return unavailable_auth(),
        };
        if matches.len() > 1 {
            let mut problem = ProblemDetails::new(
                StatusCode::BAD_REQUEST,
                "ambiguous_host",
                "Host name matches multiple visible hosts; use an agent ID",
            );
            problem.field_errors = Some(vec![crate::FieldError {
                field: "host".into(),
                code: "ambiguous_host".into(),
                message: matches.join(", "),
            }]);
            return problem_response(problem);
        }
    }
    let rows = match platform_store::vulns::list_in_scope(
        &client,
        &platform_store::vulns::ListFilter {
            host: params.host.as_deref(),
            advisory: params.advisory.as_deref(),
            severity: params.severity.as_deref(),
            cve: params.cve.as_deref(),
            fixed: params.fixed.unwrap_or(false),
            exploited: params.exploited,
            reboot_needed: params.reboot_needed,
            min_confidence: params.min_confidence,
        },
        &scope,
    )
    .await
    {
        Ok(rows) => rows,
        Err(_) => return unavailable_auth(),
    };
    let mut rows = rows;
    let mut more_available = rows.len() > 100;
    rows.truncate(100);
    let mut items: Vec<crate::VulnerabilityView> =
        rows.into_iter().map(vulnerability_view).collect();
    // Lower-confidence findings from NVD CPE ranges, only when asked for
    // (a minimum confidence at or below theirs) and never mixed into the
    // lists of fixed or reboot-pending vulnerabilities.
    let wants_cpe = params
        .min_confidence
        .is_some_and(|min| min <= CPE_MAX_CONFIDENCE)
        && !params.fixed.unwrap_or(false)
        && params.reboot_needed != Some(true)
        && params
            .advisory
            .as_deref()
            .is_none_or(|a| a.starts_with("CPE:"));
    if wants_cpe {
        let found = match cpe_findings(&client, &scope, &params).await {
            Ok(found) => found,
            Err(_) => return unavailable_auth(),
        };
        more_available |= found.len() > CPE_PAGE;
        items.extend(found.into_iter().take(CPE_PAGE).map(cpe_view));
    }
    if attach_triage(&client, &mut items).await.is_err() {
        return unavailable_auth();
    }
    Json(crate::VulnerabilityPage {
        items,
        more_available,
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    })
    .into_response()
}

/// CPE findings are never above this confidence (`openvibes-vulns`).
const CPE_MAX_CONFIDENCE: u8 = 75;
/// Most CPE findings in one page.
const CPE_PAGE: usize = 200;
/// Prefix of the advisory id a CPE finding is shown under: `CPE:CVE:product`.
const CPE_PREFIX: &str = "CPE:";

async fn cpe_findings(
    client: &platform_store::Client,
    scope: &platform_store::console_read::AgentScope,
    params: &VulnerabilityListParams,
) -> Result<Vec<platform_store::cpe::FindingRow>, platform_store::StoreError> {
    let agents = match scope {
        platform_store::console_read::AgentScope::Global => None,
        _ => Some(platform_store::console_read::agent_ids_in_scope(client, scope).await?),
    };
    // `CPE:CVE-…:product` names one finding group.
    let group = params
        .advisory
        .as_deref()
        .and_then(|a| a.strip_prefix(CPE_PREFIX));
    let (cve, product) = match group.and_then(|g| g.split_once(':')) {
        Some((cve, product)) => (Some(cve), Some(product)),
        None => (params.cve.as_deref(), None),
    };
    let min = i16::from(params.min_confidence.unwrap_or(0));
    let mut found = platform_store::cpe::list(
        client,
        min,
        params.host.as_deref(),
        cve,
        agents.as_deref(),
        (CPE_PAGE + 1) as i64,
    )
    .await?;
    if let Some(product) = product {
        found.retain(|f| f.product == product);
    }
    found.retain(|f| {
        params
            .severity
            .as_deref()
            .is_none_or(|s| cpe_severity(f.cvss).0 == s)
            && params.exploited.is_none_or(|e| e == f.exploited)
    });
    Ok(found)
}

/// Severity name and enum from a CVSS base score.
fn cpe_severity(cvss: Option<f32>) -> (&'static str, crate::VulnerabilitySeverity) {
    match cvss {
        Some(s) if s >= 9.0 => ("critical", crate::VulnerabilitySeverity::Critical),
        Some(s) if s >= 7.0 => ("important", crate::VulnerabilitySeverity::Important),
        Some(s) if s >= 4.0 => ("moderate", crate::VulnerabilitySeverity::Moderate),
        Some(s) if s > 0.0 => ("low", crate::VulnerabilitySeverity::Low),
        _ => ("unrated", crate::VulnerabilitySeverity::Unrated),
    }
}

fn cpe_view(row: platform_store::cpe::FindingRow) -> crate::VulnerabilityView {
    crate::VulnerabilityView {
        advisory_id: format!("{CPE_PREFIX}{}:{}", row.cve_id, row.product),
        severity: cpe_severity(row.cvss).1,
        title: format!("{}: {} {}", row.cve_id, row.package, row.range_text),
        url: format!("https://nvd.nist.gov/vuln/detail/{}", row.cve_id),
        packages: serde_json::json!([{
            "name": row.package, "installed": row.installed, "fixed": null,
        }]),
        agent_id: row.agent_id,
        hostname: row.hostname,
        cves: vec![row.cve_id],
        first_seen_at: row.first_seen_at.to_rfc3339_opts(SecondsFormat::Secs, true),
        fixed_at: None,
        reboot_needed: false,
        exploited: row.exploited,
        kev: row.kev,
        euvd: row.euvd,
        kev_due: row.kev_due.map(|v| v.to_string()),
        ransomware: row.ransomware,
        epss: row.epss,
        epss_percentile: row.epss_percentile,
        cvss: row.cvss,
        source: "nvd-cpe".into(),
        match_method: "cpe-nvd".into(),
        confidence: u8::try_from(row.confidence).unwrap_or(0),
        match_basis: row.basis,
        triage_state: "open".into(),
        triage_version: 0,
        assigned_to: None,
    }
}

#[utoipa::path(get, path="/api/v1/vulnerabilities/advisories/{advisory_id}", tag="vulnerabilities", params(("advisory_id"=String, Path)), responses((status=200, description="Scoped advisory and CVE enrichment", body=crate::VulnerabilityAdvisoryDetail), (status=404, description="Advisory not visible", body=crate::ProblemDetails)))]
pub(crate) async fn authenticated_vulnerability_advisory(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(advisory_id): Path<String>,
) -> Response {
    let scope =
        match authenticated_agent_scope(&state, &headers, crate::Permission::VulnerabilitiesRead)
            .await
        {
            Ok(scope) => scope,
            Err(response) => return response,
        };
    if advisory_id.is_empty()
        || advisory_id.len() > 128
        || advisory_id.chars().any(char::is_control)
    {
        return invalid_finding_query();
    }
    let client = match state.pool.get().await {
        Ok(client) => client,
        Err(_) => return unavailable_auth(),
    };
    if advisory_id.starts_with(CPE_PREFIX) {
        let params = VulnerabilityListParams {
            host: None,
            advisory: Some(advisory_id.clone()),
            severity: None,
            cve: None,
            fixed: None,
            exploited: None,
            reboot_needed: None,
            min_confidence: Some(0),
        };
        let found = match cpe_findings(&client, &scope, &params).await {
            Ok(found) if !found.is_empty() => found,
            Ok(_) => {
                return problem_response(ProblemDetails::not_found(
                    "advisory_not_found",
                    "Advisory not found",
                ));
            }
            Err(_) => return unavailable_auth(),
        };
        let first = &found[0];
        let cves = vec![crate::CveDetailView {
            cve_id: first.cve_id.clone(),
            cvss_score: first.cvss,
            cvss_version: None,
            cwe: Vec::new(),
            description: first.description.clone(),
            kev: first.kev,
            euvd_exploited: first.euvd.then(|| "listed".to_owned()),
            epss: first.epss,
        }];
        let more_available = found.len() > 100;
        let items = found.into_iter().take(100).map(cpe_view).collect();
        return Json(crate::VulnerabilityAdvisoryDetail {
            hosts: crate::VulnerabilityPage {
                items,
                more_available,
                generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            },
            cves,
        })
        .into_response();
    }
    let cves =
        match platform_store::vulns::cve_details_in_scope(&client, &advisory_id, &scope).await {
            Ok(Some(cves)) => cves,
            Ok(None) => {
                return problem_response(ProblemDetails::not_found(
                    "advisory_not_found",
                    "Advisory not found",
                ));
            }
            Err(_) => return unavailable_auth(),
        };
    let rows = match platform_store::vulns::list_in_scope(
        &client,
        &platform_store::vulns::ListFilter {
            advisory: Some(&advisory_id),
            ..Default::default()
        },
        &scope,
    )
    .await
    {
        Ok(rows) => rows,
        Err(_) => return unavailable_auth(),
    };
    // The detail's Hosts tab: as many hosts as a finding's (2,000), so
    // it is not cut off at the list's page (#239).
    // ponytail: one response; page it if advisories reach that many hosts.
    let mut rows = rows;
    let more_available = rows.len() > ADVISORY_HOSTS;
    rows.truncate(ADVISORY_HOSTS);
    let mut items: Vec<crate::VulnerabilityView> =
        rows.into_iter().map(vulnerability_view).collect();
    if attach_triage(&client, &mut items).await.is_err() {
        return unavailable_auth();
    }
    let hosts = crate::VulnerabilityPage {
        items,
        more_available,
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    };
    let cves = cves
        .into_iter()
        .map(|c| crate::CveDetailView {
            cve_id: c.cve_id,
            cvss_score: c.cvss_score,
            cvss_version: c.cvss_version,
            cwe: c.cwe,
            description: c.description,
            kev: c.kev,
            euvd_exploited: c.euvd_exploited,
            epss: c.epss,
        })
        .collect();
    Json(crate::VulnerabilityAdvisoryDetail { hosts, cves }).into_response()
}

/// Most hosts an advisory's detail lists.
const ADVISORY_HOSTS: usize = 2_000;

/// Each row's triage (triage v2), in one lookup; untriaged rows stay open.
async fn attach_triage(
    client: &platform_store::Client,
    items: &mut [crate::VulnerabilityView],
) -> Result<(), platform_store::StoreError> {
    let pairs: Vec<(String, String)> = items
        .iter()
        .map(|v| (v.agent_id.clone(), v.advisory_id.clone()))
        .collect();
    let triage = platform_store::vulnerability_triage::states(client, &pairs).await?;
    for item in items {
        if let Some(t) = triage.get(&(item.agent_id.clone(), item.advisory_id.clone())) {
            item.triage_state.clone_from(&t.state);
            item.triage_version = t.version;
            item.assigned_to.clone_from(&t.assigned_to);
        }
    }
    Ok(())
}

fn vulnerability_view(row: platform_store::vulns::VulnRow) -> crate::VulnerabilityView {
    crate::VulnerabilityView {
        agent_id: row.agent_id,
        hostname: row.hostname,
        advisory_id: row.advisory_id,
        severity: match row.severity.as_str() {
            "critical" => crate::VulnerabilitySeverity::Critical,
            "important" => crate::VulnerabilitySeverity::Important,
            "moderate" => crate::VulnerabilitySeverity::Moderate,
            "low" => crate::VulnerabilitySeverity::Low,
            _ => crate::VulnerabilitySeverity::Unrated,
        },
        title: row.title,
        url: row.url,
        cves: row.cves,
        packages: row.packages,
        first_seen_at: row.first_seen_at.to_rfc3339_opts(SecondsFormat::Secs, true),
        fixed_at: row
            .fixed_at
            .map(|v| v.to_rfc3339_opts(SecondsFormat::Secs, true)),
        reboot_needed: row.reboot_needed,
        exploited: row.exploited,
        kev: row.kev,
        euvd: row.euvd,
        kev_due: row.kev_due.map(|v| v.to_string()),
        ransomware: row.ransomware,
        epss: row.epss,
        epss_percentile: row.epss_percentile,
        cvss: row.cvss,
        source: row.source,
        match_method: row.match_method,
        confidence: row.confidence,
        match_basis: row.match_basis,
        triage_state: "open".into(),
        triage_version: 0,
        assigned_to: None,
    }
}

#[utoipa::path(get, path="/api/v1/compliance/groups", tag = "compliance", params(("since"=Option<String>, Query), ("cursor"=Option<String>, Query), ("limit"=Option<u16>, Query)), responses((status=200, description="Recent scope-filtered findings grouped by rule", body=crate::FindingGroupPage)))]
pub(crate) async fn authenticated_finding_groups(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    query: Result<Query<FindingGroupsParams>, QueryRejection>,
) -> Response {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use platform_store::console_read::{
        FindingGroupCursor, FindingGroupQuery, finding_groups_in_scope,
    };
    let scope = match authenticated_agent_scope(&state, &headers, crate::Permission::ComplianceRead)
        .await
    {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Query(params) = match query {
        Ok(v) => v,
        Err(_) => return invalid_finding_query(),
    };
    let cursor_token = match params.cursor.as_deref() {
        None => None,
        Some(encoded) if encoded.len() <= crate::MAX_CURSOR_LENGTH => {
            let bytes = match URL_SAFE_NO_PAD.decode(encoded) {
                Ok(v) => v,
                Err(_) => return invalid_finding_query(),
            };
            match serde_json::from_slice::<FindingGroupCursorToken>(&bytes) {
                Ok(token) => Some(token),
                Err(_) => return invalid_finding_query(),
            }
        }
        Some(_) => return invalid_finding_query(),
    };
    let since_text = params
        .since
        .or_else(|| cursor_token.as_ref().map(|v| v.since.clone()))
        .unwrap_or_else(|| {
            (Utc::now() - Duration::hours(24)).to_rfc3339_opts(SecondsFormat::Secs, true)
        });
    let since = match chrono::DateTime::parse_from_rfc3339(&since_text) {
        Ok(v) => v.with_timezone(&Utc),
        Err(_) => return invalid_finding_query(),
    };
    if since > Utc::now() || since < Utc::now() - Duration::days(90) {
        return invalid_finding_query();
    }
    let limit = match platform_store::console_read::PageLimit::new(
        params.limit.unwrap_or(crate::DEFAULT_PAGE_SIZE),
    ) {
        Some(v) => v,
        None => return invalid_finding_query(),
    };
    let after = match cursor_token {
        None => None,
        Some(token) if token.since == since_text && token.scope == scope => {
            let timestamp = match chrono::DateTime::parse_from_rfc3339(&token.last_observed_at) {
                Ok(v) => v.with_timezone(&Utc),
                Err(_) => return invalid_finding_query(),
            };
            Some(FindingGroupCursor {
                last_observed_at: timestamp,
                rule_set_id: token.rule_set_id,
                rule_id: token.rule_id,
            })
        }
        Some(_) => return invalid_finding_query(),
    };
    let client = match state.pool.get().await {
        Ok(v) => v,
        Err(_) => return unavailable_auth(),
    };
    let page = match finding_groups_in_scope(
        &client,
        &FindingGroupQuery {
            since,
            after,
            limit,
        },
        &scope,
    )
    .await
    {
        Ok(v) => v,
        Err(_) => return unavailable_auth(),
    };
    let items = page
        .items
        .into_iter()
        .map(|g| crate::FindingGroupView {
            rule_set_id: if g.rule_set_id.is_empty() {
                "~unknown".into()
            } else {
                g.rule_set_id
            },
            rule_id: g.rule_id,
            endpoint_count: g.endpoint_count.max(0) as u64,
            severity: match g.severity {
                platform_store::console_read::Severity::Critical => crate::Severity::Critical,
                platform_store::console_read::Severity::High => crate::Severity::High,
                platform_store::console_read::Severity::Medium => crate::Severity::Medium,
                platform_store::console_read::Severity::Low => crate::Severity::Low,
            },
            latest_message: g.latest_message,
            rule_versions: g
                .rule_versions
                .into_iter()
                .map(|v| v.max(0) as u64)
                .collect(),
            first_observed_at: g
                .first_observed_at
                .to_rfc3339_opts(SecondsFormat::Secs, true),
            last_observed_at: g
                .last_observed_at
                .to_rfc3339_opts(SecondsFormat::Secs, true),
            older_endpoint_count: g.older_endpoint_count.max(0) as u64,
            triage_counts: crate::FindingTriageCounts {
                open: g.open.max(0) as u64,
                mitigated: g.mitigated.max(0) as u64,
                accepted_risk: g.accepted_risk.max(0) as u64,
                false_positive: g.false_positive.max(0) as u64,
            },
        })
        .collect();
    let next_cursor = match page.next {
        None => None,
        Some(c) => match serde_json::to_vec(&FindingGroupCursorToken {
            since: since_text.clone(),
            scope,
            last_observed_at: c
                .last_observed_at
                .to_rfc3339_opts(SecondsFormat::Micros, true),
            rule_set_id: c.rule_set_id,
            rule_id: c.rule_id,
        }) {
            Ok(v) => Some(URL_SAFE_NO_PAD.encode(v)),
            Err(_) => return unavailable_auth(),
        },
    };
    Json(crate::FindingGroupPage {
        items,
        next_cursor,
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        since: since_text,
    })
    .into_response()
}

#[utoipa::path(get, path="/api/v1/compliance/groups/{rule_set_id}/{rule_id}/endpoints", tag = "compliance", params(("rule_set_id"=String,Path),("rule_id"=String,Path),("since"=Option<String>,Query),("include_older"=Option<bool>,Query),("cursor"=Option<String>,Query),("limit"=Option<u16>,Query)), responses((status=200,description="Scoped endpoints reporting one recent rule group",body=crate::FindingGroupEndpointPage),(status=404,description="Compliance finding group not found",body=crate::ProblemDetails)))]
pub(crate) async fn authenticated_finding_group_endpoints(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((rule_set_id, rule_id)): Path<(String, String)>,
    query: Result<Query<FindingGroupEndpointsParams>, QueryRejection>,
) -> Response {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use platform_store::console_read::{
        FindingGroupEndpointCursor, FindingGroupEndpointQuery, finding_group_endpoints_in_scope,
    };
    let scope = match authenticated_agent_scope(&state, &headers, crate::Permission::ComplianceRead)
        .await
    {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Query(params) = match query {
        Ok(v) => v,
        Err(_) => return invalid_finding_query(),
    };
    let cursor_token = match params.cursor.as_deref() {
        None => None,
        Some(encoded) if encoded.len() <= crate::MAX_CURSOR_LENGTH => {
            let bytes = match URL_SAFE_NO_PAD.decode(encoded) {
                Ok(v) => v,
                Err(_) => return invalid_finding_query(),
            };
            match serde_json::from_slice::<FindingGroupEndpointCursorToken>(&bytes) {
                Ok(token) => Some(token),
                Err(_) => return invalid_finding_query(),
            }
        }
        Some(_) => return invalid_finding_query(),
    };
    let since_text = params
        .since
        .or_else(|| cursor_token.as_ref().map(|v| v.since.clone()))
        .unwrap_or_else(|| {
            (Utc::now() - Duration::hours(24)).to_rfc3339_opts(SecondsFormat::Secs, true)
        });
    let since = match chrono::DateTime::parse_from_rfc3339(&since_text) {
        Ok(v) => v.with_timezone(&Utc),
        Err(_) => return invalid_finding_query(),
    };
    if since > Utc::now() || since < Utc::now() - Duration::days(90) {
        return invalid_finding_query();
    }
    let include_older = params.include_older.unwrap_or(false);
    let limit = match platform_store::console_read::PageLimit::new(
        params.limit.unwrap_or(crate::DEFAULT_PAGE_SIZE),
    ) {
        Some(v) => v,
        None => return invalid_finding_query(),
    };
    let actual_rule_set = if rule_set_id == "~unknown" {
        ""
    } else {
        &rule_set_id
    };
    let after = match cursor_token {
        None => None,
        Some(token)
            if token.since == since_text
                && token.include_older == include_older
                && token.scope == scope
                && token.rule_set_id == rule_set_id
                && token.rule_id == rule_id =>
        {
            let ts = match chrono::DateTime::parse_from_rfc3339(&token.last_observed_at) {
                Ok(v) => v.with_timezone(&Utc),
                Err(_) => return invalid_finding_query(),
            };
            Some(FindingGroupEndpointCursor {
                last_observed_at: ts,
                agent_id: token.agent_id,
            })
        }
        Some(_) => return invalid_finding_query(),
    };
    let client = match state.pool.get().await {
        Ok(v) => v,
        Err(_) => return unavailable_auth(),
    };
    let page = match finding_group_endpoints_in_scope(
        &client,
        actual_rule_set,
        &rule_id,
        &FindingGroupEndpointQuery {
            since,
            include_older,
            after,
            limit,
        },
        &scope,
    )
    .await
    {
        Ok(Some(v)) => v,
        Ok(None) => {
            return problem_response(ProblemDetails::not_found(
                "compliance_finding_not_found",
                "Compliance finding group not found",
            ));
        }
        Err(_) => return unavailable_auth(),
    };
    let items = page
        .items
        .into_iter()
        .map(|e| crate::FindingGroupEndpointView {
            agent_id: e.agent_id,
            hostname: e.hostname,
            first_observed_at: e
                .first_observed_at
                .to_rfc3339_opts(SecondsFormat::Secs, true),
            last_observed_at: e
                .last_observed_at
                .to_rfc3339_opts(SecondsFormat::Secs, true),
            rule_version: e.rule_version.max(0) as u64,
            triage_state: e.triage_state,
            triage_version: e.triage_version,
            assigned_to: e.assigned_to,
            accepted_until: e.accepted_until.map(|value| value.to_rfc3339()),
            ended_at: e.ended_at.map(|value| value.to_rfc3339()),
            end_approximate: e.end_approximate,
            outside_window: e.outside_window,
            origin: if e.origin == "import" {
                crate::FindingOrigin::Import
            } else {
                crate::FindingOrigin::Online
            },
            authenticated: e.authenticated,
        })
        .collect();
    let next_cursor = match page.next {
        None => None,
        Some(c) => match serde_json::to_vec(&FindingGroupEndpointCursorToken {
            since: since_text.clone(),
            include_older,
            scope,
            rule_set_id,
            rule_id,
            last_observed_at: c
                .last_observed_at
                .to_rfc3339_opts(SecondsFormat::Micros, true),
            agent_id: c.agent_id,
        }) {
            Ok(v) => Some(URL_SAFE_NO_PAD.encode(v)),
            Err(_) => return unavailable_auth(),
        },
    };
    Json(crate::FindingGroupEndpointPage {
        items,
        next_cursor,
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        since: since_text,
    })
    .into_response()
}

#[utoipa::path(post,path="/api/v1/compliance/groups/{rule_set_id}/{rule_id}/triage",tag = "compliance",params(("rule_set_id"=String,Path),("rule_id"=String,Path)),request_body=crate::BulkFindingTriageRequest,responses((status=200,description="Atomic endpoint triage update",body=crate::BulkFindingTriageResponse),(status=412,description="At least one triage version is stale",body=crate::ProblemDetails),(status=404,description="Group or endpoint is not visible",body=crate::ProblemDetails)))]
pub(crate) async fn update_authenticated_finding_group_triage(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((rule_set_id, rule_id)): Path<(String, String)>,
    payload: Result<Json<crate::BulkFindingTriageRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let (scope, user_id) =
        match authenticated_permission(&state, &headers, crate::Permission::ComplianceTriage, true)
            .await
        {
            Ok(v) => v,
            Err(r) => return r,
        };
    let Json(payload) = match payload {
        Ok(v) => v,
        Err(_) => {
            return problem_response(ProblemDetails::new(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Triage request is invalid",
            ));
        }
    };
    if payload.changes.is_empty()
        || payload.changes.len() > 100
        || payload.changes.iter().any(|x| {
            x.agent_id.is_empty()
                || x.agent_id.len() > 128
                || x.agent_id.chars().any(char::is_control)
        })
    {
        return problem_response(ProblemDetails::new(
            StatusCode::BAD_REQUEST,
            "invalid_triage",
            "Select between 1 and 100 endpoints",
        ));
    }
    let expiry = match payload
        .accepted_until
        .as_deref()
        .map(chrono::DateTime::parse_from_rfc3339)
        .transpose()
    {
        Ok(v) => v.map(|v| v.with_timezone(&Utc)),
        Err(_) => {
            return problem_response(ProblemDetails::new(
                StatusCode::BAD_REQUEST,
                "invalid_expiry",
                "accepted_until must be an RFC 3339 timestamp",
            ));
        }
    };
    let actual_rule_set = if rule_set_id == "~unknown" {
        ""
    } else {
        &rule_set_id
    };
    let changes: Vec<_> = payload
        .changes
        .iter()
        .map(|v| (v.agent_id.clone(), v.version))
        .collect();
    let mut client = match state.pool.get().await {
        Ok(v) => v,
        Err(_) => return unavailable_auth(),
    };
    let request_id = next_request_id();
    match platform_store::console_triage::update_many_with_request_id(
        &mut client,
        actual_rule_set,
        &rule_id,
        &changes,
        &scope,
        &payload.state,
        payload.assigned_to.as_deref(),
        payload.note.as_deref(),
        expiry,
        &user_id,
        Some(&request_id),
        Utc::now(),
    )
    .await
    {
        Ok(platform_store::console_triage::BulkTriageUpdate::Updated(records)) => {
            let updated = changes
                .iter()
                .zip(records)
                .map(|((id, _), record)| (id.clone(), triage_view(record)))
                .collect();
            let mut response = Json(crate::BulkFindingTriageResponse { updated }).into_response();
            response.headers_mut().insert(
                HeaderName::from_static("x-request-id"),
                HeaderValue::from_str(&request_id)
                    .expect("generated request IDs are valid headers"),
            );
            response
        }
        Ok(platform_store::console_triage::BulkTriageUpdate::Stale(items)) => {
            let mut p = ProblemDetails::new(
                StatusCode::PRECONDITION_FAILED,
                "stale_triage",
                "One or more selected endpoints changed; reload before saving",
            );
            p.field_errors = Some(
                items
                    .into_iter()
                    .map(|item| crate::FieldError {
                        field: "changes".into(),
                        code: "stale_version".into(),
                        message: format!(
                            "{} now has triage version {}",
                            item.agent_id, item.actual_version
                        ),
                    })
                    .collect(),
            );
            problem_response(p)
        }
        Ok(platform_store::console_triage::BulkTriageUpdate::NotFound) => {
            problem_response(ProblemDetails::not_found(
                "compliance_finding_not_found",
                "Compliance finding group or endpoint not found",
            ))
        }
        Ok(platform_store::console_triage::BulkTriageUpdate::InvalidTransition) => {
            problem_response(ProblemDetails::new(
                StatusCode::CONFLICT,
                "invalid_transition",
                "Requested triage transition is not allowed",
            ))
        }
        Ok(platform_store::console_triage::BulkTriageUpdate::InvalidFields) => {
            problem_response(ProblemDetails::new(
                StatusCode::BAD_REQUEST,
                "invalid_triage",
                "Triage state, note, expiry, or selection is invalid",
            ))
        }
        Ok(platform_store::console_triage::BulkTriageUpdate::AssigneeUnavailable) => {
            problem_response(ProblemDetails::new(
                StatusCode::BAD_REQUEST,
                "invalid_assignee",
                "Assignee must be an enabled analyst or admin",
            ))
        }
        Err(_) => unavailable_auth(),
    }
}
