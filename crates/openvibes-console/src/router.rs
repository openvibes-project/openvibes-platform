use std::sync::Arc;

use axum::{
    extract::{Json, Path, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::Utc;

use crate::{
    access::guard::{authenticated_permission, unavailable_auth},
    http::{
        AuthHttpState,
        middleware::assistant_answer_timeout,
        problem::{ProblemDetails, next_request_id, problem_response},
    },
};

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
