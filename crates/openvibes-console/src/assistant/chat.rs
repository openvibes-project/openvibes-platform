use std::sync::Arc;

use axum::{
    extract::{Json, State},
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
        crate::assistant::internet::current_level(&state.pool).await,
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
