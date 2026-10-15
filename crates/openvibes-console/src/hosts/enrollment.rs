//! Enrollment tokens: list, read, create, revoke.

use axum::{
    extract::{Json, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use zeroize::Zeroizing;

use crate::{
    access::guard::{authenticated_permission, unavailable_auth},
    http::{
        AuthHttpState,
        problem::{ProblemDetails, problem_response},
    },
    http::{headers::no_store, validate::valid_uuid},
};

/// Lists bounded, secret-free enrollment-token metadata.
#[utoipa::path(get,path="/api/v1/enrollment-tokens",tag="enrollment",responses((status=200,description="Newest 100 enrollment tokens without secret material",body=crate::EnrollmentTokenPage)))]
pub(crate) async fn authenticated_enrollment_tokens(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    use chrono::SecondsFormat;
    use platform_store::console_read::AgentScope;
    let (scope, actor) = match authenticated_permission(
        &state,
        &headers,
        crate::Permission::TokensRead,
        false,
    )
    .await
    {
        Ok(v) => v,
        Err(response) => return response,
    };
    if !matches!(scope, AgentScope::Global) {
        return problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "Access is not available",
        ));
    }
    let client = match state.pool.get().await {
        Ok(v) => v,
        Err(_) => return unavailable_auth(),
    };
    let tokens = match platform_store::console_auth::list_enrollment_tokens(&client, 100).await {
        Ok(v) => v,
        Err(_) => return unavailable_auth(),
    };
    if platform_store::audit::record(
        &client,
        &actor,
        "enrollment_tokens.viewed",
        Some("enrollment_tokens"),
        "success",
    )
    .await
    .is_err()
    {
        return unavailable_auth();
    }
    let response = Json(crate::EnrollmentTokenPage {
        items: tokens
            .into_iter()
            .map(|token| crate::EnrollmentTokenView {
                token_id: token.token_id,
                label: token.label,
                created_at: token
                    .created_at
                    .to_rfc3339_opts(SecondsFormat::Millis, true),
                expires_at: token
                    .expires_at
                    .to_rfc3339_opts(SecondsFormat::Millis, true),
                max_uses: token.max_uses,
                uses: token.uses,
                revoked: token.revoked,
                standing: token.standing,
            })
            .collect(),
    })
    .into_response();
    no_store(response)
}

/// Reads one enrollment-token record without revealing its secret.
#[utoipa::path(get,path="/api/v1/enrollment-tokens/{token_id}",tag="enrollment",params(("token_id"=String,Path)),responses((status=200,description="Secret-free token metadata",body=crate::EnrollmentTokenView),(status=404,description="Token not found",body=ProblemDetails)))]
pub(crate) async fn authenticated_enrollment_token(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(token_id): Path<String>,
) -> Response {
    use chrono::SecondsFormat;
    use platform_store::console_read::AgentScope;
    let (scope, actor) = match authenticated_permission(
        &state,
        &headers,
        crate::Permission::TokensRead,
        false,
    )
    .await
    {
        Ok(v) => v,
        Err(response) => return response,
    };
    if !matches!(scope, AgentScope::Global) {
        return problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "Access is not available",
        ));
    }
    let client = match state.pool.get().await {
        Ok(v) => v,
        Err(_) => return unavailable_auth(),
    };
    let token = match platform_store::console_auth::enrollment_token(&client, &token_id).await {
        Ok(Some(v)) => v,
        Ok(None) => {
            return problem_response(ProblemDetails::new(
                StatusCode::NOT_FOUND,
                "token_not_found",
                "Enrollment token not found",
            ));
        }
        Err(_) => return unavailable_auth(),
    };
    if platform_store::audit::record(
        &client,
        &actor,
        "enrollment_token.viewed",
        Some(&token_id),
        "success",
    )
    .await
    .is_err()
    {
        return unavailable_auth();
    }
    no_store(
        Json(crate::EnrollmentTokenView {
            token_id: token.token_id,
            label: token.label,
            created_at: token
                .created_at
                .to_rfc3339_opts(SecondsFormat::Millis, true),
            expires_at: token
                .expires_at
                .to_rfc3339_opts(SecondsFormat::Millis, true),
            max_uses: token.max_uses,
            uses: token.uses,
            revoked: token.revoked,
            standing: token.standing,
        })
        .into_response(),
    )
}

/// Creates an enrollment token, returning the secret once and storing only its hash.
#[utoipa::path(
    post,
    path="/api/v1/enrollment-tokens",
    tag="enrollment",
    request_body=crate::CreateEnrollmentTokenRequest,
    params(("Idempotency-Key" = String, Header, description = "Required retry key; same key and request replays metadata without the secret")),
    responses(
        (status=201,description="Token secret shown once",body=crate::CreatedEnrollmentToken),
        (status=200,description="Idempotent replay; secret unavailable",body=crate::CreatedEnrollmentToken),
        (status=400,description="Invalid token settings",body=ProblemDetails),
        (status=409,description="Idempotency key was used with different settings",body=ProblemDetails)
    )
)]
pub(crate) async fn create_authenticated_enrollment_token(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Json(request): Json<crate::CreateEnrollmentTokenRequest>,
) -> Response {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use chrono::Duration;
    use platform_store::console_read::AgentScope;
    use ring::{
        digest,
        rand::{SecureRandom, SystemRandom},
    };
    use zeroize::Zeroize;
    let Some(idempotency_key) = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .filter(|key| {
            (16..=128).contains(&key.len()) && key.bytes().all(|byte| byte.is_ascii_graphic())
        })
    else {
        return problem_response(ProblemDetails::new(
            StatusCode::BAD_REQUEST,
            "idempotency_key_required",
            "Provide an Idempotency-Key header between 16 and 128 visible ASCII characters",
        ));
    };
    if !(1..=8760).contains(&request.expires_in_hours)
        || !(1..=100_000).contains(&request.max_uses)
        || request
            .label
            .as_deref()
            .is_some_and(|label| label.chars().count() > 128 || label.chars().any(char::is_control))
    {
        return problem_response(ProblemDetails::new(
            StatusCode::BAD_REQUEST,
            "invalid_enrollment_token",
            "Expiry must be 1 to 8760 hours, uses 1 to 100000, and label at most 128 characters",
        ));
    }
    let (scope, actor) =
        match authenticated_permission(&state, &headers, crate::Permission::TokensCreate, true)
            .await
        {
            Ok(v) => v,
            Err(response) => return response,
        };
    if !matches!(scope, AgentScope::Global) {
        return problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "Access is not available",
        ));
    }
    let mut secret = [0u8; 32];
    if SystemRandom::new().fill(&mut secret).is_err() {
        return unavailable_auth();
    }
    let token = Zeroizing::new(URL_SAFE_NO_PAD.encode(secret));
    let digest_bytes = digest::digest(&digest::SHA256, &secret);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(digest_bytes.as_ref());
    secret.zeroize();
    let mut idempotency_hash = [0u8; 32];
    idempotency_hash
        .copy_from_slice(digest::digest(&digest::SHA256, idempotency_key.as_bytes()).as_ref());
    let request_body =
        serde_json::to_vec(&(request.expires_in_hours, request.max_uses, &request.label))
            .unwrap_or_default();
    let mut request_hash = [0u8; 32];
    request_hash.copy_from_slice(digest::digest(&digest::SHA256, &request_body).as_ref());
    let now = Utc::now();
    let expires_at = now + Duration::hours(i64::from(request.expires_in_hours));
    let mut client = match state.pool.get().await {
        Ok(v) => v,
        Err(_) => return unavailable_auth(),
    };
    let creation = match platform_store::console_auth::create_enrollment_token(
        &mut client,
        &platform_store::console_auth::NewConsoleEnrollmentToken {
            secret_sha256: &hash,
            label: request.label.as_deref(),
            actor_id: &actor,
            now,
            expires_at,
            max_uses: request.max_uses as i32,
            idempotency_key_sha256: &idempotency_hash,
            request_sha256: &request_hash,
        },
    )
    .await
    {
        Ok(creation) => creation,
        Err(_) => return unavailable_auth(),
    };
    let (status, token_id, response_expiry, response_token, replayed) = match creation {
        platform_store::console_auth::EnrollmentTokenCreation::Created { token_id } => (
            StatusCode::CREATED,
            token_id,
            expires_at,
            Some(token.as_str().to_owned()),
            false,
        ),
        platform_store::console_auth::EnrollmentTokenCreation::Replayed {
            token_id,
            expires_at,
        } => (StatusCode::OK, token_id, expires_at, None, true),
        platform_store::console_auth::EnrollmentTokenCreation::Conflict => {
            return problem_response(ProblemDetails::new(
                StatusCode::CONFLICT,
                "idempotency_conflict",
                "This Idempotency-Key was already used with different token settings",
            ));
        }
    };
    let response = (
        status,
        Json(crate::CreatedEnrollmentToken {
            token_id,
            token: response_token,
            replayed,
            secret_available: !replayed,
            expires_at: response_expiry.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        }),
    )
        .into_response();
    no_store(response)
}

/// Revokes one enrollment token under the global `tokens.revoke` permission.
#[utoipa::path(post,path="/api/v1/enrollment-tokens/{token_id}/revoke",tag="enrollment",params(("token_id"=String,Path)),responses((status=204,description="Token revoked"),(status=404,description="Token not found or already revoked",body=ProblemDetails)))]
pub(crate) async fn revoke_authenticated_enrollment_token(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(token_id): Path<String>,
) -> Response {
    use platform_store::console_read::AgentScope;
    if !valid_uuid(&token_id) {
        return problem_response(ProblemDetails::not_found(
            "token_not_found",
            "Token not found",
        ));
    }
    let (scope, actor) =
        match authenticated_permission(&state, &headers, crate::Permission::TokensRevoke, true)
            .await
        {
            Ok(v) => v,
            Err(response) => return response,
        };
    if !matches!(scope, AgentScope::Global) {
        return problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "Access is not available",
        ));
    }
    let mut client = match state.pool.get().await {
        Ok(v) => v,
        Err(_) => return unavailable_auth(),
    };
    match platform_store::console_auth::revoke_enrollment_token(
        &mut client,
        &token_id,
        &actor,
        Utc::now(),
    )
    .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => problem_response(ProblemDetails::not_found(
            "token_not_found",
            "Token not found or already revoked",
        )),
        Err(_) => unavailable_auth(),
    }
}
