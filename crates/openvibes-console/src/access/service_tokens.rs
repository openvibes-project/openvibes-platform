//! Service-account tokens: list, create and revoke.

use axum::{
    extract::{Json, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use platform_store::console_auth;

use crate::router::no_store;
use crate::{
    access::guard::{authenticated_permission, unavailable_auth},
    http::{
        AuthHttpState,
        problem::{ProblemDetails, problem_response},
    },
};

/// Lists a service account's secret-free token metadata.
#[utoipa::path(get,path="/api/v1/service-accounts/{service_account_id}/tokens",tag="service_accounts",params(("service_account_id"=String,Path)),responses((status=200,description="Service-token metadata",body=crate::ServiceTokenPage),(status=404,description="Service account not found",body=ProblemDetails)))]
pub(crate) async fn authenticated_service_tokens(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(service_account_id): Path<String>,
) -> Response {
    use chrono::SecondsFormat;
    let (scope, actor) = match authenticated_permission(
        &state,
        &headers,
        crate::Permission::ServiceAccountsRead,
        false,
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
    let client = match state.pool.get().await {
        Ok(value) => value,
        Err(_) => return unavailable_auth(),
    };
    let tokens = match console_auth::list_service_tokens(&client, &service_account_id).await {
        Ok(Some(value)) => value,
        Ok(None) => {
            return problem_response(ProblemDetails::new(
                StatusCode::NOT_FOUND,
                "service_account_not_found",
                "Service account not found",
            ));
        }
        Err(_) => return unavailable_auth(),
    };
    if platform_store::audit::record(
        &client,
        &actor,
        "service_tokens.viewed",
        Some(&service_account_id),
        "success",
    )
    .await
    .is_err()
    {
        return unavailable_auth();
    }
    no_store(
        Json(crate::ServiceTokenPage {
            items: tokens
                .into_iter()
                .map(|token| crate::ServiceTokenView {
                    token_id: token.token_id,
                    label: token.label,
                    created_at: token
                        .created_at
                        .to_rfc3339_opts(SecondsFormat::Millis, true),
                    expires_at: token
                        .expires_at
                        .to_rfc3339_opts(SecondsFormat::Millis, true),
                    revoked: token.revoked,
                })
                .collect(),
        })
        .into_response(),
    )
}

/// Issues an expiring service bearer secret once.
#[utoipa::path(
    post,
    path="/api/v1/service-accounts/{service_account_id}/tokens",
    tag="service_accounts",
    params(("service_account_id"=String,Path),("Idempotency-Key"=String,Header,description="Required retry key; a replay never returns the secret")),
    request_body=crate::CreateServiceTokenRequest,
    responses(
        (status=201,description="Token secret shown once",body=crate::CreatedServiceToken),
        (status=200,description="Idempotent replay; secret unavailable",body=crate::CreatedServiceToken),
        (status=404,description="Service account is missing or disabled",body=ProblemDetails),
        (status=409,description="Idempotency key was reused with different settings",body=ProblemDetails)
    )
)]
pub(crate) async fn create_authenticated_service_token(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(service_account_id): Path<String>,
    Json(request): Json<crate::CreateServiceTokenRequest>,
) -> Response {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use chrono::Duration;
    use ring::{
        digest,
        rand::{SecureRandom, SystemRandom},
    };
    use zeroize::Zeroize;
    let label = request.label.trim();
    if !(1..=8760).contains(&request.expires_in_hours)
        || label.chars().count() > 128
        || label.chars().any(char::is_control)
    {
        return problem_response(ProblemDetails::new(
            StatusCode::BAD_REQUEST,
            "invalid_service_token",
            "Provide a label of at most 128 characters and expiry from 1 to 8760 hours",
        ));
    }
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
    let (scope, actor) = match authenticated_permission(
        &state,
        &headers,
        crate::Permission::ServiceAccountsManage,
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
    let mut secret = [0u8; 32];
    if SystemRandom::new().fill(&mut secret).is_err() {
        return unavailable_auth();
    }
    let token = zeroize::Zeroizing::new(format!("ovc_{}", URL_SAFE_NO_PAD.encode(secret)));
    let hash = crate::access::auth::session_digest(token.as_str());
    secret.zeroize();
    let now = Utc::now();
    let expires_at = now + Duration::hours(i64::from(request.expires_in_hours));
    let mut idempotency_hash = [0u8; 32];
    idempotency_hash
        .copy_from_slice(digest::digest(&digest::SHA256, idempotency_key.as_bytes()).as_ref());
    let request_bytes =
        serde_json::to_vec(&(service_account_id.as_str(), label, request.expires_in_hours))
            .unwrap_or_default();
    let mut request_hash = [0u8; 32];
    request_hash.copy_from_slice(digest::digest(&digest::SHA256, &request_bytes).as_ref());
    let mut client = match state.pool.get().await {
        Ok(value) => value,
        Err(_) => return unavailable_auth(),
    };
    let creation = match console_auth::create_service_token(
        &mut client,
        &console_auth::NewServiceToken {
            service_account_id: &service_account_id,
            secret_sha256: &hash,
            label,
            actor_id: &actor,
            now,
            expires_at,
            idempotency_key_sha256: &idempotency_hash,
            request_sha256: &request_hash,
        },
    )
    .await
    {
        Ok(value) => value,
        Err(_) => return unavailable_auth(),
    };
    let (status, token_id, expiry, secret, replayed) = match creation {
        console_auth::ServiceTokenCreation::Created { token_id } => (
            StatusCode::CREATED,
            token_id,
            expires_at,
            Some(token.to_string()),
            false,
        ),
        console_auth::ServiceTokenCreation::Replayed {
            token_id,
            expires_at,
        } => (StatusCode::OK, token_id, expires_at, None, true),
        console_auth::ServiceTokenCreation::Conflict => {
            return problem_response(ProblemDetails::new(
                StatusCode::CONFLICT,
                "idempotency_conflict",
                "This Idempotency-Key was already used with different token settings",
            ));
        }
        console_auth::ServiceTokenCreation::MissingAccount => {
            return problem_response(ProblemDetails::new(
                StatusCode::NOT_FOUND,
                "service_account_not_found",
                "Service account not found or disabled",
            ));
        }
    };
    let mut response = (
        status,
        Json(crate::CreatedServiceToken {
            token_id,
            token: secret,
            replayed,
            secret_available: !replayed,
            expires_at: expiry.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        }),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Revokes one service bearer token.
#[utoipa::path(post,path="/api/v1/service-accounts/{service_account_id}/tokens/{token_id}/revoke",tag="service_accounts",params(("service_account_id"=String,Path),("token_id"=String,Path)),responses((status=204,description="Service token revoked"),(status=404,description="Token not found",body=ProblemDetails)))]
pub(crate) async fn revoke_authenticated_service_token(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((service_account_id, token_id)): Path<(String, String)>,
) -> Response {
    let (scope, actor) = match authenticated_permission(
        &state,
        &headers,
        crate::Permission::ServiceAccountsManage,
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
    let mut client = match state.pool.get().await {
        Ok(value) => value,
        Err(_) => return unavailable_auth(),
    };
    match console_auth::revoke_service_token(
        &mut client,
        &service_account_id,
        &token_id,
        &actor,
        Utc::now(),
    )
    .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => problem_response(ProblemDetails::new(
            StatusCode::NOT_FOUND,
            "service_token_not_found",
            "Service token not found or already revoked",
        )),
        Err(_) => unavailable_auth(),
    }
}
