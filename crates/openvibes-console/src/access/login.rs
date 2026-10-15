//! Sign-in: the pre-login challenge, login and logout.

use axum::{
    extract::{ConnectInfo, Extension, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::{Duration, Utc};
use platform_store::console_auth;
use zeroize::{Zeroize, Zeroizing};

use super::throttle::{ACCOUNT_FAILURE_LIMIT, SOURCE_FAILURE_LIMIT, login_throttle_buckets};
use crate::http::{
    AuthHttpState,
    middleware::request_origin,
    problem::{ProblemDetails, problem_response},
};
use platform_password::canonical_username;

#[utoipa::path(
    get,
    path = "/auth/v1/preauth",
    tag = "authentication",
    responses(
        (status = 200, description = "One-use login challenge", body = crate::PreauthResponse),
        (status = 503, description = "Authentication unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(crate) async fn preauth(State(state): State<AuthHttpState>) -> Response {
    use crate::access::auth::{SessionSecret, session_csrf, session_digest};

    let (Ok(preauth_secret), Ok(browser_secret)) =
        (SessionSecret::generate(), SessionSecret::generate())
    else {
        return problem_response(ProblemDetails::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication_unavailable",
            "Authentication is temporarily unavailable",
        ));
    };
    let (csrf_token, csrf_digest) = session_csrf(preauth_secret.cookie_value());
    let token_digest = session_digest(preauth_secret.cookie_value());
    let browser_digest = session_digest(browser_secret.cookie_value());
    let now = Utc::now();
    let client = match state.pool.get().await {
        Ok(client) => client,
        Err(_) => {
            return problem_response(ProblemDetails::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "authentication_unavailable",
                "Authentication is temporarily unavailable",
            ));
        }
    };
    if console_auth::create_preauth(
        &client,
        &console_auth::NewPreauth {
            token_sha256: &token_digest,
            csrf_sha256: &csrf_digest,
            browser_sha256: &browser_digest,
            created_at: now,
            expires_at: now + Duration::minutes(5),
        },
    )
    .await
    .is_err()
    {
        return problem_response(ProblemDetails::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication_unavailable",
            "Authentication is temporarily unavailable",
        ));
    }
    let mut response = (
        StatusCode::OK,
        axum::Json(crate::PreauthResponse { csrf_token }),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    let preauth_cookie = format!(
        "__Host-openvibes-preauth={}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=300",
        preauth_secret.cookie_value()
    );
    let browser_cookie = format!(
        "__Host-openvibes-browser={}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=300",
        browser_secret.cookie_value()
    );
    for cookie in [preauth_cookie, browser_cookie] {
        if let Ok(value) = HeaderValue::from_str(&cookie) {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
    response
}

#[utoipa::path(
    post,
    path = "/auth/v1/login",
    tag = "authentication",
    request_body = crate::LoginRequest,
    params(
        ("Origin" = String, Header, description = "Must exactly match the configured public origin"),
        ("X-CSRF-Token" = String, Header, description = "One-use token returned by pre-authentication"),
        ("Cookie" = String, Header, description = "Pre-auth and browser-binding cookies")
    ),
    responses(
        (status = 200, description = "Authenticated; sets an opaque session cookie", body = crate::LoginResponse),
        (status = 400, description = "Malformed authentication request", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Generic invalid credentials response", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Origin or CSRF check failed", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Authentication unavailable or busy", body = crate::ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(crate) async fn login(
    State(state): State<AuthHttpState>,
    ConnectInfo(peer): ConnectInfo<crate::TrustedPeer>,
    proxy_client: Option<Extension<crate::server::TrustedProxyClient>>,
    headers: HeaderMap,
    payload: Result<axum::Json<crate::LoginRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    use crate::access::auth::{
        NormalizedPassword, SessionSecret, browser_origin_allowed, csrf_token_matches,
        hash_password, named_cookie, session_cookie, session_csrf, session_digest, verify_password,
    };

    if !state.public_origin_valid
        || !browser_origin_allowed(&headers, &request_origin(&state, &headers))
        || headers.contains_key(header::AUTHORIZATION)
    {
        return problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "request_rejected",
            "The authentication request was rejected",
        ));
    }
    let axum::Json(body) = match payload {
        Ok(body) => body,
        Err(_) => {
            return problem_response(ProblemDetails::new(
                StatusCode::BAD_REQUEST,
                "invalid_auth_request",
                "The authentication request is invalid",
            ));
        }
    };
    let previous_session_hash = match named_cookie(&headers, "__Host-openvibes-session") {
        Ok(Some(secret)) => Some(session_digest(secret.expose_secret())),
        Ok(None) => None,
        Err(_) => return login_rejected(),
    };
    let preauth_secret = match named_cookie(&headers, "__Host-openvibes-preauth") {
        Ok(Some(secret)) => secret,
        _ => return login_rejected(),
    };
    let browser_secret = match named_cookie(&headers, "__Host-openvibes-browser") {
        Ok(Some(secret)) => secret,
        _ => return login_rejected(),
    };
    let expected_csrf = Zeroizing::new(session_csrf(preauth_secret.expose_secret()).0);
    if !csrf_token_matches(&headers, &expected_csrf) {
        return problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "request_rejected",
            "The authentication request was rejected",
        ));
    }
    let Some(dummy_phc) = state.dummy_password_phc.clone() else {
        return auth_unavailable();
    };
    let now = Utc::now();
    let mut client = match state.pool.get().await {
        Ok(client) => client,
        Err(_) => return auth_unavailable(),
    };
    let token_digest = session_digest(preauth_secret.expose_secret());
    let csrf_digest = session_digest(&expected_csrf);
    let browser_digest = session_digest(browser_secret.expose_secret());
    let preauth_ok =
        console_auth::consume_preauth(&client, &token_digest, &csrf_digest, &browser_digest, now)
            .await;
    match preauth_ok {
        Ok(true) => {}
        Ok(false) => return login_rejected(),
        Err(_) => return auth_unavailable(),
    }

    let username = canonical_username(&body.username);
    let source = proxy_client
        .as_ref()
        .and_then(|Extension(proxy)| proxy.source)
        .map(|address| address.to_string())
        .unwrap_or_else(|| peer.source_label());
    let source_for_limit = match proxy_client {
        Some(Extension(proxy)) => proxy.source.map(|address| address.to_string()),
        None => Some(peer.source_label()),
    };
    let (account_bucket, source_bucket) =
        login_throttle_buckets(username.as_deref(), source_for_limit.as_deref());
    let mut buckets: Vec<&[u8]> = vec![&account_bucket];
    let mut failure_limits = vec![ACCOUNT_FAILURE_LIMIT];
    if let Some(source_bucket) = source_bucket.as_ref() {
        buckets.push(source_bucket);
        failure_limits.push(SOURCE_FAILURE_LIMIT);
    }
    let throttled = match console_auth::login_is_throttled(&client, &buckets, now).await {
        Ok(throttled) => throttled,
        Err(_) => return auth_unavailable(),
    };
    let credential = if throttled || username.is_none() {
        None
    } else {
        match console_auth::credential_by_username(&client, username.as_deref().unwrap()).await {
            Ok(credential) => credential,
            Err(_) => return auth_unavailable(),
        }
    };
    let phc = credential
        .as_ref()
        .filter(|credential| credential.enabled)
        .map(|credential| credential.password_phc.clone())
        .unwrap_or(dummy_phc);
    let password_valid_input = NormalizedPassword::for_verification(&body.password).is_ok();
    let normalized = NormalizedPassword::for_verification(&body.password)
        .or_else(|_| NormalizedPassword::for_verification("invalid bounded input"))
        .expect("fixed verification input is bounded");
    let permit = match state.password_slots.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return problem_response(ProblemDetails::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "authentication_busy",
                "Authentication is temporarily busy",
            ));
        }
    };
    let dummy_for_invalid_credential = state.dummy_password_phc.clone().unwrap_or_default();
    let verification = match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let verification = match verify_password(&normalized, &phc) {
            Ok(verification) => verification,
            Err(_) => {
                verify_password(&normalized, &dummy_for_invalid_credential)?;
                crate::PasswordVerification {
                    valid: false,
                    needs_rehash: false,
                }
            }
        };
        let upgraded_phc = if verification.valid && verification.needs_rehash {
            Some(hash_password(&normalized)?.as_str().to_owned())
        } else {
            None
        };
        Ok::<_, crate::PasswordHashError>((verification, upgraded_phc))
    })
    .await
    {
        Ok(Ok(verification)) => verification,
        Ok(Err(_)) => return auth_unavailable(),
        Err(_) => return auth_unavailable(),
    };
    let succeeded = password_valid_input
        && !throttled
        && credential
            .as_ref()
            .is_some_and(|credential| credential.enabled)
        && verification.0.valid;
    if !succeeded {
        let user_agent = bounded_user_agent(&headers);
        let audit = console_auth::AuditContext {
            request_id: None,
            source_address: Some(&source),
            user_agent: user_agent.as_deref(),
        };
        if console_auth::record_login_failure(
            &mut client,
            &buckets,
            now,
            Duration::minutes(15),
            &failure_limits,
            Duration::minutes(15),
            &audit,
        )
        .await
        .is_err()
        {
            return auth_unavailable();
        }
        return login_rejected();
    }
    let credential = credential.expect("success requires a stored credential");
    if let Some(upgraded_phc) = verification.1.as_deref() {
        let user_agent = bounded_user_agent(&headers);
        let audit = console_auth::AuditContext {
            request_id: None,
            source_address: Some(&source),
            user_agent: user_agent.as_deref(),
        };
        if !matches!(
            console_auth::rehash_password(
                &mut client,
                &credential.user_id,
                credential.auth_generation,
                upgraded_phc,
                now,
                &audit,
            )
            .await,
            Ok(true)
        ) {
            return auth_unavailable();
        }
    }
    if console_auth::clear_login_throttle(&client, &buckets, now)
        .await
        .is_err()
    {
        return auth_unavailable();
    }
    let session_secret = match SessionSecret::generate() {
        Ok(secret) => secret,
        Err(_) => return auth_unavailable(),
    };
    let (csrf_token, csrf_hash) = session_csrf(session_secret.cookie_value());
    let _csrf_token = Zeroizing::new(csrf_token);
    let session_hash = session_digest(session_secret.cookie_value());
    let user_agent = bounded_user_agent(&headers);
    let session_audit = console_auth::AuditContext {
        request_id: None,
        source_address: Some(&source),
        user_agent: user_agent.as_deref(),
    };
    match console_auth::create_session(
        &mut client,
        &console_auth::NewSession {
            session_sha256: &session_hash,
            previous_session_sha256: previous_session_hash.as_ref().map(<[u8; 32]>::as_slice),
            csrf_sha256: &csrf_hash,
            user_id: &credential.user_id,
            auth_generation: credential.auth_generation,
            now,
            idle_expires_at: now + Duration::minutes(30),
            absolute_expires_at: now + Duration::hours(8),
            audit: session_audit,
        },
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => return login_rejected(),
        Err(_) => return auth_unavailable(),
    }
    let mut response = (
        StatusCode::OK,
        axum::Json(crate::LoginResponse {
            authenticated: true,
        }),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    let mut cookie_value = session_cookie(&session_secret);
    if let Ok(value) = HeaderValue::from_str(&cookie_value) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    cookie_value.zeroize();
    for cookie in ["__Host-openvibes-preauth", "__Host-openvibes-browser"] {
        response.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_static(match cookie {
                "__Host-openvibes-preauth" => {
                    "__Host-openvibes-preauth=; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"
                }
                _ => "__Host-openvibes-browser=; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=0",
            }),
        );
    }
    response
}

#[utoipa::path(
    post,
    path = "/auth/v1/logout",
    tag = "authentication",
    params(
        ("Origin" = String, Header, description = "Must exactly match the configured public origin"),
        ("X-CSRF-Token" = String, Header, description = "Synchronizer token returned by the session route"),
        ("Cookie" = String, Header, description = "Opaque browser session cookie")
    ),
    responses(
        (status = 204, description = "Session revoked and cookie cleared"),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Origin or CSRF check failed", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Authentication unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(crate) async fn logout(
    State(state): State<AuthHttpState>,
    request: axum::extract::Request,
) -> Response {
    use crate::access::auth::{
        browser_origin_allowed, csrf_token_matches, named_cookie, session_digest,
    };

    let headers = request.headers();
    if !state.public_origin_valid
        || !browser_origin_allowed(headers, &request_origin(&state, headers))
        || headers.contains_key(header::AUTHORIZATION)
    {
        return problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "request_rejected",
            "The authentication request was rejected",
        ));
    }
    let secret = match named_cookie(headers, "__Host-openvibes-session") {
        Ok(Some(secret)) => secret,
        _ => return login_rejected(),
    };
    let (expected_csrf, _) = crate::access::auth::session_csrf(secret.expose_secret());
    let expected_csrf = Zeroizing::new(expected_csrf);
    if !csrf_token_matches(headers, &expected_csrf) {
        return problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "request_rejected",
            "The authentication request was rejected",
        ));
    }
    let session_hash = session_digest(secret.expose_secret());
    let mut client = match state.pool.get().await {
        Ok(client) => client,
        Err(_) => return auth_unavailable(),
    };
    let now = Utc::now();
    let source = request
        .extensions()
        .get::<ConnectInfo<crate::TrustedPeer>>()
        .map(|ConnectInfo(address)| address.source_label());
    let user_agent = bounded_user_agent(headers);
    let audit = console_auth::AuditContext {
        request_id: None,
        source_address: source.as_deref(),
        user_agent: user_agent.as_deref(),
    };
    if console_auth::revoke_session(&mut client, &session_hash, now, &audit)
        .await
        .is_err()
    {
        return auth_unavailable();
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "__Host-openvibes-session=; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=0",
        ),
    );
    response
}

pub(crate) fn bounded_user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.chars().take(256).collect::<String>())
}

pub(crate) fn dummy_password_phc() -> Option<String> {
    platform_password::dummy_password_phc().map(str::to_owned)
}

fn login_rejected() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::UNAUTHORIZED,
        "authentication_failed",
        "Username or password is incorrect",
    ))
}

fn auth_unavailable() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "authentication_unavailable",
        "Authentication is temporarily unavailable",
    ))
}
