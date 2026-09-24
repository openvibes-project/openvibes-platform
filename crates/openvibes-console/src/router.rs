use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use axum::{
    Router,
    extract::{ConnectInfo, DefaultBodyLimit, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::{Duration, SecondsFormat, Utc};
use platform_store::{Pool, console_auth};
use std::net::SocketAddr;
use subtle::ConstantTimeEq;
use tokio::{sync::Semaphore, time::timeout};
use zeroize::{Zeroize, Zeroizing};

use crate::problem::{ProblemDetails, next_request_id, problem_response};

const MAX_REQUEST_BODY_BYTES: usize = 1_048_576;
const MAX_IN_FLIGHT_REQUESTS: usize = 128;
const REQUEST_DEADLINE: std::time::Duration = std::time::Duration::from_secs(15);
// ponytail: one shared router cap; split API and asset budgets if one starves the other.

#[cfg(feature = "embedded-ui")]
use axum::extract::Path;

#[cfg(feature = "embedded-ui")]
use crate::assets::{self, CachePolicy};
#[cfg(feature = "embedded-ui")]
use crate::frontend_contract::{BROWSER_ROUTES, PUBLIC_ASSETS};

/// Process-readiness state shared with the loopback-only health router.
#[derive(Clone, Debug, Default)]
pub struct Readiness(Arc<AtomicBool>);

#[derive(Clone)]
struct AuthHttpState {
    pool: Pool,
    public_origin: Arc<str>,
    public_origin_valid: bool,
    dummy_password_phc: Option<String>,
    password_slots: Arc<Semaphore>,
}

impl Readiness {
    /// Creates a readiness handle with the requested initial state.
    pub fn new(ready: bool) -> Self {
        Self(Arc::new(AtomicBool::new(ready)))
    }

    /// Changes the readiness response returned by `/ready`.
    pub fn set(&self, ready: bool) {
        self.0.store(ready, Ordering::Release);
    }

    fn get(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Builds the public C0 router.
///
/// It intentionally contains no health endpoints, permissive temporary
/// authentication, or catch-all SPA fall-through. When `embedded-ui` is
/// enabled, only the explicitly declared browser routes receive the SPA entry
/// document.
pub fn public_router() -> Router {
    with_request_limits(public_routes())
}

/// Builds the authenticated C3 router backed by the shared PostgreSQL store.
/// Data routes remain absent until every query applies SQL-enforced asset scope.
pub fn authenticated_router(pool: Pool, public_origin: impl Into<Arc<str>>) -> Router {
    let public_origin = public_origin.into();
    let state = AuthHttpState {
        pool,
        public_origin_valid: valid_public_origin(&public_origin),
        public_origin,
        dummy_password_phc: dummy_password_phc(),
        password_slots: Arc::new(Semaphore::new(4)),
    };
    let router = Router::new()
        .nest("/api", authenticated_api_router().with_state(state.clone()))
        .nest("/auth", authenticated_auth_router().with_state(state))
        .nest("/assets", asset_router());
    #[cfg(feature = "embedded-ui")]
    let router = router.merge(frontend_router());
    with_request_limits(router.fallback(browser_not_found))
}

fn public_routes() -> Router {
    let router = Router::new()
        .nest("/api", api_router())
        .nest("/auth", Router::new().fallback(auth_not_found))
        .nest("/assets", asset_router());

    #[cfg(feature = "embedded-ui")]
    let router = router.merge(frontend_router());

    router.fallback(browser_not_found)
}

fn with_request_limits(router: Router) -> Router {
    router
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .layer(middleware::from_fn_with_state(
            Arc::new(Semaphore::new(MAX_IN_FLIGHT_REQUESTS)),
            request_limits,
        ))
        .layer(middleware::map_response(public_security_headers))
        .layer(middleware::from_fn(request_logging))
}

async fn request_logging(request: axum::extract::Request, next: middleware::Next) -> Response {
    let method = request.method().clone();
    let path = request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|matched| matched.as_str())
        .unwrap_or("unmatched")
        .to_owned();
    let mut response = next.run(request).await;
    let request_id = response
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .unwrap_or_else(next_request_id);
    response.headers_mut().insert(
        "x-request-id",
        request_id
            .parse()
            .expect("generated request IDs are valid headers"),
    );
    tracing::info!(
        request_id = %request_id,
        method = %method,
        path = %path,
        status = response.status().as_u16(),
        "console request completed"
    );
    response
}

async fn request_limits(
    axum::extract::State(capacity): axum::extract::State<Arc<Semaphore>>,
    request: axum::extract::Request,
    next: middleware::Next,
) -> Response {
    let Ok(_permit) = capacity.try_acquire_owned() else {
        return problem_response(ProblemDetails::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "request_capacity_exceeded",
            "The console is temporarily at capacity",
        ));
    };
    match timeout(REQUEST_DEADLINE, next.run(request)).await {
        Ok(response) => response,
        Err(_) => problem_response(ProblemDetails::new(
            StatusCode::REQUEST_TIMEOUT,
            "request_timed_out",
            "The request exceeded its time limit",
        )),
    }
}

fn api_router() -> Router {
    Router::new()
        .route("/v1/session", get(session))
        .method_not_allowed_fallback(api_method_not_allowed)
        .fallback(api_not_found)
}

fn authenticated_api_router() -> Router<AuthHttpState> {
    Router::new()
        .route("/v1/session", get(authenticated_session))
        .method_not_allowed_fallback(api_method_not_allowed)
        .fallback(api_not_found)
}

fn authenticated_auth_router() -> Router<AuthHttpState> {
    Router::new()
        .route("/v1/preauth", get(preauth))
        .route("/v1/login", axum::routing::post(login))
        .route("/v1/logout", axum::routing::post(logout))
        .fallback(auth_not_found)
}

/// The public router as served on the loopback development listener: it
/// also refuses any `Host` that is not a loopback name, so a hostile web
/// page whose name resolves to 127.0.0.1 (DNS rebinding) cannot read it.
/// Requests without `Host` pass; browsers always send one.
pub fn development_router() -> Router {
    let router = public_routes();
    #[cfg(feature = "dev-seed")]
    let router = router.merge(crate::seeded::router());
    with_request_limits(router).layer(middleware::from_fn(loopback_host_only))
}

async fn loopback_host_only(request: axum::extract::Request, next: middleware::Next) -> Response {
    let allowed = request
        .headers()
        .get(header::HOST)
        .is_none_or(|host| host.to_str().is_ok_and(is_loopback_host));
    if allowed {
        next.run(request).await
    } else {
        let mut response = StatusCode::MISDIRECTED_REQUEST.into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    }
}

/// `localhost`, `127.0.0.1`, or `[::1]`, with or without a port.
fn is_loopback_host(host: &str) -> bool {
    let name = match host.strip_prefix('[') {
        Some(rest) => rest.split_once(']').map_or("", |(name, _)| name),
        None => host.rsplit_once(':').map_or(host, |(name, _)| name),
    };
    name.eq_ignore_ascii_case("localhost") || name == "127.0.0.1" || name == "::1"
}

fn valid_public_origin(origin: &str) -> bool {
    let Ok(uri) = origin.parse::<axum::http::Uri>() else {
        return false;
    };
    let Some(scheme) = uri.scheme_str() else {
        return false;
    };
    let Some(authority) = uri.authority() else {
        return false;
    };
    let Some((_, raw_authority)) = origin.split_once("://") else {
        return false;
    };
    if raw_authority.contains(['/', '?', '#'])
        || uri
            .path_and_query()
            .is_some_and(|path| path.as_str() != "/")
        || authority.as_str().contains('@')
        || origin != origin.to_ascii_lowercase()
    {
        return false;
    }
    match scheme {
        "https" => true,
        "http" => is_loopback_host(authority.as_str()),
        _ => false,
    }
}

#[cfg(feature = "embedded-ui")]
fn asset_router() -> Router {
    Router::new()
        .route("/{*path}", get(hashed_asset))
        .fallback(asset_not_found)
}

#[cfg(not(feature = "embedded-ui"))]
fn asset_router() -> Router {
    Router::new().fallback(asset_not_found)
}

#[cfg(feature = "embedded-ui")]
fn frontend_router() -> Router {
    let mut router = Router::new();
    for (route, _) in PUBLIC_ASSETS {
        let public_route = *route;
        router = router.route(
            public_route,
            get(move || async move {
                assets::public_response(public_route).unwrap_or_else(asset_not_found_response)
            }),
        );
    }
    for route in BROWSER_ROUTES {
        router = router.route(route, get(spa_index));
    }
    router
}

/// Builds the separate health router. Its listener is validated as loopback
/// by [`crate::ConsoleConfig::validate`].
pub fn health_router(readiness: Readiness) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .with_state(readiness)
}

async fn api_not_found() -> Response {
    problem_response(ProblemDetails::not_found(
        "api_not_found",
        "API resource not found",
    ))
}

/// Reports the authenticated browser session once C3 authentication exists.
///
/// C0 deliberately returns a bounded failure instead of creating a temporary
/// unauthenticated or implicitly privileged session.
#[utoipa::path(
    get,
    path = "/api/v1/session",
    tag = "session",
    responses(
        (status = 200, description = "Current authenticated browser session", body = crate::SessionResponse),
        (status = 503, description = "Authentication is not implemented until C3", body = crate::ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(crate) async fn session() -> Response {
    problem_response(ProblemDetails::authentication_unavailable())
}

async fn authenticated_session(
    State(state): State<AuthHttpState>,
    request: axum::extract::Request,
) -> Response {
    use crate::auth::{PresentedCredentials, presented_credentials, session_csrf, session_digest};

    let secret = match presented_credentials(request.headers()) {
        Ok(PresentedCredentials::Session(secret)) => secret,
        _ => {
            return problem_response(ProblemDetails::new(
                StatusCode::UNAUTHORIZED,
                "authentication_required",
                "Authentication required",
            ));
        }
    };
    let digest = session_digest(secret.expose_secret());
    let csrf = session_csrf(secret.expose_secret()).0;
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
    let active = match console_auth::session(&client, &digest, now).await {
        Ok(Some(session)) => session,
        Ok(None) => {
            return problem_response(ProblemDetails::new(
                StatusCode::UNAUTHORIZED,
                "authentication_required",
                "Authentication required",
            ));
        }
        Err(_) => {
            return problem_response(ProblemDetails::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "authentication_unavailable",
                "Authentication is temporarily unavailable",
            ));
        }
    };
    let expected_csrf_hash = crate::auth::session_digest(&csrf);
    if active.csrf_sha256.len() != expected_csrf_hash.len()
        || !bool::from(
            active
                .csrf_sha256
                .as_slice()
                .ct_eq(expected_csrf_hash.as_slice()),
        )
    {
        return problem_response(ProblemDetails::new(
            StatusCode::UNAUTHORIZED,
            "authentication_required",
            "Authentication required",
        ));
    }
    if !console_auth::touch_session(&client, &digest, now, Duration::minutes(30))
        .await
        .unwrap_or(false)
    {
        return problem_response(ProblemDetails::new(
            StatusCode::UNAUTHORIZED,
            "authentication_required",
            "Authentication required",
        ));
    }
    let bindings = match console_auth::user_role_bindings(&client, &active.user_id).await {
        Ok(bindings) => bindings,
        Err(_) => {
            return problem_response(ProblemDetails::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "authentication_unavailable",
                "Authentication is temporarily unavailable",
            ));
        }
    };
    let mut resolved = Vec::with_capacity(bindings.len());
    for binding in bindings {
        let Some(role) = built_in_role(&binding.role_id) else {
            continue;
        };
        let binding = match binding.asset_group_id {
            Some(group_id) => crate::RoleBinding::scoped(role, [group_id]),
            None => Ok(crate::RoleBinding::global(role)),
        };
        if let Ok(binding) = binding {
            resolved.push(binding);
        }
    }
    let idle_expiry = (now + Duration::minutes(30)).min(active.absolute_expires_at);
    let response = crate::SessionResponse {
        principal: crate::SessionPrincipal {
            id: active.user_id,
            display_name: active.display_name,
            username: Some(active.username),
        },
        authentication_method: crate::AuthenticationMethod::LocalPassword,
        authentication_level: crate::AuthenticationLevel::SingleFactor,
        capabilities: crate::resolve_capabilities(&resolved),
        csrf_token: csrf,
        idle_expires_at: idle_expiry.to_rfc3339_opts(SecondsFormat::Secs, true),
        absolute_expires_at: active
            .absolute_expires_at
            .to_rfc3339_opts(SecondsFormat::Secs, true),
    };
    let mut response = (StatusCode::OK, axum::Json(response)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[utoipa::path(
    get,
    path = "/auth/v1/preauth",
    tag = "authentication",
    responses(
        (status = 200, description = "One-use login challenge", body = crate::PreauthResponse),
        (status = 503, description = "Authentication unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn preauth(State(state): State<AuthHttpState>) -> Response {
    use crate::auth::{SessionSecret, session_csrf, session_digest};

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
async fn login(
    State(state): State<AuthHttpState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    payload: Result<axum::Json<crate::LoginRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    use crate::auth::{
        NormalizedPassword, SessionSecret, browser_origin_allowed, csrf_token_matches,
        hash_password, named_cookie, session_cookie, session_csrf, session_digest, verify_password,
    };

    if !state.public_origin_valid
        || !browser_origin_allowed(&headers, &state.public_origin)
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
    let source = peer.ip().to_string();
    let account_bucket = throttle_digest(
        b"account",
        username.as_deref().unwrap_or("invalid").as_bytes(),
    );
    let source_bucket = throttle_digest(b"source", source.as_bytes());
    let buckets: [&[u8]; 2] = [&account_bucket, &source_bucket];
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
            5,
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
async fn logout(State(state): State<AuthHttpState>, request: axum::extract::Request) -> Response {
    use crate::auth::{browser_origin_allowed, csrf_token_matches, named_cookie, session_digest};

    let headers = request.headers();
    if !state.public_origin_valid
        || !browser_origin_allowed(headers, &state.public_origin)
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
    let (expected_csrf, _) = crate::auth::session_csrf(secret.expose_secret());
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
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(address)| address.ip().to_string());
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

fn canonical_username(username: &str) -> Option<String> {
    if username.is_empty()
        || username.len() > 64
        || !username.is_ascii()
        || !username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._@+-".contains(&byte))
    {
        return None;
    }
    Some(username.to_ascii_lowercase())
}

fn throttle_digest(kind: &[u8], value: &[u8]) -> [u8; 32] {
    let mut input = b"openvibes-console-login-throttle-v1\0".to_vec();
    input.extend_from_slice(kind);
    input.push(0);
    input.extend_from_slice(value);
    let digest = ring::digest::digest(&ring::digest::SHA256, &input);
    let mut output = [0; 32];
    output.copy_from_slice(digest.as_ref());
    input.zeroize();
    output
}

fn bounded_user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.chars().take(256).collect::<String>())
}

fn dummy_password_phc() -> Option<String> {
    static DUMMY_PHC: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    DUMMY_PHC
        .get_or_init(|| {
            use crate::auth::{NormalizedPassword, hash_password};

            let password = NormalizedPassword::new("internal-only-dummy-console-password").ok()?;
            hash_password(&password)
                .ok()
                .map(|hash| hash.as_str().to_owned())
        })
        .clone()
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

fn built_in_role(role_id: &str) -> Option<crate::BuiltInRole> {
    match role_id {
        "viewer" => Some(crate::BuiltInRole::Viewer),
        "analyst" => Some(crate::BuiltInRole::Analyst),
        "operator" => Some(crate::BuiltInRole::Operator),
        "admin" => Some(crate::BuiltInRole::Admin),
        _ => None,
    }
}

async fn api_method_not_allowed() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        "Method not allowed for this API resource",
    ))
}

async fn auth_not_found() -> Response {
    problem_response(ProblemDetails::not_found(
        "auth_not_found",
        "Authentication resource not found",
    ))
}

async fn asset_not_found() -> Response {
    let mut response = StatusCode::NOT_FOUND.into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[cfg(feature = "embedded-ui")]
async fn spa_index() -> Response {
    assets::response("index.html", CachePolicy::NoStore)
        .expect("build.rs validates the embedded SPA entry document")
}

#[cfg(feature = "embedded-ui")]
async fn hashed_asset(Path(path): Path<String>) -> Response {
    assets::manifest_response(&format!("assets/{path}")).unwrap_or_else(asset_not_found_response)
}

#[cfg(feature = "embedded-ui")]
fn asset_not_found_response() -> Response {
    let mut response = StatusCode::NOT_FOUND.into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn browser_not_found() -> Response {
    let mut response = StatusCode::NOT_FOUND.into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn public_security_headers(mut response: Response) -> Response {
    const CSP_REPORT_ONLY: HeaderName =
        HeaderName::from_static("content-security-policy-report-only");
    const REFERRER_POLICY: HeaderName = HeaderName::from_static("referrer-policy");
    const PERMISSIONS_POLICY: HeaderName = HeaderName::from_static("permissions-policy");
    const FRAME_OPTIONS: HeaderName = HeaderName::from_static("x-frame-options");

    // Framing is refused now: the full policy below is report-only until C5,
    // and report-only does not block, so frame-ancestors is also enforced on
    // its own (with X-Frame-Options for older browsers).
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("frame-ancestors 'none'"),
    );
    response
        .headers_mut()
        .insert(FRAME_OPTIONS, HeaderValue::from_static("DENY"));

    response.headers_mut().insert(
        CSP_REPORT_ONLY,
        HeaderValue::from_static(
            "default-src 'none'; script-src 'self'; script-src-attr 'none'; style-src 'self'; style-src-attr 'none'; img-src 'self'; font-src 'none'; connect-src 'self'; form-action 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; worker-src 'none'; manifest-src 'self'",
        ),
    );
    response
        .headers_mut()
        .insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response.headers_mut().insert(
        PERMISSIONS_POLICY,
        HeaderValue::from_static("camera=(), geolocation=(), microphone=(), payment=(), usb=()"),
    );
    response
}

async fn health() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn ready(axum::extract::State(readiness): axum::extract::State<Readiness>) -> StatusCode {
    if readiness.get() {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}
