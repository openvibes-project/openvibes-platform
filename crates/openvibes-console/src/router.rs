use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use axum::{
    Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderName, HeaderValue, StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::{Duration, SecondsFormat, Utc};
use platform_store::{Pool, console_auth};
use subtle::ConstantTimeEq;
use tokio::{sync::Semaphore, time::timeout};

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
pub fn authenticated_router(pool: Pool) -> Router {
    let router = Router::new()
        .nest("/api", authenticated_api_router().with_state(pool))
        .nest("/auth", Router::new().fallback(auth_not_found))
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

fn authenticated_api_router() -> Router<Pool> {
    Router::new()
        .route("/v1/session", get(authenticated_session))
        .method_not_allowed_fallback(api_method_not_allowed)
        .fallback(api_not_found)
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
    State(pool): State<Pool>,
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
    let client = match pool.get().await {
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
