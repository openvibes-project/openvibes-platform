use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

use axum::{
    Router,
    extract::{ConnectInfo, DefaultBodyLimit, Json, Path, Query, State, rejection::QueryRejection},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::{Duration, SecondsFormat, Utc};
use platform_store::{Pool, console_auth};
use serde::Deserialize;
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::PathBuf,
};
use subtle::ConstantTimeEq;
use tokio::{sync::Semaphore, time::timeout};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    config::valid_public_origin,
    problem::{ProblemDetails, next_request_id, problem_response},
};

const MAX_REQUEST_BODY_BYTES: usize = 1_048_576;
const MAX_IN_FLIGHT_REQUESTS: usize = 128;
const REQUEST_DEADLINE: std::time::Duration = std::time::Duration::from_secs(15);
static AUDIT_EXPORT_SPOOL_ID: AtomicU64 = AtomicU64::new(1);
// ponytail: one shared router cap; split API and asset budgets if one starves the other.

#[cfg(feature = "embedded-ui")]
use crate::assets::{self, CachePolicy};
#[cfg(feature = "embedded-ui")]
use crate::frontend_contract::{BROWSER_ROUTES, PUBLIC_ASSETS};

/// Process-readiness state shared with the loopback-only health router.
#[derive(Clone, Debug, Default)]
pub struct Readiness(Arc<AtomicBool>);

#[derive(Clone)]
pub(crate) struct AuthHttpState {
    pool: Pool,
    public_origin: Arc<str>,
    public_origin_valid: bool,
    dummy_password_phc: Option<String>,
    password_slots: Arc<Semaphore>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentListParams {
    state: Option<String>,
    cursor: Option<String>,
    limit: Option<u16>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CertificateListParams {
    cursor: Option<String>,
    limit: Option<u16>,
}

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct AgentCursorToken {
    state: Option<String>,
    scope: platform_store::console_read::AgentScope,
    last_seen_at: Option<String>,
    agent_id: String,
}

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct CertificateCursorToken {
    agent_id: String,
    scope: platform_store::console_read::AgentScope,
    issued_at: String,
    serial: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LatestFindingListParams {
    severity: Option<String>,
    cursor: Option<String>,
    limit: Option<u16>,
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuditEventListParams {
    since: String,
    until: Option<String>,
    actor: Option<String>,
    action: Option<String>,
    result: Option<String>,
    cursor: Option<String>,
    limit: Option<u16>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuditEventExportParams {
    since: String,
    until: Option<String>,
    actor: Option<String>,
    action: Option<String>,
    result: Option<String>,
}

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct AuditEventCursorToken {
    since: String,
    until: Option<String>,
    actor: Option<String>,
    action: Option<String>,
    result: Option<String>,
    at: String,
    id: i64,
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
        .nest(
            "/auth",
            authenticated_auth_router().with_state(state.clone()),
        )
        .nest("/assets", asset_router());
    #[cfg(feature = "embedded-ui")]
    let router = router.merge(frontend_router());
    with_request_limits(router.fallback(browser_not_found)).layer(middleware::from_fn_with_state(
        state,
        authenticated_host_only,
    ))
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
        .route("/v1/agents/summary", get(authenticated_agent_summary))
        .route("/v1/agents", get(authenticated_agents))
        .route("/v1/agents/{agent_id}", get(authenticated_agent_detail))
        .route(
            "/v1/agents/{agent_id}/certificates",
            get(authenticated_agent_certificates),
        )
        .route("/v1/findings/summary", get(authenticated_finding_summary))
        .route("/v1/findings/latest", get(authenticated_latest_findings))
        .route(
            "/v1/findings/latest/{agent_id}/{rule_set_id}/{rule_id}",
            get(authenticated_latest_finding),
        )
        .route("/v1/findings/history", get(authenticated_finding_history))
        .route(
            "/v1/findings/history/{observed_day}/{finding_id}",
            get(authenticated_finding_event),
        )
        .route(
            "/v1/audit-retention",
            get(authenticated_audit_retention).put(update_authenticated_audit_retention),
        )
        .route("/v1/audit-events", get(authenticated_audit_events))
        .route("/v1/audit-export.csv", get(authenticated_audit_export))
        .route("/v1/access-control", get(authenticated_access_inventory))
        .route(
            "/v1/access-control/bindings",
            axum::routing::post(create_authenticated_access_binding),
        )
        .route(
            "/v1/access-control/bindings/{binding_id}",
            axum::routing::delete(revoke_authenticated_access_binding),
        )
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

async fn authenticated_host_only(
    State(state): State<AuthHttpState>,
    request: axum::extract::Request,
    next: middleware::Next,
) -> Response {
    let allowed = request.headers().get(header::HOST).is_none_or(|host| {
        let expected = state
            .public_origin
            .parse::<axum::http::Uri>()
            .ok()
            .and_then(|origin| origin.authority().cloned());
        host.to_str().is_ok_and(|host| {
            expected
                .as_ref()
                .is_some_and(|expected| host.eq_ignore_ascii_case(expected.as_str()))
        })
    });
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

/// Adds one active local-user role binding.
#[utoipa::path(
    post,
    path = "/api/v1/access-control/bindings",
    tag = "access control",
    request_body = crate::CreateAccessBindingRequest,
    responses((status = 201, description = "Role binding created", body = crate::AccessBinding), (status = 400, description = "Invalid binding request", body = ProblemDetails), (status = 409, description = "Binding conflict", body = ProblemDetails))
)]
pub(crate) async fn create_authenticated_access_binding(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Json(request): Json<crate::CreateAccessBindingRequest>,
) -> Response {
    use chrono::SecondsFormat;
    use platform_store::console_read::AgentScope;
    if !valid_uuid(&request.user_id)
        || request
            .asset_group_id
            .as_deref()
            .is_some_and(|id| !valid_uuid(id))
        || request.role_id.is_empty()
        || request.role_id.len() > 64
        || !request
            .role_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return invalid_access_binding();
    }
    let (scope, user_id) =
        match authenticated_permission(&state, &headers, crate::Permission::RbacManage, true).await
        {
            Ok(context) => context,
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
    let binding = match platform_store::console_auth::create_user_role_binding(
        &mut client,
        &request.user_id,
        &request.role_id,
        request.asset_group_id.as_deref(),
        &user_id,
        Utc::now(),
    )
    .await
    {
        Ok(Some(binding)) => binding,
        Ok(None) => {
            return problem_response(ProblemDetails::new(
                StatusCode::CONFLICT,
                "binding_conflict",
                "The role binding could not be created",
            ));
        }
        Err(_) => return unavailable_auth(),
    };
    (
        StatusCode::CREATED,
        Json(crate::AccessBinding {
            binding_id: binding.binding_id,
            user_id: binding.user_id,
            username: binding.username,
            display_name: binding.display_name,
            role_id: binding.role_id,
            asset_group_id: binding.asset_group_id,
            asset_group_name: binding.asset_group_name,
            created_at: binding
                .created_at
                .to_rfc3339_opts(SecondsFormat::Millis, true),
            created_by: binding.created_by,
        }),
    )
        .into_response()
}

#[utoipa::path(
    delete,
    path = "/api/v1/access-control/bindings/{binding_id}",
    tag = "access control",
    params(("binding_id" = String, Path, description = "Role binding UUID")),
    responses((status = 204, description = "Role binding revoked"), (status = 404, description = "Binding not found", body = ProblemDetails))
)]
pub(crate) async fn revoke_authenticated_access_binding(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(binding_id): Path<String>,
) -> Response {
    use platform_store::console_read::AgentScope;
    if !valid_uuid(&binding_id) {
        return invalid_access_binding();
    }
    let (scope, user_id) =
        match authenticated_permission(&state, &headers, crate::Permission::RbacManage, true).await
        {
            Ok(context) => context,
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
    match platform_store::console_auth::revoke_user_role_binding(
        &mut client,
        &binding_id,
        &user_id,
        Utc::now(),
    )
    .await
    {
        Ok(platform_store::console_auth::BindingRevocation::Revoked) => {
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(platform_store::console_auth::BindingRevocation::NotFound) => {
            problem_response(ProblemDetails::new(
                StatusCode::NOT_FOUND,
                "binding_not_found",
                "Access is not available",
            ))
        }
        Ok(platform_store::console_auth::BindingRevocation::LastGlobalAdmin) => {
            problem_response(ProblemDetails::new(
                StatusCode::CONFLICT,
                "last_global_admin",
                "The final global Admin binding cannot be revoked",
            ))
        }
        Err(_) => unavailable_auth(),
    }
}

fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn invalid_access_binding() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::BAD_REQUEST,
        "invalid_binding",
        "Role binding parameters are invalid",
    ))
}

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
    path = "/api/v1/agents/summary",
    tag = "agents",
    responses(
        (status = 200, description = "Agent counts visible to the current user", body = crate::AgentSummary),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Permission denied", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(crate) async fn authenticated_agent_summary(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    use platform_store::console_read::agent_summary_in_scope;

    let scope =
        match authenticated_agent_scope(&state, &headers, crate::Permission::AgentsRead).await {
            Ok(scope) => scope,
            Err(response) => return response,
        };
    let client = match state.pool.get().await {
        Ok(client) => client,
        Err(_) => return unavailable_auth(),
    };
    match agent_summary_in_scope(&client, Utc::now(), &scope).await {
        Ok(summary) => (
            StatusCode::OK,
            axum::Json(crate::AgentSummary {
                total: summary.total.try_into().unwrap_or_default(),
                active: summary.active.try_into().unwrap_or_default(),
                stale: summary.stale.try_into().unwrap_or_default(),
                revoked: summary.revoked.try_into().unwrap_or_default(),
            }),
        )
            .into_response(),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/agents",
    tag = "agents",
    params(
        ("state" = Option<String>, Query, description = "active, stale, or revoked"),
        ("cursor" = Option<String>, Query, description = "Opaque continuation cursor"),
        ("limit" = Option<u16>, Query, description = "Page size from 1 to 100")
    ),
    responses(
        (status = 200, description = "Scope-filtered agent page", body = crate::AgentPage),
        (status = 400, description = "Invalid query or cursor", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Permission denied", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(crate) async fn authenticated_agents(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    query: Result<Query<AgentListParams>, QueryRejection>,
) -> Response {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use platform_store::console_read::{
        AgentCursor, AgentQuery, AgentState, PageLimit, agents_in_scope,
    };

    let scope =
        match authenticated_agent_scope(&state, &headers, crate::Permission::AgentsRead).await {
            Ok(scope) => scope,
            Err(response) => return response,
        };
    let Query(params) = match query {
        Ok(query) => query,
        Err(_) => return invalid_agent_query(),
    };
    let limit = params.limit.unwrap_or(crate::DEFAULT_PAGE_SIZE);
    let Some(limit) = PageLimit::new(limit) else {
        return invalid_agent_query();
    };
    let agent_state = match params.state.as_deref() {
        None => None,
        Some("active") => Some(AgentState::Active),
        Some("stale") => Some(AgentState::Stale),
        Some("revoked") => Some(AgentState::Revoked),
        Some(_) => return invalid_agent_query(),
    };
    let after = match params.cursor.as_deref() {
        None => None,
        Some(encoded) if encoded.len() <= crate::MAX_CURSOR_LENGTH => {
            let decoded = match URL_SAFE_NO_PAD.decode(encoded) {
                Ok(decoded) => decoded,
                Err(_) => return invalid_agent_query(),
            };
            let token: AgentCursorToken = match serde_json::from_slice::<AgentCursorToken>(&decoded)
            {
                Ok(token) if token.state == params.state && token.scope == scope => token,
                _ => return invalid_agent_query(),
            };
            let last_seen_at = match token.last_seen_at.as_deref() {
                Some(value) => match chrono::DateTime::parse_from_rfc3339(value) {
                    Ok(value) => Some(value.with_timezone(&Utc)),
                    Err(_) => return invalid_agent_query(),
                },
                None => None,
            };
            Some(AgentCursor {
                last_seen_at,
                agent_id: token.agent_id,
            })
        }
        Some(_) => return invalid_agent_query(),
    };
    let client = match state.pool.get().await {
        Ok(client) => client,
        Err(_) => return unavailable_auth(),
    };
    let page = match agents_in_scope(
        &client,
        &AgentQuery {
            state: agent_state,
            after,
            limit,
        },
        Utc::now(),
        &scope,
    )
    .await
    {
        Ok(page) => page,
        Err(_) => return unavailable_auth(),
    };
    let items = page.items.into_iter().map(agent_view).collect();
    let next_cursor = match page.next {
        None => None,
        Some(cursor) => {
            let token = AgentCursorToken {
                state: params.state,
                scope,
                last_seen_at: cursor
                    .last_seen_at
                    .map(|value| value.to_rfc3339_opts(SecondsFormat::Micros, true)),
                agent_id: cursor.agent_id,
            };
            match serde_json::to_vec(&token) {
                Ok(token) => Some(URL_SAFE_NO_PAD.encode(token)),
                Err(_) => return unavailable_auth(),
            }
        }
    };
    (
        StatusCode::OK,
        axum::Json(crate::AgentPage {
            items,
            next_cursor,
            generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        }),
    )
        .into_response()
}

fn invalid_agent_query() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::BAD_REQUEST,
        "invalid_query",
        "Agent query parameters are invalid",
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/agents/{agent_id}",
    tag = "agents",
    params(("agent_id" = String, Path, description = "Stable agent identifier")),
    responses(
        (status = 200, description = "Visible agent detail", body = crate::AgentDetail),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Permission denied", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "Agent not found", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(crate) async fn authenticated_agent_detail(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
) -> Response {
    use platform_store::console_read::{PageLimit, agent_in_scope, certificates_in_scope};

    let scope =
        match authenticated_agent_scope(&state, &headers, crate::Permission::AgentsRead).await {
            Ok(scope) => scope,
            Err(response) => return response,
        };
    let client = match state.pool.get().await {
        Ok(client) => client,
        Err(_) => return unavailable_auth(),
    };
    let agent = match agent_in_scope(&client, &agent_id, Utc::now(), &scope).await {
        Ok(Some(agent)) => agent,
        Ok(None) => {
            return problem_response(ProblemDetails::not_found(
                "agent_not_found",
                "Agent not found",
            ));
        }
        Err(_) => return unavailable_auth(),
    };
    let certificates = match certificates_in_scope(
        &client,
        &agent_id,
        None,
        PageLimit::new(100).expect("the fixed certificate detail limit is valid"),
        &scope,
    )
    .await
    {
        Ok(page) => page.items.into_iter().map(certificate_view).collect(),
        Err(_) => return unavailable_auth(),
    };
    (
        StatusCode::OK,
        axum::Json(crate::AgentDetail {
            agent: agent_view(agent),
            certificates,
        }),
    )
        .into_response()
}

#[utoipa::path(
    get,
    path = "/api/v1/agents/{agent_id}/certificates",
    tag = "agents",
    params(
        ("agent_id" = String, Path, description = "Stable agent identifier"),
        ("cursor" = Option<String>, Query, description = "Opaque continuation cursor"),
        ("limit" = Option<u16>, Query, description = "Page size from 1 to 100")
    ),
    responses(
        (status = 200, description = "Visible certificate metadata page", body = crate::CertificatePage),
        (status = 400, description = "Invalid query or cursor", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Permission denied", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(crate) async fn authenticated_agent_certificates(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
    query: Result<Query<CertificateListParams>, QueryRejection>,
) -> Response {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use platform_store::console_read::{CertificateCursor, PageLimit, certificates_in_scope};

    let scope =
        match authenticated_agent_scope(&state, &headers, crate::Permission::AgentsRead).await {
            Ok(scope) => scope,
            Err(response) => return response,
        };
    let Query(params) = match query {
        Ok(query) => query,
        Err(_) => return invalid_agent_query(),
    };
    let Some(limit) = PageLimit::new(params.limit.unwrap_or(crate::DEFAULT_PAGE_SIZE)) else {
        return invalid_agent_query();
    };
    let after = match params.cursor.as_deref() {
        None => None,
        Some(encoded) if encoded.len() <= crate::MAX_CURSOR_LENGTH => {
            let decoded = match URL_SAFE_NO_PAD.decode(encoded) {
                Ok(decoded) => decoded,
                Err(_) => return invalid_agent_query(),
            };
            let token = match serde_json::from_slice::<CertificateCursorToken>(&decoded) {
                Ok(token) if token.agent_id == agent_id && token.scope == scope => token,
                _ => return invalid_agent_query(),
            };
            let issued_at = match chrono::DateTime::parse_from_rfc3339(&token.issued_at) {
                Ok(value) => value.with_timezone(&Utc),
                Err(_) => return invalid_agent_query(),
            };
            let Some(serial) = decode_hex(&token.serial) else {
                return invalid_agent_query();
            };
            Some(CertificateCursor { issued_at, serial })
        }
        Some(_) => return invalid_agent_query(),
    };
    let client = match state.pool.get().await {
        Ok(client) => client,
        Err(_) => return unavailable_auth(),
    };
    let page = match certificates_in_scope(&client, &agent_id, after.as_ref(), limit, &scope).await
    {
        Ok(page) => page,
        Err(_) => return unavailable_auth(),
    };
    let next_cursor = match page.next {
        None => None,
        Some(cursor) => {
            let token = CertificateCursorToken {
                agent_id,
                scope,
                issued_at: cursor
                    .issued_at
                    .to_rfc3339_opts(SecondsFormat::Micros, true),
                serial: encode_hex(&cursor.serial),
            };
            match serde_json::to_vec(&token) {
                Ok(token) => Some(URL_SAFE_NO_PAD.encode(token)),
                Err(_) => return unavailable_auth(),
            }
        }
    };
    (
        StatusCode::OK,
        axum::Json(crate::CertificatePage {
            items: page.items.into_iter().map(certificate_view).collect(),
            next_cursor,
            generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        }),
    )
        .into_response()
}

fn agent_view(agent: platform_store::console_read::Agent) -> crate::AgentView {
    use platform_store::console_read::AgentState;
    crate::AgentView {
        id: agent.agent_id,
        hostname: agent.hostname,
        status: match agent.state {
            AgentState::Active => crate::AgentStatus::Active,
            AgentState::Stale => crate::AgentStatus::Stale,
            AgentState::Revoked => crate::AgentStatus::Revoked,
        },
        enrolled_at: agent.enrolled_at.to_rfc3339_opts(SecondsFormat::Secs, true),
        revoked_at: agent
            .revoked_at
            .map(|value| value.to_rfc3339_opts(SecondsFormat::Secs, true)),
        last_seen_at: agent
            .last_seen_at
            .map(|value| value.to_rfc3339_opts(SecondsFormat::Secs, true)),
        scanner_version: agent.scanner_version,
        capabilities: agent.capabilities,
    }
}

fn certificate_view(
    certificate: platform_store::console_read::Certificate,
) -> crate::CertificateView {
    crate::CertificateView {
        serial: encode_hex(&certificate.serial),
        not_before: certificate
            .not_before
            .to_rfc3339_opts(SecondsFormat::Secs, true),
        not_after: certificate
            .not_after
            .to_rfc3339_opts(SecondsFormat::Secs, true),
        issued_at: certificate
            .issued_at
            .to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digits = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(digits, 16).ok()
        })
        .collect()
}

#[utoipa::path(
    get,
    path = "/api/v1/findings/summary",
    tag = "findings",
    responses(
        (status = 200, description = "Scope-filtered latest finding counts", body = crate::FindingSummary),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Permission denied", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(crate) async fn authenticated_finding_summary(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    let scope =
        match authenticated_agent_scope(&state, &headers, crate::Permission::FindingsRead).await {
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

#[utoipa::path(
    get,
    path = "/api/v1/access-control",
    tag = "access control",
    responses((status = 200, description = "Roles, active bindings, and asset groups", body = crate::AccessInventory))
)]
pub(crate) async fn authenticated_access_inventory(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    use chrono::SecondsFormat;
    use platform_store::console_read::AgentScope;
    let (scope, user_id) = match authenticated_permission(
        &state,
        &headers,
        crate::Permission::RbacRead,
        false,
    )
    .await
    {
        Ok(context) => context,
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
        Ok(client) => client,
        Err(_) => return unavailable_auth(),
    };
    let inventory = match platform_store::console_auth::access_inventory(&client).await {
        Ok(inventory) => inventory,
        Err(_) => return unavailable_auth(),
    };
    if platform_store::audit::record(
        &client,
        &user_id,
        "access_control.viewed",
        Some("access_control"),
        "success",
    )
    .await
    .is_err()
    {
        return unavailable_auth();
    }
    Json(crate::AccessInventory {
        roles: inventory
            .roles
            .into_iter()
            .map(|role| crate::AccessRole {
                role_id: role.role_id,
                display_name: role.display_name,
                builtin: role.builtin,
                permissions: role.permissions,
            })
            .collect(),
        bindings: inventory
            .bindings
            .into_iter()
            .map(|binding| crate::AccessBinding {
                binding_id: binding.binding_id,
                user_id: binding.user_id,
                username: binding.username,
                display_name: binding.display_name,
                role_id: binding.role_id,
                asset_group_id: binding.asset_group_id,
                asset_group_name: binding.asset_group_name,
                created_at: binding
                    .created_at
                    .to_rfc3339_opts(SecondsFormat::Millis, true),
                created_by: binding.created_by,
            })
            .collect(),
        asset_groups: inventory
            .asset_groups
            .into_iter()
            .map(|group| crate::AccessAssetGroup {
                asset_group_id: group.asset_group_id,
                name: group.name,
                selectors: group.selectors,
            })
            .collect(),
        users: inventory
            .users
            .into_iter()
            .map(|user| crate::AccessUser {
                user_id: user.user_id,
                username: user.username,
                display_name: user.display_name,
            })
            .collect(),
    })
    .into_response()
}

#[utoipa::path(
    get,
    path = "/api/v1/audit-events",
    tag = "audit",
    params(
        ("since" = String, Query, description = "Inclusive RFC3339 lower bound"),
        ("until" = Option<String>, Query, description = "Exclusive RFC3339 upper bound"),
        ("actor" = Option<String>, Query), ("action" = Option<String>, Query),
        ("result" = Option<String>, Query), ("cursor" = Option<String>, Query),
        ("limit" = Option<u16>, Query)
    ),
    responses((status = 200, description = "Safe audit event page", body = crate::AuditEventPage))
)]
pub(crate) async fn authenticated_audit_events(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    query: Result<Query<AuditEventListParams>, QueryRejection>,
) -> Response {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use chrono::{DateTime, SecondsFormat};
    use platform_store::{
        audit::{AuditCursor, AuditQuery, events},
        console_read::{AgentScope, PageLimit},
    };
    let (scope, user_id) =
        match authenticated_permission(&state, &headers, crate::Permission::AuditRead, false).await
        {
            Ok(context) => context,
            Err(response) => return response,
        };
    if !matches!(scope, AgentScope::Global) {
        return problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "Access is not available",
        ));
    }
    let Query(params) = match query {
        Ok(query) => query,
        Err(_) => return invalid_query(),
    };
    let since = match DateTime::parse_from_rfc3339(&params.since) {
        Ok(v) => v.with_timezone(&Utc),
        Err(_) => return invalid_query(),
    };
    let until = match params
        .until
        .as_deref()
        .map(DateTime::parse_from_rfc3339)
        .transpose()
    {
        Ok(v) => v.map(|v| v.with_timezone(&Utc)),
        Err(_) => return invalid_query(),
    };
    let now = Utc::now();
    if since > now
        || until.is_some_and(|v| v <= since || v > now)
        || [
            params.actor.as_deref(),
            params.action.as_deref(),
            params.result.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(|v| v.is_empty() || v.len() > 128 || v.chars().any(char::is_control))
    {
        return invalid_query();
    }
    let limit = match PageLimit::new(params.limit.unwrap_or(crate::DEFAULT_PAGE_SIZE)) {
        Some(v) => v,
        None => return invalid_query(),
    };
    let after = match params.cursor.as_deref() {
        None => None,
        Some(encoded) if encoded.len() <= crate::MAX_CURSOR_LENGTH => {
            let decoded = match URL_SAFE_NO_PAD.decode(encoded) {
                Ok(v) => v,
                Err(_) => return invalid_query(),
            };
            let token: AuditEventCursorToken = match serde_json::from_slice(&decoded) {
                Ok(v) => v,
                Err(_) => return invalid_query(),
            };
            let token_since = match DateTime::parse_from_rfc3339(&token.since) {
                Ok(v) => v.with_timezone(&Utc),
                Err(_) => return invalid_query(),
            };
            let token_until = match token
                .until
                .as_deref()
                .map(DateTime::parse_from_rfc3339)
                .transpose()
            {
                Ok(v) => v.map(|v| v.with_timezone(&Utc)),
                Err(_) => return invalid_query(),
            };
            if token_since != since
                || token_until != until
                || token.actor != params.actor
                || token.action != params.action
                || token.result != params.result
            {
                return invalid_query();
            }
            let at = match DateTime::parse_from_rfc3339(&token.at) {
                Ok(v) => v.with_timezone(&Utc),
                Err(_) => return invalid_query(),
            };
            Some(AuditCursor { at, id: token.id })
        }
        _ => return invalid_query(),
    };
    let client = match state.pool.get().await {
        Ok(v) => v,
        Err(_) => return unavailable_auth(),
    };
    let page = match events(
        &client,
        &AuditQuery {
            since,
            until,
            actor: params.actor.clone(),
            action: params.action.clone(),
            result: params.result.clone(),
            after,
            limit,
        },
    )
    .await
    {
        Ok(v) => v,
        Err(_) => return unavailable_auth(),
    };
    if platform_store::audit::record(
        &client,
        &user_id,
        "audit.accessed",
        Some("audit_events"),
        "success",
    )
    .await
    .is_err()
    {
        return unavailable_auth();
    }
    let next_cursor = page.next.and_then(|cursor| {
        let token = AuditEventCursorToken {
            since: since.to_rfc3339(),
            until: until.map(|v| v.to_rfc3339()),
            actor: params.actor,
            action: params.action,
            result: params.result,
            at: cursor.at.to_rfc3339_opts(SecondsFormat::Nanos, true),
            id: cursor.id,
        };
        serde_json::to_vec(&token)
            .map(|v| URL_SAFE_NO_PAD.encode(v))
            .ok()
    });
    Json(crate::AuditEventPage {
        items: page
            .items
            .into_iter()
            .map(|event| crate::AuditEventView {
                id: event.id.to_string(),
                at: event.at.to_rfc3339_opts(SecondsFormat::Millis, true),
                actor: event.actor,
                action: event.action,
                target: event.target,
                result: event.result,
                request_id: event.request_id,
                actor_kind: event.actor_kind,
                actor_id: event.actor_id,
                authentication_method: event.authentication_method,
                target_kind: event.target_kind,
                target_id: event.target_id,
                reason_code: event.reason_code,
            })
            .collect(),
        next_cursor,
    })
    .into_response()
}

#[utoipa::path(
    get,
    path = "/api/v1/audit-export.csv",
    tag = "audit",
    params(
        ("since" = String, Query, description = "Inclusive RFC3339 lower bound"),
        ("until" = Option<String>, Query, description = "Exclusive RFC3339 upper bound"),
        ("actor" = Option<String>, Query), ("action" = Option<String>, Query),
        ("result" = Option<String>, Query)
    ),
    responses(
        (status = 200, description = "Filtered audit events as CSV", content_type = "text/csv"),
        (status = 413, description = "Export exceeds the row or byte limit", body = ProblemDetails)
    )
)]
pub(crate) async fn authenticated_audit_export(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    query: Result<Query<AuditEventExportParams>, QueryRejection>,
) -> Response {
    use chrono::DateTime;
    use platform_store::audit::{AuditExportQuery, MAX_EXPORT_BYTES, export_events, record_export};
    let (scope, user_id) =
        match authenticated_permission(&state, &headers, crate::Permission::AuditExport, false)
            .await
        {
            Ok(context) => context,
            Err(response) => return response,
        };
    if !matches!(scope, platform_store::console_read::AgentScope::Global) {
        return problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "Access is not available",
        ));
    }
    let Query(params) = match query {
        Ok(query) => query,
        Err(_) => return invalid_query(),
    };
    let since = match DateTime::parse_from_rfc3339(&params.since) {
        Ok(v) => v.with_timezone(&Utc),
        Err(_) => return invalid_query(),
    };
    let until = match params
        .until
        .as_deref()
        .map(DateTime::parse_from_rfc3339)
        .transpose()
    {
        Ok(v) => v.map(|v| v.with_timezone(&Utc)),
        Err(_) => return invalid_query(),
    };
    let now = Utc::now();
    if since > now
        || until.is_some_and(|v| v <= since || v > now)
        || [
            params.actor.as_deref(),
            params.action.as_deref(),
            params.result.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(|v| v.is_empty() || v.len() > 128 || v.chars().any(char::is_control))
    {
        return invalid_query();
    }
    let query = AuditExportQuery {
        since,
        until,
        actor: params.actor,
        action: params.action,
        result: params.result,
    };
    let client = match state.pool.get().await {
        Ok(v) => v,
        Err(_) => return unavailable_auth(),
    };
    let export = match export_events(&client, &query).await {
        Ok(v) => v,
        Err(_) => return unavailable_auth(),
    };
    if export.too_large {
        return export_too_large();
    }
    let mut csv = Vec::new();
    csv.extend_from_slice(b"event_id,at,actor,action,target,result,request_id,actor_kind,actor_id,authentication_method,target_kind,target_id,reason_code\r\n");
    for event in &export.items {
        let fields = [
            event.id.to_string(),
            event.at.to_rfc3339(),
            event.actor.clone(),
            event.action.clone(),
            event.target.clone().unwrap_or_default(),
            event.result.clone(),
            event.request_id.clone().unwrap_or_default(),
            event.actor_kind.clone().unwrap_or_default(),
            event.actor_id.clone().unwrap_or_default(),
            event.authentication_method.clone().unwrap_or_default(),
            event.target_kind.clone().unwrap_or_default(),
            event.target_id.clone().unwrap_or_default(),
            event.reason_code.clone().unwrap_or_default(),
        ];
        let row = fields
            .iter()
            .map(|value| csv_field(value))
            .collect::<Vec<_>>()
            .join(",")
            + "\r\n";
        if csv.len().saturating_add(row.len()) > MAX_EXPORT_BYTES {
            return export_too_large();
        }
        csv.extend_from_slice(row.as_bytes());
    }
    let spool = match PrivateAuditSpool::create(&csv) {
        Ok(v) => v,
        Err(_) => return unavailable_auth(),
    };
    let bytes = match spool.read() {
        Ok(v) => v,
        Err(_) => return unavailable_auth(),
    };
    let digest = ring::digest::digest(&ring::digest::SHA256, &bytes);
    let sha256 = digest
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if record_export(&client, &user_id, &query, export.items.len(), &sha256)
        .await
        .is_err()
    {
        return unavailable_auth();
    }
    let body = futures_util::stream::unfold((spool, Some(bytes)), |(spool, bytes)| async move {
        bytes.map(|bytes| (Ok::<_, std::io::Error>(bytes), (spool, None)))
    });
    let mut response = axum::body::Body::from_stream(body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/csv; charset=utf-8"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"openvibes-audit.csv\""),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

fn csv_field(value: &str) -> String {
    let mut safe = value.to_owned();
    let first = value.trim_start_matches(char::is_whitespace).chars().next();
    if matches!(first, Some('=' | '+' | '-' | '@' | '\t' | '\r')) {
        safe.insert(0, '\'');
    }
    format!("\"{}\"", safe.replace('"', "\"\""))
}

struct PrivateAuditSpool(PathBuf);

impl PrivateAuditSpool {
    fn create(bytes: &[u8]) -> std::io::Result<Self> {
        for _ in 0..16 {
            let id = AUDIT_EXPORT_SPOOL_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("openvibes-audit-{}-{id}.csv", std::process::id()));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(mut file) => {
                    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
                        drop(file);
                        let _ = fs::remove_file(&path);
                        return Err(error);
                    }
                    return Ok(Self(path));
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate private export spool",
        ))
    }

    fn read(&self) -> std::io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        std::fs::File::open(&self.0)?.read_to_end(&mut bytes)?;
        Ok(bytes)
    }
}

impl Drop for PrivateAuditSpool {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn export_too_large() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::PAYLOAD_TOO_LARGE,
        "export_too_large",
        "The filtered audit export exceeds the download limits",
    ))
}

fn invalid_query() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::BAD_REQUEST,
        "invalid_query",
        "Audit event query parameters are invalid",
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/audit-retention",
    tag = "audit",
    responses(
        (status = 200, description = "Current audit retention policy", body = crate::AuditRetentionPolicy, headers(("ETag" = String, description = "Policy version"))),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Permission denied", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(crate) async fn authenticated_audit_retention(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    let (scope, user_id) =
        match authenticated_permission(&state, &headers, crate::Permission::AuditRead, false).await
        {
            Ok(context) => context,
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
        Ok(client) => client,
        Err(_) => return unavailable_auth(),
    };
    match platform_store::audit::retention_policy(&client).await {
        Ok(policy) => {
            if platform_store::audit::record(
                &client,
                &user_id,
                "audit.accessed",
                Some("audit_retention"),
                "success",
            )
            .await
            .is_err()
            {
                return unavailable_auth();
            }
            retention_policy_response(policy)
        }
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(
    put,
    path = "/api/v1/audit-retention",
    tag = "audit",
    request_body = crate::UpdateAuditRetentionRequest,
    params(
        ("If-Match" = String, Header, description = "Quoted policy version from ETag"),
        ("Origin" = String, Header, description = "Must exactly match configured origin"),
        ("X-CSRF-Token" = String, Header, description = "Session synchronizer token")
    ),
    responses(
        (status = 200, description = "Updated retention policy", body = crate::AuditRetentionPolicy, headers(("ETag" = String, description = "New policy version"))),
        (status = 400, description = "Invalid retention value or request", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Origin, CSRF, or permission check failed", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "Policy version is stale", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 428, description = "If-Match is required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Update unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(crate) async fn update_authenticated_audit_retention(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    payload: Result<
        Json<crate::UpdateAuditRetentionRequest>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Response {
    let (scope, user_id) = match authenticated_permission(
        &state,
        &headers,
        crate::Permission::AuditRetentionManage,
        true,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    if !matches!(scope, platform_store::console_read::AgentScope::Global) {
        return problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "Access is not available",
        ));
    }
    let expected_version = match parse_if_match_version(&headers) {
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
                "If-Match must contain one quoted policy version",
            ));
        }
    };
    let Json(payload) = match payload {
        Ok(payload) => payload,
        Err(_) => {
            return problem_response(ProblemDetails::new(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Retention request is invalid",
            ));
        }
    };
    if !(1..=36_500).contains(&payload.retention_days) {
        return problem_response(ProblemDetails::new(
            StatusCode::BAD_REQUEST,
            "invalid_retention",
            "Retention must be between 1 and 36500 days",
        ));
    }
    let mut client = match state.pool.get().await {
        Ok(client) => client,
        Err(_) => return unavailable_auth(),
    };
    match platform_store::audit::update_retention_policy(
        &mut client,
        payload.retention_days as i32,
        expected_version,
        &user_id,
        Utc::now(),
    )
    .await
    {
        Ok(Some(policy)) => retention_policy_response(policy),
        Ok(None) => problem_response(ProblemDetails::new(
            StatusCode::PRECONDITION_FAILED,
            "stale_policy",
            "Audit retention policy changed; reload before saving",
        )),
        Err(_) => unavailable_auth(),
    }
}

fn parse_if_match_version(headers: &HeaderMap) -> Result<Option<i64>, ()> {
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

fn retention_policy_response(policy: platform_store::audit::RetentionPolicy) -> Response {
    let etag = format!("\"{}\"", policy.version);
    let mut response = (
        StatusCode::OK,
        Json(crate::AuditRetentionPolicy {
            retention_days: policy.retention_days.try_into().unwrap_or_default(),
            version: policy.version.try_into().unwrap_or_default(),
            updated_at: policy.updated_at.to_rfc3339_opts(SecondsFormat::Secs, true),
            updated_by: policy.updated_by,
        }),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(value) = HeaderValue::from_str(&etag) {
        response.headers_mut().insert(header::ETAG, value);
    }
    response
}

#[utoipa::path(
    get,
    path = "/api/v1/findings/latest",
    tag = "findings",
    params(
        ("severity" = Option<String>, Query, description = "critical, high, medium, or low"),
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

    let scope =
        match authenticated_agent_scope(&state, &headers, crate::Permission::FindingsRead).await {
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
    path = "/api/v1/findings/latest/{agent_id}/{rule_set_id}/{rule_id}",
    tag = "findings",
    params(
        ("agent_id" = String, Path, description = "Stable agent identifier"),
        ("rule_set_id" = String, Path, description = "Rule set id or reserved ~unknown"),
        ("rule_id" = String, Path, description = "Rule identifier")
    ),
    responses(
        (status = 200, description = "Visible latest observation", body = crate::FindingView),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Permission denied", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "Finding not found", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(crate) async fn authenticated_latest_finding(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((agent_id, rule_set_id, rule_id)): Path<(String, String, String)>,
) -> Response {
    let scope =
        match authenticated_agent_scope(&state, &headers, crate::Permission::FindingsRead).await {
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
            "finding_not_found",
            "Finding not found",
        )),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/findings/history",
    tag = "findings",
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

    let scope =
        match authenticated_agent_scope(&state, &headers, crate::Permission::FindingsRead).await {
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
    path = "/api/v1/findings/history/{observed_day}/{finding_id}",
    tag = "findings",
    params(
        ("observed_day" = String, Path, description = "UTC partition date"),
        ("finding_id" = String, Path, description = "Stable finding identifier")
    ),
    responses(
        (status = 200, description = "Visible immutable finding event", body = crate::FindingHistoryEntry),
        (status = 400, description = "Invalid partition date", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Permission denied", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "Finding event not found", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(crate) async fn authenticated_finding_event(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((observed_day, finding_id)): Path<(String, String)>,
) -> Response {
    let scope =
        match authenticated_agent_scope(&state, &headers, crate::Permission::FindingsRead).await {
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
            "finding_not_found",
            "Finding not found",
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

async fn authenticated_agent_scope(
    state: &AuthHttpState,
    headers: &HeaderMap,
    permission: crate::Permission,
) -> Result<platform_store::console_read::AgentScope, Response> {
    authenticated_permission(state, headers, permission, false)
        .await
        .map(|(scope, _user_id)| scope)
}

async fn authenticated_permission(
    state: &AuthHttpState,
    headers: &HeaderMap,
    permission: crate::Permission,
    csrf_required: bool,
) -> Result<(platform_store::console_read::AgentScope, String), Response> {
    use crate::auth::{PresentedCredentials, presented_credentials, session_csrf, session_digest};
    use platform_store::console_read::AgentScope;

    let secret = match presented_credentials(headers) {
        Ok(PresentedCredentials::Session(secret)) => secret,
        _ => return Err(authentication_required()),
    };
    let digest = session_digest(secret.expose_secret());
    let csrf = session_csrf(secret.expose_secret()).0;
    let now = Utc::now();
    let client = state.pool.get().await.map_err(|_| unavailable_auth())?;
    let active = console_auth::session(&client, &digest, now)
        .await
        .map_err(|_| unavailable_auth())?
        .ok_or_else(authentication_required)?;
    let expected_csrf_hash = session_digest(&csrf);
    if active.csrf_sha256.len() != expected_csrf_hash.len()
        || !bool::from(
            active
                .csrf_sha256
                .as_slice()
                .ct_eq(expected_csrf_hash.as_slice()),
        )
    {
        return Err(authentication_required());
    }
    if csrf_required
        && (!state.public_origin_valid
            || !crate::browser_origin_allowed(headers, &state.public_origin)
            || !crate::csrf_token_matches(headers, &csrf))
    {
        return Err(problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "request_rejected",
            "The request was rejected",
        )));
    }
    if !console_auth::touch_session(&client, &digest, now, Duration::minutes(30))
        .await
        .unwrap_or(false)
    {
        return Err(authentication_required());
    }
    let bindings = console_auth::user_role_bindings(&client, &active.user_id)
        .await
        .map_err(|_| unavailable_auth())?;
    let mut resolved = Vec::with_capacity(bindings.len());
    for binding in bindings {
        let Some(role) = built_in_role(&binding.role_id) else {
            continue;
        };
        let resolved_binding = match binding.asset_group_id {
            Some(group_id) => crate::RoleBinding::scoped(role, [group_id]),
            None => Ok(crate::RoleBinding::global(role)),
        };
        if let Ok(binding) = resolved_binding {
            resolved.push(binding);
        }
    }
    let capabilities = crate::resolve_capabilities(&resolved);
    match capabilities
        .iter()
        .find(|capability| capability.permission == permission)
    {
        Some(capability) => match &capability.scope {
            crate::PermissionScope::Global => Ok((AgentScope::Global, active.user_id)),
            crate::PermissionScope::AssetGroups { asset_group_ids } => Ok((
                AgentScope::AssetGroups(asset_group_ids.clone()),
                active.user_id,
            )),
        },
        None => Err(problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "Access is not available",
        ))),
    }
}

fn authentication_required() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::UNAUTHORIZED,
        "authentication_required",
        "Authentication required",
    ))
}

fn unavailable_auth() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "authentication_unavailable",
        "Authentication is temporarily unavailable",
    ))
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
    ConnectInfo(peer): ConnectInfo<crate::TrustedPeer>,
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
        .get::<ConnectInfo<crate::TrustedPeer>>()
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
