use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

use axum::{
    Router,
    extract::{
        ConnectInfo, DefaultBodyLimit, Extension, Json, Path, Query, State,
        rejection::QueryRejection,
    },
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
const ASSISTANT_REQUEST_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);
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
    pub(crate) pool: Pool,
    public_origin: Arc<str>,
    public_origin_valid: bool,
    /// Lowercase `Host` values served: `public_origin`'s authority and every
    /// name the certificate covers at the console's port (board #71).
    allowed_hosts: Arc<[String]>,
    dummy_password_phc: Option<String>,
    pub(crate) password_slots: Arc<Semaphore>,
    assistant: Option<crate::assistant::AssistantRuntime>,
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
    authenticated_router_with_assistant(pool, public_origin, [], None)
}

/// As [`authenticated_router`], also serving `hosts` (`name:port`, e.g. the
/// certificate's IP addresses) besides `public_origin`'s own (board #71).
pub fn authenticated_router_for_hosts(
    pool: Pool,
    public_origin: impl Into<Arc<str>>,
    hosts: impl IntoIterator<Item = String>,
) -> Router {
    authenticated_router_with_assistant(pool, public_origin, hosts, None)
}

pub(crate) fn authenticated_router_with_assistant(
    pool: Pool,
    public_origin: impl Into<Arc<str>>,
    hosts: impl IntoIterator<Item = String>,
    assistant: Option<crate::assistant::AssistantRuntime>,
) -> Router {
    let public_origin = public_origin.into();
    let mut allowed_hosts: Vec<String> = public_origin
        .parse::<axum::http::Uri>()
        .ok()
        .and_then(|origin| origin.authority().map(|a| a.as_str().to_ascii_lowercase()))
        .into_iter()
        .chain(hosts.into_iter().map(|host| host.to_ascii_lowercase()))
        .collect();
    allowed_hosts.sort();
    allowed_hosts.dedup();
    let state = AuthHttpState {
        pool,
        public_origin_valid: valid_public_origin(&public_origin),
        allowed_hosts: allowed_hosts.into(),
        public_origin,
        dummy_password_phc: dummy_password_phc(),
        password_slots: Arc::new(Semaphore::new(4)),
        assistant,
    };
    let router = Router::new()
        .nest(
            "/api",
            authenticated_api_router()
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    crate::auth_first::authenticate_first,
                ))
                .with_state(state.clone()),
        )
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
    let deadline = if request.uri().path().starts_with("/api/v1/assistant/") {
        ASSISTANT_REQUEST_DEADLINE
    } else {
        REQUEST_DEADLINE
    };
    match timeout(deadline, next.run(request)).await {
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
        .route(
            "/v1/session/password",
            axum::routing::post(crate::users::change_password),
        )
        .route("/v1/assistant/status", get(authenticated_assistant_status))
        .route(
            "/v1/assistant/messages",
            axum::routing::post(authenticated_assistant_message),
        )
        .route("/v1/agents/summary", get(authenticated_agent_summary))
        .route("/v1/agents", get(authenticated_agents))
        .route("/v1/agents/{agent_id}", get(authenticated_agent_detail))
        .route(
            "/v1/agents/{agent_id}/tags/preview",
            axum::routing::post(preview_authenticated_agent_tags),
        )
        .route(
            "/v1/agents/{agent_id}/tags",
            axum::routing::put(apply_authenticated_agent_tags),
        )
        .route(
            "/v1/agents/{agent_id}/revoke",
            axum::routing::post(revoke_authenticated_agent),
        )
        .route(
            "/v1/agents/{agent_id}/certificates",
            get(authenticated_agent_certificates),
        )
        .route("/v1/findings/summary", get(authenticated_finding_summary))
        .route("/v1/findings/groups", get(authenticated_finding_groups))
        .route(
            "/v1/findings/groups/{rule_set_id}/{rule_id}/endpoints",
            get(authenticated_finding_group_endpoints),
        )
        .route(
            "/v1/findings/groups/{rule_set_id}/{rule_id}/triage",
            axum::routing::post(update_authenticated_finding_group_triage),
        )
        .route("/v1/findings/latest", get(authenticated_latest_findings))
        .route(
            "/v1/findings/latest/{agent_id}/{rule_set_id}/{rule_id}",
            get(authenticated_latest_finding),
        )
        .route(
            "/v1/findings/latest/{agent_id}/{rule_set_id}/{rule_id}/triage",
            get(authenticated_finding_triage).put(update_authenticated_finding_triage),
        )
        .route("/v1/findings/history", get(authenticated_finding_history))
        .route(
            "/v1/vulnerabilities/summary",
            get(authenticated_vulnerability_summary),
        )
        .route("/v1/vulnerabilities", get(authenticated_vulnerabilities))
        .route(
            "/v1/vulnerabilities/advisories/{advisory_id}",
            get(authenticated_vulnerability_advisory),
        )
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
            "/v1/enrollment-tokens",
            get(authenticated_enrollment_tokens).post(create_authenticated_enrollment_token),
        )
        .route(
            "/v1/enrollment-tokens/{token_id}",
            get(authenticated_enrollment_token),
        )
        .route(
            "/v1/enrollment-tokens/{token_id}/revoke",
            axum::routing::post(revoke_authenticated_enrollment_token),
        )
        .route(
            "/v1/service-accounts",
            get(authenticated_service_accounts).post(create_authenticated_service_account),
        )
        .route(
            "/v1/service-accounts/{service_account_id}/disable",
            axum::routing::post(disable_authenticated_service_account),
        )
        .route(
            "/v1/service-accounts/{service_account_id}/tokens",
            get(authenticated_service_tokens).post(create_authenticated_service_token),
        )
        .route(
            "/v1/service-accounts/{service_account_id}/tokens/{token_id}/revoke",
            axum::routing::post(revoke_authenticated_service_token),
        )
        .route("/v1/rule-sets", get(authenticated_rule_sets))
        .route(
            "/v1/rule-sets/{rule_set_id}/bundles",
            get(authenticated_rule_bundles),
        )
        .route(
            "/v1/rule-bundles/preview",
            axum::routing::post(preview_authenticated_rule_bundle),
        )
        .route(
            "/v1/rule-bundles/publish",
            axum::routing::post(publish_authenticated_rule_bundle),
        )
        .route(
            "/v1/access-control/asset-groups",
            axum::routing::post(create_authenticated_asset_group),
        )
        .route(
            "/v1/access-control/asset-groups/{group_id}",
            axum::routing::put(update_authenticated_asset_group),
        )
        .route(
            "/v1/access-control/bindings",
            axum::routing::post(create_authenticated_access_binding),
        )
        .route(
            "/v1/access-control/users",
            axum::routing::post(crate::users::create_user),
        )
        .route(
            "/v1/access-control/bindings/{binding_id}",
            axum::routing::delete(revoke_authenticated_access_binding),
        )
        .route(
            "/v1/dashboards",
            get(crate::dashboards::list_dashboards).post(crate::dashboards::create_dashboard),
        )
        .route(
            "/v1/dashboards/{dashboard_id}",
            get(crate::dashboards::get_dashboard)
                .put(crate::dashboards::update_dashboard)
                .delete(crate::dashboards::delete_dashboard),
        )
        .route(
            "/v1/dashboards/{dashboard_id}/sharing",
            axum::routing::put(crate::dashboards::share_dashboard),
        )
        .route(
            "/v1/me/home",
            get(crate::dashboards::get_home).put(crate::dashboards::set_home),
        )
        .route(
            "/v1/agents/{agent_id}/packages",
            get(crate::software::list_host_packages),
        )
        .route("/v1/software", get(crate::software::list_software))
        .route(
            "/v1/software/{manager}/{name}",
            get(crate::software::get_software),
        )
        .route(
            "/v1/agents/{agent_id}/services",
            get(crate::ports::get_host_services),
        )
        .route("/v1/ports", get(crate::ports::list_ports))
        .route("/v1/ports/{protocol}/{port}", get(crate::ports::get_port))
        .route("/v1/services", get(crate::ports::list_services))
        .route("/v1/services/{unit}", get(crate::ports::get_unit))
        .route(
            "/v1/cases",
            get(crate::cases::list_cases).post(crate::cases::create_case),
        )
        .route("/v1/cases/for-item", get(crate::cases::cases_for_item))
        .route("/v1/cases/assignees", get(crate::cases::list_assignees))
        .route(
            "/v1/cases/{case_id}",
            get(crate::cases::get_case).put(crate::cases::update_case),
        )
        .route(
            "/v1/cases/{case_id}/notes",
            axum::routing::post(crate::cases::add_note),
        )
        .route(
            "/v1/cases/{case_id}/items",
            axum::routing::post(crate::cases::add_item),
        )
        .route(
            "/v1/cases/{case_id}/items/{item_id}",
            axum::routing::delete(crate::cases::remove_item),
        )
        .route(
            "/v1/cases/{case_id}/items/{item_id}/outcome",
            axum::routing::put(crate::cases::set_item_outcome),
        )
        .route("/v1/alarms", get(crate::alarms::list_alarms))
        .route("/v1/alarms/{alarm_id}", get(crate::alarms::get_alarm))
        .route(
            "/v1/alarms/{alarm_id}/triage",
            axum::routing::put(crate::alarms::update_alarm_triage),
        )
        .route(
            "/v1/alarm-suppressions",
            get(crate::alarm_suppressions::list_suppressions)
                .post(crate::alarm_suppressions::create_suppression),
        )
        .route(
            "/v1/alarm-suppressions/{suppression_id}",
            axum::routing::delete(crate::alarm_suppressions::remove_suppression),
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
    // The 421 page's own look loads under any name: fixed files, no data.
    // This layer is outside the others, so both answers get the console's
    // security headers here (CSP, nosniff, framing; reviewer on #116).
    if let Some(response) = misdirected_asset(request.uri().path()) {
        return public_security_headers(response).await;
    }
    let allowed = request.headers().get(header::HOST).is_none_or(|host| {
        host.to_str()
            .is_ok_and(|host| state.allowed_hosts.contains(&host.to_ascii_lowercase()))
    });
    if allowed {
        next.run(request).await
    } else {
        public_security_headers(misdirected(&state.public_origin)).await
    }
}

/// 421 for a name this console does not serve: a short page with the right
/// address, never a blank one (board #71). Still refused, so a hostile name
/// resolving here (DNS rebinding) reads nothing.
fn misdirected(public_origin: &str) -> Response {
    let origin = html_escape(public_origin);
    // Board #81: the sign-in page's look (its own stylesheet and wordmarks,
    // as the console's CSP allows no inline style) and plain words.
    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>OpenVIBES: wrong address</title>\
         <link rel=\"stylesheet\" href=\"/misdirected/page.css\"></head><body>\
         <main class=\"signin\"><div class=\"signin__card\"><picture>\
         <source srcset=\"/misdirected/wordmark-dark.svg\" media=\"(prefers-color-scheme: dark)\">\
         <img class=\"signin__logo\" src=\"/misdirected/wordmark-light.svg\" alt=\"OpenVIBES\">\
         </picture><h1>Wrong address</h1>\
         <p>This OpenVIBES console does not answer to the address you opened.</p>\
         <a class=\"button\" href=\"{origin}/\">Open the console</a>\
         <p class=\"address\">{origin}</p>\
         <p class=\"hint\">If that link does not open from where you are, ask whoever set up \
         OpenVIBES which address to use.</p></div></main></body></html>"
    );
    let mut response = (StatusCode::MISDIRECTED_REQUEST, body).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response
}

/// The 421 page's stylesheet and wordmarks, by exact path.
fn misdirected_asset(path: &str) -> Option<Response> {
    let (body, kind): (&'static str, &'static str) = match path {
        "/misdirected/page.css" => (include_str!("misdirected.css"), "text/css; charset=utf-8"),
        "/misdirected/wordmark-light.svg" => (
            include_str!("../web/public/brand/openvibes-wordmark-light.svg"),
            "image/svg+xml",
        ),
        "/misdirected/wordmark-dark.svg" => (
            include_str!("../web/public/brand/openvibes-wordmark-dark.svg"),
            "image/svg+xml",
        ),
        _ => return None,
    };
    let mut response = body.into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(kind));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600"),
    );
    Some(response)
}

fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The origin a browser request must carry: `https://` + the `Host` it was
/// sent to (already one this console serves), or `public_origin` without one.
fn request_origin(state: &AuthHttpState, headers: &axum::http::HeaderMap) -> String {
    headers
        .get(header::HOST)
        .and_then(|host| host.to_str().ok())
        .map_or_else(
            || state.public_origin.to_string(),
            |host| format!("https://{host}"),
        )
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

fn validated_agent_tags(
    tags: Vec<crate::AgentTagInput>,
) -> Option<Vec<platform_store::console_auth::AgentTag>> {
    if tags.len() > 64 {
        return None;
    }
    let mut tags = tags
        .into_iter()
        .map(|tag| platform_store::console_auth::AgentTag {
            key: tag.key,
            value: tag.value,
        })
        .collect::<Vec<_>>();
    if tags.iter().any(|tag| {
        tag.key.is_empty()
            || tag.key.len() > 64
            || tag.value.is_empty()
            || tag.value.len() > 256
            || tag.key.chars().any(char::is_control)
            || tag.value.chars().any(char::is_control)
    }) {
        return None;
    }
    tags.sort_by(|a, b| a.key.cmp(&b.key));
    if tags.windows(2).any(|pair| pair[0].key == pair[1].key) {
        return None;
    }
    Some(tags)
}

fn validated_group_request(
    request: crate::SaveAssetGroupRequest,
) -> Option<(String, Vec<platform_store::console_auth::AgentTag>)> {
    let name = request.name.trim().to_owned();
    if name.is_empty()
        || name.chars().count() > 128
        || name.chars().any(char::is_control)
        || request.selectors.is_empty()
        || request.selectors.len() > 32
    {
        return None;
    }
    let mut selectors = request
        .selectors
        .into_iter()
        .map(|s| platform_store::console_auth::AgentTag {
            key: s.key,
            value: s.value,
        })
        .collect::<Vec<_>>();
    if selectors.iter().any(|s| {
        s.key.is_empty()
            || s.key.chars().count() > 64
            || s.value.is_empty()
            || s.value.chars().count() > 256
            || s.key.chars().any(char::is_control)
            || s.value.chars().any(char::is_control)
    }) {
        return None;
    }
    selectors.sort_by(|a, b| a.key.cmp(&b.key));
    if selectors.windows(2).any(|w| w[0].key == w[1].key) {
        return None;
    }
    Some((name, selectors))
}

async fn save_authenticated_asset_group(
    state: AuthHttpState,
    headers: HeaderMap,
    group_id: Option<String>,
    request: crate::SaveAssetGroupRequest,
) -> Response {
    use platform_store::console_read::AgentScope;
    if group_id.as_deref().is_some_and(|id| !valid_uuid(id)) {
        return problem_response(ProblemDetails::new(
            StatusCode::BAD_REQUEST,
            "invalid_asset_group",
            "The asset group id is invalid",
        ));
    }
    let Some((name, selectors)) = validated_group_request(request) else {
        return problem_response(ProblemDetails::new(
            StatusCode::BAD_REQUEST,
            "invalid_asset_group",
            "Provide a name and 1 to 32 unique exact selectors within the documented lengths",
        ));
    };
    let (scope, actor) = match authenticated_permission(
        &state,
        &headers,
        crate::Permission::AssetGroupsManage,
        true,
    )
    .await
    {
        Ok(value) => value,
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
        Ok(client) => client,
        Err(_) => return unavailable_auth(),
    };
    match platform_store::console_auth::save_asset_group(
        &mut client,
        group_id.as_deref(),
        &name,
        &selectors,
        &actor,
        Utc::now(),
    )
    .await
    {
        Ok(Some(group)) => {
            let created = group_id.is_none();
            (
                if created {
                    StatusCode::CREATED
                } else {
                    StatusCode::OK
                },
                Json(crate::AccessAssetGroup {
                    asset_group_id: group.asset_group_id,
                    name: group.name,
                    selectors: group.selectors,
                }),
            )
                .into_response()
        }
        Ok(None) => problem_response(ProblemDetails::not_found(
            "asset_group_not_found",
            "Asset group not found",
        )),
        Err(platform_store::StoreError::Query) => problem_response(ProblemDetails::new(
            StatusCode::CONFLICT,
            "asset_group_conflict",
            "The asset group name is already in use or the change could not be saved",
        )),
        Err(_) => unavailable_auth(),
    }
}

/// Creates an asset group from a bounded conjunction of exact tag selectors.
#[utoipa::path(post,path="/api/v1/access-control/asset-groups",tag="access control",request_body=crate::SaveAssetGroupRequest,responses((status=201,description="Asset group created",body=crate::AccessAssetGroup),(status=400,description="Invalid selector set",body=ProblemDetails),(status=409,description="Name conflict",body=ProblemDetails)))]
pub(crate) async fn create_authenticated_asset_group(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Json(request): Json<crate::SaveAssetGroupRequest>,
) -> Response {
    save_authenticated_asset_group(state, headers, None, request).await
}

/// Replaces an asset group's name and complete selector conjunction.
#[utoipa::path(put,path="/api/v1/access-control/asset-groups/{group_id}",tag="access control",params(("group_id"=String,Path)),request_body=crate::SaveAssetGroupRequest,responses((status=200,description="Asset group updated",body=crate::AccessAssetGroup),(status=400,description="Invalid selector set",body=ProblemDetails),(status=404,description="Asset group not found",body=ProblemDetails),(status=409,description="Name conflict",body=ProblemDetails)))]
pub(crate) async fn update_authenticated_asset_group(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(group_id): Path<String>,
    Json(request): Json<crate::SaveAssetGroupRequest>,
) -> Response {
    save_authenticated_asset_group(state, headers, Some(group_id), request).await
}

fn agent_tag_preview_response(
    preview: platform_store::console_auth::AgentTagPreview,
) -> crate::AgentTagPreviewResponse {
    let tags = |items: Vec<platform_store::console_auth::AgentTag>| {
        items
            .into_iter()
            .map(|tag| crate::AgentTagInput {
                key: tag.key,
                value: tag.value,
            })
            .collect()
    };
    let groups = |items: Vec<(String, String)>| {
        items
            .into_iter()
            .map(|(asset_group_id, name)| crate::AgentTagGroupImpact {
                asset_group_id,
                name,
            })
            .collect()
    };
    let bindings = |items: Vec<platform_store::console_auth::TagBindingImpact>| {
        items
            .into_iter()
            .map(|binding| crate::AgentTagBindingImpact {
                binding_id: binding.binding_id,
                username: binding.username,
                role_id: binding.role_id,
                asset_group_name: binding.asset_group_name,
            })
            .collect()
    };
    crate::AgentTagPreviewResponse {
        current: tags(preview.current),
        proposed: tags(preview.proposed),
        gained_groups: groups(preview.gained_groups),
        lost_groups: groups(preview.lost_groups),
        gained_bindings: bindings(preview.gained_bindings),
        lost_bindings: bindings(preview.lost_bindings),
        preview_token: preview.token,
    }
}

/// Previews asset group membership changes for an agent's complete tag set.
#[utoipa::path(post, path="/api/v1/agents/{agent_id}/tags/preview", tag="agents", params(("agent_id"=String,Path)), request_body=crate::AgentTagChangeRequest, responses((status=200,description="Membership impact preview",body=crate::AgentTagPreviewResponse),(status=400,description="Invalid tag set",body=ProblemDetails),(status=404,description="Agent not found",body=ProblemDetails)))]
pub(crate) async fn preview_authenticated_agent_tags(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
    Json(request): Json<crate::AgentTagChangeRequest>,
) -> Response {
    use platform_store::console_read::AgentScope;
    if !valid_agent_id(&agent_id) {
        return problem_response(ProblemDetails::new(
            StatusCode::BAD_REQUEST,
            "invalid_agent_id",
            "The agent id is invalid",
        ));
    }
    let Some(tags) = validated_agent_tags(request.tags) else {
        return problem_response(ProblemDetails::new(
            StatusCode::BAD_REQUEST,
            "invalid_tags",
            "Provide at most 64 unique, non-empty tags within key and value limits",
        ));
    };
    let (scope, _) = match authenticated_permission(
        &state,
        &headers,
        crate::Permission::AssetGroupsManage,
        true,
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
    match platform_store::console_auth::preview_agent_tags(&client, &agent_id, &tags).await {
        Ok(Some(preview)) => {
            (StatusCode::OK, Json(agent_tag_preview_response(preview))).into_response()
        }
        Ok(None) => problem_response(ProblemDetails::not_found(
            "agent_not_found",
            "Agent not found",
        )),
        Err(_) => unavailable_auth(),
    }
}

/// Applies an agent tag set only while its membership preview remains current.
#[utoipa::path(put, path="/api/v1/agents/{agent_id}/tags", tag="agents", params(("agent_id"=String,Path)), request_body=crate::ApplyAgentTagsRequest, responses((status=204,description="Tags changed and impact audited"),(status=409,description="Preview is stale",body=crate::AgentTagPreviewResponse),(status=400,description="Invalid tag set",body=ProblemDetails)))]
pub(crate) async fn apply_authenticated_agent_tags(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
    Json(request): Json<crate::ApplyAgentTagsRequest>,
) -> Response {
    use platform_store::console_read::AgentScope;
    if !valid_agent_id(&agent_id)
        || request.preview_token.len() != 64
        || !request.preview_token.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return problem_response(ProblemDetails::new(
            StatusCode::BAD_REQUEST,
            "invalid_tag_change",
            "The tag change request is invalid",
        ));
    }
    let Some(tags) = validated_agent_tags(request.tags) else {
        return problem_response(ProblemDetails::new(
            StatusCode::BAD_REQUEST,
            "invalid_tags",
            "Provide at most 64 unique, non-empty tags within key and value limits",
        ));
    };
    let (scope, actor) = match authenticated_permission(
        &state,
        &headers,
        crate::Permission::AssetGroupsManage,
        true,
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
    let mut client = match state.pool.get().await {
        Ok(v) => v,
        Err(_) => return unavailable_auth(),
    };
    match platform_store::console_auth::apply_agent_tags(
        &mut client,
        &agent_id,
        &tags,
        &request.preview_token,
        &actor,
        Utc::now(),
    )
    .await
    {
        Ok(None) => StatusCode::NO_CONTENT.into_response(),
        Ok(Some(preview)) => (
            StatusCode::CONFLICT,
            Json(agent_tag_preview_response(preview)),
        )
            .into_response(),
        Err(_) => unavailable_auth(),
    }
}

/// Revokes one visible agent and records an operator reason.
#[utoipa::path(post,path="/api/v1/agents/{agent_id}/revoke",tag="agents",params(("agent_id"=String,Path)),request_body=crate::RevokeAgentRequest,responses((status=204,description="Agent revoked"),(status=404,description="Agent not found in the current scope",body=ProblemDetails),(status=400,description="Invalid reason",body=ProblemDetails)))]
pub(crate) async fn revoke_authenticated_agent(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
    Json(request): Json<crate::RevokeAgentRequest>,
) -> Response {
    if !valid_agent_id(&agent_id)
        || request.reason.trim().is_empty()
        || request.reason.chars().count() > 500
        || request.reason.chars().any(char::is_control)
    {
        return problem_response(ProblemDetails::new(
            StatusCode::BAD_REQUEST,
            "invalid_revoke_reason",
            "Provide a non-empty reason up to 500 characters",
        ));
    }
    let (scope, actor) =
        match authenticated_permission(&state, &headers, crate::Permission::AgentsRevoke, true)
            .await
        {
            Ok(value) => value,
            Err(response) => return response,
        };
    let mut client = match state.pool.get().await {
        Ok(value) => value,
        Err(_) => return unavailable_auth(),
    };
    match platform_store::console_auth::revoke_agent_in_scope(
        &mut client,
        &agent_id,
        &scope,
        &actor,
        request.reason.trim(),
        Utc::now(),
    )
    .await
    {
        Ok(
            platform_store::agents::Revoke::Revoked
            | platform_store::agents::Revoke::AlreadyRevoked,
        ) => StatusCode::NO_CONTENT.into_response(),
        Ok(platform_store::agents::Revoke::Unknown) => problem_response(ProblemDetails::not_found(
            "agent_not_found",
            "Agent not found",
        )),
        Ok(platform_store::agents::Revoke::Imported) => problem_response(ProblemDetails::new(
            StatusCode::CONFLICT,
            "imported_host_cannot_be_revoked",
            "Imported hosts cannot be revoked",
        )),
        Err(_) => unavailable_auth(),
    }
}

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
            })
            .collect(),
    })
    .into_response();
    no_store(response)
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
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

/// Lists service accounts without secret material.
#[utoipa::path(get,path="/api/v1/service-accounts",tag="service_accounts",responses((status=200,description="Service-account metadata",body=crate::ServiceAccountPage)))]
pub(crate) async fn authenticated_service_accounts(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
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
    let accounts = match console_auth::list_service_accounts(&client).await {
        Ok(value) => value,
        Err(_) => return unavailable_auth(),
    };
    if platform_store::audit::record(
        &client,
        &actor,
        "service_accounts.viewed",
        Some("service_accounts"),
        "success",
    )
    .await
    .is_err()
    {
        return unavailable_auth();
    }
    no_store(
        Json(crate::ServiceAccountPage {
            items: accounts
                .into_iter()
                .map(|account| crate::ServiceAccountView {
                    service_account_id: account.service_account_id,
                    name: account.name,
                    enabled: account.enabled,
                    created_at: account
                        .created_at
                        .to_rfc3339_opts(SecondsFormat::Millis, true),
                    active_tokens: account.active_tokens,
                    role_ids: account.role_ids,
                })
                .collect(),
        })
        .into_response(),
    )
}

/// Creates a named service identity with one initial global built-in role.
#[utoipa::path(post,path="/api/v1/service-accounts",tag="service_accounts",request_body=crate::CreateServiceAccountRequest,responses((status=201,description="Service account created",body=crate::ServiceAccountView),(status=409,description="Name already exists",body=ProblemDetails)))]
pub(crate) async fn create_authenticated_service_account(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Json(request): Json<crate::CreateServiceAccountRequest>,
) -> Response {
    let name = request.name.trim();
    if name.is_empty()
        || name.chars().count() > 128
        || name.chars().any(char::is_control)
        || !matches!(
            request.role_id.as_str(),
            "viewer" | "analyst" | "operator" | "admin"
        )
    {
        return problem_response(ProblemDetails::new(
            StatusCode::BAD_REQUEST,
            "invalid_service_account",
            "Provide a valid name and built-in global role",
        ));
    }
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
    let id = match console_auth::create_service_account(
        &mut client,
        name,
        &request.role_id,
        &actor,
        Utc::now(),
    )
    .await
    {
        Ok(Some(id)) => id,
        Ok(None) => {
            return problem_response(ProblemDetails::new(
                StatusCode::CONFLICT,
                "service_account_conflict",
                "A service account with this name already exists",
            ));
        }
        Err(_) => return unavailable_auth(),
    };
    let response = Json(crate::ServiceAccountView {
        service_account_id: id,
        name: name.to_owned(),
        enabled: true,
        created_at: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        active_tokens: 0,
        role_ids: vec![request.role_id],
    })
    .into_response();
    let mut response = response;
    *response.status_mut() = StatusCode::CREATED;
    no_store(response)
}

/// Disables an account and revokes its issued tokens.
#[utoipa::path(post,path="/api/v1/service-accounts/{service_account_id}/disable",tag="service_accounts",params(("service_account_id"=String,Path)),responses((status=204,description="Service account disabled"),(status=404,description="Unknown or already disabled",body=ProblemDetails)))]
pub(crate) async fn disable_authenticated_service_account(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(service_account_id): Path<String>,
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
    match console_auth::disable_service_account(
        &mut client,
        &service_account_id,
        &actor,
        Utc::now(),
    )
    .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => problem_response(ProblemDetails::new(
            StatusCode::NOT_FOUND,
            "service_account_not_found",
            "Service account not found or already disabled",
        )),
        Err(_) => unavailable_auth(),
    }
}

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
    let hash = crate::auth::session_digest(token.as_str());
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

/// Shared signature verifier for exact signed-envelope request bytes.
async fn verify_console_rule_envelope(
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
    let (scope, actor) =
        match authenticated_permission(&state, &headers, crate::Permission::RulesRead, false).await
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
    let (scope, actor) =
        match authenticated_permission(&state, &headers, crate::Permission::RulesRead, false).await
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

fn valid_agent_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
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
        (status = 503, description = "Authentication store is unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")
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
    if !background_request(request.headers())
        && !console_auth::touch_session(&client, &digest, now, Duration::minutes(30))
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
    let mut capabilities = if active.password_must_change {
        Vec::new() // nothing but setting the password until then (#85)
    } else {
        crate::resolve_capabilities(&resolved)
    };
    if state.assistant.is_none() {
        capabilities.retain(|capability| capability.permission != crate::Permission::AssistantUse);
    }
    let response = crate::SessionResponse {
        principal: crate::SessionPrincipal {
            id: active.user_id,
            display_name: active.display_name,
            username: Some(active.username),
        },
        authentication_method: crate::AuthenticationMethod::LocalPassword,
        authentication_level: crate::AuthenticationLevel::SingleFactor,
        capabilities,
        csrf_token: csrf,
        idle_expires_at: idle_expiry.to_rfc3339_opts(SecondsFormat::Secs, true),
        absolute_expires_at: active
            .absolute_expires_at
            .to_rfc3339_opts(SecondsFormat::Secs, true),
        password_must_change: active.password_must_change,
    };
    let mut response = (StatusCode::OK, axum::Json(response)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
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
        match authenticated_permission(&state, &headers, crate::Permission::FindingsRead, false)
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
    let assistant_scope = match &agent_scope {
        ConsoleScope::Global => platform_store::assistant::AgentScope::All,
        ConsoleScope::AssetGroups(_) => {
            let client = match state.pool.get().await {
                Ok(client) => client,
                Err(_) => return unavailable_auth(),
            };
            let ids = match platform_store::console_read::agent_ids_in_scope(&client, &agent_scope)
                .await
            {
                Ok(ids) => ids,
                Err(_) => return unavailable_auth(),
            };
            platform_store::assistant::AgentScope::Only(ids)
        }
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
    let lookups = crate::assistant::ConsoleReadLookups::new(
        platform_assistant::StoreLookups::new(state.pool.clone(), assistant_scope, settings.now),
        state.pool.clone(),
        agent_scope,
        settings.now,
    );
    let backend: Arc<dyn platform_assistant::ChatBackend> =
        Arc::new(crate::assistant::LeasedChatBackend::new(
            runtime.backend.clone(),
            user_permit,
            capacity_permit,
        ));
    let started = Instant::now();
    let request_id = next_request_id();
    let answer = tokio::time::timeout(
        Duration::seconds(30).to_std().unwrap_or_default(),
        platform_assistant::answer(
            backend,
            &lookups,
            settings,
            &history,
            &request.question,
            None,
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
                imported: summary.imported.try_into().unwrap_or_default(),
                // Agent and platform release in lockstep; if that ever
                // changes, compare against the newest published agent RPM.
                platform_version: env!("CARGO_PKG_VERSION").to_owned(),
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
        ("state" = Option<String>, Query, description = "active, stale, revoked, or imported"),
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
        Some("imported") => Some(AgentState::Imported),
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
            AgentState::Imported => crate::AgentStatus::Imported,
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
        os_id: agent.os_id,
        os_version: agent.os_version,
        running_kernel: agent.running_kernel,
        inventory_at: agent
            .inventory_at
            .map(|value| value.to_rfc3339_opts(SecondsFormat::Secs, true)),
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

fn parse_if_match_zero_version(headers: &HeaderMap) -> Result<Option<i64>, ()> {
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

#[utoipa::path(get, path = "/api/v1/findings/latest/{agent_id}/{rule_set_id}/{rule_id}/triage", tag = "findings", params(("agent_id" = String, Path), ("rule_set_id" = String, Path), ("rule_id" = String, Path)), responses((status = 200, description = "Current finding triage", body = crate::FindingTriageView, headers(("ETag" = String, description = "Triage version"))), (status = 404, description = "Finding not found", body = crate::ProblemDetails), (status = 403, description = "Permission denied", body = crate::ProblemDetails)))]
pub(crate) async fn authenticated_finding_triage(
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
        Ok(Some(_)) => {
            match platform_store::console_triage::get(&client, &agent_id, rule_set_id, &rule_id)
                .await
            {
                Ok(Some(record)) => triage_response(record),
                Ok(None) => problem_response(ProblemDetails::not_found(
                    "finding_not_found",
                    "Finding not found",
                )),
                Err(_) => unavailable_auth(),
            }
        }
        Ok(None) => problem_response(ProblemDetails::not_found(
            "finding_not_found",
            "Finding not found",
        )),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(put, path = "/api/v1/findings/latest/{agent_id}/{rule_set_id}/{rule_id}/triage", tag = "findings", params(("agent_id" = String, Path), ("rule_set_id" = String, Path), ("rule_id" = String, Path), ("If-Match" = String, Header)), request_body = crate::UpdateFindingTriageRequest, responses((status = 200, description = "Updated finding triage", body = crate::FindingTriageView, headers(("ETag" = String, description = "New triage version"))), (status = 412, description = "Stale triage version", body = crate::ProblemDetails), (status = 428, description = "If-Match is required", body = crate::ProblemDetails)))]
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
        match authenticated_permission(&state, &headers, crate::Permission::FindingsTriage, true)
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
                "finding_not_found",
                "Finding not found",
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
        Ok(platform_store::console_triage::TriageUpdate::NotFound) => problem_response(
            ProblemDetails::not_found("finding_not_found", "Finding not found"),
        ),
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

#[utoipa::path(get, path="/api/v1/vulnerabilities", tag="vulnerabilities", params(("host"=Option<String>, Query), ("advisory"=Option<String>, Query), ("severity"=Option<String>, Query), ("cve"=Option<String>, Query), ("fixed"=Option<bool>, Query), ("exploited"=Option<bool>, Query), ("reboot_needed"=Option<bool>, Query)), responses((status=200, description="Prioritised, scope-filtered vulnerabilities", body=crate::VulnerabilityPage), (status=400, description="Invalid filters", body=crate::ProblemDetails)))]
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
        },
        &scope,
    )
    .await
    {
        Ok(rows) => rows,
        Err(_) => return unavailable_auth(),
    };
    let mut rows = rows;
    let more_available = rows.len() > 100;
    rows.truncate(100);
    let items = rows.into_iter().map(vulnerability_view).collect();
    Json(crate::VulnerabilityPage {
        items,
        more_available,
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    })
    .into_response()
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
    let mut rows = rows;
    let more_available = rows.len() > 100;
    rows.truncate(100);
    let hosts = crate::VulnerabilityPage {
        items: rows.into_iter().map(vulnerability_view).collect(),
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
    }
}

#[utoipa::path(get, path="/api/v1/findings/groups", tag="findings", params(("since"=Option<String>, Query), ("cursor"=Option<String>, Query), ("limit"=Option<u16>, Query)), responses((status=200, description="Recent scope-filtered findings grouped by rule", body=crate::FindingGroupPage)))]
pub(crate) async fn authenticated_finding_groups(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    query: Result<Query<FindingGroupsParams>, QueryRejection>,
) -> Response {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use platform_store::console_read::{
        FindingGroupCursor, FindingGroupQuery, finding_groups_in_scope,
    };
    let scope =
        match authenticated_agent_scope(&state, &headers, crate::Permission::FindingsRead).await {
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
                investigating: g.investigating.max(0) as u64,
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

#[utoipa::path(get, path="/api/v1/findings/groups/{rule_set_id}/{rule_id}/endpoints", tag="findings", params(("rule_set_id"=String,Path),("rule_id"=String,Path),("since"=Option<String>,Query),("include_older"=Option<bool>,Query),("cursor"=Option<String>,Query),("limit"=Option<u16>,Query)), responses((status=200,description="Scoped endpoints reporting one recent rule group",body=crate::FindingGroupEndpointPage),(status=404,description="Finding group not found",body=crate::ProblemDetails)))]
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
    let scope =
        match authenticated_agent_scope(&state, &headers, crate::Permission::FindingsRead).await {
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
                "finding_not_found",
                "Finding group not found",
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

#[utoipa::path(post,path="/api/v1/findings/groups/{rule_set_id}/{rule_id}/triage",tag="findings",params(("rule_set_id"=String,Path),("rule_id"=String,Path)),request_body=crate::BulkFindingTriageRequest,responses((status=200,description="Atomic endpoint triage update",body=crate::BulkFindingTriageResponse),(status=412,description="At least one triage version is stale",body=crate::ProblemDetails),(status=404,description="Group or endpoint is not visible",body=crate::ProblemDetails)))]
pub(crate) async fn update_authenticated_finding_group_triage(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((rule_set_id, rule_id)): Path<(String, String)>,
    payload: Result<Json<crate::BulkFindingTriageRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let (scope, user_id) =
        match authenticated_permission(&state, &headers, crate::Permission::FindingsTriage, true)
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
        Ok(platform_store::console_triage::BulkTriageUpdate::NotFound) => problem_response(
            ProblemDetails::not_found("finding_not_found", "Finding group or endpoint not found"),
        ),
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

async fn authenticated_agent_scope(
    state: &AuthHttpState,
    headers: &HeaderMap,
    permission: crate::Permission,
) -> Result<platform_store::console_read::AgentScope, Response> {
    authenticated_permission(state, headers, permission, false)
        .await
        .map(|(scope, _user_id)| scope)
}

pub(crate) async fn authenticated_permission(
    state: &AuthHttpState,
    headers: &HeaderMap,
    permission: crate::Permission,
    csrf_required: bool,
) -> Result<(platform_store::console_read::AgentScope, String), Response> {
    use crate::auth::{PresentedCredentials, presented_credentials, session_digest};
    use platform_store::console_read::AgentScope;

    let now = Utc::now();
    let secret = match presented_credentials(headers) {
        Ok(PresentedCredentials::Session(secret)) => secret,
        Ok(PresentedCredentials::Bearer(secret)) => {
            if csrf_required {
                // Browser mutations require a session-bound CSRF value; bearer
                // mutations are not enabled by this first API adapter.
                return Err(problem_response(ProblemDetails::new(
                    StatusCode::FORBIDDEN,
                    "permission_denied",
                    "Access is not available",
                )));
            }
            let digest = session_digest(secret.expose_secret());
            let client = state.pool.get().await.map_err(|_| unavailable_auth())?;
            let token = console_auth::active_service_token(&client, &digest, now)
                .await
                .map_err(|_| unavailable_auth())?
                .ok_or_else(authentication_required)?;
            let mut resolved = Vec::with_capacity(token.bindings.len());
            for binding in token.bindings {
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
            return match capabilities
                .iter()
                .find(|capability| capability.permission == permission)
            {
                Some(capability) => match &capability.scope {
                    crate::PermissionScope::Global => {
                        Ok((AgentScope::Global, token.service_account_id))
                    }
                    crate::PermissionScope::AssetGroups { asset_group_ids } => Ok((
                        AgentScope::AssetGroups(asset_group_ids.clone()),
                        token.service_account_id,
                    )),
                },
                None => Err(problem_response(ProblemDetails::new(
                    StatusCode::FORBIDDEN,
                    "permission_denied",
                    "Access is not available",
                ))),
            };
        }
        _ => return Err(authentication_required()),
    };
    let user = session_capabilities(state, headers, secret.expose_secret(), csrf_required).await?;
    match user
        .capabilities
        .iter()
        .find(|capability| capability.permission == permission)
    {
        Some(capability) => match &capability.scope {
            crate::PermissionScope::Global => Ok((AgentScope::Global, user.user_id)),
            crate::PermissionScope::AssetGroups { asset_group_ids } => Ok((
                AgentScope::AssetGroups(asset_group_ids.clone()),
                user.user_id,
            )),
        },
        None => Err(problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "Access is not available",
        ))),
    }
}

/// A signed-in browser user and their effective capabilities. Bearer
/// tokens are refused: dashboards and preferences belong to people.
pub(crate) struct SessionUser {
    pub(crate) user_id: String,
    pub(crate) capabilities: Vec<crate::EffectiveCapability>,
}

pub(crate) async fn session_user(
    state: &AuthHttpState,
    headers: &HeaderMap,
    csrf_required: bool,
) -> Result<SessionUser, Response> {
    use crate::auth::{PresentedCredentials, presented_credentials};
    match presented_credentials(headers) {
        Ok(PresentedCredentials::Session(secret)) => {
            session_capabilities(state, headers, secret.expose_secret(), csrf_required).await
        }
        Ok(PresentedCredentials::Bearer(_)) => Err(problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "Access is not available",
        ))),
        _ => Err(authentication_required()),
    }
}

/// Verifies the session cookie and CSRF and touches the session, without
/// the `password_must_change` gate: the set-password route needs a session
/// while the flag is set. Returns the session and its digest.
pub(crate) async fn checked_session(
    state: &AuthHttpState,
    headers: &HeaderMap,
    secret: &str,
    csrf_required: bool,
) -> Result<(console_auth::Session, [u8; 32]), Response> {
    use crate::auth::{session_csrf, session_digest};
    let now = Utc::now();
    let digest = session_digest(secret);
    let csrf = session_csrf(secret).0;
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
            || !crate::browser_origin_allowed(headers, &request_origin(state, headers))
            || !crate::csrf_token_matches(headers, &csrf))
    {
        return Err(problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "request_rejected",
            "The request was rejected",
        )));
    }
    if !background_request(headers)
        && !console_auth::touch_session(&client, &digest, now, Duration::minutes(30))
            .await
            .unwrap_or(false)
    {
        return Err(authentication_required());
    }
    Ok((active, digest))
}

/// A request the web app makes on its own (the live-alarm poll), marked
/// with `X-OpenVIBES-Background: 1`. It is checked like any other, but it
/// does not extend the session's idle expiry: an unattended open console
/// still signs out after 30 idle minutes.
pub(crate) fn background_request(headers: &HeaderMap) -> bool {
    headers
        .get("x-openvibes-background")
        .is_some_and(|value| value.as_bytes() == b"1")
}

/// 403 for a user who must set their own password first.
pub(crate) fn password_change_required() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::FORBIDDEN,
        "password_change_required",
        "Set your own password first",
    ))
}

/// The session path shared by `authenticated_permission` and `session_user`:
/// verifies the session and CSRF, touches it, refuses a user who must still
/// set their own password, and resolves capabilities.
async fn session_capabilities(
    state: &AuthHttpState,
    headers: &HeaderMap,
    secret: &str,
    csrf_required: bool,
) -> Result<SessionUser, Response> {
    let (active, _digest) = checked_session(state, headers, secret, csrf_required).await?;
    // One gate for every session route (#85): until the user replaces a
    // one-time password, only the session read, setting the password and
    // sign-out work, and those do not come through here.
    if active.password_must_change {
        return Err(password_change_required());
    }
    let client = state.pool.get().await.map_err(|_| unavailable_auth())?;
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
    Ok(SessionUser {
        user_id: active.user_id,
        capabilities,
    })
}

pub(crate) fn authentication_required() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::UNAUTHORIZED,
        "authentication_required",
        "Authentication required",
    ))
}

pub(crate) fn unavailable_auth() -> Response {
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
    proxy_client: Option<Extension<crate::server::TrustedProxyClient>>,
    headers: HeaderMap,
    payload: Result<axum::Json<crate::LoginRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    use crate::auth::{
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
async fn logout(State(state): State<AuthHttpState>, request: axum::extract::Request) -> Response {
    use crate::auth::{browser_origin_allowed, csrf_token_matches, named_cookie, session_digest};

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

use platform_password::canonical_username;

/// Failed password checks per account (sign-in and set-password together)
/// before the account is locked for the window.
pub(crate) const ACCOUNT_FAILURE_LIMIT: i32 = 5;
const SOURCE_FAILURE_LIMIT: i32 = 25;

/// The per-account throttle bucket sign-in uses; set-password counts a wrong
/// current password against it too (#85).
pub(crate) fn account_throttle_bucket(username: &str) -> [u8; 32] {
    login_throttle_buckets(Some(username), None).0
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

fn login_throttle_buckets(
    username: Option<&str>,
    source: Option<&str>,
) -> ([u8; 32], Option<[u8; 32]>) {
    let username = username.unwrap_or("invalid");
    let account = throttle_digest(b"account", username.as_bytes());
    let source = source.map(|source| throttle_digest(b"source-address", source.as_bytes()));
    (account, source)
}

pub(crate) fn bounded_user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.chars().take(256).collect::<String>())
}

fn dummy_password_phc() -> Option<String> {
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
    const REFERRER_POLICY: HeaderName = HeaderName::from_static("referrer-policy");
    const PERMISSIONS_POLICY: HeaderName = HeaderName::from_static("permissions-policy");
    const FRAME_OPTIONS: HeaderName = HeaderName::from_static("x-frame-options");

    // Enforce the complete browser policy on every public response.
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; script-src 'self'; script-src-attr 'none'; style-src 'self'; style-src-attr 'none'; img-src 'self'; font-src 'none'; connect-src 'self'; form-action 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; worker-src 'none'; manifest-src 'self'",
        ),
    );
    response
        .headers_mut()
        .insert(FRAME_OPTIONS, HeaderValue::from_static("DENY"));
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

#[cfg(test)]
mod login_throttle_tests {
    use super::login_throttle_buckets;

    #[test]
    fn source_throttle_is_per_address_and_account_throttle_is_per_user() {
        let alice = login_throttle_buckets(Some("alice"), Some("192.0.2.9"));
        let bob = login_throttle_buckets(Some("bob"), Some("192.0.2.9"));
        let alice_elsewhere = login_throttle_buckets(Some("alice"), Some("192.0.2.10"));
        assert_ne!(alice.0, bob.0);
        assert_eq!(alice.1, bob.1);
        assert_eq!(alice.0, alice_elsewhere.0);
        assert_ne!(alice.1, alice_elsewhere.1);
        assert_eq!(login_throttle_buckets(Some("alice"), None).1, None);
    }
}
