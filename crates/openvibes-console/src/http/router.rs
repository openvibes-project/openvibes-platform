//! Router assembly: the public, authenticated, development and health
//! routers, and the state the authenticated one shares with its handlers.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use axum::{Router, http::StatusCode, middleware, routing::get};
use platform_store::Pool;
use tokio::sync::Semaphore;

#[cfg(feature = "embedded-ui")]
use super::frontend::frontend_router;
use super::{
    frontend::{asset_router, browser_not_found},
    middleware::{authenticated_host_only, loopback_host_only, with_request_limits},
    routes::{api_router, auth_not_found, authenticated_api_router, authenticated_auth_router},
};
use crate::{access::login::dummy_password_phc, config::valid_public_origin};

/// Process-readiness state shared with the loopback-only health router.
#[derive(Clone, Debug, Default)]
pub struct Readiness(Arc<AtomicBool>);

#[derive(Clone)]
pub(crate) struct AuthHttpState {
    pub(crate) pool: Pool,
    pub(crate) public_origin: Arc<str>,
    pub(crate) public_origin_valid: bool,
    /// Lowercase `Host` values served: `public_origin`'s authority and every
    /// name the certificate covers at the console's port (board #71).
    pub(crate) allowed_hosts: Arc<[String]>,
    pub(crate) dummy_password_phc: Option<String>,
    pub(crate) password_slots: Arc<Semaphore>,
    pub(crate) assistant: Option<crate::assistant::AssistantRuntime>,
    /// `None` when the About page's newer-version check is turned off.
    pub(crate) update_checker: Option<Arc<crate::about::UpdateChecker>>,
    /// `None` when the agent install package is not configured.
    pub(crate) agent_install: Option<Arc<crate::config::AgentInstallConfig>>,
    /// Shared live-presence check behind the agent event stream.
    pub(crate) presence: crate::hosts::presence::PresenceHub,
    /// The rule signer's socket: where a site rule set is signed to publish.
    pub(crate) signer_socket: Arc<std::path::Path>,
    /// The fetch service's socket (assistant internet lookups).
    pub(crate) fetch_socket: Arc<std::path::Path>,
    /// The picture helper's socket (profile picture conversion).
    pub(crate) picture_socket: Arc<std::path::Path>,
    /// Internet lookups used per user this hour.
    pub(crate) internet_limits: Arc<crate::assistant::fetch_client::Limits>,
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
    authenticated_router_with_assistant(
        pool,
        public_origin,
        [],
        None,
        None,
        None,
        (None, None, None),
    )
}

/// As [`authenticated_router`], with the rule signer at `socket` instead of
/// its default path (tests, unusual installs).
pub fn authenticated_router_with_signer(
    pool: Pool,
    public_origin: impl Into<Arc<str>>,
    socket: std::path::PathBuf,
) -> Router {
    authenticated_router_with_assistant(
        pool,
        public_origin,
        [],
        None,
        None,
        None,
        (Some(socket), None, None),
    )
}

/// As [`authenticated_router`], with the fetch service at `socket` (tests).
pub fn authenticated_router_with_fetch(
    pool: Pool,
    public_origin: impl Into<Arc<str>>,
    socket: std::path::PathBuf,
) -> Router {
    authenticated_router_with_assistant(
        pool,
        public_origin,
        [],
        None,
        None,
        None,
        (None, Some(socket), None),
    )
}

/// As [`authenticated_router`], offering the agent install command and
/// package built from `agent_install` (tests; the server reads it from
/// `console.toml`).
pub fn authenticated_router_with_agent_install(
    pool: Pool,
    public_origin: impl Into<Arc<str>>,
    agent_install: crate::config::AgentInstallConfig,
) -> Router {
    authenticated_router_with_assistant(
        pool,
        public_origin,
        [],
        None,
        None,
        Some(agent_install),
        (None, None, None),
    )
}

/// As [`authenticated_router`], with the picture helper at `socket` (tests).
pub fn authenticated_router_with_picture(
    pool: Pool,
    public_origin: impl Into<Arc<str>>,
    socket: std::path::PathBuf,
) -> Router {
    authenticated_router_with_assistant(
        pool,
        public_origin,
        [],
        None,
        None,
        None,
        (None, None, Some(socket)),
    )
}

/// Where the rule signer listens (`openvibes-signer.service`).
const DEFAULT_SIGNER_SOCKET: &str = "/run/openvibes-signer/sign.sock";

/// As [`authenticated_router`], also serving `hosts` (`name:port`, e.g. the
/// certificate's IP addresses) besides `public_origin`'s own (board #71).
pub fn authenticated_router_for_hosts(
    pool: Pool,
    public_origin: impl Into<Arc<str>>,
    hosts: impl IntoIterator<Item = String>,
) -> Router {
    authenticated_router_with_assistant(
        pool,
        public_origin,
        hosts,
        None,
        None,
        None,
        (None, None, None),
    )
}

pub(crate) fn authenticated_router_with_assistant(
    pool: Pool,
    public_origin: impl Into<Arc<str>>,
    hosts: impl IntoIterator<Item = String>,
    assistant: Option<crate::assistant::AssistantRuntime>,
    update_checker: Option<Arc<crate::about::UpdateChecker>>,
    agent_install: Option<crate::config::AgentInstallConfig>,
    // The rule signer's, fetch service's and picture helper's sockets; `None` is the default path.
    (signer_socket, fetch_socket, picture_socket): (
        Option<std::path::PathBuf>,
        Option<std::path::PathBuf>,
        Option<std::path::PathBuf>,
    ),
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
        update_checker,
        agent_install: agent_install.map(Arc::new),
        presence: crate::hosts::presence::PresenceHub::default(),
        signer_socket: signer_socket
            .unwrap_or_else(|| std::path::PathBuf::from(DEFAULT_SIGNER_SOCKET))
            .into(),
        fetch_socket: fetch_socket
            .unwrap_or_else(|| {
                std::path::PathBuf::from(crate::assistant::fetch_client::DEFAULT_FETCH_SOCKET)
            })
            .into(),
        picture_socket: picture_socket
            .unwrap_or_else(|| {
                std::path::PathBuf::from(crate::access::pictures::DEFAULT_PICTURE_SOCKET)
            })
            .into(),
        internet_limits: Arc::default(),
    };
    let router = Router::new()
        .nest(
            "/api",
            authenticated_api_router()
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    crate::access::auth_first::authenticate_first,
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

/// Builds the separate health router. Its listener is validated as loopback
/// by [`crate::ConsoleConfig::validate`].
pub fn health_router(readiness: Readiness) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .with_state(readiness)
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
