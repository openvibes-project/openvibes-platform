use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use axum::{
    Router,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};

use crate::problem::{ProblemDetails, problem_response};

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
/// It intentionally contains no health endpoints, frontend fall-through, or
/// permissive temporary authentication. Feature routers can be nested under
/// their declared prefixes in later milestones.
pub fn public_router() -> Router {
    Router::new()
        .nest("/api", Router::new().fallback(api_not_found))
        .nest("/auth", Router::new().fallback(auth_not_found))
        .nest("/assets", Router::new().fallback(asset_not_found))
        .fallback(browser_not_found)
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

async fn browser_not_found() -> Response {
    let mut response = StatusCode::NOT_FOUND.into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
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
