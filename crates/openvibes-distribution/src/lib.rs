#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! The distribution service: serves operator-published, offline-signed rule
//! bundles to authenticated agents (`POST /v1/rule-bundle`).

mod config;

use std::{fmt, future::Future};

use axum::{
    Router,
    body::Bytes,
    extract::{FromRef, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use openvibes_core::RuleBundleRequest;
use platform_agent_server::{ApiError, AuthenticatedAgent, ServerError};
use platform_store::{Pool, rules::Served};
use tokio::net::TcpListener;

pub use config::{DistributionConfig, load_config};

/// Startup failures; messages never include file contents or secrets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DistributionError {
    /// The configuration is missing, invalid, or out of range.
    Config,
    /// A certificate or key file is unreadable or invalid.
    Tls,
    /// The database is unreachable at startup.
    Database,
    /// A listener could not be bound.
    Listen,
}

impl fmt::Display for DistributionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Config => "invalid distribution configuration",
            Self::Tls => "invalid TLS or CA certificate or key file",
            Self::Database => "database unavailable",
            Self::Listen => "cannot bind a listener",
        })
    }
}

impl std::error::Error for DistributionError {}

impl From<ServerError> for DistributionError {
    fn from(error: ServerError) -> Self {
        match error {
            ServerError::Config => Self::Config,
            ServerError::Tls => Self::Tls,
            ServerError::Database => Self::Database,
            ServerError::Listen => Self::Listen,
        }
    }
}

#[derive(Clone)]
struct AppState {
    pool: Pool,
}

impl FromRef<AppState> for Pool {
    fn from_ref(state: &AppState) -> Pool {
        state.pool.clone()
    }
}

/// `POST /v1/rule-bundle`: the set's current envelope, byte for byte, when
/// the agent's version is older; 204 when it is current; 404 when the set
/// is unknown, retired, or has nothing published. Authentication runs
/// first, so an unauthenticated client never learns how bodies are parsed.
async fn rule_bundle(
    AuthenticatedAgent(_): AuthenticatedAgent,
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let request: RuleBundleRequest = platform_agent_server::parse(&body)?;
    let current = request
        .current_version
        .map(|version| i64::try_from(version).unwrap_or(i64::MAX));
    let client = state.pool.get().await.map_err(|_| ApiError::Unavailable)?;
    Ok(
        match platform_store::rules::serve(&client, request.rule_set_id.as_str(), current).await? {
            Served::Unknown => ApiError::NotFound.into_response(),
            Served::UpToDate => StatusCode::NO_CONTENT.into_response(),
            Served::Envelope(bytes) => {
                ([(header::CONTENT_TYPE, "application/json")], bytes).into_response()
            }
        },
    )
}

/// Binds `listen` and `health_listen`, then [`run`]s until `shutdown`.
pub async fn serve(
    config: DistributionConfig,
    shutdown: impl Future<Output = ()>,
) -> Result<(), DistributionError> {
    let listener = TcpListener::bind(config.listen)
        .await
        .map_err(|_| DistributionError::Listen)?;
    let health = TcpListener::bind(config.health_listen)
        .await
        .map_err(|_| DistributionError::Listen)?;
    run(config, listener, health, shutdown).await
}

/// Serves on already-bound listeners until `shutdown` completes.
pub async fn run(
    config: DistributionConfig,
    listener: TcpListener,
    health_listener: TcpListener,
    shutdown: impl Future<Output = ()>,
) -> Result<(), DistributionError> {
    config.validate()?;
    platform_agent_server::run(
        &config.settings(),
        listener,
        health_listener,
        |pool| {
            Router::new()
                .route("/v1/rule-bundle", post(rule_bundle))
                .with_state(AppState { pool })
        },
        shutdown,
    )
    .await
    .map_err(DistributionError::from)
}

/// Whether `body` is a valid `RuleBundleRequest`. Exposed for fixture tests.
#[doc(hidden)]
pub fn accepts(body: &[u8]) -> bool {
    platform_agent_server::parse::<RuleBundleRequest>(body).is_ok()
}
