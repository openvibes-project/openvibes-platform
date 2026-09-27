use std::{future::Future, sync::Arc};

use axum::{Router, extract::FromRef, routing::post};
use platform_pki::Issuer;
use platform_store::Pool;
use tokio::net::TcpListener;

use crate::{IngestConfig, IngestError};

/// Shared per-process state.
#[derive(Clone)]
pub(crate) struct AppState {
    pub pool: Pool,
    pub issuer: Arc<Issuer>,
    pub client_certificate_days: u32,
    pub finding_retention_days: u32,
    /// Inventory reports being handled; at most `max_inventory_in_flight`.
    pub inventory_slots: Arc<tokio::sync::Semaphore>,
}

impl FromRef<AppState> for Pool {
    fn from_ref(state: &AppState) -> Pool {
        state.pool.clone()
    }
}

/// Takes an inventory slot before the body is read, so at most
/// `max_inventory_in_flight` inventory bodies (each up to 8 MiB) are held at
/// once; a request that finds none free is answered 503 without buffering.
async fn inventory_slot(
    axum::extract::State(state): axum::extract::State<AppState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let Ok(_slot) = state.inventory_slots.clone().try_acquire_owned() else {
        return platform_agent_server::ApiError::Busy.into_response();
    };
    next.run(request).await
}

/// Both inventory endpoints: the 8 MiB body limit and the shared inventory
/// slots, built in one place so they cannot drift apart.
fn inventory_route(
    route: axum::routing::MethodRouter<AppState>,
    state: &AppState,
) -> axum::routing::MethodRouter<AppState> {
    route
        .layer(axum::extract::DefaultBodyLimit::max(
            platform_agent_server::MAX_INVENTORY_BYTES,
        ))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            inventory_slot,
        ))
}

fn routes(state: AppState) -> Router {
    Router::new()
        .route("/v1/heartbeat", post(crate::delivery::heartbeat))
        .route("/v1/findings", post(crate::delivery::findings))
        .route(
            "/v1/inventory",
            inventory_route(post(crate::delivery::inventory), &state),
        )
        .route(
            "/v1/inventory/changes",
            inventory_route(post(crate::delivery::inventory_changes), &state),
        )
        .route("/v1/enroll", post(crate::enroll::enroll))
        .route("/v1/renew", post(crate::enroll::renew))
        .with_state(state)
}

/// Binds `listen` and `health_listen`, then [`run`]s until `shutdown`.
pub async fn serve(
    config: IngestConfig,
    shutdown: impl Future<Output = ()>,
) -> Result<(), IngestError> {
    let listener = TcpListener::bind(config.listen)
        .await
        .map_err(|_| IngestError::Listen)?;
    let health = TcpListener::bind(config.health_listen)
        .await
        .map_err(|_| IngestError::Listen)?;
    run(config, listener, health, shutdown).await
}

/// Serves on already-bound listeners until `shutdown` completes.
pub async fn run(
    config: IngestConfig,
    listener: TcpListener,
    health_listener: TcpListener,
    shutdown: impl Future<Output = ()>,
) -> Result<(), IngestError> {
    config.validate()?;
    let read = |path| platform_agent_server::read_pem(path).map_err(IngestError::from);
    let issuer = Issuer::load(
        &read(&config.issuing_certificate_file)?,
        &read(&config.issuing_key_file)?,
    )
    .map_err(|_| IngestError::Tls)?;
    let issuer = Arc::new(issuer);
    let (client_certificate_days, finding_retention_days) = (
        config.client_certificate_days,
        config.finding_retention_days,
    );
    let inventory_slots = Arc::new(tokio::sync::Semaphore::new(config.max_inventory_in_flight));
    platform_agent_server::run(
        &config.settings(),
        listener,
        health_listener,
        move |pool| {
            routes(AppState {
                pool,
                issuer,
                client_certificate_days,
                finding_retention_days,
                inventory_slots,
            })
        },
        shutdown,
    )
    .await
    .map_err(IngestError::from)
}
