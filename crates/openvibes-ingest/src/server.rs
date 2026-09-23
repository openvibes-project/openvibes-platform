use std::{future::Future, sync::Arc, time::Duration};

use axum::{Extension, Router, routing::post};
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use platform_pki::Issuer;
use platform_store::Pool;
use tokio::{net::TcpListener, sync::Semaphore};
use tokio_rustls::TlsAcceptor;

use crate::{
    IngestConfig, IngestError,
    auth::{AuthenticatedAgent, Peer},
    error::ApiError,
    health,
    tls::{read_pem, server_config},
};

/// Shared per-process state.
#[derive(Clone)]
#[expect(
    dead_code,
    reason = "issuer, limits, and semaphore are used by PM3 tasks 4 to 6"
)]
pub(crate) struct AppState {
    pub pool: Pool,
    pub issuer: Arc<Issuer>,
    pub client_certificate_days: u32,
    pub finding_retention_days: u32,
    pub in_flight: Arc<Semaphore>,
}

/// Placeholder until the endpoint lands in a later PM3 task.
async fn not_yet(_agent: AuthenticatedAgent) -> ApiError {
    ApiError::NotImplemented
}

fn routes(state: AppState) -> Router {
    Router::new()
        .route("/v1/heartbeat", post(not_yet))
        .route("/v1/findings", post(not_yet))
        .route("/v1/renew", post(not_yet))
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
    let pool = platform_store::connect(&config.database_url)
        .await
        .map_err(|_| IngestError::Database)?;
    let issuer = Issuer::load(
        &read_pem(&config.issuing_certificate_file)?,
        &read_pem(&config.issuing_key_file)?,
    )
    .map_err(|_| IngestError::Tls)?;
    let acceptor = TlsAcceptor::from(server_config(&config)?);
    let state = AppState {
        pool: pool.clone(),
        issuer: Arc::new(issuer),
        client_certificate_days: config.client_certificate_days,
        finding_retention_days: config.finding_retention_days,
        in_flight: Arc::new(Semaphore::new(config.max_in_flight)),
    };
    let router = routes(state);
    let health = tokio::spawn(async move {
        let _ = axum::serve(health_listener, health::router(pool)).await;
    });
    let timeout = Duration::from_secs(config.request_timeout_seconds);
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => break,
            accepted = listener.accept() => {
                let Ok((tcp, _)) = accepted else { continue };
                let acceptor = acceptor.clone();
                let router = router.clone();
                tokio::spawn(async move {
                    let Ok(Ok(tls)) = tokio::time::timeout(timeout, acceptor.accept(tcp)).await else {
                        return;
                    };
                    let peer = tls
                        .get_ref()
                        .1
                        .peer_certificates()
                        .and_then(|chain| chain.first().cloned())
                        .map(|leaf| leaf.into_owned());
                    let service = TowerToHyperService::new(router.layer(Extension(Peer(peer))));
                    let _ = hyper::server::conn::http1::Builder::new()
                        .timer(TokioTimer::new())
                        .header_read_timeout(timeout)
                        .serve_connection(TokioIo::new(tls), service)
                        .await;
                });
            }
        }
    }
    health.abort();
    Ok(())
}
