use std::{future::Future, sync::Arc, time::Duration};

use axum::{Extension, Router, extract::DefaultBodyLimit, middleware, routing::post};
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    server::graceful::GracefulShutdown,
    service::TowerToHyperService,
};
use platform_pki::Issuer;
use platform_store::Pool;
use tokio::{net::TcpListener, sync::Semaphore};
use tokio_rustls::TlsAcceptor;

use crate::{
    IngestConfig, IngestError,
    auth::Peer,
    health,
    tls::{read_pem, server_config},
};

/// Shared per-process state.
#[derive(Clone)]
pub(crate) struct AppState {
    pub pool: Pool,
    pub issuer: Arc<Issuer>,
    pub client_certificate_days: u32,
    pub finding_retention_days: u32,
    pub in_flight: Arc<Semaphore>,
    pub request_timeout: Duration,
}

fn routes(state: AppState) -> Router {
    Router::new()
        .route("/v1/heartbeat", post(crate::delivery::heartbeat))
        .route("/v1/findings", post(crate::delivery::findings))
        .route("/v1/enroll", post(crate::enroll::enroll))
        .route("/v1/renew", post(crate::enroll::renew))
        .layer(DefaultBodyLimit::max(crate::request::MAX_BODY_BYTES))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            crate::limits::bound,
        ))
        .layer(middleware::from_fn(crate::limits::log))
        .with_state(state)
}

/// Disables Nagle: a small response otherwise waits about 40 ms for the
/// client's delayed ACK of the handshake's last flight.
fn no_delay(tcp: tokio::net::TcpStream) -> tokio::net::TcpStream {
    let _ = tcp.set_nodelay(true);
    tcp
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
    let pool = platform_store::connect_sized(&config.database_url, config.database_pool_size)
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
        request_timeout: Duration::from_secs(config.request_timeout_seconds),
    };
    let connections = Arc::new(Semaphore::new(config.max_connections));
    let router = routes(state);
    let health = tokio::spawn(async move {
        let _ = axum::serve(health_listener, health::router(pool)).await;
    });
    let timeout = Duration::from_secs(config.request_timeout_seconds);
    // Tracks every accepted connection so shutdown can drain them.
    let graceful = GracefulShutdown::new();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => break,
            // Accept only while a connection slot is free; the rest wait in
            // the kernel backlog instead of consuming descriptors and tasks.
            permit = connections.clone().acquire_owned() => {
                let Ok(permit) = permit else { break };
                let tcp = tokio::select! {
                    () = &mut shutdown => break,
                    accepted = listener.accept() => match accepted {
                        Ok((tcp, _)) => no_delay(tcp),
                        Err(_) => {
                            // For example EMFILE: back off instead of spinning.
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            continue;
                        }
                    },
                };
                let acceptor = acceptor.clone();
                let router = router.clone();
                let watcher = graceful.watcher();
                tokio::spawn(async move {
                    let _permit = permit;
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
                    let connection = hyper::server::conn::http1::Builder::new()
                        .timer(TokioTimer::new())
                        .header_read_timeout(timeout)
                        .serve_connection(TokioIo::new(tls), service);
                    let _ = watcher.watch(connection).await;
                });
            }
        }
    }
    health.abort();
    // Stop accepting, let requests in flight finish (each is bounded by the
    // request deadline), then return. Idle keep-alive connections close now.
    let _ = tokio::time::timeout(timeout, graceful.shutdown()).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn accepted_sockets_disable_nagle() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (tcp, _) = listener.accept().await.unwrap();
        assert!(super::no_delay(tcp).nodelay().unwrap());
    }
}
