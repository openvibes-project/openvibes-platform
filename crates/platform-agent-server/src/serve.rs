use std::{future::Future, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use axum::{Extension, Router, extract::DefaultBodyLimit, middleware};
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    server::graceful::GracefulShutdown,
    service::TowerToHyperService,
};
use platform_store::Pool;
use tokio::{net::TcpListener, sync::Semaphore};
use tokio_rustls::TlsAcceptor;

use crate::{MAX_BODY_BYTES, ServerError, auth::Peer, health, limits::Limits, tls::server_config};

/// The settings every agent-facing service shares; each service maps its
/// own configuration file onto them.
#[derive(Clone, Debug)]
pub struct Settings {
    /// Agent-facing TLS listener.
    pub listen: SocketAddr,
    /// Loopback health listener (`/health`, `/ready`).
    pub health_listen: SocketAddr,
    /// Server certificate chain, leaf first.
    pub server_certificate_file: PathBuf,
    /// Server private key.
    pub server_key_file: PathBuf,
    /// CA that issued accepted client certificates.
    pub client_ca_file: PathBuf,
    /// PostgreSQL connection for the service's role.
    pub database_url: String,
    /// Requests served at once; above this, 503.
    pub max_in_flight: usize,
    /// Deadline for the TLS handshake, the request headers, and each whole
    /// request, 1 to 300 seconds.
    pub request_timeout_seconds: u64,
    /// Open client connections at once, 1 to 65536.
    pub max_connections: usize,
    /// Database connections, 1 to 1024.
    pub database_pool_size: usize,
}

impl Settings {
    /// Rejects relative paths, a non-loopback health listener, and
    /// out-of-range values.
    pub fn validate(&self) -> Result<(), ServerError> {
        platform_config::require_absolute(&[
            &self.server_certificate_file,
            &self.server_key_file,
            &self.client_ca_file,
        ])
        .map_err(|_| ServerError::Config)?;
        // Health and readiness are unauthenticated: loopback only.
        let valid = self.health_listen.ip().is_loopback()
            && self.max_in_flight >= 1
            && (1..=300).contains(&self.request_timeout_seconds)
            && (1..=65_536).contains(&self.max_connections)
            && (1..=1024).contains(&self.database_pool_size);
        if valid {
            Ok(())
        } else {
            Err(ServerError::Config)
        }
    }
}

/// Disables Nagle: a small response otherwise waits about 40 ms for the
/// client's delayed ACK of the handshake's last flight.
fn no_delay(tcp: tokio::net::TcpStream) -> tokio::net::TcpStream {
    let _ = tcp.set_nodelay(true);
    tcp
}

/// Serves `app`'s routes on `listener` (TLS 1.3, optional client
/// certificate) and health on `health_listener` until `shutdown`, then
/// drains requests in flight. `app` receives the database pool and returns
/// its routes with their state applied; the body limit, load controls, and
/// request log are added here.
pub async fn run(
    settings: &Settings,
    listener: TcpListener,
    health_listener: TcpListener,
    app: impl FnOnce(Pool) -> Router,
    shutdown: impl Future<Output = ()>,
) -> Result<(), ServerError> {
    settings.validate()?;
    let pool = platform_store::connect_sized(&settings.database_url, settings.database_pool_size)
        .await
        .map_err(|error| match error {
            platform_store::StoreError::InvalidUrl => ServerError::Config,
            _ => ServerError::Database,
        })?;
    let acceptor = TlsAcceptor::from(server_config(
        &settings.server_certificate_file,
        &settings.server_key_file,
        &settings.client_ca_file,
    )?);
    let limits = Limits {
        in_flight: Arc::new(Semaphore::new(settings.max_in_flight)),
        request_timeout: Duration::from_secs(settings.request_timeout_seconds),
    };
    let connections = Arc::new(Semaphore::new(settings.max_connections));
    let router = app(pool.clone())
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::from_fn_with_state(limits, crate::limits::bound))
        .layer(middleware::from_fn(crate::limits::log));
    let health = tokio::spawn(async move {
        let _ = axum::serve(health_listener, health::router(pool)).await;
    });
    let timeout = Duration::from_secs(settings.request_timeout_seconds);
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
