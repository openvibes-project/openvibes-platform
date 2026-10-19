//! Serving: binding the configured listeners, the public and health
//! servers, readiness, and graceful shutdown.

use std::{
    future::{Future, IntoFuture},
    io,
    time::Duration,
};

use axum::{Router, http::HeaderValue, middleware, response::Response};
use tokio::{
    net::TcpListener,
    sync::watch,
    time::{sleep, timeout},
};

#[cfg(unix)]
use super::listeners::bind_unix_listener;
use super::{
    listeners::{CappedListener, MAX_PUBLIC_CONNECTIONS, PublicListener, TrustedPeer},
    tls::{certificate_hosts, load_tls_acceptor, plain_http, read_tls_pem},
    trusted_proxy::{TrustedProxyPeers, trusted_proxy_only},
};
use crate::{
    ConsoleConfig, ConsoleError, ConsoleTransportMode, Readiness, development_router, health_router,
};

const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
const READINESS_CHECK_INTERVAL: Duration = Duration::from_secs(5);
const READINESS_CHECK_TIMEOUT: Duration = Duration::from_secs(5);

const MAX_HEALTH_CONNECTIONS: usize = 16;

/// Binds the configured public and health listeners and serves until shutdown.
pub async fn serve(
    config: ConsoleConfig,
    shutdown: impl Future<Output = ()>,
) -> Result<(), ConsoleError> {
    config.validate()?;
    // With direct TLS, every name the certificate covers is served.
    let hosts = match (&config.transport_mode, &config.server_certificate_file) {
        (ConsoleTransportMode::DirectTls, Some(path)) => {
            certificate_hosts(&read_tls_pem(path)?, config.development_listen.port())
        }
        _ => Vec::new(),
    };
    let (public_router, readiness_pool) = match (&config.database_url, &config.public_origin) {
        (Some(database_url), Some(public_origin)) => {
            let pool = platform_store::connect(database_url).await?;
            let client = pool
                .get()
                .await
                .map_err(|_| platform_store::StoreError::Unavailable)?;
            let actual = platform_store::schema_version(&client).await?;
            if actual != Some(platform_store::SCHEMA_VERSION) {
                return Err(ConsoleError::SchemaVersion {
                    actual,
                    expected: platform_store::SCHEMA_VERSION,
                });
            }
            drop(client);
            let assistant_runtime = config
                .assistant
                .as_ref()
                .filter(|assistant| assistant.enabled)
                .map(|assistant| {
                    assistant
                        .validate()
                        .map_err(|_| ConsoleError::Config)
                        .and_then(crate::assistant::AssistantRuntime::new)
                })
                .transpose()?
                .flatten();
            crate::about::mark_started();
            (
                crate::http::authenticated_router_with_assistant(
                    pool.clone(),
                    public_origin.as_str(),
                    hosts.clone(),
                    assistant_runtime,
                    config
                        .update_check
                        .then(|| std::sync::Arc::new(crate::about::UpdateChecker::new())),
                    config.agent_install.clone(),
                    (None, None),
                ),
                Some(pool),
            )
        }
        (None, None) => (development_router(), None),
        _ => return Err(ConsoleError::Config),
    };
    let health_listener = TcpListener::bind(config.health_listen).await?;
    let tls = if config.transport_mode == ConsoleTransportMode::DirectTls {
        config
            .server_certificate_file
            .as_deref()
            .zip(config.server_key_file.as_deref())
            .map(|(certificate, key)| load_tls_acceptor(certificate, key))
            .transpose()?
    } else {
        None
    };

    #[cfg(not(unix))]
    if config.unix_socket_file.is_some() {
        return Err(ConsoleError::Config);
    }
    #[cfg(unix)]
    let (public_listener, socket_guard) = if let Some(path) = config.unix_socket_file.as_deref() {
        let (listener, guard) = bind_unix_listener(path)?;
        (PublicListener::Unix(listener), Some(guard))
    } else {
        let listener = TcpListener::bind(config.development_listen).await?;
        let mut listener = CappedListener::new(listener, MAX_PUBLIC_CONNECTIONS, tls);
        listener.plain_http = plain_http(&config, hosts).into();
        (PublicListener::Tcp(listener), None)
    };
    #[cfg(not(unix))]
    let public_listener = PublicListener::Tcp({
        let mut listener = CappedListener::new(
            TcpListener::bind(config.development_listen).await?,
            MAX_PUBLIC_CONNECTIONS,
            tls,
        );
        listener.plain_http = plain_http(&config, hosts).into();
        listener
    });

    let result = run_with_router(
        public_listener,
        health_listener,
        config.transport_mode,
        config.trusted_proxy_addresses,
        config.trusted_proxy_uids,
        public_router,
        readiness_pool,
        shutdown,
    )
    .await;
    #[cfg(unix)]
    drop(socket_guard);
    result
}

/// Serves already-bound listeners. This is exposed for process-level and
/// integration tests that need ephemeral ports.
pub async fn run(
    public_listener: TcpListener,
    health_listener: TcpListener,
    shutdown: impl Future<Output = ()>,
) -> Result<(), ConsoleError> {
    run_with_router(
        PublicListener::Tcp(CappedListener::new(
            public_listener,
            MAX_PUBLIC_CONNECTIONS,
            None,
        )),
        health_listener,
        ConsoleTransportMode::Development,
        vec![],
        vec![],
        development_router(),
        None,
        shutdown,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_with_router(
    public_listener: PublicListener,
    health_listener: TcpListener,
    transport_mode: ConsoleTransportMode,
    trusted_proxy_addresses: Vec<std::net::IpAddr>,
    trusted_proxy_uids: Vec<u32>,
    public_router: Router,
    readiness_pool: Option<platform_store::Pool>,
    shutdown: impl Future<Output = ()>,
) -> Result<(), ConsoleError> {
    let public_transport_safe = match &public_listener {
        PublicListener::Tcp(listener) => {
            if listener.tls.is_some() {
                transport_mode == ConsoleTransportMode::DirectTls
            } else {
                transport_mode != ConsoleTransportMode::DirectTls
                    && listener.listener.local_addr()?.ip().is_loopback()
            }
        }
        #[cfg(unix)]
        PublicListener::Unix(_) => transport_mode == ConsoleTransportMode::ReverseProxy,
    };
    if !public_transport_safe || !health_listener.local_addr()?.ip().is_loopback() {
        return Err(ConsoleError::Config);
    }

    let public_router = if transport_mode == ConsoleTransportMode::ReverseProxy {
        public_router.layer(middleware::from_fn_with_state(
            std::sync::Arc::new(TrustedProxyPeers {
                addresses: trusted_proxy_addresses.into_iter().collect(),
                uids: trusted_proxy_uids.into_iter().collect(),
            }),
            trusted_proxy_only,
        ))
    } else {
        public_router
    };
    let public_router = if transport_mode != ConsoleTransportMode::Development {
        public_router.layer(middleware::map_response(hsts_header))
    } else {
        public_router
    };

    let readiness = Readiness::new(true);
    let (stop_sender, public_stop) = watch::channel(false);
    let health_stop = public_stop.clone();
    let readiness_monitor = readiness_pool.map(|pool| {
        let readiness = readiness.clone();
        let mut stop = public_stop.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = sleep(READINESS_CHECK_INTERVAL) => {
                        let ready = timeout(READINESS_CHECK_TIMEOUT, database_is_ready(&pool))
                            .await
                            .unwrap_or(false);
                        readiness.set(ready);
                    }
                    changed = stop.changed() => {
                        if changed.is_err() || *stop.borrow() {
                            break;
                        }
                    }
                }
            }
        })
    });
    let public = axum::serve(
        public_listener,
        public_router.into_make_service_with_connect_info::<TrustedPeer>(),
    )
    .with_graceful_shutdown(stop_requested(public_stop))
    .into_future();
    let health = axum::serve(
        CappedListener::new(health_listener, MAX_HEALTH_CONNECTIONS, None),
        health_router(readiness.clone()),
    )
    .with_graceful_shutdown(stop_requested(health_stop))
    .into_future();
    tokio::pin!(public);
    tokio::pin!(health);
    tokio::pin!(shutdown);

    enum First {
        Shutdown,
        Public(io::Result<()>),
        Health(io::Result<()>),
    }

    let first = tokio::select! {
        result = &mut public => First::Public(result),
        result = &mut health => First::Health(result),
        () = &mut shutdown => First::Shutdown,
    };

    // Readiness changes before either listener is asked to stop accepting.
    // Existing requests then receive a bounded graceful-drain window.
    readiness.set(false);
    let _ = stop_sender.send(true);

    let drain = async {
        match first {
            First::Shutdown => {
                let (public_result, health_result) = tokio::join!(&mut public, &mut health);
                public_result?;
                health_result
            }
            First::Public(public_result) => {
                public_result?;
                health.await
            }
            First::Health(health_result) => {
                health_result?;
                public.await
            }
        }
    };
    let result = timeout(GRACEFUL_SHUTDOWN_TIMEOUT, drain)
        .await
        .map_err(|_| {
            ConsoleError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "console graceful shutdown timed out",
            ))
        })?
        .map_err(ConsoleError::Io);
    if let Some(monitor) = readiness_monitor {
        let _ = monitor.await;
    }
    result
}

async fn hsts_header(mut response: Response) -> Response {
    response.headers_mut().insert(
        "strict-transport-security",
        HeaderValue::from_static("max-age=31536000"),
    );
    response
}

async fn database_is_ready(pool: &platform_store::Pool) -> bool {
    let Ok(client) = pool.get().await else {
        return false;
    };
    matches!(
        platform_store::schema_version(&client).await,
        Ok(Some(platform_store::SCHEMA_VERSION))
    )
}

async fn stop_requested(mut receiver: watch::Receiver<bool>) {
    if *receiver.borrow() {
        return;
    }
    let _ = receiver.wait_for(|stop| *stop).await;
}
