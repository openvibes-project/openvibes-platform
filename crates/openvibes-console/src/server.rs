use std::{
    fs::File,
    future::{Future, IntoFuture},
    io::{self, Read},
    net::SocketAddr,
    path::Path,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use axum::{
    Router,
    extract::connect_info::Connected,
    http::HeaderValue,
    middleware,
    response::Response,
    serve::{IncomingStream, Listener},
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore, watch},
    task::JoinSet,
    time::{sleep, timeout},
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

use crate::{
    ConsoleConfig, ConsoleError, Readiness, authenticated_router, development_router, health_router,
};

const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
const READINESS_CHECK_INTERVAL: Duration = Duration::from_secs(5);
const READINESS_CHECK_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PUBLIC_CONNECTIONS: usize = 256;
const MAX_HEALTH_CONNECTIONS: usize = 16;
const MAX_TLS_FILE_BYTES: u64 = 1024 * 1024;
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

fn read_tls_pem(path: &Path) -> Result<Vec<u8>, ConsoleError> {
    if !path.is_absolute() {
        return Err(ConsoleError::Config);
    }
    let mut bytes = Vec::new();
    let read = File::open(path)?
        .take(MAX_TLS_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if read as u64 > MAX_TLS_FILE_BYTES {
        return Err(ConsoleError::Config);
    }
    Ok(bytes)
}

fn load_tls_acceptor(
    certificate_path: &Path,
    key_path: &Path,
) -> Result<TlsAcceptor, ConsoleError> {
    let certificate_pem = read_tls_pem(certificate_path)?;
    let certificates: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(&certificate_pem)
            .collect::<Result<_, _>>()
            .map_err(|_| ConsoleError::Config)?;
    if certificates.is_empty() {
        return Err(ConsoleError::Config);
    }
    let key_pem = read_tls_pem(key_path)?;
    let key = PrivateKeyDer::from_pem_slice(&key_pem).map_err(|_| ConsoleError::Config)?;
    let mut provider = rustls::crypto::ring::default_provider();
    provider
        .cipher_suites
        .retain(|suite| matches!(suite, rustls::SupportedCipherSuite::Tls13(_)));
    let config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| ConsoleError::Config)?
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .map_err(|_| ConsoleError::Config)?;
    let mut config = config;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(std::sync::Arc::new(config)))
}

struct CappedListener {
    listener: TcpListener,
    capacity: std::sync::Arc<Semaphore>,
    tls: Option<TlsAcceptor>,
    handshakes: JoinSet<(io::Result<TlsStream<CappedStream>>, TrustedPeer)>,
}

/// Socket peer address supplied by the console's capped TCP listener.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrustedPeer(SocketAddr);

impl TrustedPeer {
    /// Wraps a peer address when constructing an in-process router request.
    pub fn new(address: SocketAddr) -> Self {
        Self(address)
    }

    /// Returns the remote IP address.
    pub fn ip(self) -> std::net::IpAddr {
        self.0.ip()
    }
}

impl CappedListener {
    fn new(listener: TcpListener, limit: usize, tls: Option<TlsAcceptor>) -> Self {
        Self {
            listener,
            capacity: std::sync::Arc::new(Semaphore::new(limit)),
            tls,
            handshakes: JoinSet::new(),
        }
    }
}

struct CappedStream {
    stream: TcpStream,
    _permit: OwnedSemaphorePermit,
}

impl AsyncRead for CappedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

impl AsyncWrite for CappedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write_vectored(context, buffers)
    }
}

enum CappedIo {
    Plain(CappedStream),
    Tls(TlsStream<CappedStream>),
}

impl AsyncRead for CappedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_read(context, buffer),
            Self::Tls(stream) => Pin::new(stream).poll_read(context, buffer),
        }
    }
}

impl AsyncWrite for CappedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_write(context, buffer),
            Self::Tls(stream) => Pin::new(stream).poll_write(context, buffer),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_flush(context),
            Self::Tls(stream) => Pin::new(stream).poll_flush(context),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(context),
            Self::Tls(stream) => Pin::new(stream).poll_shutdown(context),
        }
    }
}

impl Listener for CappedListener {
    type Io = CappedIo;
    type Addr = TrustedPeer;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            if self.tls.is_none() {
                let permit = self
                    .capacity
                    .clone()
                    .acquire_owned()
                    .await
                    .expect("connection permits stay open for the listener lifetime");
                match self.listener.accept().await {
                    Ok((stream, address)) => {
                        return (
                            CappedIo::Plain(CappedStream {
                                stream,
                                _permit: permit,
                            }),
                            TrustedPeer(address),
                        );
                    }
                    Err(error) => {
                        tracing::error!(%error, "console listener accept failed");
                        sleep(Duration::from_millis(50)).await;
                    }
                }
                continue;
            }

            tokio::select! {
                accepted = self.listener.accept() => {
                    match accepted {
                        Ok((stream, address)) => {
                            let Ok(permit) = self.capacity.clone().try_acquire_owned() else {
                                drop(stream);
                                continue;
                            };
                            let capped = CappedStream { stream, _permit: permit };
                            let tls = self.tls.as_ref().expect("TLS mode has an acceptor").clone();
                            self.handshakes.spawn(async move {
                                let result = match timeout(TLS_HANDSHAKE_TIMEOUT, tls.accept(capped)).await {
                                    Ok(result) => result,
                                    Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out")),
                                };
                                (result, TrustedPeer(address))
                            });
                        }
                        Err(error) => {
                            tracing::error!(%error, "console listener accept failed");
                            sleep(Duration::from_millis(50)).await;
                        }
                    }
                }
                completed = self.handshakes.join_next(), if !self.handshakes.is_empty() => {
                    match completed {
                        Some(Ok((Ok(stream), peer))) => return (CappedIo::Tls(stream), peer),
                        Some(Ok((Err(error), _))) => tracing::debug!(%error, "console TLS handshake failed"),
                        Some(Err(error)) => tracing::error!(%error, "console TLS handshake task failed"),
                        None => {}
                    }
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.listener.local_addr().map(TrustedPeer)
    }
}

impl Connected<IncomingStream<'_, CappedListener>> for TrustedPeer {
    fn connect_info(stream: IncomingStream<'_, CappedListener>) -> Self {
        *stream.remote_addr()
    }
}

/// Binds the C0 development and health listeners and serves them until
/// `shutdown` resolves.
pub async fn serve(
    config: ConsoleConfig,
    shutdown: impl Future<Output = ()>,
) -> Result<(), ConsoleError> {
    config.validate()?;
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
            (
                authenticated_router(pool.clone(), public_origin.as_str()),
                Some(pool),
            )
        }
        (None, None) => (development_router(), None),
        _ => return Err(ConsoleError::Config),
    };
    let public_listener = TcpListener::bind(config.development_listen).await?;
    let health_listener = TcpListener::bind(config.health_listen).await?;
    let tls = config
        .server_certificate_file
        .as_deref()
        .zip(config.server_key_file.as_deref())
        .map(|(certificate, key)| load_tls_acceptor(certificate, key))
        .transpose()?;
    run_with_router(
        public_listener,
        health_listener,
        tls,
        public_router,
        readiness_pool,
        shutdown,
    )
    .await
}

/// Serves already-bound listeners. This is exposed for process-level and
/// integration tests that need ephemeral ports.
pub async fn run(
    public_listener: TcpListener,
    health_listener: TcpListener,
    shutdown: impl Future<Output = ()>,
) -> Result<(), ConsoleError> {
    run_with_router(
        public_listener,
        health_listener,
        None,
        development_router(),
        None,
        shutdown,
    )
    .await
}

async fn run_with_router(
    public_listener: TcpListener,
    health_listener: TcpListener,
    tls: Option<TlsAcceptor>,
    public_router: Router,
    readiness_pool: Option<platform_store::Pool>,
    shutdown: impl Future<Output = ()>,
) -> Result<(), ConsoleError> {
    if (tls.is_none() && !public_listener.local_addr()?.ip().is_loopback())
        || !health_listener.local_addr()?.ip().is_loopback()
    {
        return Err(ConsoleError::Config);
    }

    let public_router = if tls.is_some() {
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
        CappedListener::new(public_listener, MAX_PUBLIC_CONNECTIONS, tls),
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
