use std::{
    collections::HashSet,
    fs::File,
    future::{Future, IntoFuture},
    io::{self, Read},
    net::{IpAddr, SocketAddr},
    path::Path,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use axum::{
    Router,
    extract::{ConnectInfo, State, connect_info::Connected},
    http::{HeaderValue, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    serve::{IncomingStream, Listener},
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
#[cfg(unix)]
use std::{
    fs,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore, watch},
    task::JoinSet,
    time::{sleep, timeout},
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

use crate::{
    ConsoleConfig, ConsoleError, ConsoleTransportMode, Readiness, authenticated_router,
    development_router, health_router,
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

/// Socket peer identity supplied by a capped console listener.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrustedPeer(PeerIdentity);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PeerIdentity {
    Tcp(SocketAddr),
    #[cfg(unix)]
    UnixUid(u32),
}

impl TrustedPeer {
    /// Wraps a peer address when constructing an in-process router request.
    pub fn new(address: SocketAddr) -> Self {
        Self(PeerIdentity::Tcp(address))
    }

    /// Returns a stable source label for throttling and audit metadata.
    pub fn source_label(self) -> String {
        match self.0 {
            PeerIdentity::Tcp(address) => address.ip().to_string(),
            #[cfg(unix)]
            PeerIdentity::UnixUid(uid) => format!("unix-uid:{uid}"),
        }
    }

    fn is_allowed(self, addresses: &HashSet<IpAddr>, uids: &HashSet<u32>) -> bool {
        match self.0 {
            PeerIdentity::Tcp(address) => addresses.contains(&address.ip()),
            #[cfg(unix)]
            PeerIdentity::UnixUid(uid) => uids.contains(&uid),
        }
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
    #[cfg(unix)]
    Unix(CappedUnixStream),
}

#[cfg(unix)]
struct CappedUnixStream {
    stream: UnixStream,
    _permit: OwnedSemaphorePermit,
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
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(&mut stream.stream).poll_read(context, buffer),
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
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(&mut stream.stream).poll_write(context, buffer),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_flush(context),
            Self::Tls(stream) => Pin::new(stream).poll_flush(context),
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(&mut stream.stream).poll_flush(context),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(context),
            Self::Tls(stream) => Pin::new(stream).poll_shutdown(context),
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(&mut stream.stream).poll_shutdown(context),
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
                            TrustedPeer(PeerIdentity::Tcp(address)),
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
                                (result, TrustedPeer(PeerIdentity::Tcp(address)))
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
        self.listener
            .local_addr()
            .map(|address| TrustedPeer(PeerIdentity::Tcp(address)))
    }
}

impl Connected<IncomingStream<'_, CappedListener>> for TrustedPeer {
    fn connect_info(stream: IncomingStream<'_, CappedListener>) -> Self {
        *stream.remote_addr()
    }
}

#[cfg(unix)]
struct CappedUnixListener {
    listener: UnixListener,
    capacity: std::sync::Arc<Semaphore>,
    owner_uid: u32,
}

#[cfg(unix)]
impl Listener for CappedUnixListener {
    type Io = CappedIo;
    type Addr = TrustedPeer;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let permit = self
                .capacity
                .clone()
                .acquire_owned()
                .await
                .expect("connection permits stay open for the listener lifetime");
            match self.listener.accept().await {
                Ok((stream, _)) => match stream.peer_cred() {
                    Ok(credentials) => {
                        return (
                            CappedIo::Unix(CappedUnixStream {
                                stream,
                                _permit: permit,
                            }),
                            TrustedPeer(PeerIdentity::UnixUid(credentials.uid())),
                        );
                    }
                    Err(error) => {
                        tracing::debug!(%error, "console Unix peer credentials unavailable");
                        drop(stream);
                        drop(permit);
                    }
                },
                Err(error) => {
                    tracing::error!(%error, "console Unix listener accept failed");
                    sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(TrustedPeer(PeerIdentity::UnixUid(self.owner_uid)))
    }
}

#[cfg(unix)]
impl Connected<IncomingStream<'_, CappedUnixListener>> for TrustedPeer {
    fn connect_info(stream: IncomingStream<'_, CappedUnixListener>) -> Self {
        *stream.remote_addr()
    }
}

enum PublicListener {
    Tcp(CappedListener),
    #[cfg(unix)]
    Unix(CappedUnixListener),
}

#[cfg(unix)]
struct UnixSocketGuard {
    path: std::path::PathBuf,
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl Drop for UnixSocketGuard {
    fn drop(&mut self) {
        if let Ok(metadata) = fs::symlink_metadata(&self.path)
            && metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(unix)]
fn bind_unix_listener(path: &Path) -> Result<(CappedUnixListener, UnixSocketGuard), ConsoleError> {
    if !path.is_absolute() {
        return Err(ConsoleError::Config);
    }
    let parent = path.parent().ok_or(ConsoleError::Config)?;
    let parent_metadata = fs::metadata(parent)?;
    if !parent_metadata.is_dir() || parent_metadata.mode() & 0o022 != 0 {
        return Err(ConsoleError::Config);
    }
    if let Ok(existing) = fs::symlink_metadata(path) {
        if !existing.file_type().is_socket() || existing.uid() != parent_metadata.uid() {
            return Err(ConsoleError::Config);
        }
        fs::remove_file(path)?;
    }

    let listener = UnixListener::bind(path)?;
    let metadata = fs::symlink_metadata(path)?;
    let guard = UnixSocketGuard {
        path: path.to_path_buf(),
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    fs::set_permissions(path, fs::Permissions::from_mode(0o660))?;
    Ok((
        CappedUnixListener {
            listener,
            capacity: std::sync::Arc::new(Semaphore::new(MAX_PUBLIC_CONNECTIONS)),
            owner_uid: metadata.uid(),
        },
        guard,
    ))
}

impl Listener for PublicListener {
    type Io = CappedIo;
    type Addr = TrustedPeer;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self {
            Self::Tcp(listener) => listener.accept().await,
            #[cfg(unix)]
            Self::Unix(listener) => listener.accept().await,
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        match self {
            Self::Tcp(listener) => listener.local_addr(),
            #[cfg(unix)]
            Self::Unix(listener) => listener.local_addr(),
        }
    }
}

impl Connected<IncomingStream<'_, PublicListener>> for TrustedPeer {
    fn connect_info(stream: IncomingStream<'_, PublicListener>) -> Self {
        *stream.remote_addr()
    }
}

/// Binds the configured public and health listeners and serves until shutdown.
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
        (
            PublicListener::Tcp(CappedListener::new(listener, MAX_PUBLIC_CONNECTIONS, tls)),
            None,
        )
    };
    #[cfg(not(unix))]
    let public_listener = PublicListener::Tcp(CappedListener::new(
        TcpListener::bind(config.development_listen).await?,
        MAX_PUBLIC_CONNECTIONS,
        tls,
    ));

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

struct TrustedProxyPeers {
    addresses: HashSet<IpAddr>,
    uids: HashSet<u32>,
}

async fn trusted_proxy_only(
    State(allowed): State<std::sync::Arc<TrustedProxyPeers>>,
    request: axum::extract::Request,
    next: middleware::Next,
) -> Response {
    let trusted = request
        .extensions()
        .get::<ConnectInfo<TrustedPeer>>()
        .is_some_and(|ConnectInfo(peer)| peer.is_allowed(&allowed.addresses, &allowed.uids));
    if trusted {
        next.run(request).await
    } else {
        let mut response = StatusCode::FORBIDDEN.into_response();
        response
            .headers_mut()
            .insert("cache-control", HeaderValue::from_static("no-store"));
        response
    }
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
