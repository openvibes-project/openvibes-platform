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
    http::{HeaderMap, HeaderValue, StatusCode},
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
    ConsoleConfig, ConsoleError, ConsoleTransportMode, Readiness, development_router, health_router,
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
    plain_http: std::sync::Arc<PlainHttp>,
}

/// Where plain http on the TLS port is sent (board #71): the served hosts
/// (`name:port`, lowercase) and the canonical origin for any other `Host`.
#[derive(Default)]
struct PlainHttp {
    hosts: Vec<String>,
    origin: String,
}

/// Socket peer identity supplied by a capped console listener.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrustedPeer(PeerIdentity);

/// Client address parsed from a header supplied by an authenticated proxy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TrustedProxyClient {
    pub source: Option<IpAddr>,
}

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
            plain_http: std::sync::Arc::default(),
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
    Tls(Box<TlsStream<CappedStream>>),
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
                            let plain_http = self.plain_http.clone();
                            self.handshakes.spawn(async move {
                                let result = match timeout(TLS_HANDSHAKE_TIMEOUT, handshake(tls, capped, &plain_http)).await {
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
                        Some(Ok((Ok(stream), peer))) => {
                            return (CappedIo::Tls(Box::new(stream)), peer);
                        }
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

/// A TLS handshake, or for plain http on this port a redirect to https
/// instead of TLS alert bytes a browser shows as garbage (board #71).
async fn handshake(
    tls: TlsAcceptor,
    mut stream: CappedStream,
    plain_http: &PlainHttp,
) -> io::Result<TlsStream<CappedStream>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut first = [0_u8; 1];
    // 0x16 starts every TLS handshake record.
    if stream.stream.peek(&mut first).await? == 1 && first[0] != 0x16 {
        // Read the request head first: closing with it unread would reset
        // the connection before the browser sees the answer.
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        while request.len() < 8192 && !request.windows(4).any(|w| w == b"\r\n\r\n") {
            let read = stream.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
        }
        stream
            .write_all(&plain_http_answer(&request, plain_http))
            .await?;
        stream.shutdown().await?;
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "plain HTTP on the TLS port",
        ));
    }
    tls.accept(stream).await
}

/// `301` to `https://` + the request's `Host` when this console serves it,
/// else to the canonical origin, never to a name it does not serve; a
/// plain `400` note when there is neither.
fn plain_http_answer(request: &[u8], to: &PlainHttp) -> Vec<u8> {
    let served = String::from_utf8_lossy(request)
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("host")
                .then(|| value.trim().to_ascii_lowercase())
        })
        .filter(|host| to.hosts.contains(host))
        .map(|host| format!("https://{host}"));
    match served.or_else(|| (!to.origin.is_empty()).then(|| to.origin.clone())) {
        Some(origin) => format!(
            "HTTP/1.1 301 Moved Permanently\r\nLocation: {origin}/\r\n\
             Content-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n\
             This OpenVIBES console speaks https only: open {origin}/\n"
        ),
        None => "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\n\
                 Connection: close\r\n\r\nThis OpenVIBES console speaks https only.\n"
            .to_owned(),
    }
    .into_bytes()
}

/// `name:port` for every name the console's certificate covers (board #71):
/// the DNS names and IP addresses of its subjectAltName, IPv6 in brackets,
/// and the bare name too on 443, where browsers leave the port out. The
/// console serves these besides `public_origin`, so it opens by IP (over a
/// VPN) or as localhost (through a tunnel).
pub(crate) fn certificate_hosts(pem: &[u8], port: u16) -> Vec<String> {
    use x509_parser::extensions::GeneralName;
    let Some(Ok(der)) = CertificateDer::pem_slice_iter(pem).next() else {
        return Vec::new();
    };
    let Ok((_, certificate)) = x509_parser::parse_x509_certificate(&der) else {
        return Vec::new();
    };
    let Ok(Some(names)) = certificate.subject_alternative_name() else {
        return Vec::new();
    };
    let mut hosts = Vec::new();
    for name in &names.value.general_names {
        let host = match name {
            GeneralName::DNSName(dns) => (*dns).to_owned(),
            GeneralName::IPAddress(bytes) => match <[u8; 4]>::try_from(*bytes) {
                Ok(v4) => std::net::Ipv4Addr::from(v4).to_string(),
                Err(_) => match <[u8; 16]>::try_from(*bytes) {
                    Ok(v6) => format!("[{}]", std::net::Ipv6Addr::from(v6)),
                    Err(_) => continue,
                },
            },
            _ => continue,
        };
        hosts.push(format!("{host}:{port}"));
        if port == 443 {
            hosts.push(host);
        }
    }
    hosts
}

/// The served hosts, as the router has them: `public_origin`'s authority
/// and the certificate's names.
fn plain_http(config: &ConsoleConfig, mut hosts: Vec<String>) -> PlainHttp {
    let origin = config.public_origin.clone().unwrap_or_default();
    if let Some(authority) = origin
        .parse::<axum::http::Uri>()
        .ok()
        .and_then(|uri| uri.authority().map(|a| a.as_str().to_owned()))
    {
        hosts.push(authority);
    }
    for host in &mut hosts {
        host.make_ascii_lowercase();
    }
    PlainHttp { hosts, origin }
}

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
                crate::router::authenticated_router_with_assistant(
                    pool.clone(),
                    public_origin.as_str(),
                    hosts.clone(),
                    assistant_runtime,
                    config
                        .update_check
                        .then(|| std::sync::Arc::new(crate::about::UpdateChecker::new())),
                    config.agent_install.clone(),
                    None,
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

struct TrustedProxyPeers {
    addresses: HashSet<IpAddr>,
    uids: HashSet<u32>,
}

async fn trusted_proxy_only(
    State(allowed): State<std::sync::Arc<TrustedProxyPeers>>,
    mut request: axum::extract::Request,
    next: middleware::Next,
) -> Response {
    let trusted = request
        .extensions()
        .get::<ConnectInfo<TrustedPeer>>()
        .is_some_and(|ConnectInfo(peer)| peer.is_allowed(&allowed.addresses, &allowed.uids));
    if trusted {
        let source = trusted_forwarded_address(request.headers());
        request
            .extensions_mut()
            .insert(TrustedProxyClient { source });
        next.run(request).await
    } else {
        let mut response = StatusCode::FORBIDDEN.into_response();
        response
            .headers_mut()
            .insert("cache-control", HeaderValue::from_static("no-store"));
        response
    }
}

fn trusted_forwarded_address(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get_all("x-forwarded-for")
        .iter()
        .next_back()
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.rsplit(',').next())
        .and_then(|value| value.trim().parse().ok())
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

#[cfg(test)]
mod trusted_proxy_header_tests {
    use super::trusted_forwarded_address;
    use axum::http::{HeaderMap, HeaderValue};
    use std::net::IpAddr;

    #[test]
    fn uses_the_last_forwarded_ip_from_the_authenticated_proxy() {
        let mut headers = HeaderMap::new();
        headers.append("x-forwarded-for", HeaderValue::from_static("198.51.100.23"));
        headers.append("x-forwarded-for", HeaderValue::from_static("192.0.2.8"));
        assert_eq!(
            trusted_forwarded_address(&headers),
            Some("192.0.2.8".parse::<IpAddr>().unwrap())
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("192.0.2.8, 198.51.100.4"),
        );
        assert_eq!(
            trusted_forwarded_address(&headers),
            Some("198.51.100.4".parse::<IpAddr>().unwrap())
        );
        headers.insert("x-forwarded-for", HeaderValue::from_static("host.invalid"));
        assert_eq!(trusted_forwarded_address(&headers), None);
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("192.0.2.8, invalid"),
        );
        assert_eq!(trusted_forwarded_address(&headers), None);
    }
}

#[cfg(test)]
mod certificate_hosts_tests {
    use super::certificate_hosts;

    fn pem(names: &[&str]) -> String {
        let names: Vec<String> = names.iter().map(|n| (*n).to_owned()).collect();
        rcgen::generate_simple_self_signed(names)
            .unwrap()
            .cert
            .pem()
    }

    #[test]
    fn dns_names_and_ips_become_hosts_at_the_port() {
        let hosts = certificate_hosts(
            pem(&[
                "metabox-lnx",
                "localhost",
                "127.0.0.1",
                "192.168.1.10",
                "::1",
            ])
            .as_bytes(),
            8443,
        );
        for want in [
            "metabox-lnx:8443",
            "localhost:8443",
            "127.0.0.1:8443",
            "192.168.1.10:8443",
            "[::1]:8443",
        ] {
            assert!(
                hosts.iter().any(|h| h == want),
                "{want} missing in {hosts:?}"
            );
        }
        assert!(
            !hosts.iter().any(|h| h == "metabox-lnx"),
            "no bare name off 443"
        );
    }

    #[test]
    fn on_443_the_bare_name_is_served_too() {
        let hosts = certificate_hosts(pem(&["metabox-lnx"]).as_bytes(), 443);
        assert_eq!(hosts, ["metabox-lnx:443", "metabox-lnx"]);
    }

    fn served() -> super::PlainHttp {
        super::PlainHttp {
            hosts: vec!["metabox-lnx:8443".into(), "127.0.0.1:8443".into()],
            origin: "https://metabox-lnx:8443".into(),
        }
    }

    fn answer(request: &[u8], to: &super::PlainHttp) -> String {
        String::from_utf8(super::plain_http_answer(request, to)).unwrap()
    }

    #[test]
    fn plain_http_is_sent_to_https_on_the_same_served_host() {
        let answer = answer(
            b"GET /x HTTP/1.1\r\nhost: 127.0.0.1:8443\r\n\r\n",
            &served(),
        );
        assert!(answer.starts_with("HTTP/1.1 301 "), "{answer}");
        assert!(
            answer.contains("\r\nLocation: https://127.0.0.1:8443/\r\n"),
            "{answer}"
        );
        assert!(
            answer.ends_with("open https://127.0.0.1:8443/\n"),
            "{answer}"
        );
    }

    #[test]
    fn any_other_host_is_sent_to_the_canonical_origin() {
        // Reviewer on #99: never redirect to a name this console does not serve.
        for request in [
            &b"GET / HTTP/1.1\r\nHost: evil.example\r\n\r\n"[..],
            b"GET / HTTP/1.1\r\nHost: evil.example/\"><x\r\n\r\n",
            b"GET / HTTP/1.1\r\n\r\n",
        ] {
            let answer = answer(request, &served());
            assert!(
                answer.contains("\r\nLocation: https://metabox-lnx:8443/\r\n"),
                "{answer}"
            );
            assert!(!answer.contains("evil"), "{answer}");
        }
        let answer = answer(b"GET / HTTP/1.1\r\n\r\n", &super::PlainHttp::default());
        assert!(
            answer.starts_with("HTTP/1.1 400 ") && !answer.contains("Location"),
            "{answer}"
        );
    }

    #[tokio::test]
    async fn a_plain_http_client_reads_the_answer() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
            client
                .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1:8443\r\n\r\n")
                .await
                .unwrap();
            let mut answer = String::new();
            client.read_to_string(&mut answer).await.unwrap();
            answer
        });
        let (stream, _) = listener.accept().await.unwrap();
        let permit = std::sync::Arc::new(tokio::sync::Semaphore::new(1))
            .try_acquire_owned()
            .unwrap();
        let (certificate, key) = {
            let key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            (key.cert.der().clone(), key.signing_key.serialize_der())
        };
        let config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key).into(),
        )
        .unwrap();
        let result = super::handshake(
            tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config)),
            super::CappedStream {
                stream,
                _permit: permit,
            },
            &served(),
        )
        .await;
        assert!(result.is_err());
        assert!(
            client
                .await
                .unwrap()
                .contains("Location: https://127.0.0.1:8443/")
        );
    }

    #[test]
    fn a_broken_certificate_serves_no_extra_names() {
        assert!(certificate_hosts(b"not a certificate", 8443).is_empty());
    }
}
