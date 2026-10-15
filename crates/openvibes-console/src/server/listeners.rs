//! The capped listeners: TCP (plain or TLS) and Unix socket, each with a
//! connection limit, and the peer identity they hand to the router.

use std::{
    collections::HashSet,
    io,
    net::{IpAddr, SocketAddr},
    path::Path,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use axum::{
    extract::connect_info::Connected,
    serve::{IncomingStream, Listener},
};
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
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::{sleep, timeout},
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

use super::tls::{PlainHttp, handshake};
use crate::ConsoleError;

pub(super) const MAX_PUBLIC_CONNECTIONS: usize = 256;

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) struct CappedListener {
    pub(super) listener: TcpListener,
    capacity: std::sync::Arc<Semaphore>,
    pub(super) tls: Option<TlsAcceptor>,
    handshakes: JoinSet<(io::Result<TlsStream<CappedStream>>, TrustedPeer)>,
    pub(super) plain_http: std::sync::Arc<PlainHttp>,
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

    pub(super) fn is_allowed(self, addresses: &HashSet<IpAddr>, uids: &HashSet<u32>) -> bool {
        match self.0 {
            PeerIdentity::Tcp(address) => addresses.contains(&address.ip()),
            #[cfg(unix)]
            PeerIdentity::UnixUid(uid) => uids.contains(&uid),
        }
    }
}

impl CappedListener {
    pub(super) fn new(listener: TcpListener, limit: usize, tls: Option<TlsAcceptor>) -> Self {
        Self {
            listener,
            capacity: std::sync::Arc::new(Semaphore::new(limit)),
            tls,
            handshakes: JoinSet::new(),
            plain_http: std::sync::Arc::default(),
        }
    }
}

pub(super) struct CappedStream {
    pub(super) stream: TcpStream,
    pub(super) _permit: OwnedSemaphorePermit,
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

pub(super) enum CappedIo {
    Plain(CappedStream),
    Tls(Box<TlsStream<CappedStream>>),
    #[cfg(unix)]
    Unix(CappedUnixStream),
}

#[cfg(unix)]
pub(super) struct CappedUnixStream {
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
pub(super) struct CappedUnixListener {
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

pub(super) enum PublicListener {
    Tcp(CappedListener),
    #[cfg(unix)]
    Unix(CappedUnixListener),
}

#[cfg(unix)]
pub(super) struct UnixSocketGuard {
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
pub(super) fn bind_unix_listener(
    path: &Path,
) -> Result<(CappedUnixListener, UnixSocketGuard), ConsoleError> {
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
