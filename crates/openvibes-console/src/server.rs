use std::{
    future::{Future, IntoFuture},
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use axum::{
    Router,
    extract::connect_info::Connected,
    serve::{IncomingStream, Listener},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore, watch},
    time::{sleep, timeout},
};

use crate::{
    ConsoleConfig, ConsoleError, Readiness, authenticated_router, development_router, health_router,
};

const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PUBLIC_CONNECTIONS: usize = 256;
const MAX_HEALTH_CONNECTIONS: usize = 16;

struct CappedListener {
    listener: TcpListener,
    capacity: std::sync::Arc<Semaphore>,
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
    fn new(listener: TcpListener, limit: usize) -> Self {
        Self {
            listener,
            capacity: std::sync::Arc::new(Semaphore::new(limit)),
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

impl Listener for CappedListener {
    type Io = CappedStream;
    type Addr = TrustedPeer;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        let permit = self
            .capacity
            .clone()
            .acquire_owned()
            .await
            .expect("connection permits stay open for the listener lifetime");
        loop {
            match self.listener.accept().await {
                Ok((stream, address)) => {
                    return (
                        CappedStream {
                            stream,
                            _permit: permit,
                        },
                        TrustedPeer(address),
                    );
                }
                Err(error) => {
                    tracing::error!(%error, "console listener accept failed");
                    sleep(Duration::from_millis(50)).await;
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
    let public_router = match (&config.database_url, &config.public_origin) {
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
            authenticated_router(pool, public_origin.as_str())
        }
        (None, None) => development_router(),
        _ => return Err(ConsoleError::Config),
    };
    let public_listener = TcpListener::bind(config.development_listen).await?;
    let health_listener = TcpListener::bind(config.health_listen).await?;
    run_with_router(public_listener, health_listener, public_router, shutdown).await
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
        development_router(),
        shutdown,
    )
    .await
}

async fn run_with_router(
    public_listener: TcpListener,
    health_listener: TcpListener,
    public_router: Router,
    shutdown: impl Future<Output = ()>,
) -> Result<(), ConsoleError> {
    if !public_listener.local_addr()?.ip().is_loopback()
        || !health_listener.local_addr()?.ip().is_loopback()
    {
        return Err(ConsoleError::Config);
    }

    let readiness = Readiness::new(true);
    let (stop_sender, public_stop) = watch::channel(false);
    let health_stop = public_stop.clone();
    let public = axum::serve(
        CappedListener::new(public_listener, MAX_PUBLIC_CONNECTIONS),
        public_router.into_make_service_with_connect_info::<TrustedPeer>(),
    )
    .with_graceful_shutdown(stop_requested(public_stop))
    .into_future();
    let health = axum::serve(
        CappedListener::new(health_listener, MAX_HEALTH_CONNECTIONS),
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
    timeout(GRACEFUL_SHUTDOWN_TIMEOUT, drain)
        .await
        .map_err(|_| {
            ConsoleError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "console graceful shutdown timed out",
            ))
        })?
        .map_err(ConsoleError::Io)
}

async fn stop_requested(mut receiver: watch::Receiver<bool>) {
    if *receiver.borrow() {
        return;
    }
    let _ = receiver.wait_for(|stop| *stop).await;
}
