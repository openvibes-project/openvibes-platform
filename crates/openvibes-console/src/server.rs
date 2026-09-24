use std::{
    future::{Future, IntoFuture},
    io,
    time::Duration,
};

use tokio::{net::TcpListener, sync::watch, time::timeout};

use crate::{ConsoleConfig, ConsoleError, Readiness, development_router, health_router};

const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

/// Binds the C0 development and health listeners and serves them until
/// `shutdown` resolves.
pub async fn serve(
    config: ConsoleConfig,
    shutdown: impl Future<Output = ()>,
) -> Result<(), ConsoleError> {
    config.validate()?;
    let public_listener = TcpListener::bind(config.development_listen).await?;
    let health_listener = TcpListener::bind(config.health_listen).await?;
    run(public_listener, health_listener, shutdown).await
}

/// Serves already-bound listeners. This is exposed for process-level and
/// integration tests that need ephemeral ports.
pub async fn run(
    public_listener: TcpListener,
    health_listener: TcpListener,
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
    let public = axum::serve(public_listener, development_router())
        .with_graceful_shutdown(stop_requested(public_stop))
        .into_future();
    let health = axum::serve(health_listener, health_router(readiness.clone()))
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
