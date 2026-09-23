use std::future::{Future, IntoFuture};

use tokio::net::TcpListener;

use crate::{ConsoleConfig, ConsoleError, Readiness, health_router, public_router};

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
    let public = axum::serve(public_listener, public_router()).into_future();
    let health = axum::serve(health_listener, health_router(readiness.clone())).into_future();
    tokio::pin!(public);
    tokio::pin!(health);
    tokio::pin!(shutdown);

    let result = tokio::select! {
        result = &mut public => result,
        result = &mut health => result,
        () = &mut shutdown => return Ok(()),
    };
    readiness.set(false);
    result.map_err(ConsoleError::Io)
}
