//! The `openvibes-vulns` service: checks each Fedora release its hosts run
//! at start and every interval, re-matches a host when ingest notifies
//! `inventory_changed`, and serves loopback `/health` and `/ready`.

use std::{future::Future, time::Duration};

use axum::{Router, extract::State, http::StatusCode, routing::get};
use chrono::Utc;
use platform_store::{Pool, vulns};
use tokio::{net::TcpListener, sync::mpsc};
use tokio_postgres::{AsyncMessage, NoTls};

use crate::{
    config::VulnsConfig,
    feed::SourceId,
    fetch::{self, Checked, Fetcher},
    matching,
};

/// Runs until `shutdown`. Startup failures are returned as messages.
pub async fn run(
    config: VulnsConfig,
    health: TcpListener,
    shutdown: impl Future<Output = ()>,
) -> Result<(), String> {
    config.validate()?;
    let fetcher = Fetcher::new(
        &config.metalink_url,
        config.proxy_url.as_deref(),
        config.max_download_bytes,
    )?;
    let pool = platform_store::connect(&config.database_url)
        .await
        .map_err(|error| error.to_string())?;
    let health_pool = pool.clone();
    let health_task = tokio::spawn(async move {
        let app = Router::new()
            .route("/health", get(|| async { StatusCode::OK }))
            .route("/ready", get(ready))
            .with_state(health_pool);
        let _ = axum::serve(health, app).await;
    });
    let (changed, mut notifications) = mpsc::unbounded_channel();
    let listener = tokio::spawn(listen(config.database_url.clone(), changed));
    let mut interval =
        tokio::time::interval(Duration::from_secs(config.check_interval_minutes * 60));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => break,
            _ = interval.tick() => check_all(&pool, &fetcher, &config.arch).await,
            Some(agent) = notifications.recv() => rematch(&pool, &agent).await,
        }
    }
    listener.abort();
    health_task.abort();
    Ok(())
}

async fn ready(State(pool): State<Pool>) -> StatusCode {
    let Ok(client) = pool.get().await else {
        return StatusCode::SERVICE_UNAVAILABLE;
    };
    match platform_store::schema_version(&client).await {
        Ok(Some(version)) if version == platform_store::SCHEMA_VERSION => StatusCode::OK,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}

/// Checks every Fedora release hosts report; one failure never stops the
/// others.
async fn check_all(pool: &Pool, fetcher: &Fetcher, arch: &str) {
    let Ok(mut client) = pool.get().await else {
        tracing::warn!("database unavailable; feed check skipped");
        return;
    };
    let releases = match vulns::fedora_releases(&client).await {
        Ok(releases) => releases,
        Err(error) => {
            tracing::warn!(%error, "cannot list releases");
            return;
        }
    };
    for release in releases {
        let source = SourceId {
            os_id: "fedora".into(),
            os_version: release,
            arch: arch.to_owned(),
        };
        match fetch::check(&mut client, fetcher, &source, Utc::now()).await {
            Ok(Checked::Unchanged) => tracing::info!(source = %source.name(), "feed unchanged"),
            Ok(Checked::Imported(report)) => tracing::info!(
                source = %source.name(),
                advisories = report.advisories,
                open = report.open,
                "feed imported"
            ),
            Err(error) => tracing::warn!(source = %source.name(), %error, "feed check failed"),
        }
    }
}

async fn rematch(pool: &Pool, agent: &str) {
    let Ok(mut client) = pool.get().await else {
        tracing::warn!("database unavailable; host re-match skipped");
        return;
    };
    match matching::match_host(&mut client, agent, Utc::now()).await {
        Ok(open) => tracing::info!(agent_id = %agent, open, "host re-matched"),
        Err(error) => tracing::warn!(agent_id = %agent, %error, "host re-match failed"),
    }
}

/// Keeps a dedicated connection listening for `inventory_changed`,
/// reconnecting every 30 s after a failure.
async fn listen(url: String, changed: mpsc::UnboundedSender<String>) {
    loop {
        if let Ok((client, mut connection)) = tokio_postgres::connect(&url, NoTls).await {
            let sender = changed.clone();
            let driver = tokio::spawn(async move {
                while let Some(message) =
                    std::future::poll_fn(|cx| connection.poll_message(cx)).await
                {
                    match message {
                        Ok(AsyncMessage::Notification(note)) => {
                            let _ = sender.send(note.payload().to_owned());
                        }
                        Err(_) => break,
                        Ok(_) => {}
                    }
                }
            });
            if client
                .batch_execute("LISTEN inventory_changed")
                .await
                .is_ok()
            {
                let _ = driver.await;
            }
            drop(client);
            tracing::warn!("inventory notifications lost; reconnecting");
        }
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}
