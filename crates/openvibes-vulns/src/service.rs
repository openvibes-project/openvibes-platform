//! The `openvibes-vulns` service: checks each Fedora release its hosts run
//! and the KEV and EPSS sources at start and every interval, re-matches a host when ingest notifies
//! `inventory_changed`, and serves loopback `/health` and `/ready`.

use std::{future::Future, time::Duration};

use axum::{Router, extract::State, http::StatusCode, routing::get};
use chrono::Utc;
use platform_store::{Pool, vulns};
use tokio::{net::TcpListener, sync::mpsc};
use tokio_postgres::{AsyncMessage, NoTls};

use crate::{
    config::VulnsConfig,
    enrich::Source,
    feed::SourceId,
    fetch::{self, Checked, Fetcher},
    matching,
    osv_fetch::{self, OsvSync},
    sources::{self, NvdClient},
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
    let every = Duration::from_secs(config.check_interval_minutes * 60);
    // NVD is paced to its rate limit, so it runs apart from the main loop.
    let nvd_task = if config.nvd_url.is_empty() {
        None
    } else {
        let key = config
            .nvd_api_key_file
            .as_deref()
            .map(sources::read_api_key)
            .transpose()?;
        let nvd = NvdClient::new(&fetcher, &config.nvd_url, key, None)?;
        Some(tokio::spawn(nvd_loop(pool.clone(), nvd, every)))
    };
    // OSV's first imports are large downloads: apart from the main loop.
    let osv_task = if config.osv_url.is_empty() {
        None
    } else {
        let osv = OsvSync::new(
            &fetcher,
            &config.osv_url,
            &config.osv_dir,
            config.osv_max_download_bytes,
            osv_fetch::MAX_CHANGES,
        )?;
        Some(tokio::spawn(osv_loop(pool.clone(), osv, every)))
    };
    let (changed, mut notifications) = mpsc::unbounded_channel();
    let listener = tokio::spawn(listen(config.database_url.clone(), changed));
    let mut interval = tokio::time::interval(every);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => break,
            _ = interval.tick() => {
                check_all(&pool, &fetcher, &config.arch).await;
                enrich_all(&pool, &fetcher, &config).await;
            }
            Some(agent) = notifications.recv() => rematch(&pool, &agent).await,
        }
    }
    listener.abort();
    health_task.abort();
    for task in [nvd_task, osv_task].into_iter().flatten() {
        task.abort();
    }
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

/// Syncs OSV for the releases hosts run, every interval (first at start).
async fn osv_loop(pool: Pool, osv: OsvSync, every: Duration) {
    let mut interval = tokio::time::interval(every);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        let Ok(mut client) = pool.get().await else {
            tracing::warn!("database unavailable; osv sync skipped");
            continue;
        };
        let groups = match osv_fetch::releases_by_ecosystem(&client).await {
            Ok(groups) => groups,
            Err(error) => {
                tracing::warn!(%error, "cannot list osv releases");
                continue;
            }
        };
        for (ecosystem, releases) in groups {
            match osv_fetch::sync(&mut client, &osv, ecosystem, &releases, Utc::now()).await {
                Ok(synced) => tracing::info!(ecosystem, ?synced, "osv synced"),
                Err(error) => tracing::warn!(ecosystem, %error, "osv sync failed"),
            }
        }
    }
}

/// Runs NVD sync every interval (first at start).
async fn nvd_loop(pool: Pool, nvd: NvdClient, every: Duration) {
    let mut interval = tokio::time::interval(every);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        let Ok(mut client) = pool.get().await else {
            tracing::warn!("database unavailable; nvd sync skipped");
            continue;
        };
        match sources::sync_nvd(&mut client, &nvd, Utc::now()).await {
            Ok(report) => tracing::info!(
                updated = report.updated,
                backfilled = report.backfilled,
                unknown = report.unknown,
                "nvd synced"
            ),
            Err(error) => tracing::warn!(%error, "nvd sync failed"),
        }
    }
}

/// Checks each enabled enrichment source; priority is computed when read,
/// so nothing is re-matched.
async fn enrich_all(pool: &Pool, fetcher: &Fetcher, config: &VulnsConfig) {
    let Ok(mut client) = pool.get().await else {
        tracing::warn!("database unavailable; enrichment check skipped");
        return;
    };
    for (source, url) in [
        (Source::Kev, &config.kev_url),
        (Source::Epss, &config.epss_url),
    ] {
        if url.is_empty() {
            continue;
        }
        match fetch::check_enrichment(&mut client, fetcher, source, url, Utc::now()).await {
            Ok(None) => tracing::info!(%source, "enrichment unchanged"),
            Ok(Some(cves)) => tracing::info!(%source, cves, "enrichment imported"),
            Err(error) => tracing::warn!(%source, %error, "enrichment check failed"),
        }
    }
    if !config.euvd_url.is_empty() {
        match sources::check_euvd(&mut client, fetcher, &config.euvd_url, 100, Utc::now()).await {
            Ok(None) => tracing::info!(source = "euvd", "enrichment unchanged"),
            Ok(Some(cves)) => tracing::info!(source = "euvd", cves, "enrichment imported"),
            Err(error) => tracing::warn!(source = "euvd", %error, "enrichment check failed"),
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
