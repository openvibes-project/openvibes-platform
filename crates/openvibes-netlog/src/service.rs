//! The loop: datagrams, a flush every `batch_seconds`, devices reloaded
//! every 30 s and on SIGHUP. One task, so no locks; a slow flush leaves
//! datagrams in the kernel's receive buffer.
// ponytail: single task; split receive and store if a flush ever takes
// longer than the socket buffer covers.

use std::{collections::HashMap, future::Future, net::IpAddr, time::Duration};

use axum::{Router, extract::State, http::StatusCode, routing::get};
use chrono::Utc;
use platform_store::{
    Pool, device_alarms,
    devices::{self, Counters},
};
use tokio::{
    net::{TcpListener, UdpSocket},
    signal::unix::{SignalKind, signal},
};

use crate::{
    cef::MAX_DATAGRAM,
    collapse::Collapser,
    config::NetlogConfig,
    handle::{HostCounters, handle},
};

pub async fn run(
    config: NetlogConfig,
    socket: UdpSocket,
    health: TcpListener,
    shutdown: impl Future<Output = ()>,
) -> Result<(), String> {
    config.validate()?;
    let pool = platform_store::connect_sized(&config.database_url, 2)
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
    let window = chrono::Duration::minutes(i64::try_from(config.collapse_minutes).unwrap_or(10));
    let mut collapser = Collapser::new(window, config.max_collapse_keys);
    let mut known: HashMap<IpAddr, i64> = HashMap::new();
    let mut counters: HashMap<i64, Counters> = HashMap::new();
    let mut host = HostCounters::default();
    let mut buf = vec![0_u8; MAX_DATAGRAM];
    let mut flush = tokio::time::interval(Duration::from_secs(config.batch_seconds));
    let mut reload = tokio::time::interval(Duration::from_secs(30));
    let mut hup = signal(SignalKind::hangup()).map_err(|error| format!("SIGHUP: {error}"))?;
    // Before the first datagram: otherwise packets that arrive while the
    // first reload is pending are dropped as unknown senders.
    load_devices(&pool, &mut known).await;
    reload.reset();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => break,
            received = socket.recv_from(&mut buf) => {
                if let Ok((n, from)) = received {
                    handle(&buf[..n], from.ip(), Utc::now(), &known, &mut counters, &mut collapser, &mut host);
                }
            }
            _ = flush.tick() => store(&pool, &mut counters, &mut collapser, &mut host).await,
            _ = reload.tick() => load_devices(&pool, &mut known).await,
            _ = hup.recv() => load_devices(&pool, &mut known).await,
        }
    }
    store(&pool, &mut counters, &mut collapser, &mut host).await;
    health_task.abort();
    Ok(())
}

async fn load_devices(pool: &Pool, known: &mut HashMap<IpAddr, i64>) {
    let Ok(client) = pool.get().await else {
        tracing::warn!("database unavailable; devices not reloaded");
        return;
    };
    match devices::active(&client).await {
        Ok(list) => {
            *known = list
                .into_iter()
                .map(|(id, address)| (address, id))
                .collect()
        }
        Err(error) => tracing::warn!(%error, "devices not reloaded"),
    }
}

/// Alarms first (they matter most), then counters. Whatever fails stays in
/// memory for the next tick.
async fn store(
    pool: &Pool,
    counters: &mut HashMap<i64, Counters>,
    collapser: &mut Collapser,
    host: &mut HostCounters,
) {
    let Ok(mut client) = pool.get().await else {
        tracing::warn!(
            waiting = collapser.dirty().len(),
            "database unavailable; alarms kept for the next try"
        );
        return;
    };
    let batch = collapser.dirty();
    if !batch.is_empty() {
        match device_alarms::insert_batch(&mut client, &batch, Utc::now()).await {
            Ok(done) => {
                collapser.stored(&batch);
                host.unstorable += u64::from(done.unstorable);
            }
            Err(error) => {
                tracing::warn!(%error, "storing device alarms failed; kept for the next try");
                return;
            }
        }
    }
    let ids: Vec<i64> = counters.keys().copied().collect();
    for id in ids {
        if devices::flush(&mut client, id, &counters[&id])
            .await
            .is_ok()
        {
            counters.remove(&id);
        }
    }
    if *host != HostCounters::default() {
        tracing::info!(
            unknown_sender = host.unknown_sender,
            collapse_full = host.collapse_full,
            unstorable = host.unstorable,
            "netlog dropped datagrams"
        );
        *host = HostCounters::default();
    }
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
