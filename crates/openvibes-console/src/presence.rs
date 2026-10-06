//! Live agent presence: `GET /api/v1/agents/events` is a server-sent event
//! stream that says when the fleet's online set changed (an agent came
//! online or went offline), so the console refetches its agent views at
//! once instead of waiting for a poll. Events carry no agent data: the
//! browser reads the changed views through the usual scoped API calls, so
//! the stream leaks nothing a viewer could not read. One background task
//! compares a cheap database fingerprint every few seconds, and only while
//! someone is watching.

use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use futures_util::stream;
use tokio::{sync::watch, time::timeout};

use crate::router::{AuthHttpState, authenticated_permission};

/// How often the shared task compares the fleet's online fingerprint.
const CHECK_EVERY: Duration = Duration::from_secs(5);
/// A stream closes after this long; the browser reconnects, which also
/// re-checks its session and lets a graceful shutdown finish.
const STREAM_LIFETIME: Duration = Duration::from_secs(60);
/// A comment line goes out this often so proxies keep the stream open.
const KEEP_ALIVE: Duration = Duration::from_secs(20);

/// Shared by every stream: a version that rises when the online set changes.
#[derive(Clone)]
pub(crate) struct PresenceHub {
    tx: Arc<watch::Sender<u64>>,
    running: Arc<AtomicBool>,
}

impl Default for PresenceHub {
    fn default() -> Self {
        Self {
            tx: Arc::new(watch::channel(0).0),
            running: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl PresenceHub {
    /// A receiver for changes, starting the shared check if it is not
    /// running. The check stops by itself once nobody is watching.
    fn subscribe(&self, pool: platform_store::Pool) -> watch::Receiver<u64> {
        let receiver = self.tx.subscribe();
        if !self.running.swap(true, Ordering::AcqRel) {
            let tx = self.tx.clone();
            let running = self.running.clone();
            tokio::spawn(async move {
                let mut last = None;
                loop {
                    tokio::time::sleep(CHECK_EVERY).await;
                    if tx.receiver_count() == 0 {
                        running.store(false, Ordering::Release);
                        // A viewer may have subscribed between the count and
                        // the store (it saw `running` and spawned nothing):
                        // take over unless another task already did.
                        if tx.receiver_count() == 0 || running.swap(true, Ordering::AcqRel) {
                            break;
                        }
                    }
                    let Ok(client) = pool.get().await else {
                        continue;
                    };
                    if let Ok(print) =
                        platform_store::console_read::online_fingerprint(&client, Utc::now()).await
                    {
                        if last.is_some_and(|seen| seen != print) {
                            tx.send_modify(|version| *version += 1);
                        }
                        last = Some(print);
                    }
                }
            });
        }
        receiver
    }
}

/// The event stream. Needs `agents.read`; marked background by the web app
/// so it does not extend the session.
pub(crate) async fn agent_events(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) =
        authenticated_permission(&state, &headers, crate::Permission::AgentsRead, false).await
    {
        return response;
    }
    let receiver = state.presence.subscribe(state.pool.clone());
    let deadline = tokio::time::Instant::now() + STREAM_LIFETIME;
    // First frame tells the browser the stream is live (and sets its retry).
    let opening = Bytes::from_static(b"retry: 3000\n: connected\n\n");
    let body = stream::unfold(
        (receiver, Some(opening)),
        move |(mut receiver, first)| async move {
            if let Some(frame) = first {
                return Some((Ok::<_, Infallible>(frame), (receiver, None)));
            }
            let wait = deadline
                .saturating_duration_since(tokio::time::Instant::now())
                .min(KEEP_ALIVE);
            if wait.is_zero() {
                return None;
            }
            let frame = match timeout(wait, receiver.changed()).await {
                Ok(Ok(())) => Bytes::from_static(b"event: presence\ndata: changed\n\n"),
                Ok(Err(_)) => return None,
                Err(_) => Bytes::from_static(b": keep-alive\n\n"),
            };
            Some((Ok(frame), (receiver, None)))
        },
    );
    let mut response = (StatusCode::OK, Body::from_stream(body)).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
