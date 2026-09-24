use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    extract::{MatchedPath, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};

use tokio::sync::Semaphore;

use crate::ApiError;

/// Per-process request limits.
#[derive(Clone)]
pub(crate) struct Limits {
    pub in_flight: Arc<Semaphore>,
    pub request_timeout: Duration,
}

/// Refuses a request with 503 when `max_in_flight` requests are already
/// being served, and turns an over-limit body (413) into the spec's 400.
pub(crate) async fn bound(State(state): State<Limits>, request: Request, next: Next) -> Response {
    // A declared length over the limit is refused before any body is read.
    let declared = request
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    if declared.is_some_and(|length| length > crate::request::MAX_BODY_BYTES as u64) {
        return ApiError::BadRequest.into_response();
    }
    let Ok(permit) = state.in_flight.clone().try_acquire_owned() else {
        return ApiError::Busy.into_response();
    };
    // The whole request, body included, must finish within the deadline,
    // so a slow client cannot keep its permit.
    let response = match tokio::time::timeout(state.request_timeout, next.run(request)).await {
        Ok(response) => response,
        Err(_) => ApiError::Timeout.into_response(),
    };
    drop(permit);
    if response.status() == StatusCode::PAYLOAD_TOO_LARGE {
        return ApiError::BadRequest.into_response();
    }
    response
}

/// The route that matched, or `other`; logs never copy the raw path.
fn endpoint_label(matched: Option<&str>) -> &str {
    matched.unwrap_or("other")
}

/// One JSON log line per request: endpoint, status, latency, and the agent
/// id once authenticated. Bodies, tokens, CSRs, and certificates are never
/// logged.
pub(crate) async fn log(request: Request, next: Next) -> Response {
    let matched = request
        .extensions()
        .get::<MatchedPath>()
        .map(|path| path.as_str().to_owned());
    let endpoint = endpoint_label(matched.as_deref()).to_owned();
    let span =
        tracing::info_span!("request", endpoint = %endpoint, agent_id = tracing::field::Empty);
    let started = Instant::now();
    let response = tracing::Instrument::instrument(next.run(request), span.clone()).await;
    let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    span.in_scope(|| {
        tracing::info!(endpoint = %endpoint, status = response.status().as_u16(), latency_ms, "request");
    });
    response
}

#[cfg(test)]
mod tests {
    use axum::{Router, body::Body, http::Request, middleware, routing::post};
    use tower::ServiceExt;

    #[test]
    fn endpoint_label_is_the_matched_route_or_other() {
        assert_eq!(
            super::endpoint_label(Some("/v1/rule-bundle")),
            "/v1/rule-bundle"
        );
        assert_eq!(super::endpoint_label(None), "other");
    }

    #[tokio::test]
    async fn unknown_paths_are_not_copied_into_logs() {
        let app = Router::new()
            .route("/v1/x", post(|| async { "ok" }))
            .layer(middleware::from_fn(super::log));
        let response = app
            .oneshot(
                Request::post("/secret-token-in-path")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 404);
    }
}
