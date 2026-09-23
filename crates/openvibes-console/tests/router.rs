use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use openvibes_console::{Readiness, health_router, public_router};
use serde_json::Value;
use tower::ServiceExt;

#[tokio::test]
async fn unknown_api_route_is_problem_json_and_never_html() {
    let response = public_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/not-real")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/problem+json"
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let problem: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(problem["code"], "api_not_found");
    assert_eq!(problem["status"], 404);
    assert!(problem["request_id"].as_str().unwrap().starts_with("c0-"));
    assert!(!String::from_utf8_lossy(&body).contains("<html"));
}

#[tokio::test]
async fn unknown_asset_is_an_empty_real_404() {
    let response = public_router()
        .oneshot(
            Request::builder()
                .uri("/assets/missing.js")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(response.headers().get(header::CONTENT_TYPE).is_none());
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert!(
        to_bytes(response.into_body(), 1024)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn public_router_does_not_expose_health_endpoints() {
    for path in ["/health", "/ready"] {
        let response = public_router()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn readiness_is_independent_from_liveness() {
    let readiness = Readiness::new(false);
    let health = health_router(readiness.clone());

    let live = health
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(live.status(), StatusCode::NO_CONTENT);

    let unavailable = health
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);

    readiness.set(true);
    let ready = health
        .oneshot(
            Request::builder()
                .uri("/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ready.status(), StatusCode::NO_CONTENT);
}
