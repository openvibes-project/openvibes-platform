use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use openvibes_console::{Readiness, health_router, public_router};
use serde_json::Value;
use tower::ServiceExt;

fn assert_public_security_headers(response: &axum::response::Response) {
    assert!(
        response
            .headers()
            .contains_key("content-security-policy-report-only")
    );
    assert_eq!(
        response.headers().get("referrer-policy").unwrap(),
        "no-referrer"
    );
    assert_eq!(
        response
            .headers()
            .get(header::X_CONTENT_TYPE_OPTIONS)
            .unwrap(),
        "nosniff"
    );
    assert!(response.headers().contains_key("permissions-policy"));
}

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
    assert_public_security_headers(&response);
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
    assert_public_security_headers(&response);
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
        assert_public_security_headers(&response);
    }
}

#[tokio::test]
async fn reserved_prefixes_never_receive_browser_html() {
    for path in [
        "/api",
        "/api/unknown",
        "/auth",
        "/auth/unknown",
        "/assets",
        "/assets/unknown.js",
        "/brand",
        "/brand/unknown.svg",
        "/health",
        "/ready",
    ] {
        let response = public_router()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        assert_public_security_headers(&response);
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        assert!(!String::from_utf8_lossy(&body).contains("<!doctype html>"));
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

#[cfg(feature = "embedded-ui")]
#[tokio::test]
async fn known_browser_routes_serve_the_no_store_spa_entry() {
    for path in [
        "/",
        "/findings",
        "/agents",
        "/enrollment",
        "/rule-sets",
        "/access",
        "/service-accounts",
        "/audit",
    ] {
        let response = public_router()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_public_security_headers(&response);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
    }
}

#[cfg(feature = "embedded-ui")]
#[tokio::test]
async fn unknown_browser_route_is_not_spa_fallback() {
    let response = public_router()
        .oneshot(
            Request::builder()
                .uri("/not-a-console-route")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
}

#[cfg(feature = "embedded-ui")]
#[tokio::test]
async fn embedded_assets_have_explicit_types_and_cache_policies() {
    let manifest = public_router()
        .oneshot(
            Request::builder()
                .uri("/app.webmanifest")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(manifest.status(), StatusCode::OK);
    assert_eq!(
        manifest.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/manifest+json; charset=utf-8"
    );
    assert_eq!(
        manifest.headers().get(header::CACHE_CONTROL).unwrap(),
        "public, max-age=0, must-revalidate"
    );

    let bootstrap = public_router()
        .oneshot(
            Request::builder()
                .uri("/theme-bootstrap.js")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bootstrap.status(), StatusCode::OK);
    assert_eq!(
        bootstrap.headers().get(header::CONTENT_TYPE).unwrap(),
        "text/javascript; charset=utf-8"
    );
    assert_eq!(
        bootstrap.headers().get(header::CACHE_CONTROL).unwrap(),
        "public, max-age=0, must-revalidate"
    );

    let brand = public_router()
        .oneshot(
            Request::builder()
                .uri("/brand/openvibes-mark-placeholder.svg")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(brand.status(), StatusCode::OK);
    assert_eq!(
        brand.headers().get(header::CONTENT_TYPE).unwrap(),
        "image/svg+xml"
    );
    assert_eq!(
        brand.headers().get(header::CACHE_CONTROL).unwrap(),
        "public, max-age=0, must-revalidate"
    );

    let index = public_router()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let index = String::from_utf8(
        to_bytes(index.into_body(), 128 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    for (marker, expected_type) in [
        ("src=\"/assets/", "text/javascript; charset=utf-8"),
        ("href=\"/assets/", "text/css; charset=utf-8"),
    ] {
        let start = index.find(marker).expect("entry document asset") + marker.len() - 8;
        let relative = &index[start..];
        let end = relative.find('"').expect("closing asset quote");
        let path = &relative[..end];
        let response = public_router()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            expected_type
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "public, max-age=31536000, immutable"
        );
        assert_eq!(
            response
                .headers()
                .get(header::X_CONTENT_TYPE_OPTIONS)
                .unwrap(),
            "nosniff"
        );
    }
}
