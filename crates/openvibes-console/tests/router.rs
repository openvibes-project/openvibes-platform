use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use openvibes_console::{
    Readiness, TrustedPeer, authenticated_router, authenticated_router_for_hosts,
    development_router, health_router, public_router,
};
use serde_json::Value;
use tower::ServiceExt;

fn assert_public_security_headers(response: &axum::response::Response) {
    let csp = response.headers().get("content-security-policy").unwrap();
    assert!(csp.to_str().unwrap().contains("default-src 'none'"));
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
    assert_eq!(response.headers().get("x-frame-options").unwrap(), "DENY");
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
    let response_id = response
        .headers()
        .get("x-request-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
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
    assert_eq!(problem["request_id"], response_id);
    assert!(!String::from_utf8_lossy(&body).contains("<html"));
}

#[tokio::test]
async fn session_contract_fails_closed_until_authentication_exists() {
    let response = public_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/session")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
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
    assert_eq!(problem["code"], "authentication_unavailable");
    assert_eq!(problem["status"], 503);
    assert!(problem.get("principal").is_none());
}

#[tokio::test]
async fn authenticated_session_rejects_missing_or_malformed_credentials_without_store_access() {
    let pool = platform_store::connect_sized("host=/socket-that-does-not-exist user=none", 1)
        .await
        .unwrap();
    for cookie in [None, Some("__Host-openvibes-session=malformed")] {
        let mut request = Request::builder().uri("/api/v1/session");
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, cookie);
        }
        let response = authenticated_router(pool.clone(), "https://console.example")
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_public_security_headers(&response);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let problem: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(problem["code"], "authentication_required");
        assert_eq!(problem["status"], 401);
        assert!(problem.get("principal").is_none());
    }
}

#[tokio::test]
async fn preauth_does_not_issue_browser_secrets_when_the_store_is_unavailable() {
    let pool = platform_store::connect_sized("host=/socket-that-does-not-exist user=none", 1)
        .await
        .unwrap();
    let response = authenticated_router(pool, "https://console.example")
        .oneshot(
            Request::builder()
                .uri("/auth/v1/preauth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_public_security_headers(&response);
    assert!(!response.headers().contains_key(header::SET_COOKIE));
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let problem: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(problem["code"], "authentication_unavailable");
    assert_eq!(problem["status"], 503);
}

#[tokio::test]
async fn login_rejects_bad_origin_before_consulting_credentials() {
    let pool = platform_store::connect_sized("host=/socket-that-does-not-exist user=none", 1)
        .await
        .unwrap();
    let response = authenticated_router(pool, "https://console.example")
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/v1/login")
                .header(header::ORIGIN, "https://attacker.example")
                .header(header::CONTENT_TYPE, "application/json")
                .extension(axum::extract::ConnectInfo(TrustedPeer::new(
                    "127.0.0.1:4242".parse::<std::net::SocketAddr>().unwrap(),
                )))
                .body(Body::from(r#"{"username":"alice","password":"incorrect"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_public_security_headers(&response);
    assert!(!response.headers().contains_key(header::SET_COOKIE));
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let problem: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(problem["code"], "request_rejected");
}

#[tokio::test]
async fn malformed_login_body_uses_problem_details() {
    let pool = platform_store::connect_sized("host=/socket-that-does-not-exist user=none", 1)
        .await
        .unwrap();
    let response = authenticated_router(pool, "https://console.example")
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/v1/login")
                .header(header::ORIGIN, "https://console.example")
                .header(header::CONTENT_TYPE, "application/json")
                .extension(axum::extract::ConnectInfo(TrustedPeer::new(
                    "127.0.0.1:4242".parse::<std::net::SocketAddr>().unwrap(),
                )))
                .body(Body::from("{"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/problem+json"
    );
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(body["code"], "invalid_auth_request");
}

#[tokio::test]
async fn invalid_public_origins_cannot_enable_browser_login() {
    for origin in [
        "null",
        "http://console.example",
        "https://Console.example",
        "https://console.example/path",
    ] {
        let pool = platform_store::connect_sized("host=/socket-that-does-not-exist user=none", 1)
            .await
            .unwrap();
        let response = authenticated_router(pool, origin)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/v1/login")
                    .header(header::ORIGIN, origin)
                    .header(header::CONTENT_TYPE, "application/json")
                    .extension(axum::extract::ConnectInfo(TrustedPeer::new(
                        "127.0.0.1:4242".parse::<std::net::SocketAddr>().unwrap(),
                    )))
                    .body(Body::from(r#"{"username":"alice","password":"incorrect"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "origin: {origin}");
    }
}

#[tokio::test]
async fn authenticated_router_rejects_unconfigured_hosts() {
    let pool = platform_store::connect_sized("host=/socket-that-does-not-exist user=none", 1)
        .await
        .unwrap();
    let response = authenticated_router(pool, "https://console.example")
        .oneshot(
            Request::builder()
                .uri("/api/v1/session")
                .header(header::HOST, "attacker.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::MISDIRECTED_REQUEST);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
}

/// Board #71: the console answers every name its certificate covers (an IP
/// over a VPN, localhost through a tunnel), and says where it is otherwise.
#[tokio::test]
async fn certificate_names_are_served_and_others_told_where_to_go() {
    let router = || async {
        let pool = platform_store::connect_sized("host=/socket-that-does-not-exist user=none", 1)
            .await
            .unwrap();
        authenticated_router_for_hosts(
            pool,
            "https://metabox-lnx:8443",
            ["192.168.1.10:8443".to_owned(), "localhost:8443".to_owned()],
        )
    };
    let get = |host: &str| {
        Request::builder()
            .uri("/api/v1/session")
            .header(header::HOST, host)
            .body(Body::empty())
            .unwrap()
    };
    for host in ["metabox-lnx:8443", "192.168.1.10:8443", "LOCALHOST:8443"] {
        let response = router().await.oneshot(get(host)).await.unwrap();
        assert_ne!(response.status(), StatusCode::MISDIRECTED_REQUEST, "{host}");
    }
    let response = router()
        .await
        .oneshot(get("attacker.example"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::MISDIRECTED_REQUEST);
    // The console's own headers here too (reviewer on #116).
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    assert!(
        response
            .headers()
            .contains_key(header::CONTENT_SECURITY_POLICY)
    );
    assert!(
        response.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/html"),
        "a page, not a blank"
    );
    let body =
        String::from_utf8(to_bytes(response.into_body(), 8192).await.unwrap().to_vec()).unwrap();
    assert!(
        body.contains(r#"href="https://metabox-lnx:8443/""#),
        "{body}"
    );
    assert!(body.contains(">Open the console</a>"), "{body}");
    assert!(
        body.contains(r#"<p class="address">https://metabox-lnx:8443</p>"#),
        "{body}"
    );
    // Board #81: the sign-in look, under the console's CSP (no inline style).
    assert!(
        body.contains(r#"<link rel="stylesheet" href="/misdirected/page.css">"#),
        "{body}"
    );
    assert!(body.contains("/misdirected/wordmark-light.svg"), "{body}");
    assert!(!body.contains("style="), "{body}");
    assert!(!body.contains("certificate"), "plain words: {body}");
}

/// Reviewer on #99: a request without `Host` passes the host check, so its
/// Origin must still be the canonical one, never anything else.
#[tokio::test]
async fn without_a_host_only_the_canonical_origin_may_log_in() {
    for (origin, allowed) in [
        ("https://metabox-lnx:8443", true),
        ("https://192.168.1.10:8443", false),
        ("https://attacker.example", false),
    ] {
        let pool = platform_store::connect_sized("host=/socket-that-does-not-exist user=none", 1)
            .await
            .unwrap();
        let response = authenticated_router_for_hosts(
            pool,
            "https://metabox-lnx:8443",
            ["192.168.1.10:8443".to_owned()],
        )
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/v1/login")
                .header(header::ORIGIN, origin)
                .header(header::CONTENT_TYPE, "application/json")
                .extension(axum::extract::ConnectInfo(TrustedPeer::new(
                    "127.0.0.1:4242".parse::<std::net::SocketAddr>().unwrap(),
                )))
                .body(Body::from("{"))
                .unwrap(),
        )
        .await
        .unwrap();
        let expected = if allowed {
            StatusCode::BAD_REQUEST
        } else {
            StatusCode::FORBIDDEN
        };
        assert_eq!(response.status(), expected, "{origin}");
    }
}

/// Board #81: the 421 page's own stylesheet and wordmarks load under any
/// Host (they hold no data); nothing else does.
#[tokio::test]
async fn the_misdirected_page_assets_load_under_any_host() {
    for (path, kind) in [
        ("/misdirected/page.css", "text/css"),
        ("/misdirected/wordmark-light.svg", "image/svg+xml"),
        ("/misdirected/wordmark-dark.svg", "image/svg+xml"),
    ] {
        let pool = platform_store::connect_sized("host=/socket-that-does-not-exist user=none", 1)
            .await
            .unwrap();
        let response = authenticated_router(pool, "https://metabox-lnx:8443")
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header(header::HOST, "192.0.2.7:8443")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(
            response.headers()["x-content-type-options"],
            "nosniff",
            "{path}"
        );
        assert!(
            response.headers()[header::CONTENT_SECURITY_POLICY]
                .to_str()
                .unwrap()
                .contains("style-src 'self'"),
            "{path}"
        );
        assert!(
            response.headers()[header::CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with(kind),
            "{path}"
        );
    }
    let pool = platform_store::connect_sized("host=/socket-that-does-not-exist user=none", 1)
        .await
        .unwrap();
    let response = authenticated_router(pool, "https://metabox-lnx:8443")
        .oneshot(
            Request::builder()
                .uri("/misdirected/../api/v1/session")
                .header(header::HOST, "192.0.2.7:8443")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::MISDIRECTED_REQUEST);
}

#[tokio::test]
async fn a_login_origin_must_match_the_host_it_came_to() {
    let login = |host: &str, origin: &str| {
        Request::builder()
            .method("POST")
            .uri("/auth/v1/login")
            .header(header::HOST, host)
            .header(header::ORIGIN, origin)
            .header(header::CONTENT_TYPE, "application/json")
            .extension(axum::extract::ConnectInfo(TrustedPeer::new(
                "127.0.0.1:4242".parse::<std::net::SocketAddr>().unwrap(),
            )))
            .body(Body::from("{"))
            .unwrap()
    };
    for (host, origin, allowed) in [
        ("192.168.1.10:8443", "https://192.168.1.10:8443", true),
        ("metabox-lnx:8443", "https://metabox-lnx:8443", true),
        // Another allowed name is still cross-origin for this request.
        ("192.168.1.10:8443", "https://metabox-lnx:8443", false),
        ("192.168.1.10:8443", "https://attacker.example", false),
    ] {
        let pool = platform_store::connect_sized("host=/socket-that-does-not-exist user=none", 1)
            .await
            .unwrap();
        let response = authenticated_router_for_hosts(
            pool,
            "https://metabox-lnx:8443",
            ["192.168.1.10:8443".to_owned()],
        )
        .oneshot(login(host, origin))
        .await
        .unwrap();
        // The origin check comes first: past it, a malformed body is a 400.
        let expected = if allowed {
            StatusCode::BAD_REQUEST
        } else {
            StatusCode::FORBIDDEN
        };
        assert_eq!(response.status(), expected, "{host} {origin}");
    }
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
    assert!(response.headers().get("x-request-id").is_some());
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
        "/vulnerabilities",
        "/login",
        "/dashboards/overview",
        "/dashboards/3f2b9c1e-6a4d-4e2f-9b1a-7c5d8e0f1a2b",
    ] {
        let response = public_router()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_public_security_headers(&response);
        assert!(response.headers().get("x-request-id").is_some());
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
async fn retired_v1_routes_and_nested_dashboard_paths_are_not_served() {
    for path in ["/assistant", "/dashboards", "/dashboards/a/b"] {
        let response = public_router()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
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
                .uri("/brand/openvibes-mark.svg")
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

#[tokio::test]
async fn a_wrong_method_on_an_api_route_is_problem_json() {
    let response = public_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/session")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/problem+json"
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap()).unwrap();
    assert_eq!(body["code"], "method_not_allowed");
    assert_eq!(body["status"], 405);
}

#[tokio::test]
async fn the_development_listener_answers_only_loopback_host_names() {
    let request = |host: &str| {
        Request::builder()
            .uri("/api/v1/session")
            .header(header::HOST, host)
            .body(Body::empty())
            .unwrap()
    };
    // DNS rebinding: a hostile page's name resolving to 127.0.0.1.
    let response = development_router()
        .oneshot(request("evil.example"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::MISDIRECTED_REQUEST);
    for host in [
        "localhost:18490",
        "127.0.0.1:18490",
        "[::1]:18490",
        "localhost",
    ] {
        let response = development_router().oneshot(request(host)).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{host}");
    }
}
