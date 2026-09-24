use std::{
    hash::{BuildHasher, Hasher},
    net::SocketAddr,
};

use axum::{
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{Request, StatusCode, header},
};
use chrono::Utc;
use openvibes_console::{NormalizedPassword, TrustedPeer, authenticated_router, hash_password};
use platform_store::{
    self,
    console_auth::{NewLocalUser, create_local_user},
};
use serde_json::Value;
use tower::ServiceExt;

struct TestDb {
    pool: platform_store::Pool,
    admin_url: String,
    name: String,
}

impl TestDb {
    async fn create() -> Self {
        let admin_url = std::env::var("OPENVIBES_TEST_DATABASE_URL")
            .expect("set OPENVIBES_TEST_DATABASE_URL via scripts/test-db.sh");
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u64(std::process::id().into());
        let name = format!("ov_console_http_{:016x}", hasher.finish());
        let admin = platform_store::connect(&admin_url).await.unwrap();
        admin
            .get()
            .await
            .unwrap()
            .batch_execute(&format!("CREATE DATABASE {name}"))
            .await
            .unwrap();
        let pool = platform_store::connect(&database_url(&admin_url, &name))
            .await
            .unwrap();
        Self {
            pool,
            admin_url,
            name,
        }
    }

    async fn drop(self) {
        self.pool.close();
        let admin = platform_store::connect(&self.admin_url).await.unwrap();
        admin
            .get()
            .await
            .unwrap()
            .batch_execute(&format!("DROP DATABASE {} WITH (FORCE)", self.name))
            .await
            .unwrap();
    }
}

fn database_url(url: &str, name: &str) -> String {
    let (head, query) = url
        .split_once('?')
        .map_or((url, None), |(h, q)| (h, Some(q)));
    let head = &head[..head.rfind('/').expect("database URL has a path")];
    match query {
        Some(query) => format!("{head}/{name}?{query}"),
        None => format!("{head}/{name}"),
    }
}

fn cookie_pair(response: &axum::response::Response, name: &str) -> String {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|value| {
            value
                .starts_with(name)
                .then(|| value.split(';').next().unwrap().to_owned())
        })
        .unwrap_or_else(|| panic!("missing {name} cookie"))
}

async fn new_preauth(router: &axum::Router) -> (String, String, String) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/auth/v1/preauth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let preauth_cookie = cookie_pair(&response, "__Host-openvibes-preauth=");
    let browser_cookie = cookie_pair(&response, "__Host-openvibes-browser=");
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    (
        preauth_cookie,
        browser_cookie,
        body["csrf_token"].as_str().unwrap().to_owned(),
    )
}

#[tokio::test]
async fn local_login_uses_one_use_preauth_and_returns_an_active_session() {
    if std::env::var_os("OPENVIBES_TEST_DATABASE_URL").is_none() {
        eprintln!("skipping PostgreSQL auth journey: OPENVIBES_TEST_DATABASE_URL is unset");
        return;
    }
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    let enrolled_at = Utc::now();
    for id in [
        "agent.00000000-0000-4000-8000-000000000101",
        "agent.00000000-0000-4000-8000-000000000102",
    ] {
        client
            .execute(
                "INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at)
                 VALUES ($1, 'active', $2, $2)",
                &[&id, &enrolled_at],
            )
            .await
            .unwrap();
    }
    let password = "violet-satellite-mountain-otter-2026";
    let normalized = NormalizedPassword::new(password).unwrap();
    let phc = hash_password(&normalized).unwrap();
    create_local_user(
        &mut client,
        &NewLocalUser {
            user_id: "11111111-1111-4111-8111-111111111111",
            binding_id: "22222222-2222-4222-8222-222222222222",
            username: "alice",
            display_name: "Alice Example",
            password_phc: phc.as_str(),
            role_id: "admin",
            actor_id: "test-bootstrap",
            now: Utc::now(),
        },
    )
    .await
    .unwrap();
    drop(client);

    let router = authenticated_router(db.pool.clone(), "https://console.example");
    let (preauth_cookie, browser_cookie, csrf) = new_preauth(&router).await;
    let address: SocketAddr = "127.0.0.1:4242".parse().unwrap();
    let login = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/v1/login")
                .header(header::ORIGIN, "https://console.example")
                .header("sec-fetch-site", "same-origin")
                .header("x-csrf-token", csrf)
                .header(
                    header::COOKIE,
                    format!("{preauth_cookie}; {browser_cookie}"),
                )
                .header(header::CONTENT_TYPE, "application/json")
                .extension(ConnectInfo(TrustedPeer::new(address)))
                .body(Body::from(format!(
                    "{{\"username\":\"alice\",\"password\":\"{password}\"}}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    assert_eq!(
        cookie_pair(&login, "__Host-openvibes-session=")
            .split('=')
            .count(),
        2
    );
    assert_eq!(
        login.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let session_cookie = cookie_pair(&login, "__Host-openvibes-session=");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/session")
                .header(header::COOKIE, session_cookie.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let session: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 16_384).await.unwrap()).unwrap();
    assert_eq!(session["principal"]["username"], "alice");
    assert_eq!(session["authentication_method"], "local_password");
    assert!(
        session["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|capability| {
                capability["permission"] == "rbac.manage" && capability["scope"]["kind"] == "global"
            })
    );
    let unauthenticated_summary = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/agents/summary")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthenticated_summary.status(), StatusCode::UNAUTHORIZED);
    let summary = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/agents/summary")
                .header(header::COOKIE, session_cookie.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(summary.status(), StatusCode::OK);
    let summary: Value =
        serde_json::from_slice(&to_bytes(summary.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(summary["total"], 2);
    let first_page = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/agents?limit=1")
                .header(header::COOKIE, session_cookie.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first_page.status(), StatusCode::OK);
    let first_page: Value =
        serde_json::from_slice(&to_bytes(first_page.into_body(), 8192).await.unwrap()).unwrap();
    assert_eq!(
        first_page["items"][0]["id"],
        "agent.00000000-0000-4000-8000-000000000101"
    );
    let cursor = first_page["next_cursor"].as_str().unwrap();
    let second_page = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/agents?limit=1&cursor={cursor}"))
                .header(header::COOKIE, session_cookie.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second_page.status(), StatusCode::OK);
    let second_page: Value =
        serde_json::from_slice(&to_bytes(second_page.into_body(), 8192).await.unwrap()).unwrap();
    assert_eq!(
        second_page["items"][0]["id"],
        "agent.00000000-0000-4000-8000-000000000102"
    );
    let mismatched_cursor = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/agents?state=active&limit=1&cursor={cursor}"
                ))
                .header(header::COOKIE, session_cookie.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(mismatched_cursor.status(), StatusCode::BAD_REQUEST);
    let old_session_cookie = session_cookie.clone();
    let (preauth_cookie, browser_cookie, csrf) = new_preauth(&router).await;
    let rotated_login = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/v1/login")
                .header(header::ORIGIN, "https://console.example")
                .header("sec-fetch-site", "same-origin")
                .header("x-csrf-token", &csrf)
                .header(
                    header::COOKIE,
                    format!("{preauth_cookie}; {browser_cookie}; {old_session_cookie}"),
                )
                .header(header::CONTENT_TYPE, "application/json")
                .extension(ConnectInfo(TrustedPeer::new(address)))
                .body(Body::from(format!(
                    "{{\"username\":\"alice\",\"password\":\"{password}\"}}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rotated_login.status(), StatusCode::OK);
    let session_cookie = cookie_pair(&rotated_login, "__Host-openvibes-session=");
    assert_ne!(session_cookie, old_session_cookie);
    let old_session = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/session")
                .header(header::COOKIE, old_session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(old_session.status(), StatusCode::UNAUTHORIZED);
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/session")
                .header(header::COOKIE, session_cookie.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let session: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 16_384).await.unwrap()).unwrap();

    let logout = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/v1/logout")
                .header(header::ORIGIN, "https://console.example")
                .header("sec-fetch-site", "same-origin")
                .header("x-csrf-token", session["csrf_token"].as_str().unwrap())
                .header(header::COOKIE, session_cookie.clone())
                .extension(ConnectInfo(TrustedPeer::new(address)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(logout.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        logout.headers().get_all(header::SET_COOKIE).iter().count(),
        1
    );
    let after_logout = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/session")
                .header(header::COOKIE, session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(after_logout.status(), StatusCode::UNAUTHORIZED);

    let (preauth_cookie, browser_cookie, csrf) = new_preauth(&router).await;
    let failed_login = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/v1/login")
                .header(header::ORIGIN, "https://console.example")
                .header("sec-fetch-site", "same-origin")
                .header("x-csrf-token", &csrf)
                .header(
                    header::COOKIE,
                    format!("{preauth_cookie}; {browser_cookie}"),
                )
                .header(header::CONTENT_TYPE, "application/json")
                .extension(ConnectInfo(TrustedPeer::new(address)))
                .body(Body::from(
                    r#"{"username":"alice","password":"wrong password"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(failed_login.status(), StatusCode::UNAUTHORIZED);
    assert!(!failed_login.headers().contains_key(header::SET_COOKIE));
    let failed_body: Value =
        serde_json::from_slice(&to_bytes(failed_login.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(failed_body["code"], "authentication_failed");

    let (preauth_cookie, browser_cookie, csrf) = new_preauth(&router).await;
    let missing_login = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/v1/login")
                .header(header::ORIGIN, "https://console.example")
                .header("sec-fetch-site", "same-origin")
                .header("x-csrf-token", &csrf)
                .header(
                    header::COOKIE,
                    format!("{preauth_cookie}; {browser_cookie}"),
                )
                .header(header::CONTENT_TYPE, "application/json")
                .extension(ConnectInfo(TrustedPeer::new(address)))
                .body(Body::from(
                    r#"{"username":"nobody","password":"wrong password"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_login.status(), StatusCode::UNAUTHORIZED);
    let missing_body: Value =
        serde_json::from_slice(&to_bytes(missing_login.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(missing_body["code"], failed_body["code"]);
    assert_eq!(missing_body["title"], failed_body["title"]);
    let client = db.pool.get().await.unwrap();
    let failures: i64 = client
        .query_one(
            "SELECT count(*) FROM audit_log WHERE action = 'auth.login.failed'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(failures, 2);
    let logouts: i64 = client
        .query_one(
            "SELECT count(*) FROM audit_log WHERE action = 'auth.logout.succeeded'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(logouts, 1);
    let throttles: i64 = client
        .query_one(
            "SELECT count(*) FROM console_auth_throttle WHERE failures = 1",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(throttles, 2);
    drop(client);
    db.drop().await;
}
