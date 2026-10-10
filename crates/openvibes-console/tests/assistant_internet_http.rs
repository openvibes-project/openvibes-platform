//! The assistant internet setting over HTTP: permission, preconditions, validation, audit.

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
use platform_store::console_auth::{NewLocalUser, create_local_user};
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
        let drop_client = admin.get().await.unwrap();
        // DROP grows with partitions; no statement timeout for it.
        drop_client
            .batch_execute("SET statement_timeout = 0")
            .await
            .unwrap();
        drop_client
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

const PASSWORD: &str = "violet-satellite-mountain-otter-2026";

async fn user(
    client: &mut platform_store::Client,
    id: &str,
    binding: &str,
    name: &str,
    role: &str,
) {
    let phc = hash_password(&NormalizedPassword::new(PASSWORD).unwrap()).unwrap();
    create_local_user(
        client,
        &NewLocalUser {
            user_id: id,
            binding_id: binding,
            username: name,
            display_name: name,
            password_phc: phc.as_str(),
            role_id: role,
            actor_id: "test",
            actor_kind: "local_admin",
            password_must_change: false,
            now: Utc::now(),
        },
    )
    .await
    .unwrap();
}

/// Signs in and returns (session cookie, CSRF token).
async fn login(router: &axum::Router, username: &str) -> (String, String) {
    let (preauth, browser, csrf) = new_preauth(router).await;
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/v1/login")
                .header(header::ORIGIN, "https://console.example")
                .header("sec-fetch-site", "same-origin")
                .header("x-csrf-token", csrf)
                .header(header::COOKIE, format!("{preauth}; {browser}"))
                .header(header::CONTENT_TYPE, "application/json")
                .extension(ConnectInfo(TrustedPeer::new(
                    "127.0.0.1:4242".parse::<SocketAddr>().unwrap(),
                )))
                .body(Body::from(format!(
                    "{{\"username\":\"{username}\",\"password\":\"{PASSWORD}\"}}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = cookie_pair(&response, "__Host-openvibes-session=");
    let session = call(router, "GET", "/api/v1/session", &cookie, "", None, None).await;
    (cookie, session.1["csrf_token"].as_str().unwrap().to_owned())
}

/// One request; returns (status, JSON body or Null, ETag).
async fn call(
    router: &axum::Router,
    method: &str,
    uri: &str,
    cookie: &str,
    csrf: &str,
    body: Option<Value>,
    if_match: Option<&str>,
) -> (StatusCode, Value, Option<String>) {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::COOKIE, cookie)
        .header(header::ORIGIN, "https://console.example")
        .header("sec-fetch-site", "same-origin")
        .header("x-csrf-token", csrf)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(version) = if_match {
        request = request.header(header::IF_MATCH, version);
    }
    let response = router
        .clone()
        .oneshot(
            request
                .body(Body::from(body.map(|b| b.to_string()).unwrap_or_default()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let etag = response
        .headers()
        .get(header::ETAG)
        .map(|v| v.to_str().unwrap().to_owned());
    let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        etag,
    )
}

async fn setup() -> (TestDb, axum::Router) {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    user(
        &mut client,
        "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
        "alice",
        "admin",
    )
    .await;
    user(
        &mut client,
        "33333333-3333-4333-8333-333333333333",
        "44444444-4444-4444-8444-444444444444",
        "bob",
        "analyst",
    )
    .await;
    drop(client);
    let router = authenticated_router(db.pool.clone(), "https://console.example");
    (db, router)
}

#[tokio::test]
async fn assistant_internet_is_admin_only_conditional_and_validated() {
    let (db, router) = setup().await;
    let uri = "/api/v1/assistant-internet";
    let (cookie, csrf) = login(&router, "bob").await;
    let (status, ..) = call(&router, "GET", uri, &cookie, &csrf, None, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (cookie, csrf) = login(&router, "alice").await;
    let (status, body, etag) = call(&router, "GET", uri, &cookie, &csrf, None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(etag.as_deref(), Some("\"1\""));
    assert_eq!(body["level"], 0);
    assert_eq!(body["platform_domain"], "console.example");
    assert_eq!(body["internal_domains"], serde_json::json!([]));

    let put = |body: Value, if_match: Option<&'static str>| {
        let (router, cookie, csrf) = (router.clone(), cookie.clone(), csrf.clone());
        async move { call(&router, "PUT", uri, &cookie, &csrf, Some(body), if_match).await }
    };
    let ok = serde_json::json!({"level": 1, "searxng_url": null, "internal_domains": ["intranet"]});
    let (status, ..) = put(ok.clone(), None).await;
    assert_eq!(status, StatusCode::PRECONDITION_REQUIRED);
    let (status, ..) = put(ok.clone(), Some("\"9\"")).await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    for (url, level) in [
        (serde_json::json!(null), 2),
        (serde_json::json!(""), 2),
        (serde_json::json!("ftp://x"), 2),
        (serde_json::json!("http://search.example.com"), 2),
    ] {
        let bad = serde_json::json!({"level": level, "searxng_url": url, "internal_domains": []});
        let (status, body, _) = put(bad, Some("\"1\"")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{url}");
        assert_eq!(body["code"], "invalid_setting", "{url}");
    }
    let bad = serde_json::json!({"level": 3, "searxng_url": null, "internal_domains": []});
    assert_eq!(put(bad, Some("\"1\"")).await.0, StatusCode::BAD_REQUEST);
    let bad =
        serde_json::json!({"level": 1, "searxng_url": null, "internal_domains": ["Bad Name"]});
    assert_eq!(put(bad, Some("\"1\"")).await.0, StatusCode::BAD_REQUEST);

    let lan = serde_json::json!({"level": 2, "searxng_url": "http://192.168.1.5:8080", "internal_domains": []});
    assert_eq!(put(lan, Some("\"1\"")).await.0, StatusCode::OK);
    let (status, body, etag) = put(ok, Some("\"2\"")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(etag.as_deref(), Some("\"3\""));
    assert_eq!(body["version"], 3);
    assert_eq!(body["level"], 1);
    assert_eq!(body["updated_by"], "11111111-1111-4111-8111-111111111111");
    let rows: i64 = db
        .pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT count(*) FROM audit_log WHERE action = 'assistant.internet.changed'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(rows, 2);
    db.drop().await;
}
