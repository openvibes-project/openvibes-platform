//! Dashboards over HTTP: auth, ownership, sharing, versions, validation, audit.

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
use serde_json::{Value, json};
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

fn layout() -> Value {
    json!({"schema": 1, "widgets": [{"id": "w1", "type": "number", "x": 0, "y": 0, "w": 3, "h": 2, "config": {"metric": "agents.active"}}]})
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
async fn owner_lifecycle_with_etags_and_preconditions() {
    let (db, router) = setup().await;
    assert_eq!(
        call(&router, "GET", "/api/v1/dashboards", "", "", None, None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let (cookie, csrf) = login(&router, "alice").await;
    let (status, created, etag) = call(
        &router,
        "POST",
        "/api/v1/dashboards",
        &cookie,
        &csrf,
        Some(json!({"name": " Morning ", "layout": layout()})),
        None,
    )
    .await;
    assert_eq!(
        (status, created["name"].as_str(), etag.as_deref()),
        (StatusCode::CREATED, Some("Morning"), Some("\"1\""))
    );
    let uri = format!(
        "/api/v1/dashboards/{}",
        created["dashboard_id"].as_str().unwrap()
    );
    let (_, page, _) = call(
        &router,
        "GET",
        "/api/v1/dashboards",
        &cookie,
        "",
        None,
        None,
    )
    .await;
    assert_eq!(page["items"][0]["mine"], true);
    let body = json!({"name": "Morning check", "layout": layout()});
    assert_eq!(
        call(
            &router,
            "PUT",
            &uri,
            &cookie,
            &csrf,
            Some(body.clone()),
            None
        )
        .await
        .0,
        StatusCode::PRECONDITION_REQUIRED
    );
    let (status, updated, etag) = call(
        &router,
        "PUT",
        &uri,
        &cookie,
        &csrf,
        Some(body.clone()),
        Some("\"1\""),
    )
    .await;
    assert_eq!(
        (status, updated["version"].as_u64(), etag.as_deref()),
        (StatusCode::OK, Some(2), Some("\"2\""))
    );
    assert_eq!(
        call(
            &router,
            "PUT",
            &uri,
            &cookie,
            &csrf,
            Some(body),
            Some("\"1\"")
        )
        .await
        .0,
        StatusCode::PRECONDITION_FAILED
    );
    assert_eq!(
        call(&router, "DELETE", &uri, &cookie, &csrf, None, None)
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(&router, "GET", &uri, &cookie, "", None, None).await.0,
        StatusCode::NOT_FOUND
    );
    db.drop().await;
}

#[tokio::test]
async fn malformed_id_is_not_found() {
    let (db, router) = setup().await;
    let (cookie, _) = login(&router, "alice").await;
    assert_eq!(
        call(
            &router,
            "GET",
            "/api/v1/dashboards/not-a-uuid",
            &cookie,
            "",
            None,
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    db.drop().await;
}

#[tokio::test]
async fn invalid_layouts_are_refused_with_field_errors() {
    let (db, router) = setup().await;
    let (cookie, csrf) = login(&router, "alice").await;
    let bad = json!({"name": "X", "layout": {"schema": 1, "widgets": [{"id": "w1", "type": "pie-chart", "x": 0, "y": 0, "w": 3, "h": 2, "config": {}}]}});
    let (status, problem, _) = call(
        &router,
        "POST",
        "/api/v1/dashboards",
        &cookie,
        &csrf,
        Some(bad),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        problem["field_errors"][0]["field"],
        "layout.widgets[0].type"
    );
    assert_eq!(
        call(
            &router,
            "POST",
            "/api/v1/dashboards",
            &cookie,
            &csrf,
            Some(json!({"name": "", "layout": layout()})),
            None
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        call(
            &router,
            "POST",
            "/api/v1/dashboards",
            &cookie,
            &csrf,
            Some(json!({"name": "X", "layout": [1]})),
            None
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        call(
            &router,
            "POST",
            "/api/v1/dashboards",
            &cookie,
            &csrf,
            Some(json!({"name": "X"})),
            None
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    db.drop().await;
}

#[tokio::test]
async fn sharing_needs_the_permission_and_shows_read_only_to_the_role() {
    let (db, router) = setup().await;
    let (alice, alice_csrf) = login(&router, "alice").await;
    let (bob, bob_csrf) = login(&router, "bob").await;
    let (_, own, _) = call(
        &router,
        "POST",
        "/api/v1/dashboards",
        &bob,
        &bob_csrf,
        Some(json!({"name": "Bob's", "layout": layout()})),
        None,
    )
    .await;
    let bob_uri = format!(
        "/api/v1/dashboards/{}/sharing",
        own["dashboard_id"].as_str().unwrap()
    );
    assert_eq!(
        call(
            &router,
            "PUT",
            &bob_uri,
            &bob,
            &bob_csrf,
            Some(json!({"role_id": "viewer"})),
            None
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let (_, team, _) = call(
        &router,
        "POST",
        "/api/v1/dashboards",
        &alice,
        &alice_csrf,
        Some(json!({"name": "Team", "layout": layout()})),
        None,
    )
    .await;
    let id = team["dashboard_id"].as_str().unwrap().to_owned();
    let uri = format!("/api/v1/dashboards/{id}");
    assert_eq!(
        call(&router, "GET", &uri, &bob, "", None, None).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(
            &router,
            "PUT",
            &format!("{uri}/sharing"),
            &alice,
            &alice_csrf,
            Some(json!({"role_id": "no_such"})),
            None
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let (status, shared, _) = call(
        &router,
        "PUT",
        &format!("{uri}/sharing"),
        &alice,
        &alice_csrf,
        Some(json!({"role_id": "analyst"})),
        None,
    )
    .await;
    assert_eq!(
        (status, shared["shared_role_id"].as_str()),
        (StatusCode::OK, Some("analyst"))
    );
    let (_, seen, _) = call(&router, "GET", &uri, &bob, "", None, None).await;
    assert_eq!(
        (seen["mine"].as_bool(), seen["owner_display_name"].as_str()),
        (Some(false), Some("alice"))
    );
    assert_eq!(
        call(
            &router,
            "PUT",
            &uri,
            &bob,
            &bob_csrf,
            Some(json!({"name": "x", "layout": layout()})),
            Some("\"2\"")
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            &router,
            "PUT",
            "/api/v1/me/home",
            &bob,
            &bob_csrf,
            Some(json!({"dashboard_id": id})),
            None
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        call(&router, "GET", "/api/v1/me/home", &bob, "", None, None)
            .await
            .1["dashboard_id"],
        id.as_str()
    );
    call(
        &router,
        "PUT",
        &format!("{uri}/sharing"),
        &alice,
        &alice_csrf,
        Some(json!({"role_id": null})),
        None,
    )
    .await;
    assert_eq!(
        call(&router, "GET", &uri, &bob, "", None, None).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(&router, "GET", "/api/v1/me/home", &bob, "", None, None)
            .await
            .1["dashboard_id"],
        Value::Null
    );
    db.drop().await;
}

#[tokio::test]
async fn bearer_tokens_are_refused_and_changes_are_audited() {
    let (db, router) = setup().await;
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/dashboards")
                .header(header::AUTHORIZATION, "Bearer ovst_anything")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let (cookie, csrf) = login(&router, "alice").await;
    call(
        &router,
        "POST",
        "/api/v1/dashboards",
        &cookie,
        &csrf,
        Some(json!({"name": "A", "layout": layout()})),
        None,
    )
    .await;
    let client = db.pool.get().await.unwrap();
    let count: i64 = client
        .query_one(
            "SELECT count(*) FROM audit_log WHERE action = 'dashboard.create'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1);
    drop(client);
    db.drop().await;
}
