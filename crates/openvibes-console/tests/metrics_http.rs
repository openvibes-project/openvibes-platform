//! Count history over HTTP: scoping, live today point, input checks.

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
        let name = format!("ov_console_metrics_{:016x}", hasher.finish());
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

const A: &str = "agent.00000000-0000-4000-8000-000000000501";
const B: &str = "agent.00000000-0000-4000-8000-000000000502";
const GROUP_A: &str = "33333333-3333-4333-8333-333333333333";

/// Two hosts, a global viewer (vera) and a viewer bound to group A (sam).
async fn setup() -> (TestDb, axum::Router) {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    let mut sql = format!(
        "INSERT INTO agents (agent_id, status, enrolled_at, hostname, last_seen_at) VALUES
            ('{A}', 'active', now(), 'host-a', now()), ('{B}', 'active', now(), 'host-b', now());
         INSERT INTO console_asset_groups VALUES ('{GROUP_A}', 'A', now(), 'test');
         INSERT INTO console_asset_group_selectors VALUES ('{GROUP_A}', 'env', 'a', now());
         INSERT INTO console_agent_tags VALUES ('{A}', 'env', 'a', now(), 'test');"
    );
    for day in ["2026-10-05", "2026-10-06"] {
        for (agent, critical) in [(A, 1), (B, 5)] {
            sql.push_str(&format!(
                "INSERT INTO host_daily_counts VALUES ('{day}', '{agent}', 'active',
                    0,0,0,0, {critical},0,0,0,0,0, false, 0,0,0,0);"
            ));
        }
    }
    client.batch_execute(&sql).await.unwrap();
    user(
        &mut client,
        "11111111-1111-4111-8111-111111111112",
        "21111111-1111-4111-8111-111111111112",
        "vera",
        "viewer",
    )
    .await;
    user(
        &mut client,
        "11111111-1111-4111-8111-111111111113",
        "21111111-1111-4111-8111-111111111113",
        "sam",
        "viewer",
    )
    .await;
    client
        .execute(
            "UPDATE console_role_bindings SET asset_group_id = $1::text::uuid
             WHERE binding_id = '21111111-1111-4111-8111-111111111113'",
            &[&GROUP_A],
        )
        .await
        .unwrap();
    drop(client);
    let router = authenticated_router(db.pool.clone(), "https://console.example");
    (db, router)
}

async fn get(router: &axum::Router, cookie: &str, uri: &str) -> (StatusCode, Value) {
    let (status, body, _) = call(router, "GET", uri, cookie, "", None, None).await;
    (status, body)
}

#[tokio::test]
async fn history_sums_visible_hosts_and_appends_today() {
    if std::env::var_os("OPENVIBES_TEST_DATABASE_URL").is_none() {
        return;
    }
    let (db, router) = setup().await;
    let uri = "/api/v1/metrics/history?metric=vulns.open.critical&days=365";
    let (vera, _) = login(&router, "vera").await;
    let (status, global) = get(&router, &vera, uri).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        global["points"][0],
        serde_json::json!({"day": "2026-10-05", "value": 6})
    );
    let (sam, _) = login(&router, "sam").await;
    let (_, scoped) = get(&router, &sam, uri).await;
    assert_eq!(scoped["points"][0]["value"], 1);
    let last = global["points"].as_array().unwrap().last().unwrap();
    assert_eq!(last["day"], Utc::now().date_naive().to_string());
    db.drop().await;
}

#[tokio::test]
async fn history_refuses_bad_input_and_anonymous_callers() {
    if std::env::var_os("OPENVIBES_TEST_DATABASE_URL").is_none() {
        return;
    }
    let (db, router) = setup().await;
    let (vera, _) = login(&router, "vera").await;
    let (status, body) = get(
        &router,
        &vera,
        "/api/v1/metrics/history?metric=nope&days=30",
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["field_errors"][0]["code"], "unknown_metric");
    let (status, body) = get(
        &router,
        &vera,
        "/api/v1/metrics/history?metric=alarms.active&days=12",
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["field_errors"][0]["code"], "invalid_days");
    let (status, _) = get(
        &router,
        "",
        "/api/v1/metrics/history?metric=alarms.active&days=7",
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    db.drop().await;
}

#[tokio::test]
async fn a_fresh_install_has_only_todays_point() {
    if std::env::var_os("OPENVIBES_TEST_DATABASE_URL").is_none() {
        return;
    }
    let (db, router) = setup().await;
    let client = db.pool.get().await.unwrap();
    client
        .execute("DELETE FROM host_daily_counts", &[])
        .await
        .unwrap();
    drop(client);
    let (vera, _) = login(&router, "vera").await;
    let (_, body) = get(
        &router,
        &vera,
        "/api/v1/metrics/history?metric=alarms.active&days=7",
    )
    .await;
    assert_eq!(body["points"].as_array().unwrap().len(), 1);
    db.drop().await;
}
