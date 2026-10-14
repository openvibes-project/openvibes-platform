//! Rule-set assignment over HTTP: permissions, switches, audit, host view.

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

const WEB: &str = "55555555-5555-4555-8555-555555555555";
const AGENT: &str = "agent.00000000-0000-4000-8000-000000000001";
const ALICE: &str = "11111111-1111-4111-8111-111111111111";
const LIST: &str = "/api/v1/rule-set-assignments";
const L1: &str = "/api/v1/rule-set-assignments/hardening-linux-l1";

async fn setup() -> (TestDb, axum::Router) {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    user(
        &mut client,
        ALICE,
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
    user(
        &mut client,
        "77777777-7777-4777-8777-777777777777",
        "88888888-8888-4888-8888-888888888888",
        "carol",
        "operator",
    )
    .await;
    client
        .batch_execute(&format!(
            "INSERT INTO agents (agent_id, status, enrolled_at) VALUES ('{AGENT}', 'active', now());
             INSERT INTO console_agent_tags VALUES ('{AGENT}', 'env', 'web', now(), 'test');
             INSERT INTO console_asset_groups VALUES ('{WEB}', 'web', now(), 'test');
             INSERT INTO console_asset_group_selectors VALUES ('{WEB}', 'env', 'web', now());"
        ))
        .await
        .unwrap();
    drop(client);
    let router = authenticated_router(db.pool.clone(), "https://console.example");
    (db, router)
}

#[tokio::test]
async fn rule_readers_and_publishers_see_the_switches_and_only_publishers_change_them() {
    let (db, router) = setup().await;
    let off = serde_json::json!({"default_enabled": false});
    // An analyst holds neither rules.read nor rules.upload.
    let (cookie, csrf) = login(&router, "bob").await;
    let (status, ..) = call(&router, "GET", LIST, &cookie, &csrf, None, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, ..) = call(&router, "PUT", L1, &cookie, &csrf, Some(off.clone()), None).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an analyst has no rules.upload"
    );

    // An operator reads through rules.upload, so it can add overrides.
    let (cookie, csrf) = login(&router, "carol").await;
    let (status, body, _) = call(&router, "GET", LIST, &cookie, &csrf, None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        serde_json::json!({
            "items": [
                {"rule_set_id": "hardening-linux-l1", "default_enabled": true, "published": false, "groups": []},
                {"rule_set_id": "hardening-linux-l2", "default_enabled": false, "published": false, "groups": []}
            ],
            "asset_groups": [{"asset_group_id": WEB, "name": "web"}]
        })
    );

    let (cookie, csrf) = login(&router, "alice").await;
    let (status, ..) = call(&router, "GET", LIST, &cookie, &csrf, None, None).await;
    assert_eq!(status, StatusCode::OK, "an admin holds rules.read");
    let (status, ..) = call(
        &router,
        "PUT",
        L1,
        &cookie,
        "wrong",
        Some(off.clone()),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a write needs the CSRF token"
    );
    let (status, body, _) = call(&router, "PUT", L1, &cookie, &csrf, Some(off), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["default_enabled"], false);
    let bad = serde_json::json!({"default_enabled": "no"});
    let (status, body, _) = call(&router, "PUT", L1, &cookie, &csrf, Some(bad), None).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_request"))
    );
    let (status, body, _) = call(
        &router,
        "PUT",
        "/api/v1/rule-set-assignments/baseline",
        &cookie,
        &csrf,
        Some(serde_json::json!({"default_enabled": false})),
        None,
    )
    .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("rule_set_not_assignable"))
    );
    let audited = db
        .pool
        .get()
        .await
        .unwrap()
        .query(
            "SELECT actor, actor_id, actor_display FROM audit_log
                WHERE action = 'rules.assignment.change'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(audited.len(), 1);
    assert_eq!(
        (
            audited[0].get::<_, &str>(0),
            audited[0].get::<_, &str>(1),
            audited[0].get::<_, &str>(2)
        ),
        (ALICE, ALICE, "alice")
    );
    db.drop().await;
}

#[tokio::test]
async fn group_overrides_and_the_host_view() {
    let (db, router) = setup().await;
    let (cookie, csrf) = login(&router, "alice").await;
    let group = format!("{L1}/groups/{WEB}");
    let host = format!("/api/v1/agents/{AGENT}/rule-set-assignments");
    let (_, body, _) = call(&router, "GET", &host, &cookie, &csrf, None, None).await;
    assert_eq!(
        body["items"][0],
        serde_json::json!(
        {"rule_set_id": "hardening-linux-l1", "enabled": true, "source": "default"})
    );
    let (status, body, _) = call(
        &router,
        "PUT",
        &group,
        &cookie,
        &csrf,
        Some(serde_json::json!({"enabled": false})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["groups"],
        serde_json::json!([{"asset_group_id": WEB, "name": "web", "enabled": false}])
    );
    let (_, body, _) = call(&router, "GET", &host, &cookie, &csrf, None, None).await;
    assert_eq!(
        body["items"][0],
        serde_json::json!(
        {"rule_set_id": "hardening-linux-l1", "enabled": false, "source": "group"})
    );
    for _ in 0..2 {
        let (status, body, _) = call(&router, "DELETE", &group, &cookie, &csrf, None, None).await;
        assert_eq!(
            (status, body["groups"].clone()),
            (StatusCode::OK, serde_json::json!([]))
        );
    }
    let unknown = format!("{L1}/groups/66666666-6666-4666-8666-666666666666");
    let (status, body, _) = call(
        &router,
        "PUT",
        &unknown,
        &cookie,
        &csrf,
        Some(serde_json::json!({"enabled": true})),
        None,
    )
    .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("asset_group_not_found"))
    );
    let (status, body, _) = call(
        &router,
        "GET",
        "/api/v1/agents/agent.00000000-0000-4000-8000-000000000099/rule-set-assignments",
        &cookie,
        &csrf,
        None,
        None,
    )
    .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("agent_not_found"))
    );
    db.drop().await;
}

#[tokio::test]
async fn the_host_view_stays_within_the_callers_asset_groups() {
    let (db, router) = setup().await;
    let outside = "agent.00000000-0000-4000-8000-000000000002";
    db.pool
        .get()
        .await
        .unwrap()
        .batch_execute(&format!(
            "INSERT INTO agents (agent_id, status, enrolled_at) VALUES ('{outside}', 'active', now());
             UPDATE console_role_bindings SET asset_group_id = '{WEB}'
              WHERE user_id = '33333333-3333-4333-8333-333333333333';"
        ))
        .await
        .unwrap();
    // bob (analyst) holds agents.read for the web group only.
    let (cookie, csrf) = login(&router, "bob").await;
    let inside = format!("/api/v1/agents/{AGENT}/rule-set-assignments");
    let (status, ..) = call(&router, "GET", &inside, &cookie, &csrf, None, None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, body, _) = call(
        &router,
        "GET",
        &format!("/api/v1/agents/{outside}/rule-set-assignments"),
        &cookie,
        &csrf,
        None,
        None,
    )
    .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("agent_not_found"))
    );
    db.drop().await;
}
