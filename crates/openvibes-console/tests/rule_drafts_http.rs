//! Draft rules for the site's own rule sets over HTTP: permissions, the
//! agent's own checks, versions, audit.

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
        let name = format!("ov_console_drafts_{:016x}", hasher.finish());
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

/// A migrated database with an admin, an operator and a viewer.
async fn setup() -> (TestDb, axum::Router) {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    for (n, name, role) in [
        (1, "alice", "admin"),
        (2, "olga", "operator"),
        (3, "vera", "viewer"),
    ] {
        user(
            &mut client,
            &format!("11111111-1111-4111-8111-11111111111{n}"),
            &format!("21111111-1111-4111-8111-11111111111{n}"),
            name,
            role,
        )
        .await;
    }
    drop(client);
    let router = authenticated_router(db.pool.clone(), "https://console.example");
    (db, router)
}

fn rule(expression: &str) -> Value {
    json!({
        "title": "Redis is exposed",
        "severity": "high",
        "confidence": 90,
        "expression": expression,
        "finding_message": "Redis listens beyond loopback."
    })
}

#[tokio::test]
async fn drafts_are_checked_saved_versioned_listed_and_deleted() {
    if std::env::var_os("OPENVIBES_TEST_DATABASE_URL").is_none() {
        return;
    }
    let (db, router) = setup().await;
    let one = "/api/v1/rule-drafts/site/port.redis.exposed";

    let (cookie, csrf) = login(&router, "vera").await;
    let (status, _, _) = call(
        &router,
        "PUT",
        one,
        &cookie,
        &csrf,
        Some(rule("true")),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a viewer may not write rules"
    );
    let (status, _, _) = call(
        &router,
        "GET",
        "/api/v1/rule-drafts/site",
        &cookie,
        &csrf,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "a viewer may not read rules");

    let (cookie, csrf) = login(&router, "olga").await;
    let good = rule("'6379' in facts['port.tcp.exposed']");
    let (status, saved, _) = call(
        &router,
        "PUT",
        one,
        &cookie,
        &csrf,
        Some(good.clone()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    assert_eq!(
        (saved["version"].as_u64(), saved["rule_set_id"].as_str()),
        (Some(1), Some("site"))
    );

    // Saving the same rule again keeps its version; a change raises it.
    let (_, again, _) = call(
        &router,
        "PUT",
        one,
        &cookie,
        &csrf,
        Some(good.clone()),
        None,
    )
    .await;
    assert_eq!(again["version"], 1);
    let mut changed = good.clone();
    changed["confidence"] = json!(80);
    let (_, changed, _) = call(&router, "PUT", one, &cookie, &csrf, Some(changed), None).await;
    assert_eq!(changed["version"], 2);

    // The agent's own checks refuse a bad expression and name the field.
    let (status, bad, _) = call(
        &router,
        "PUT",
        one,
        &cookie,
        &csrf,
        Some(rule("this is not cel ((")),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(bad["ok"], false);
    assert_eq!(bad["problems"][0]["field"], "expression");
    let (status, check, _) = call(
        &router,
        "POST",
        &format!("{one}/check"),
        &cookie,
        &csrf,
        Some(rule("true")),
        None,
    )
    .await;
    assert_eq!((status, &check["ok"]), (StatusCode::OK, &json!(true)));

    // Alarm rules need a program prefilter; findings rules take none.
    let alarm = "/api/v1/rule-drafts/site-alarms/alarm.nginx.shell";
    let mut event = rule("event['process.name'] == 'sh'");
    let (status, bad, _) = call(
        &router,
        "PUT",
        alarm,
        &cookie,
        &csrf,
        Some(event.clone()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{bad}");
    assert_eq!(bad["problems"][0]["field"], "programs");
    event["programs"] = json!(["nginx"]);
    let (status, saved, _) = call(&router, "PUT", alarm, &cookie, &csrf, Some(event), None).await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    let mut with_programs = rule("true");
    with_programs["programs"] = json!(["sh"]);
    let (status, _, _) = call(
        &router,
        "PUT",
        "/api/v1/rule-drafts/site/r1",
        &cookie,
        &csrf,
        Some(with_programs),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    let (status, _, _) = call(
        &router,
        "PUT",
        "/api/v1/rule-drafts/baseline/r1",
        &cookie,
        &csrf,
        Some(rule("true")),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "only the site's own sets have drafts"
    );

    let (_, list, _) = call(
        &router,
        "GET",
        "/api/v1/rule-drafts/site",
        &cookie,
        &csrf,
        None,
        None,
    )
    .await;
    assert_eq!(list["items"].as_array().unwrap().len(), 1);
    let (status, _, _) = call(&router, "DELETE", one, &cookie, &csrf, None, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, _) = call(&router, "DELETE", one, &cookie, &csrf, None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let client = db.pool.get().await.unwrap();
    let actions: Vec<String> = client
        .query(
            "SELECT action FROM audit_log WHERE action LIKE 'rule_draft.%' ORDER BY id",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(
        actions,
        [
            "rule_draft.saved",
            "rule_draft.saved",
            "rule_draft.saved",
            "rule_draft.saved",
            "rule_draft.deleted"
        ]
    );
    drop(client);
    db.drop().await;
}
