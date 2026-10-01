//! Threat alarms over HTTP (P14): permissions, scope, triage, audit.

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
use openvibes_core::{Alarm, AlarmProcess, Confidence, Identifier, Severity};
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
        let name = format!("ov_console_alarms_{:016x}", hasher.finish());
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

const AGENT: &str = "agent.00000000-0000-4000-8000-000000000301";

/// A migrated database with an admin, a viewer, and one alarm; its id.
async fn setup() -> (TestDb, axum::Router, i64) {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    let now = Utc::now();
    platform_store::ensure_partitions(&client, now.date_naive() - chrono::Duration::days(1), 2)
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO agents (agent_id, status, enrolled_at, hostname)
             VALUES ($1, 'active', $2, 'web-01')",
            &[&AGENT, &now],
        )
        .await
        .unwrap();
    user(
        &mut client,
        "11111111-1111-4111-8111-111111111111",
        "21111111-1111-4111-8111-111111111111",
        "alice",
        "admin",
    )
    .await;
    user(
        &mut client,
        "11111111-1111-4111-8111-111111111112",
        "21111111-1111-4111-8111-111111111112",
        "vera",
        "viewer",
    )
    .await;
    let process = |exe: &str| AlarmProcess {
        pid: 1,
        exe: exe.into(),
        args: vec!["sh".into(), "-c".into(), "id".into()],
        cwd: None,
        uid: 48,
        euid: 48,
        truncated: false,
        seeded: false,
    };
    let alarm = Alarm {
        alarm_id: Identifier::new(format!("alarm.{:032x}", 1)).unwrap(),
        rule_set_id: Identifier::new("baseline").unwrap(),
        rule_set_version: 1,
        rule_id: Identifier::new("web-server-spawns-shell").unwrap(),
        rule_version: 1,
        severity: Severity::High,
        confidence: Confidence::new(80).unwrap(),
        message: "A web server started a shell".into(),
        first_seen_unix_ms: now.timestamp_millis(),
        last_seen_unix_ms: now.timestamp_millis(),
        count: 1,
        process: process("/usr/bin/sh"),
        ancestors: vec![process("/usr/sbin/nginx")],
    };
    let partitions = platform_store::partition_days_of(&client, "alarms")
        .await
        .unwrap();
    let row = platform_store::alarms::row(
        &alarm,
        now - chrono::Duration::days(1),
        now + chrono::Duration::minutes(5),
        &partitions,
    )
    .unwrap();
    platform_store::alarms::insert_batch(&mut client, AGENT, 0, &[row], now)
        .await
        .unwrap();
    let id: i64 = client
        .query_one("SELECT id FROM alarms", &[])
        .await
        .unwrap()
        .get(0);
    drop(client);
    let router = authenticated_router(db.pool.clone(), "https://console.example");
    (db, router, id)
}

#[tokio::test]
async fn alarms_are_listed_shown_and_triaged_with_permissions_and_audit() {
    if std::env::var_os("OPENVIBES_TEST_DATABASE_URL").is_none() {
        return;
    }
    let (db, router, id) = setup().await;
    let (cookie, csrf) = login(&router, "vera").await;
    let (status, page, _) =
        call(&router, "GET", "/api/v1/alarms", &cookie, &csrf, None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page["items"][0]["id"], id.to_string());
    assert_eq!(page["items"][0]["parent_exe"], "/usr/sbin/nginx");
    assert_eq!(page["next_cursor"], Value::Null);
    let uri = format!("/api/v1/alarms/{id}");
    let (status, alarm, etag) = call(&router, "GET", &uri, &cookie, &csrf, None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(alarm["process"]["args"], json!(["sh", "-c", "id"]));
    assert_eq!(alarm["triage"]["state"], "open");
    assert_eq!(etag.as_deref(), Some("\"1\""));
    let triage = format!("/api/v1/alarms/{id}/triage");
    let body = json!({"state": "investigating"});
    // A viewer may read but not triage.
    let (status, _, _) = call(
        &router,
        "PUT",
        &triage,
        &cookie,
        &csrf,
        Some(body.clone()),
        Some("\"1\""),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (cookie, csrf) = login(&router, "alice").await;
    let (status, _, _) = call(
        &router,
        "PUT",
        &triage,
        &cookie,
        &csrf,
        Some(body.clone()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_REQUIRED);
    let (status, saved, etag) = call(
        &router,
        "PUT",
        &triage,
        &cookie,
        &csrf,
        Some(body.clone()),
        Some("\"1\""),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    assert_eq!(
        (saved["state"].as_str(), etag.as_deref()),
        (Some("investigating"), Some("\"2\""))
    );
    let (status, _, _) = call(
        &router,
        "PUT",
        &triage,
        &cookie,
        &csrf,
        Some(body),
        Some("\"1\""),
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    let (status, _, _) = call(
        &router,
        "PUT",
        &triage,
        &cookie,
        &csrf,
        Some(json!({"state": "false_positive"})),
        Some("\"2\""),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a completed state needs a note"
    );
    for missing in ["/api/v1/alarms/999999", "/api/v1/alarms/not-a-number"] {
        let (status, _, _) = call(&router, "GET", missing, &cookie, &csrf, None, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{missing}");
    }
    let audited: i64 = db
        .pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT count(*) FROM audit_log WHERE action = 'alarm.triage.changed'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(audited, 1);
    db.drop().await;
}

#[tokio::test]
async fn suppressions_are_created_from_an_alarm_listed_and_removed() {
    if std::env::var_os("OPENVIBES_TEST_DATABASE_URL").is_none() {
        return;
    }
    let (db, router, id) = setup().await;
    let (cookie, csrf) = login(&router, "vera").await;
    let body =
        json!({"alarm_id": id.to_string(), "scope": "program", "note": "nginx health check"});
    let (status, _, _) = call(
        &router,
        "POST",
        "/api/v1/alarm-suppressions",
        &cookie,
        &csrf,
        Some(body.clone()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "a viewer may not suppress");

    let (cookie, csrf) = login(&router, "alice").await;
    let (status, created, _) = call(
        &router,
        "POST",
        "/api/v1/alarm-suppressions",
        &cookie,
        &csrf,
        Some(body),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["exe"], "/usr/bin/sh");
    assert_eq!(created["agent_id"], Value::Null);
    let (status, _, _) = call(
        &router,
        "POST",
        "/api/v1/alarm-suppressions",
        &cookie,
        &csrf,
        Some(json!({"alarm_id": id.to_string(), "scope": "anywhere", "note": "x"})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, list, _) = call(
        &router,
        "GET",
        "/api/v1/alarm-suppressions",
        &cookie,
        &csrf,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list["items"].as_array().unwrap().len(), 1);
    let one = format!(
        "/api/v1/alarm-suppressions/{}",
        created["id"].as_str().unwrap()
    );
    let (status, _, _) = call(&router, "DELETE", &one, &cookie, &csrf, None, None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, _) = call(&router, "DELETE", &one, &cookie, &csrf, None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    db.drop().await;
}
