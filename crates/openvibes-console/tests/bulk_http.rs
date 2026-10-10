//! Bulk triage over HTTP (triage v2): permissions, the note rule, cases,
//! vulnerability triage.

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

const WEB: &str = "agent.00000000-0000-4000-8000-000000000301";
const DB: &str = "agent.00000000-0000-4000-8000-000000000302";

/// Two hosts, each with one test alarm and one open vulnerability; an admin
/// and a viewer.
async fn setup() -> (TestDb, axum::Router, Vec<i64>) {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    let now = Utc::now();
    platform_store::ensure_partitions(&client, now.date_naive() - chrono::Duration::days(1), 2)
        .await
        .unwrap();
    client
        .batch_execute(&format!(
            "INSERT INTO agents (agent_id, status, enrolled_at, hostname) VALUES
                ('{WEB}', 'active', now(), 'web-01'), ('{DB}', 'active', now(), 'db-01');
             INSERT INTO alarms (first_seen_day, agent_id, alarm_id, rule_set_id, rule_set_version,
                 rule_id, rule_version, severity, confidence, message, first_seen, last_seen, count,
                 process, ancestors, received_at)
             SELECT (now() AT TIME ZONE 'UTC')::date, g, md5(g), 'baseline', 1, 'r', 1, 'high', 80,
                 'm', now(), now(), 1, '{{\"exe\":\"/usr/bin/sh\"}}', '[]', now()
             FROM unnest(ARRAY['{WEB}', '{DB}']) g;
             INSERT INTO advisories (advisory_id, source, os_id, os_version, severity, title, url)
             VALUES ('FEDORA-1', 'fedora', 'fedora', '44', 'important', 'openssl', 'https://x'),
                    ('FEDORA-2', 'fedora', 'fedora', '44', 'low', 'bash', 'https://x');
             INSERT INTO vulnerabilities (agent_id, advisory_id, packages, first_seen_at,
                fixed_at, last_evaluated_at)
             SELECT g, 'FEDORA-1', '[]', now(), NULL, now() FROM unnest(ARRAY['{WEB}', '{DB}']) g;
             INSERT INTO vulnerabilities (agent_id, advisory_id, packages, first_seen_at,
                fixed_at, last_evaluated_at) VALUES ('{WEB}', 'FEDORA-2', '[]', now(), NULL, now());"
        ))
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
    let ids = client
        .query("SELECT id FROM alarms ORDER BY agent_id", &[])
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    drop(client);
    let router = authenticated_router(db.pool.clone(), "https://console.example");
    (db, router, ids)
}

#[tokio::test]
async fn bulk_triage_needs_the_permission_a_note_to_close_and_fitting_items() {
    let (db, router, ids) = setup().await;
    let items = json!(
        ids.iter()
            .map(|id| json!({"id": id.to_string()}))
            .collect::<Vec<_>>()
    );
    let close = |note: Option<&str>| json!({"action": "state", "state": "mitigated", "note": note, "items": items});
    let (cookie, csrf) = login(&router, "vera").await;
    let (status, _, _) = call(
        &router,
        "POST",
        "/api/v1/alarms/bulk",
        &cookie,
        &csrf,
        Some(close(Some("x"))),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "a viewer cannot triage");
    let (cookie, csrf) = login(&router, "alice").await;
    let (status, body, _) = call(
        &router,
        "POST",
        "/api/v1/alarms/bulk",
        &cookie,
        &csrf,
        Some(close(None)),
        None,
    )
    .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_triage"))
    );
    let (status, body, _) = call(
        &router,
        "POST",
        "/api/v1/alarms/bulk",
        &cookie,
        &csrf,
        Some(close(Some("test alarms"))),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        (
            body["changed"].as_u64(),
            body["skipped"].as_array().map(Vec::len)
        ),
        (Some(2), Some(0))
    );
    // An item that does not fit the list is refused, nothing done.
    let wrong = json!({"action": "state", "state": "open", "items": [{"advisory_id": "FEDORA-1"}]});
    let (status, body, _) = call(
        &router,
        "POST",
        "/api/v1/alarms/bulk",
        &cookie,
        &csrf,
        Some(wrong),
        None,
    )
    .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_items"))
    );
    // Without CSRF.
    let (status, _, _) = call(
        &router,
        "POST",
        "/api/v1/alarms/bulk",
        &cookie,
        "",
        Some(close(Some("x"))),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    db.drop().await;
}

#[tokio::test]
async fn items_go_into_one_open_case_and_vulnerabilities_triage_per_host() {
    let (db, router, ids) = setup().await;
    let (cookie, csrf) = login(&router, "alice").await;
    let items = json!(
        ids.iter()
            .map(|id| json!({"id": id.to_string()}))
            .collect::<Vec<_>>()
    );
    let first = json!({"action": "case", "new_case_title": "2 alarms: test", "new_case_severity": "high", "items": items});
    let (status, body, _) = call(
        &router,
        "POST",
        "/api/v1/alarms/bulk",
        &cookie,
        &csrf,
        Some(first),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["changed"].as_u64(), Some(2));
    assert!(body["case_number"].as_i64().is_some());
    // The lists' case badges: both alarms, under that case's number.
    let (_, active, _) = call(
        &router,
        "GET",
        "/api/v1/cases/active-items?kind=alarm",
        &cookie,
        &csrf,
        None,
        None,
    )
    .await;
    let refs: Vec<&str> = active["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["ref"].as_str().unwrap())
        .collect();
    assert_eq!(refs.len(), 2, "{active}");
    assert!(
        active["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|i| i["case_number"] == body["case_number"])
    );
    let second = json!({"action": "case", "new_case_title": "again", "items": items});
    let (_, body, _) = call(
        &router,
        "POST",
        "/api/v1/alarms/bulk",
        &cookie,
        &csrf,
        Some(second),
        None,
    )
    .await;
    assert_eq!(body["changed"].as_u64(), Some(0));
    assert!(
        body["skipped"]
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s["reason"] == "in another open case")
    );
    // An advisory expands to both hosts.
    let vulns = json!({"action": "state", "state": "false_positive", "note": "not affected", "items": [{"advisory_id": "FEDORA-1"}]});
    let (status, body, _) = call(
        &router,
        "POST",
        "/api/v1/vulnerabilities/bulk",
        &cookie,
        &csrf,
        Some(vulns),
        None,
    )
    .await;
    assert_eq!(
        (status, body["changed"].as_u64()),
        (StatusCode::OK, Some(2)),
        "{body}"
    );
    // One host, version-checked; the list shows the state.
    let one = format!("/api/v1/vulnerabilities/advisories/FEDORA-1/hosts/{WEB}/triage");
    let reopen = json!({"state": "open"});
    // WEB is at version 1 after the bulk change: 0 is stale.
    let (status, _, _) = call(
        &router,
        "PUT",
        &one,
        &cookie,
        &csrf,
        Some(reopen.clone()),
        Some("\"0\""),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::PRECONDITION_FAILED,
        "version 1 is current"
    );
    let (status, saved, etag) = call(
        &router,
        "PUT",
        &one,
        &cookie,
        &csrf,
        Some(reopen),
        Some("\"1\""),
    )
    .await;
    assert_eq!(
        (status, saved["state"].as_str(), etag.as_deref()),
        (StatusCode::OK, Some("open"), Some("\"2\""))
    );
    // A vulnerability never triaged is version 0, and that is accepted.
    let first = format!("/api/v1/vulnerabilities/advisories/FEDORA-2/hosts/{WEB}/triage");
    let accept = json!({"state": "mitigated", "note": "compensating control"});
    let (status, saved, _) = call(
        &router,
        "PUT",
        &first,
        &cookie,
        &csrf,
        Some(accept),
        Some("\"0\""),
    )
    .await;
    assert_eq!(
        (status, saved["version"].as_i64()),
        (StatusCode::OK, Some(1)),
        "{saved}"
    );
    let (_, list, _) = call(
        &router,
        "GET",
        "/api/v1/vulnerabilities?advisory=FEDORA-1",
        &cookie,
        &csrf,
        None,
        None,
    )
    .await;
    let states: Vec<&str> = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["triage_state"].as_str().unwrap())
        .collect();
    assert_eq!(states.len(), 2);
    assert!(
        states.contains(&"open") && states.contains(&"false_positive"),
        "{states:?}"
    );
    db.drop().await;
}
