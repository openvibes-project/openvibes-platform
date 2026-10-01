//! Installed software over HTTP (assets v1): routes, paging, filters,
//! errors. Scope and counting rules are tested in platform-store.

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
        let name = format!("ov_console_software_{:016x}", hasher.finish());
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

const AGENT: &str = "agent.00000000-0000-4000-8000-000000000401";

/// A viewer, and one host with openssl (vulnerable), bash and glibc.
async fn setup() -> (TestDb, axum::Router) {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    client
        .batch_execute(&format!(
            "INSERT INTO agents (agent_id, status, enrolled_at, hostname, last_seen_at)
             VALUES ('{AGENT}', 'active', now(), 'web-01', now());
             INSERT INTO package_versions (id, manager, name, epoch, version, release, arch) VALUES
                (1, 'rpm', 'openssl', 1, '3.0.13', '1.fc44', 'x86_64'),
                (2, 'rpm', 'bash', 0, '5.2', '1.fc44', 'x86_64'),
                (3, 'rpm', 'glibc', 0, '2.41', '1.fc44', 'x86_64');
             INSERT INTO host_packages VALUES ('{AGENT}', 1), ('{AGENT}', 2), ('{AGENT}', 3);
             INSERT INTO advisories (advisory_id, source, os_id, os_version, severity, title, url)
             VALUES ('FEDORA-1', 'fedora', 'fedora', '44', 'important', 'openssl', 'https://x');
             INSERT INTO vulnerabilities (agent_id, advisory_id, packages, first_seen_at,
                last_evaluated_at)
             VALUES ('{AGENT}', 'FEDORA-1', '[{{\"name\": \"openssl\"}}]', now(), now());"
        ))
        .await
        .unwrap();
    user(
        &mut client,
        "11111111-1111-4111-8111-111111111112",
        "21111111-1111-4111-8111-111111111112",
        "vera",
        "viewer",
    )
    .await;
    drop(client);
    let router = authenticated_router(db.pool.clone(), "https://console.example");
    (db, router)
}

async fn get(router: &axum::Router, cookie: &str, uri: &str) -> (StatusCode, Value) {
    let (status, body, _) = call(router, "GET", uri, cookie, "", None, None).await;
    (status, body)
}

fn names(page: &Value, list: &str) -> Vec<String> {
    page[list]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["name"].as_str().unwrap_or_default().to_owned())
        .collect()
}

#[tokio::test]
async fn a_hosts_packages_page_by_name_and_flag_vulnerable_ones() {
    if std::env::var_os("OPENVIBES_TEST_DATABASE_URL").is_none() {
        return;
    }
    let (db, router) = setup().await;
    let (cookie, _) = login(&router, "vera").await;
    let base = format!("/api/v1/agents/{AGENT}/packages");
    let (status, page) = get(&router, &cookie, &format!("{base}?limit=2")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(names(&page, "items"), ["bash", "glibc"]);
    let cursor = page["next_cursor"].as_str().unwrap().to_owned();
    let (_, rest) = get(&router, &cookie, &format!("{base}?limit=2&cursor={cursor}")).await;
    assert_eq!(names(&rest, "items"), ["openssl"]);
    assert_eq!(rest["items"][0]["fixable_vulnerable"], true);
    assert_eq!(rest["items"][0]["epoch"], 1);
    assert_eq!(rest["next_cursor"], Value::Null);
    let (_, filtered) = get(&router, &cookie, &format!("{base}?q=SSL")).await;
    assert_eq!(names(&filtered, "items"), ["openssl"]);
    let unknown = "/api/v1/agents/agent.00000000-0000-4000-8000-000000000999/packages";
    assert_eq!(
        get(&router, &cookie, unknown).await.0,
        StatusCode::NOT_FOUND
    );
    db.drop().await;
}

#[tokio::test]
async fn fleet_software_lists_filters_and_details() {
    if std::env::var_os("OPENVIBES_TEST_DATABASE_URL").is_none() {
        return;
    }
    let (db, router) = setup().await;
    let (cookie, _) = login(&router, "vera").await;
    let (status, page) = get(&router, &cookie, "/api/v1/software?limit=2").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(names(&page, "items"), ["bash", "glibc"]);
    assert_eq!(page["items"][0]["hosts"], 1);
    let cursor = page["next_cursor"].as_str().unwrap().to_owned();
    let (_, rest) = get(
        &router,
        &cookie,
        &format!("/api/v1/software?cursor={cursor}"),
    )
    .await;
    assert_eq!(names(&rest, "items"), ["openssl"]);
    let (_, vulnerable) = get(&router, &cookie, "/api/v1/software?fixable=true").await;
    assert_eq!(names(&vulnerable, "items"), ["openssl"]);
    assert_eq!(vulnerable["items"][0]["fixable_vulnerable_hosts"], 1);

    let (status, detail) = get(&router, &cookie, "/api/v1/software/rpm/openssl").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(detail["versions"][0]["version"], "3.0.13");
    assert_eq!(detail["versions"][0]["hosts"], 1);
    assert_eq!(detail["hosts"][0]["hostname"], "web-01");
    assert_eq!(detail["hosts"][0]["version"], "1:3.0.13-1.fc44");
    assert_eq!(detail["hosts"][0]["fixable_vulnerable"], true);
    assert_eq!(
        get(&router, &cookie, "/api/v1/software/rpm/nothing")
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    db.drop().await;
}

#[tokio::test]
async fn bad_queries_are_refused_and_a_session_is_required() {
    if std::env::var_os("OPENVIBES_TEST_DATABASE_URL").is_none() {
        return;
    }
    let (db, router) = setup().await;
    let (cookie, _) = login(&router, "vera").await;
    let long = "x".repeat(129);
    for uri in [
        "/api/v1/software?limit=0".to_owned(),
        "/api/v1/software?limit=101".to_owned(),
        "/api/v1/software?cursor=not-a-cursor".to_owned(),
        format!("/api/v1/software?q={long}"),
        "/api/v1/software?unknown=1".to_owned(),
        format!("/api/v1/agents/{AGENT}/packages?cursor=e30"),
        "/api/v1/software/rpm/openssl?cursor=W10".to_owned(),
    ] {
        assert_eq!(
            get(&router, &cookie, &uri).await.0,
            StatusCode::BAD_REQUEST,
            "{uri}"
        );
    }
    assert_eq!(
        get(&router, "", "/api/v1/software").await.0,
        StatusCode::UNAUTHORIZED
    );
    db.drop().await;
}

#[tokio::test]
async fn ports_and_services_per_host_and_across_hosts() {
    if std::env::var_os("OPENVIBES_TEST_DATABASE_URL").is_none() {
        return;
    }
    let (db, router) = setup().await;
    db.pool
        .get()
        .await
        .unwrap()
        .batch_execute(&format!(
            "UPDATE agents SET services_at = now(), services_owners = 'partial'
                WHERE agent_id = '{AGENT}';
             INSERT INTO host_listeners VALUES
                ('{AGENT}', 'tcp', '0.0.0.0', 443, true, 'nginx.service', 'nginx'),
                ('{AGENT}', 'tcp', '127.0.0.1', 5432, false, NULL, NULL);
             INSERT INTO host_services VALUES
                ('{AGENT}', 'nginx.service', '{{nginx}}', 3, 'root');"
        ))
        .await
        .unwrap();
    let (cookie, _) = login(&router, "vera").await;
    let (status, host) = get(
        &router,
        &cookie,
        &format!("/api/v1/agents/{AGENT}/services"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(host["owners"], "partial");
    assert_eq!(host["listeners"][0]["port"], 443, "exposed first");
    assert_eq!(host["listeners"][0]["address"], "0.0.0.0");
    assert_eq!(host["services"][0]["programs"][0], "nginx");
    let (_, exposed) = get(&router, &cookie, "/api/v1/ports?exposed=true").await;
    assert_eq!(exposed.as_array().unwrap().len(), 1);
    assert_eq!(exposed[0]["services"][0], "nginx.service");
    let (_, all) = get(&router, &cookie, "/api/v1/ports").await;
    assert_eq!(all.as_array().unwrap().len(), 2);
    let (_, units) = get(&router, &cookie, "/api/v1/services").await;
    assert_eq!(units[0]["hosts"], 1);
    let missing = "/api/v1/agents/agent.00000000-0000-4000-8000-0000000004ff/services";
    assert_eq!(
        get(&router, &cookie, missing).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(&router, &cookie, "/api/v1/ports?exposed=maybe").await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        get(&router, "", "/api/v1/ports").await.0,
        StatusCode::UNAUTHORIZED
    );
    db.drop().await;
}
