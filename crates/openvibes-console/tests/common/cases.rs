//! The cases HTTP harness shared by the `cases_http*.rs` tests: a throwaway
//! database with two hosts (web-01 in production, db-01 not), four people,
//! sign-in and one-request helpers.
#![allow(
    unused_imports,
    unused_macros,
    reason = "each test binary uses some of these"
)]

pub use std::{
    hash::{BuildHasher, Hasher},
    net::SocketAddr,
};

pub use axum::http::StatusCode;
pub use axum::{
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{Request, header},
};
pub use chrono::Utc;
pub use openvibes_console::{NormalizedPassword, TrustedPeer, authenticated_router, hash_password};
pub use platform_store::console_auth::{NewLocalUser, create_local_user};
pub use serde_json::{Value, json};
pub use tower::ServiceExt;

pub struct TestDb {
    pub pool: platform_store::Pool,
    pub admin_url: String,
    pub name: String,
}

impl TestDb {
    pub async fn create() -> Self {
        let admin_url = std::env::var("OPENVIBES_TEST_DATABASE_URL")
            .expect("set OPENVIBES_TEST_DATABASE_URL via scripts/test-db.sh");
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u64(std::process::id().into());
        let name = format!("ov_console_cases_{:016x}", hasher.finish());
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

    pub async fn drop(self) {
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

pub fn database_url(url: &str, name: &str) -> String {
    let (head, query) = url
        .split_once('?')
        .map_or((url, None), |(h, q)| (h, Some(q)));
    let head = &head[..head.rfind('/').expect("database URL has a path")];
    match query {
        Some(query) => format!("{head}/{name}?{query}"),
        None => format!("{head}/{name}"),
    }
}

pub fn cookie_pair(response: &axum::response::Response, name: &str) -> String {
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

pub async fn new_preauth(router: &axum::Router) -> (String, String, String) {
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

pub const PASSWORD: &str = "violet-satellite-mountain-otter-2026";

pub async fn user(
    client: &mut platform_store::Client,
    id: &str,
    binding: &str,
    name: &str,
    role: &str,
) {
    super::ensure_role(client, role).await;
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
pub async fn login(router: &axum::Router, username: &str) -> (String, String) {
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
pub async fn call(
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

pub const ALICE: &str = "11111111-1111-4111-8111-111111111111"; // admin
pub const BOB: &str = "33333333-3333-4333-8333-333333333333"; // analyst, production only
pub const VERA: &str = "55555555-5555-4555-8555-555555555555"; // viewer: no cases.read
pub const DAVE: &str = "77777777-7777-4777-8777-777777777777"; // analyst

pub const WEB: &str = "agent.00000000-0000-4000-8000-000000000001"; // production
pub const DB: &str = "agent.00000000-0000-4000-8000-000000000002"; // not
pub const PROD: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

/// A signed-in browser: its cookie and CSRF token.
pub struct Session {
    pub cookie: String,
    pub csrf: String,
}

pub struct Fx {
    pub db: TestDb,
    pub router: axum::Router,
    pub web_alarm: String,
    pub db_alarm: String,
}

impl Fx {
    pub async fn session(&self, username: &str) -> Session {
        let (cookie, csrf) = login(&self.router, username).await;
        Session { cookie, csrf }
    }

    pub async fn send(
        &self,
        who: &Session,
        method: &str,
        uri: &str,
        body: Option<Value>,
        if_match: Option<&str>,
    ) -> (StatusCode, Value, Option<String>) {
        call(
            &self.router,
            method,
            uri,
            &who.cookie,
            &who.csrf,
            body,
            if_match,
        )
        .await
    }

    pub async fn get(&self, who: &Session, uri: &str) -> (StatusCode, Value) {
        let (status, body, _) = self.send(who, "GET", uri, None, None).await;
        (status, body)
    }

    /// Opens a case and returns its detail; the test fails if refused.
    pub async fn open(&self, who: &Session, title: &str, items: Value) -> Value {
        let (status, case, _) = self
            .send(
                who,
                "POST",
                "/api/v1/cases",
                Some(json!({"title": title, "items": items})),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{case}");
        case
    }

    pub async fn sql(&self, statement: &str) {
        let client = self.db.pool.get().await.unwrap();
        client.batch_execute(statement).await.unwrap();
    }

    pub async fn audit(&self) -> Vec<(String, String)> {
        let client = self.db.pool.get().await.unwrap();
        client
            .query(
                "SELECT action, detail::text FROM audit_log WHERE action LIKE 'case.%' ORDER BY id",
                &[],
            )
            .await
            .unwrap()
            .iter()
            .map(|row| (row.get(0), row.get(1)))
            .collect()
    }
}

pub fn case_uri(case: &Value) -> String {
    format!("/api/v1/cases/{}", case["case_id"].as_str().unwrap())
}

pub fn version(case: &Value) -> String {
    format!("\"{}\"", case["version"])
}

pub fn item_of<'a>(case: &'a Value, kind: &str) -> &'a Value {
    case["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["kind"] == kind)
        .unwrap_or_else(|| panic!("no {kind} item in {case}"))
}

/// The PUT body that keeps a case as it is, with `changes` on top.
pub fn put_body(case: &Value, changes: Value) -> Value {
    let mut body = json!({
        "title": case["title"],
        "severity": case["severity"],
        "status": case["status"],
        "assignee_user_id": case["assignee"]["user_id"],
    });
    for (key, value) in changes.as_object().unwrap() {
        body[key] = value.clone();
    }
    body
}

pub fn field_errors(problem: &Value) -> Vec<(String, String)> {
    problem["field_errors"]
        .as_array()
        .map(|errors| {
            errors
                .iter()
                .map(|e| {
                    (
                        e["field"].as_str().unwrap().to_owned(),
                        e["code"].as_str().unwrap().to_owned(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Two hosts (web-01 in production, db-01 not) with an alarm, a finding, a
/// vulnerability and a package each, an admin, a production-only analyst, a
/// global analyst and a viewer.
pub async fn setup() -> Option<Fx> {
    std::env::var_os("OPENVIBES_TEST_DATABASE_URL")?;
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    let now = Utc::now();
    platform_store::ensure_partitions(&client, now.date_naive() - chrono::Duration::days(1), 3)
        .await
        .unwrap();
    client
        .batch_execute(&format!(
            "INSERT INTO agents (agent_id, status, enrolled_at, hostname, last_seen_at) VALUES
                ('{WEB}', 'active', now(), 'web-01', now()),
                ('{DB}', 'active', now(), 'db-01', now());
             INSERT INTO console_asset_groups VALUES ('{PROD}', 'prod', now(), 't');
             INSERT INTO console_host_group_members VALUES ('{PROD}', '{WEB}', now(), 't');
             INSERT INTO current_findings (agent_id, rule_set_id, rule_id, last_finding_id,
                rule_version, severity, first_observed_at, last_observed_at, last_observed_day,
                scan_id, confidence, message, evidence, received_at, origin, authenticated)
             VALUES
                ('{WEB}', 'baseline', 'ssh-root', 'f1', 1, 'high', now(), now(), current_date,
                 'scan.1', 90, 'Root login over SSH', '{{}}', now(), 'online', true),
                ('{DB}', 'baseline', 'ssh-root', 'f2', 1, 'low', now(), now(), current_date,
                 'scan.1', 90, 'Root login over SSH', '{{}}', now(), 'online', true);
             INSERT INTO package_versions (id, manager, name, epoch, version, release, arch) VALUES
                (1, 'rpm', 'openssl', 0, '3.0', '1', 'x86_64'),
                (2, 'rpm', 'bash', 0, '5.2', '1', 'x86_64');
             INSERT INTO host_packages VALUES ('{WEB}', 1), ('{DB}', 2);
             INSERT INTO advisories (advisory_id, source, os_id, os_version, severity, title, url)
             VALUES ('FEDORA-1', 'fedora', 'fedora', '44', 'important', 'openssl update', 'https://x');
             INSERT INTO vulnerabilities (agent_id, advisory_id, packages, first_seen_at,
                fixed_at, last_evaluated_at) VALUES
                ('{WEB}', 'FEDORA-1', '[]', now(), NULL, now()),
                ('{DB}', 'FEDORA-1', '[]', now(), NULL, now());"
        ))
        .await
        .unwrap();
    let mut alarm_ids = Vec::new();
    for (agent, alarm_id) in [(WEB, "alarm.1"), (DB, "alarm.2")] {
        let id: i64 = client
            .query_one(
                "INSERT INTO alarms (first_seen_day, agent_id, alarm_id, rule_set_id,
                    rule_set_version, rule_id, rule_version, severity, confidence, message,
                    first_seen, last_seen, count, process, ancestors, received_at)
                 VALUES ((now() AT TIME ZONE 'UTC')::date, $1, $2, 'baseline', 1, 'shell', 1,
                    'medium', 80, 'A web server started a shell', now(), now(), 1,
                    '{\"exe\": \"/usr/bin/sh\"}', '[]', now())
                 RETURNING id",
                &[&agent, &alarm_id],
            )
            .await
            .unwrap()
            .get(0);
        alarm_ids.push(id.to_string());
    }
    for (id, binding, name, role) in [
        (
            ALICE,
            "22222222-2222-4222-8222-222222222222",
            "alice",
            "admin",
        ),
        (
            BOB,
            "44444444-4444-4444-8444-444444444444",
            "bob",
            "analyst",
        ),
        (
            VERA,
            "66666666-6666-4666-8666-666666666666",
            "vera",
            "viewer",
        ),
        (
            DAVE,
            "88888888-8888-4888-8888-888888888888",
            "dave",
            "analyst",
        ),
    ] {
        user(&mut client, id, binding, name, role).await;
    }
    super::scope_bindings(
        &mut client,
        "binding_id = '44444444-4444-4444-8444-444444444444'",
        PROD,
    )
    .await;
    drop(client);
    let router = authenticated_router(db.pool.clone(), "https://console.example");
    Some(Fx {
        db,
        router,
        web_alarm: alarm_ids[0].clone(),
        db_alarm: alarm_ids[1].clone(),
    })
}

macro_rules! fixture {
    () => {
        match setup().await {
            Some(fx) => fx,
            None => return,
        }
    };
}

pub(crate) use fixture;
