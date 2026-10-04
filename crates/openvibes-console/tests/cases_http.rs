//! Cases over HTTP: permissions, CSRF, bearer tokens, scope, versions,
//! exclusive items, closing rules, validation and audit.

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

const ALICE: &str = "11111111-1111-4111-8111-111111111111"; // admin
const BOB: &str = "33333333-3333-4333-8333-333333333333"; // analyst, production only
const VERA: &str = "55555555-5555-4555-8555-555555555555"; // viewer: no cases.read
const DAVE: &str = "77777777-7777-4777-8777-777777777777"; // analyst

const WEB: &str = "agent.00000000-0000-4000-8000-000000000001"; // production
const DB: &str = "agent.00000000-0000-4000-8000-000000000002"; // not
const PROD: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

/// A signed-in browser: its cookie and CSRF token.
struct Session {
    cookie: String,
    csrf: String,
}

struct Fx {
    db: TestDb,
    router: axum::Router,
    web_alarm: String,
    db_alarm: String,
}

impl Fx {
    async fn session(&self, username: &str) -> Session {
        let (cookie, csrf) = login(&self.router, username).await;
        Session { cookie, csrf }
    }

    async fn send(
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

    async fn get(&self, who: &Session, uri: &str) -> (StatusCode, Value) {
        let (status, body, _) = self.send(who, "GET", uri, None, None).await;
        (status, body)
    }

    /// Opens a case and returns its detail; the test fails if refused.
    async fn open(&self, who: &Session, title: &str, items: Value) -> Value {
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

    async fn sql(&self, statement: &str) {
        let client = self.db.pool.get().await.unwrap();
        client.batch_execute(statement).await.unwrap();
    }

    async fn audit(&self) -> Vec<(String, String)> {
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

fn case_uri(case: &Value) -> String {
    format!("/api/v1/cases/{}", case["case_id"].as_str().unwrap())
}

fn version(case: &Value) -> String {
    format!("\"{}\"", case["version"])
}

fn item_of<'a>(case: &'a Value, kind: &str) -> &'a Value {
    case["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["kind"] == kind)
        .unwrap_or_else(|| panic!("no {kind} item in {case}"))
}

/// The PUT body that keeps a case as it is, with `changes` on top.
fn put_body(case: &Value, changes: Value) -> Value {
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

fn field_errors(problem: &Value) -> Vec<(String, String)> {
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
async fn setup() -> Option<Fx> {
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
             INSERT INTO console_agent_tags VALUES
                ('{WEB}', 'env', 'prod', now(), 't'), ('{DB}', 'env', 'dev', now(), 't');
             INSERT INTO console_asset_groups VALUES ('{PROD}', 'prod', now(), 't');
             INSERT INTO console_asset_group_selectors VALUES ('{PROD}', 'env', 'prod', now());
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
    client
        .batch_execute(&format!(
            "UPDATE console_role_bindings SET asset_group_id = '{PROD}'
             WHERE binding_id = '44444444-4444-4444-8444-444444444444'"
        ))
        .await
        .unwrap();
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

#[tokio::test]
async fn every_route_needs_a_session() {
    let fx = fixture!();
    let case = "00000000-0000-4000-8000-000000000000";
    let item = "00000000-0000-4000-8000-000000000001";
    for (method, uri) in [
        ("GET", "/api/v1/cases".to_owned()),
        ("POST", "/api/v1/cases".to_owned()),
        ("GET", "/api/v1/cases/for-item?kind=host&ref=x".to_owned()),
        ("GET", "/api/v1/cases/assignees".to_owned()),
        ("GET", format!("/api/v1/cases/{case}")),
        ("PUT", format!("/api/v1/cases/{case}")),
        ("POST", format!("/api/v1/cases/{case}/notes")),
        ("POST", format!("/api/v1/cases/{case}/items")),
        ("DELETE", format!("/api/v1/cases/{case}/items/{item}")),
        ("PUT", format!("/api/v1/cases/{case}/items/{item}/outcome")),
    ] {
        let (status, body, _) = call(
            &fx.router,
            method,
            &uri,
            "",
            "",
            Some(json!({})),
            Some("\"1\""),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {uri}: {body}");
        assert_eq!(body["code"], "authentication_required");
    }
    fx.db.drop().await;
}

#[tokio::test]
async fn without_cases_read_or_manage_every_route_is_forbidden() {
    let fx = fixture!();
    let vera = fx.session("vera").await;
    let alice = fx.session("alice").await;
    let created = fx
        .open(&alice, "Visible", json!([{"kind": "host", "ref": WEB}]))
        .await;
    let case = created["case_id"].as_str().unwrap();
    let item = created["items"][0]["item_id"].as_str().unwrap();
    for (method, uri, body) in [
        ("GET", "/api/v1/cases".to_owned(), None),
        (
            "GET",
            "/api/v1/cases/for-item?kind=host&ref=x".to_owned(),
            None,
        ),
        ("GET", "/api/v1/cases/assignees".to_owned(), None),
        ("GET", format!("/api/v1/cases/{case}"), None),
        (
            "POST",
            "/api/v1/cases".to_owned(),
            Some(json!({"title": "No"})),
        ),
        (
            "PUT",
            format!("/api/v1/cases/{case}"),
            Some(put_body(&created, json!({}))),
        ),
        (
            "POST",
            format!("/api/v1/cases/{case}/notes"),
            Some(json!({"body": "x"})),
        ),
        (
            "POST",
            format!("/api/v1/cases/{case}/items"),
            Some(json!({"kind": "host", "ref": DB})),
        ),
        ("DELETE", format!("/api/v1/cases/{case}/items/{item}"), None),
        (
            "PUT",
            format!("/api/v1/cases/{case}/items/{item}/outcome"),
            Some(json!({"outcome": null})),
        ),
    ] {
        let (status, problem, _) = fx.send(&vera, method, &uri, body, Some("\"1\"")).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri}: {problem}");
        assert_eq!(problem["code"], "permission_denied");
    }
    // Nothing was created, changed or audited by the refused requests.
    let (_, page) = fx.get(&alice, "/api/v1/cases?status=all").await;
    assert_eq!(page["items"].as_array().unwrap().len(), 1);
    assert_eq!(page["items"][0]["item_count"], 1);
    assert_eq!(fx.audit().await.len(), 2, "create and item add only");
    fx.db.drop().await;
}

#[tokio::test]
async fn bearer_tokens_are_refused_even_for_reads() {
    use sha2::{Digest, Sha256};
    let fx = fixture!();
    // A valid service token with an admin role (it would be allowed
    // everything else) and one nobody issued.
    let secret = "ovst_0123456789abcdef0123456789abcdef0123456789a";
    let digest = Sha256::digest(secret.as_bytes());
    let mut client = fx.db.pool.get().await.unwrap();
    let account = platform_store::console_auth::create_service_account(
        &mut client,
        "ci",
        "admin",
        ALICE,
        Utc::now(),
    )
    .await
    .unwrap()
    .unwrap();
    client
        .execute(
            "INSERT INTO console_service_tokens (token_id, service_account_id, token_sha256, label,
                created_at, expires_at, created_by)
             VALUES (gen_random_uuid(), $1::text::uuid, $2, 'test', now(), now() + interval '1 day', 'test')",
            &[&account, &digest.as_slice()],
        )
        .await
        .unwrap();
    drop(client);
    for (token, expected) in [
        (secret, StatusCode::FORBIDDEN),
        ("ovst_anything", StatusCode::UNAUTHORIZED),
    ] {
        for (method, uri) in [
            ("GET", "/api/v1/cases"),
            ("GET", "/api/v1/cases/assignees"),
            ("GET", "/api/v1/cases/for-item?kind=host&ref=x"),
            ("GET", "/api/v1/cases/00000000-0000-4000-8000-000000000000"),
            ("POST", "/api/v1/cases"),
            ("PUT", "/api/v1/cases/00000000-0000-4000-8000-000000000000"),
            (
                "POST",
                "/api/v1/cases/00000000-0000-4000-8000-000000000000/notes",
            ),
        ] {
            let response = fx
                .router
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(uri)
                        .header(header::AUTHORIZATION, format!("Bearer {token}"))
                        .header(header::IF_MATCH, "\"1\"")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from("{\"title\":\"x\"}"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected, "{method} {uri} with {token}");
        }
    }
    let count: i64 = fx
        .db
        .pool
        .get()
        .await
        .unwrap()
        .query_one("SELECT count(*) FROM cases", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
    fx.db.drop().await;
}

#[tokio::test]
async fn changes_need_the_csrf_token_and_the_console_origin() {
    let fx = fixture!();
    let alice = fx.session("alice").await;
    let created = fx.open(&alice, "CSRF", json!([])).await;
    let uri = case_uri(&created);
    let body = put_body(&created, json!({"title": "Hijacked"}));
    for (csrf, origin, fetch_site) in [
        ("", "https://console.example", "same-origin"),
        ("wrong", "https://console.example", "same-origin"),
        (alice.csrf.as_str(), "https://evil.example", "same-origin"),
        (alice.csrf.as_str(), "https://console.example", "cross-site"),
    ] {
        let response = fx
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(&uri)
                    .header(header::COOKIE, &alice.cookie)
                    .header(header::ORIGIN, origin)
                    .header("sec-fetch-site", fetch_site)
                    .header("x-csrf-token", csrf)
                    .header(header::IF_MATCH, version(&created))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "{csrf:?} {origin} {fetch_site}"
        );
    }
    let (_, unchanged) = fx.get(&alice, &uri).await;
    assert_eq!(unchanged["title"], "CSRF");
    fx.db.drop().await;
}

#[tokio::test]
async fn a_case_is_opened_read_changed_noted_and_closed_with_versions_and_audit() {
    let fx = fixture!();
    let alice = fx.session("alice").await;
    let finding = format!("{WEB}/baseline/ssh-root");
    let (status, created, etag) = fx
        .send(
            &alice,
            "POST",
            "/api/v1/cases",
            Some(json!({
                "title": "  SSH on web-01  ",
                "assignee_user_id": DAVE.to_uppercase(),
                "items": [
                    {"kind": "host", "ref": WEB},
                    {"kind": "finding", "ref": finding},
                    {"kind": "alarm", "ref": fx.web_alarm},
                ]
            })),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(etag.as_deref(), Some("\"1\""));
    assert_eq!(created["title"], "SSH on web-01");
    assert_eq!(created["status"], "open");
    assert_eq!(created["severity"], "high", "highest item severity");
    assert_eq!(created["assignee"]["username"], "dave");
    assert_eq!(created["opened_by"]["username"], "alice");
    assert_eq!(
        (
            created["item_count"].clone(),
            created["pending_item_count"].clone()
        ),
        (json!(3), json!(2))
    );
    assert!(created["number"].as_i64().unwrap() > 0);
    assert_eq!(created["resolution"], Value::Null);
    let host = item_of(&created, "host");
    assert_eq!(host["ref"], WEB);
    assert_eq!(host["hostname"], "web-01");
    assert_eq!(host["title"], "web-01");
    assert_eq!(host["active"], true);
    let finding_item = item_of(&created, "finding");
    assert_eq!(finding_item["title"], "Root login over SSH");
    assert_eq!(finding_item["evidence_gone"], false);
    assert_eq!(created["events"][0]["kind"], "created");
    assert_eq!(created["events"][0]["actor"]["username"], "alice");
    let uri = case_uri(&created);

    // Read it back, as another analyst.
    let dave = fx.session("dave").await;
    let (status, read, etag) = fx.send(&dave, "GET", &uri, None, None).await;
    assert_eq!((status, etag.as_deref()), (StatusCode::OK, Some("\"1\"")));
    assert_eq!(read["case_id"], created["case_id"]);
    let (_, page) = fx.get(&dave, "/api/v1/cases?assignee=me").await;
    assert_eq!(page["items"][0]["case_id"], created["case_id"]);
    assert_eq!(
        page["items"][0].get("items"),
        None,
        "the list has counts, not items"
    );

    // A note goes on the timeline; the case moves on.
    let secret = "the admin password is hunter2";
    let (status, note, _) = fx
        .send(
            &dave,
            "POST",
            &format!("{uri}/notes"),
            Some(json!({"body": secret})),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{note}");
    assert_eq!(
        (note["kind"].clone(), note["body"].clone()),
        (json!("note"), json!(secret))
    );
    assert_eq!(note["actor"]["username"], "dave");

    // Changing it needs the version.
    let body = put_body(
        &read,
        json!({"status": "investigating", "title": "SSH root login"}),
    );
    let (status, problem, _) = fx.send(&dave, "PUT", &uri, Some(body.clone()), None).await;
    assert_eq!(
        (status, problem["code"].clone()),
        (
            StatusCode::PRECONDITION_REQUIRED,
            json!("precondition_required")
        )
    );
    let (status, problem, _) = fx
        .send(&dave, "PUT", &uri, Some(body.clone()), Some("1"))
        .await;
    assert_eq!(
        (status, problem["code"].clone()),
        (StatusCode::BAD_REQUEST, json!("invalid_precondition"))
    );
    let (status, saved, etag) = fx
        .send(&dave, "PUT", &uri, Some(body.clone()), Some("\"1\""))
        .await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    assert_eq!(
        (saved["status"].clone(), saved["title"].clone()),
        (json!("investigating"), json!("SSH root login"))
    );
    assert_eq!(etag.as_deref(), Some("\"2\""));
    let (status, problem, _) = fx
        .send(&alice, "PUT", &uri, Some(body), Some("\"1\""))
        .await;
    assert_eq!(
        (status, problem["code"].clone()),
        (StatusCode::PRECONDITION_FAILED, json!("stale_case"))
    );

    // Closing needs outcomes first.
    let close = put_body(
        &saved,
        json!({"status": "closed", "resolution": "mitigated", "resolution_note": "Disabled root login"}),
    );
    let (status, problem, _) = fx
        .send(&alice, "PUT", &uri, Some(close.clone()), Some("\"2\""))
        .await;
    assert_eq!(
        (status, problem["code"].clone()),
        (StatusCode::CONFLICT, json!("items_unresolved"))
    );
    for kind in ["finding", "alarm"] {
        let item = item_of(&saved, kind)["item_id"].as_str().unwrap();
        let (status, set, _) = fx
            .send(
                &alice,
                "PUT",
                &format!("{uri}/items/{item}/outcome"),
                Some(json!({"outcome": "false_positive", "note": "Expected for this host"})),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{set}");
        assert_eq!(set["outcome"], "false_positive");
    }
    let (status, closed, etag) = fx
        .send(&alice, "PUT", &uri, Some(close), Some("\"2\""))
        .await;
    assert_eq!(status, StatusCode::OK, "{closed}");
    assert_eq!(etag.as_deref(), Some("\"3\""));
    assert_eq!(closed["status"], "closed");
    assert_eq!(closed["resolution"], "mitigated");
    assert_eq!(closed["resolution_note"], "Disabled root login");
    assert!(closed["closed_at"].is_string());
    assert!(
        closed["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|i| i["active"] == false)
    );
    let kinds: Vec<_> = closed["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        kinds,
        [
            "created",
            "assigned",
            "item_added",
            "item_added",
            "item_added",
            "note",
            "status",
            "item_outcome",
            "item_outcome",
            "resolved"
        ]
    );

    // The audit log says what happened and never what was written.
    let audit = fx.audit().await;
    let actions: Vec<_> = audit.iter().map(|(a, _)| a.as_str()).collect();
    assert_eq!(
        actions,
        [
            "case.create",
            "case.item.add",
            "case.item.add",
            "case.item.add",
            "case.note",
            "case.update",
            "case.item.outcome",
            "case.item.outcome",
            "case.close"
        ]
    );
    assert!(
        audit.iter().all(|(_, detail)| !detail.contains("hunter2")),
        "{audit:?}"
    );
    fx.db.drop().await;
}

#[tokio::test]
async fn closing_is_refused_without_a_resolution_a_note_or_a_date() {
    let fx = fixture!();
    let alice = fx.session("alice").await;
    let case = fx
        .open(&alice, "Closing", json!([{"kind": "host", "ref": WEB}]))
        .await;
    let uri = case_uri(&case);
    let tomorrow = (Utc::now() + chrono::Duration::days(1)).to_rfc3339();
    let yesterday = (Utc::now() - chrono::Duration::days(1)).to_rfc3339();
    for (changes, field, code) in [
        (
            json!({"status": "closed"}),
            "resolution",
            "resolution_required",
        ),
        (
            json!({"status": "closed", "resolution": "mitigated"}),
            "resolution_note",
            "resolution_note_required",
        ),
        (
            json!({"status": "closed", "resolution": "mitigated", "resolution_note": "   "}),
            "resolution_note",
            "resolution_note_required",
        ),
        (
            json!({"status": "closed", "resolution": "fixed", "resolution_note": "x"}),
            "resolution",
            "invalid_resolution",
        ),
        (
            json!({"status": "closed", "resolution": "accepted_risk", "resolution_note": "x"}),
            "accepted_until",
            "accepted_until_required",
        ),
        (
            json!({"status": "closed", "resolution": "accepted_risk", "resolution_note": "x", "accepted_until": yesterday}),
            "accepted_until",
            "accepted_until_past",
        ),
        (
            json!({"status": "closed", "resolution": "mitigated", "resolution_note": "x", "accepted_until": tomorrow}),
            "accepted_until",
            "accepted_until_not_allowed",
        ),
        (
            json!({"status": "closed", "resolution": "mitigated", "resolution_note": "x", "accepted_until": "next week"}),
            "accepted_until",
            "invalid_timestamp",
        ),
        (
            json!({"status": "open", "resolution": "mitigated"}),
            "resolution",
            "resolution_not_allowed",
        ),
        (json!({"status": "done"}), "status", "invalid_status"),
        (
            json!({"severity": "urgent"}),
            "severity",
            "invalid_severity",
        ),
        (json!({"title": ""}), "title", "invalid_title"),
        (json!({"title": "t".repeat(121)}), "title", "invalid_title"),
    ] {
        let (status, problem, _) = fx
            .send(
                &alice,
                "PUT",
                &uri,
                Some(put_body(&case, changes.clone())),
                Some(&version(&case)),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{changes}: {problem}"
        );
        assert_eq!(problem["code"], "invalid_case");
        assert_eq!(
            field_errors(&problem),
            [(field.to_owned(), code.to_owned())],
            "{changes}"
        );
    }
    // None of that changed the case.
    let (_, same) = fx.get(&alice, &uri).await;
    assert_eq!(
        (same["version"].clone(), same["status"].clone()),
        (json!(1), json!("open"))
    );
    // A date and a note are enough for accepted risk, and it carries both.
    let (status, closed, _) = fx
        .send(
            &alice,
            "PUT",
            &uri,
            Some(put_body(&case, json!({"status": "closed", "resolution": "accepted_risk", "resolution_note": "Until the rebuild", "accepted_until": tomorrow}))),
            Some("\"1\""),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{closed}");
    assert_eq!(closed["resolution"], "accepted_risk");
    assert!(closed["accepted_until"].is_string());
    // A closed case keeps how it ended, takes no items and no outcomes.
    let (status, problem, _) = fx
        .send(&alice, "PUT", &uri, Some(put_body(&closed, json!({"resolution": "mitigated", "resolution_note": "Changed", "accepted_until": null}))), Some(&version(&closed)))
        .await;
    assert_eq!(
        (status, problem["code"].clone()),
        (StatusCode::CONFLICT, json!("case_closed"))
    );
    let (status, problem, _) = fx
        .send(
            &alice,
            "POST",
            &format!("{uri}/items"),
            Some(json!({"kind": "host", "ref": DB})),
            None,
        )
        .await;
    assert_eq!(
        (status, problem["code"].clone()),
        (StatusCode::CONFLICT, json!("case_closed"))
    );
    let host = closed["items"][0]["item_id"].as_str().unwrap();
    let (status, problem, _) = fx
        .send(&alice, "DELETE", &format!("{uri}/items/{host}"), None, None)
        .await;
    assert_eq!(
        (status, problem["code"].clone()),
        (StatusCode::CONFLICT, json!("case_closed"))
    );
    // Reopening clears the resolution.
    let (status, reopened, _) = fx
        .send(
            &alice,
            "PUT",
            &uri,
            Some(put_body(&closed, json!({"status": "investigating"}))),
            Some(&version(&closed)),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{reopened}");
    assert_eq!(
        (
            reopened["resolution"].clone(),
            reopened["accepted_until"].clone(),
            reopened["closed_at"].clone()
        ),
        (Value::Null, Value::Null, Value::Null)
    );
    assert!(reopened["items"][0]["active"].as_bool().unwrap());
    fx.db.drop().await;
}

#[tokio::test]
async fn an_item_cannot_be_in_two_open_cases() {
    let fx = fixture!();
    let alice = fx.session("alice").await;
    let dave = fx.session("dave").await;
    let finding = format!("{WEB}/baseline/ssh-root");
    let vuln = format!("{WEB}/FEDORA-1");
    let items = json!([
        {"kind": "alarm", "ref": fx.web_alarm},
        {"kind": "finding", "ref": finding},
        {"kind": "vulnerability", "ref": vuln},
    ]);
    let first = fx.open(&alice, "First", items.clone()).await;
    let number = first["number"].as_i64().unwrap();
    // Creating another case with any of them is refused, naming the first.
    for item in items.as_array().unwrap() {
        let (status, problem, _) = fx
            .send(
                &dave,
                "POST",
                "/api/v1/cases",
                Some(json!({"title": "Second", "items": [item]})),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{problem}");
        assert_eq!(problem["code"], "item_in_case");
        assert_eq!(problem["case_number"], number);
    }
    let (_, page) = fx.get(&dave, "/api/v1/cases?status=all").await;
    assert_eq!(
        page["items"].as_array().unwrap().len(),
        1,
        "the refused creates left nothing behind"
    );
    // So is adding it to an existing case; adding it twice to one is its own error.
    let second = fx.open(&dave, "Second", json!([])).await;
    let second_uri = case_uri(&second);
    let (status, problem, _) = fx
        .send(
            &dave,
            "POST",
            &format!("{second_uri}/items"),
            Some(json!({"kind": "alarm", "ref": fx.web_alarm})),
            None,
        )
        .await;
    assert_eq!(
        (
            status,
            problem["code"].clone(),
            problem["case_number"].clone()
        ),
        (StatusCode::CONFLICT, json!("item_in_case"), json!(number))
    );
    let (status, problem, _) = fx
        .send(
            &alice,
            "POST",
            &format!("{}/items", case_uri(&first)),
            Some(json!({"kind": "alarm", "ref": fx.web_alarm})),
            None,
        )
        .await;
    assert_eq!(
        (status, problem["code"].clone()),
        (StatusCode::CONFLICT, json!("item_already_in_case"))
    );
    // The same host can be in both, and the other host's vulnerability is another item.
    for (uri, kind, reference) in [
        (&second_uri, "host", WEB.to_owned()),
        (&case_uri(&first), "host", WEB.to_owned()),
        (&second_uri, "vulnerability", format!("{DB}/FEDORA-1")),
    ] {
        let (status, added, _) = fx
            .send(
                &dave,
                "POST",
                &format!("{uri}/items"),
                Some(json!({"kind": kind, "ref": reference})),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{added}");
    }
    // for-item says where an exclusive item is, and lists a host's cases.
    let (_, found) = fx
        .get(
            &dave,
            &format!("/api/v1/cases/for-item?kind=alarm&ref={}", fx.web_alarm),
        )
        .await;
    assert_eq!(found["items"].as_array().unwrap().len(), 1);
    assert_eq!(found["items"][0]["case"]["number"], number);
    assert_eq!(
        found["items"][0]["item_id"],
        item_of(&first, "alarm")["item_id"]
    );
    let (_, found) = fx
        .get(
            &dave,
            &format!("/api/v1/cases/for-item?kind=host&ref={WEB}"),
        )
        .await;
    assert_eq!(found["items"].as_array().unwrap().len(), 2);
    // Closing the first frees its alarm.
    for kind in ["alarm", "finding", "vulnerability"] {
        let item = item_of(&first, kind)["item_id"].as_str().unwrap();
        let (status, set, _) = fx
            .send(
                &alice,
                "PUT",
                &format!("{}/items/{item}/outcome", case_uri(&first)),
                Some(json!({"outcome": "false_positive", "note": "ok"})),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{set}");
    }
    let (status, closed, _) = fx
        .send(&alice, "PUT", &case_uri(&first), Some(put_body(&first, json!({"status": "closed", "resolution": "false_positive", "resolution_note": "Known"}))), Some("\"1\""))
        .await;
    assert_eq!(status, StatusCode::OK, "{closed}");
    let (status, added, _) = fx
        .send(
            &dave,
            "POST",
            &format!("{second_uri}/items"),
            Some(json!({"kind": "alarm", "ref": fx.web_alarm})),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{added}");
    // Reopening the first now conflicts with the second.
    let (status, problem, _) = fx
        .send(
            &alice,
            "PUT",
            &case_uri(&first),
            Some(put_body(&closed, json!({"status": "open"}))),
            Some(&version(&closed)),
        )
        .await;
    assert_eq!(
        (status, problem["code"].clone()),
        (StatusCode::CONFLICT, json!("item_in_case"))
    );
    assert_eq!(problem["case_number"], second["number"]);
    fx.db.drop().await;
}

#[tokio::test]
async fn a_scoped_user_sees_and_adds_only_what_is_in_scope() {
    let fx = fixture!();
    let alice = fx.session("alice").await;
    let bob = fx.session("bob").await;
    let mixed = fx
        .open(
            &alice,
            "Mixed",
            json!([
                {"kind": "host", "ref": WEB},
                {"kind": "host", "ref": DB},
                {"kind": "alarm", "ref": fx.db_alarm},
            ]),
        )
        .await;
    let only_db = fx
        .open(&alice, "Only db-01", json!([{"kind": "host", "ref": DB}, {"kind": "finding", "ref": format!("{DB}/baseline/ssh-root")}]))
        .await;
    // Bob sees the mixed case without the db-01 items, in counts too.
    let (status, seen) = fx.get(&bob, &case_uri(&mixed)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(seen["items"].as_array().unwrap().len(), 1);
    assert_eq!(seen["items"][0]["ref"], WEB);
    assert_eq!(seen["item_count"], 1);
    assert_eq!(
        seen["pending_item_count"], 0,
        "the hidden alarm is not counted"
    );
    let rendered = seen.to_string();
    assert!(!rendered.contains(DB), "{rendered}");
    assert!(
        seen["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item["kind"] != "alarm")
    );
    let kinds: Vec<_> = seen["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["created", "item_added"], "only the item he can see");
    // The other case does not exist for him: not in the list, not by id, not by search.
    let (_, page) = fx.get(&bob, "/api/v1/cases?status=all").await;
    assert_eq!(page["items"].as_array().unwrap().len(), 1);
    let (_, found) = fx
        .get(&bob, &format!("/api/v1/cases?q=C-{}", only_db["number"]))
        .await;
    assert!(found["items"].as_array().unwrap().is_empty());
    let hidden = case_uri(&only_db);
    let (status, problem) = fx.get(&bob, &hidden).await;
    assert_eq!(
        (status, problem["code"].clone()),
        (StatusCode::NOT_FOUND, json!("case_not_found"))
    );
    let unknown = fx
        .get(&bob, "/api/v1/cases/00000000-0000-4000-8000-000000000000")
        .await;
    assert_eq!(unknown.0, StatusCode::NOT_FOUND);
    assert_eq!(
        unknown.1["code"], problem["code"],
        "same answer for an absent and a hidden case"
    );
    let item = only_db["items"][0]["item_id"].as_str().unwrap();
    for (method, uri, body, if_match) in [
        (
            "PUT",
            hidden.clone(),
            Some(put_body(&only_db, json!({"title": "Mine"}))),
            Some("\"1\""),
        ),
        (
            "POST",
            format!("{hidden}/notes"),
            Some(json!({"body": "hello"})),
            None,
        ),
        (
            "POST",
            format!("{hidden}/items"),
            Some(json!({"kind": "host", "ref": WEB})),
            None,
        ),
        ("DELETE", format!("{hidden}/items/{item}"), None, None),
        (
            "PUT",
            format!("{hidden}/items/{item}/outcome"),
            Some(json!({"outcome": "false_positive", "note": "x"})),
            None,
        ),
    ] {
        let (status, problem, _) = fx.send(&bob, method, &uri, body, if_match).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {uri}: {problem}");
        assert_eq!(problem["code"], "case_not_found", "404, never 403");
    }
    // He cannot add what is out of scope, and a missing object looks the same.
    let bobs = fx
        .open(&bob, "Bob's case", json!([{"kind": "host", "ref": WEB}]))
        .await;
    let bobs_uri = case_uri(&bobs);
    let missing_host = format!("{DB}x");
    for (kind, reference) in [
        ("host", DB),
        ("alarm", fx.db_alarm.as_str()),
        ("finding", &format!("{DB}/baseline/ssh-root")),
        ("vulnerability", &format!("{DB}/FEDORA-1")),
        ("software", "rpm/bash"),
        ("host", &missing_host),
        ("alarm", "999999"),
    ] {
        let (status, problem, _) = fx
            .send(
                &bob,
                "POST",
                &format!("{bobs_uri}/items"),
                Some(json!({"kind": kind, "ref": reference})),
                None,
            )
            .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{kind} {reference}: {problem}"
        );
        assert_eq!(problem["code"], "item_not_found");
    }
    let (status, problem, _) = fx
        .send(
            &bob,
            "POST",
            "/api/v1/cases",
            Some(json!({"title": "No", "items": [{"kind": "host", "ref": DB}]})),
            None,
        )
        .await;
    assert_eq!(
        (status, problem["code"].clone()),
        (StatusCode::NOT_FOUND, json!("item_not_found"))
    );
    // His own are fine.
    let (status, added, _) = fx
        .send(
            &bob,
            "POST",
            &format!("{bobs_uri}/items"),
            Some(json!({"kind": "software", "ref": "rpm/openssl"})),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{added}");
    // Closing with items he cannot see is refused, without saying what.
    let (status, problem, _) = fx
        .send(
            &bob,
            "PUT",
            &case_uri(&mixed),
            Some(put_body(
                &seen,
                json!({"status": "closed", "resolution": "mitigated", "resolution_note": "Done"}),
            )),
            Some(&version(&seen)),
        )
        .await;
    assert_eq!(
        (status, problem["code"].clone()),
        (StatusCode::CONFLICT, json!("hidden_items_unresolved"))
    );
    // for-item never reveals a case he cannot see.
    let (_, found) = fx
        .get(&bob, &format!("/api/v1/cases/for-item?kind=host&ref={DB}"))
        .await;
    assert!(found["items"].as_array().unwrap().is_empty());
    // Someone assigned to a case sees it, with only the items they may.
    let (status, assigned, _) = fx
        .send(
            &alice,
            "PUT",
            &hidden,
            Some(put_body(&only_db, json!({"assignee_user_id": BOB}))),
            Some("\"1\""),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{assigned}");
    let (status, as_assignee) = fx.get(&bob, &hidden).await;
    assert_eq!(status, StatusCode::OK);
    assert!(as_assignee["items"].as_array().unwrap().is_empty());
    fx.db.drop().await;
}

#[tokio::test]
async fn resolved_needs_the_evidence_to_be_gone() {
    let fx = fixture!();
    let alice = fx.session("alice").await;
    let finding = format!("{WEB}/baseline/ssh-root");
    let case = fx
        .open(
            &alice,
            "Evidence",
            json!([{"kind": "finding", "ref": finding}, {"kind": "host", "ref": WEB}]),
        )
        .await;
    let uri = case_uri(&case);
    let item = item_of(&case, "finding")["item_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let outcome_uri = format!("{uri}/items/{item}/outcome");
    let (status, problem, _) = fx
        .send(
            &alice,
            "PUT",
            &outcome_uri,
            Some(json!({"outcome": "resolved"})),
            None,
        )
        .await;
    assert_eq!(
        (status, problem["code"].clone()),
        (StatusCode::CONFLICT, json!("evidence_present"))
    );
    // The agent stops reporting it.
    fx.sql(&format!(
        "UPDATE current_findings SET ended_at = now() WHERE agent_id = '{WEB}'"
    ))
    .await;
    let (_, now_gone) = fx.get(&alice, &uri).await;
    assert_eq!(item_of(&now_gone, "finding")["evidence_gone"], true);
    let (status, set, _) = fx
        .send(
            &alice,
            "PUT",
            &outcome_uri,
            Some(json!({"outcome": "resolved"})),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{set}");
    assert_eq!(set["outcome"], "resolved");
    // Marking needs a note; hosts take no outcome; unknown outcomes are refused.
    for (item, body, field, code) in [
        (
            item.clone(),
            json!({"outcome": "false_positive"}),
            "note",
            "note_required",
        ),
        (
            item.clone(),
            json!({"outcome": "accepted_risk", "note": " "}),
            "note",
            "note_required",
        ),
        (
            item.clone(),
            json!({"outcome": "fixed"}),
            "outcome",
            "invalid_outcome",
        ),
        (
            item_of(&case, "host")["item_id"]
                .as_str()
                .unwrap()
                .to_owned(),
            json!({"outcome": "resolved"}),
            "outcome",
            "outcome_not_applicable",
        ),
    ] {
        let (status, problem, _) = fx
            .send(
                &alice,
                "PUT",
                &format!("{uri}/items/{item}/outcome"),
                Some(body.clone()),
                None,
            )
            .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{body}: {problem}"
        );
        assert_eq!(
            field_errors(&problem),
            [(field.to_owned(), code.to_owned())]
        );
    }
    // Clearing sets it back to pending.
    let (status, cleared, _) = fx
        .send(
            &alice,
            "PUT",
            &outcome_uri,
            Some(json!({"outcome": null})),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{cleared}");
    assert_eq!(cleared["outcome"], Value::Null);
    // An unknown or foreign item id is a plain 404.
    for bad in ["00000000-0000-4000-8000-000000000000", "nope"] {
        let (status, problem, _) = fx
            .send(
                &alice,
                "PUT",
                &format!("{uri}/items/{bad}/outcome"),
                Some(json!({"outcome": null})),
                None,
            )
            .await;
        assert_eq!(
            (status, problem["code"].clone()),
            (StatusCode::NOT_FOUND, json!("item_not_found"))
        );
    }
    fx.db.drop().await;
}

#[tokio::test]
async fn items_can_be_removed_and_assignees_are_users_who_read_cases() {
    let fx = fixture!();
    let alice = fx.session("alice").await;
    let vera = fx.session("vera").await;
    let case = fx
        .open(
            &alice,
            "Remove",
            json!([{"kind": "host", "ref": WEB}, {"kind": "alarm", "ref": fx.web_alarm}]),
        )
        .await;
    let uri = case_uri(&case);
    let alarm = item_of(&case, "alarm")["item_id"].as_str().unwrap();
    let (status, _, _) = fx
        .send(
            &alice,
            "DELETE",
            &format!("{uri}/items/{alarm}"),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, problem, _) = fx
        .send(
            &alice,
            "DELETE",
            &format!("{uri}/items/{alarm}"),
            None,
            None,
        )
        .await;
    assert_eq!(
        (status, problem["code"].clone()),
        (StatusCode::NOT_FOUND, json!("item_not_found"))
    );
    let (_, after) = fx.get(&alice, &uri).await;
    assert_eq!(after["items"].as_array().unwrap().len(), 1);
    assert!(
        after["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["kind"] == "item_removed" && e["detail"]["item_ref"] == fx.web_alarm)
    );
    // The alarm is free for another case.
    fx.open(
        &alice,
        "Elsewhere",
        json!([{"kind": "alarm", "ref": fx.web_alarm}]),
    )
    .await;

    let (status, assignees) = fx.get(&alice, "/api/v1/cases/assignees").await;
    assert_eq!(status, StatusCode::OK);
    let names: Vec<_> = assignees["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["username"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["alice", "bob", "dave"], "not the viewer");
    assert_eq!(assignees["items"][0]["user_id"], ALICE);
    assert_eq!(
        fx.get(&vera, "/api/v1/cases/assignees").await.0,
        StatusCode::FORBIDDEN
    );
    // A viewer cannot be assigned, nor a stranger.
    for who in [VERA, "99999999-9999-4999-8999-999999999999", "nobody"] {
        let (status, problem, _) = fx
            .send(
                &alice,
                "PUT",
                &uri,
                Some(put_body(&after, json!({"assignee_user_id": who}))),
                Some(&version(&after)),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{who}: {problem}");
        assert_eq!(
            field_errors(&problem),
            [(
                "assignee_user_id".to_owned(),
                "assignee_unavailable".to_owned()
            )]
        );
    }
    let (status, _, _) = fx
        .send(
            &alice,
            "POST",
            "/api/v1/cases",
            Some(json!({"title": "x", "assignee_user_id": VERA})),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    // Assign, then unassign by leaving it out.
    let (_, assigned, _) = fx
        .send(
            &alice,
            "PUT",
            &uri,
            Some(put_body(&after, json!({"assignee_user_id": DAVE}))),
            Some(&version(&after)),
        )
        .await;
    assert_eq!(assigned["assignee"]["username"], "dave");
    let body =
        json!({"title": assigned["title"], "severity": assigned["severity"], "status": "open"});
    let (status, unassigned, _) = fx
        .send(&alice, "PUT", &uri, Some(body), Some(&version(&assigned)))
        .await;
    assert_eq!(status, StatusCode::OK, "{unassigned}");
    assert_eq!(unassigned["assignee"], Value::Null);
    fx.db.drop().await;
}

#[tokio::test]
async fn requests_are_validated_and_the_list_pages_and_filters() {
    let fx = fixture!();
    let alice = fx.session("alice").await;
    // Bad bodies.
    for body in [
        json!({}),
        json!({"title": 5}),
        json!({"title": "x", "surprise": true}),
        json!({"title": "x", "items": "all"}),
        json!({"title": "x", "items": [{"kind": "host"}]}),
    ] {
        let (status, problem, _) = fx
            .send(&alice, "POST", "/api/v1/cases", Some(body.clone()), None)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {problem}");
        assert_eq!(problem["code"], "invalid_request");
    }
    for (body, field, code) in [
        (json!({"title": ""}), "title", "invalid_title"),
        (json!({"title": "t".repeat(121)}), "title", "invalid_title"),
        (
            json!({"title": "x", "severity": "urgent"}),
            "severity",
            "invalid_severity",
        ),
        (
            json!({"title": "x", "items": [{"kind": "port", "ref": "tcp/22"}]}),
            "kind",
            "invalid_kind",
        ),
        (
            json!({"title": "x", "items": [{"kind": "alarm", "ref": "04"}]}),
            "ref",
            "invalid_ref",
        ),
        (
            json!({"title": "x", "items": (0..51).map(|n| json!({"kind": "software", "ref": format!("rpm/p{n}")})).collect::<Vec<_>>()}),
            "items",
            "too_many_items",
        ),
    ] {
        let (status, problem, _) = fx
            .send(&alice, "POST", "/api/v1/cases", Some(body.clone()), None)
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{problem}");
        assert_eq!(
            field_errors(&problem),
            [(field.to_owned(), code.to_owned())],
            "{body}"
        );
    }
    // Notes.
    let case = fx
        .open(&alice, "Notes", json!([{"kind": "host", "ref": WEB}]))
        .await;
    let uri = case_uri(&case);
    for body in [
        json!({"body": ""}),
        json!({"body": "   "}),
        json!({"body": "x".repeat(4001)}),
        json!({"body": "bell\u{7}"}),
    ] {
        let (status, problem, _) = fx
            .send(&alice, "POST", &format!("{uri}/notes"), Some(body), None)
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{problem}");
    }
    let (status, _, _) = fx
        .send(
            &alice,
            "POST",
            &format!("{uri}/notes"),
            Some(json!({"text": "x"})),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // Query errors.
    for query in [
        "status=done",
        "severity=urgent",
        "limit=0",
        "limit=101",
        "cursor=garbage",
        "surprise=1",
    ] {
        let (status, problem) = fx.get(&alice, &format!("/api/v1/cases?{query}")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}: {problem}");
    }
    for query in ["", "?kind=host", "?ref=x"] {
        let (status, _) = fx
            .get(&alice, &format!("/api/v1/cases/for-item{query}"))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}");
    }
    let (status, problem) = fx
        .get(&alice, "/api/v1/cases/for-item?kind=port&ref=x")
        .await;
    assert_eq!(
        (status, field_errors(&problem)),
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            vec![("kind".to_owned(), "invalid_kind".to_owned())]
        )
    );

    // Paging and filters over three more cases.
    for (title, severity) in [("Alpha", "low"), ("Bravo", "high"), ("Charlie", "high")] {
        let (status, created, _) = fx
            .send(
                &alice,
                "POST",
                "/api/v1/cases",
                Some(json!({"title": title, "severity": severity, "assignee_user_id": DAVE})),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
    }
    let (_, first) = fx.get(&alice, "/api/v1/cases?limit=2").await;
    let titles: Vec<_> = first["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["title"].as_str().unwrap())
        .collect();
    assert_eq!(titles, ["Charlie", "Bravo"], "newest change first");
    let cursor = first["next_cursor"].as_str().unwrap();
    let (_, second) = fx
        .get(&alice, &format!("/api/v1/cases?limit=2&cursor={cursor}"))
        .await;
    let titles: Vec<_> = second["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["title"].as_str().unwrap())
        .collect();
    assert_eq!(titles, ["Alpha", "Notes"]);
    assert_eq!(second["next_cursor"], Value::Null);
    let (_, high) = fx
        .get(&alice, "/api/v1/cases?severity=high&assignee=none")
        .await;
    assert!(high["items"].as_array().unwrap().is_empty());
    let (_, high) = fx
        .get(
            &alice,
            &format!("/api/v1/cases?severity=high&assignee={DAVE}"),
        )
        .await;
    assert_eq!(high["items"].as_array().unwrap().len(), 2);
    let (_, found) = fx.get(&alice, "/api/v1/cases?q=brav").await;
    assert_eq!(found["items"][0]["title"], "Bravo");
    let (_, none) = fx.get(&alice, "/api/v1/cases?status=closed").await;
    assert!(none["items"].as_array().unwrap().is_empty());
    fx.db.drop().await;
}

#[tokio::test]
async fn accepted_risk_that_runs_out_reopens_the_case_when_it_is_next_read() {
    let fx = fixture!();
    let alice = fx.session("alice").await;
    let case = fx
        .open(&alice, "Accept", json!([{"kind": "host", "ref": WEB}]))
        .await;
    let uri = case_uri(&case);
    let until = (Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    let (status, closed, _) = fx
        .send(&alice, "PUT", &uri, Some(put_body(&case, json!({"status": "closed", "resolution": "accepted_risk", "resolution_note": "Until Friday", "accepted_until": until}))), Some("\"1\""))
        .await;
    assert_eq!(status, StatusCode::OK, "{closed}");
    let (_, still_closed) = fx.get(&alice, &uri).await;
    assert_eq!(still_closed["status"], "closed");
    // Time passes.
    fx.sql("UPDATE cases SET accepted_until = now() - interval '1 minute'")
        .await;
    let (_, page) = fx.get(&alice, "/api/v1/cases").await;
    assert_eq!(
        page["items"][0]["status"], "open",
        "the default list shows it again"
    );
    let (_, reopened) = fx.get(&alice, &uri).await;
    assert_eq!(
        (
            reopened["status"].clone(),
            reopened["resolution"].clone(),
            reopened["accepted_until"].clone()
        ),
        (json!("open"), Value::Null, Value::Null)
    );
    assert_eq!(reopened["version"], 3);
    let last = reopened["events"].as_array().unwrap().last().unwrap();
    assert_eq!(
        (
            last["kind"].clone(),
            last["actor"].clone(),
            last["detail"]["reason"].clone()
        ),
        (
            json!("reopened"),
            Value::Null,
            json!("accepted_risk_expired")
        )
    );
    fx.db.drop().await;
}
