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
use chrono::{Duration, Utc};
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
    for day in [
        "(now() AT TIME ZONE 'UTC')::date - 2",
        "(now() AT TIME ZONE 'UTC')::date - 1",
    ] {
        for (agent, critical) in [(A, 1), (B, 5)] {
            sql.push_str(&format!(
                "INSERT INTO host_daily_counts VALUES ({day}, '{agent}', 'active',
                    0,0,0,0,0, {critical},0,0,0,0,0, false, 0,0,0,0);"
            ));
        }
    }
    // A stored row for today (replaced by the live value) and one dated
    // tomorrow (clock skew, restored backup; never served).
    for (day, critical) in [
        ("(now() AT TIME ZONE 'UTC')::date", 99),
        ("(now() AT TIME ZONE 'UTC')::date + 1", 77),
    ] {
        sql.push_str(&format!(
            "INSERT INTO host_daily_counts VALUES ({day}, '{B}', 'active',
                0,0,0,0,0, {critical},0,0,0,0,0, false, 0,0,0,0);"
        ));
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
    let uri = "/api/v1/metrics/history?metric=vulns.open.critical&days=7";
    let (vera, _) = login(&router, "vera").await;
    let (status, global) = get(&router, &vera, uri).await;
    assert_eq!(status, StatusCode::OK);
    let today = Utc::now().date_naive();
    let day = |n: i64| (today - Duration::days(n)).to_string();
    // Stored today (99) and tomorrow (77) rows are not served: the last
    // point is today's live value, once.
    assert_eq!(
        global["points"],
        serde_json::json!([
            {"day": day(2), "value": 6},
            {"day": day(1), "value": 6},
            {"day": day(0), "value": 0},
        ])
    );
    let (sam, _) = login(&router, "sam").await;
    let (_, scoped) = get(&router, &sam, uri).await;
    assert_eq!(scoped["points"][0]["value"], 1);
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

/// Every catalogue metric's live value equals the count the console's
/// summaries and lists show for the same data (global scope).
#[tokio::test]
async fn live_values_match_the_summaries_and_lists() {
    if std::env::var_os("OPENVIBES_TEST_DATABASE_URL").is_none() {
        return;
    }
    let (db, router) = setup().await;
    let client = db.pool.get().await.unwrap();
    let today = Utc::now().date_naive();
    platform_store::ensure_partitions(&client, today - Duration::days(1), 2)
        .await
        .unwrap();
    let mut sql = format!(
        "INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at) VALUES
            ('agent.00000000-0000-4000-8000-000000000503', 'revoked', now(), now()),
            ('agent.00000000-0000-4000-8000-000000000504', 'active', now(), now() - interval '1 day');
         INSERT INTO host_vulnerability_counts
             (agent_id, no_fix, critical, important, moderate, low, unrated, reboot, counted_at)
         VALUES ('{A}', 2, 1, 2, 3, 4, 5, 1, now()), ('{B}', 1, 6, 0, 1, 0, 2, 0, now());
         INSERT INTO advisories (advisory_id, source, os_id, os_version, severity, title, url)
             VALUES ('ADV-1', 's', 'debian', '12', 'critical', 't', 'u');
         INSERT INTO advisory_cves VALUES ('ADV-1', 'CVE-1');
         INSERT INTO cve_enrichment (cve_id, kev_added) VALUES ('CVE-1', '2026-01-01');
         INSERT INTO vulnerabilities (agent_id, advisory_id, packages, first_seen_at, last_evaluated_at)
             VALUES ('{B}', 'ADV-1', '[]', now(), now());"
    );
    // Every severity (info included) in every state, on both hosts.
    sql.push_str(&format!(
        "INSERT INTO alarms (first_seen_day, agent_id, alarm_id, rule_set_id, rule_set_version,
             rule_id, rule_version, severity, confidence, message, first_seen, last_seen, count,
             process, ancestors, received_at, state, note)
         SELECT (now() AT TIME ZONE 'UTC')::date, g, md5(g || s || t), 'rs', 1, 'r', 1, s, 50,
             'm', now(), now(), 1, '{{}}', '[]', now(), t, 'n'
         FROM unnest(ARRAY['{A}', '{B}']) g,
              unnest(ARRAY['critical', 'high', 'medium', 'low', 'info']) s,
              unnest(ARRAY['open', 'mitigated', 'false_positive']) t;"
    ));
    for (i, (agent, severity)) in [
        (A, "critical"),
        (A, "high"),
        (B, "medium"),
        (B, "low"),
        (B, "high"),
    ]
    .iter()
    .enumerate()
    {
        sql.push_str(&format!(
            "INSERT INTO current_findings (agent_id, rule_id, last_finding_id, rule_version,
                 severity, first_observed_at, last_observed_at, last_observed_day, scan_id,
                 confidence, message, evidence, received_at, origin, authenticated)
             VALUES ('{agent}', 'rule-{i}', 'f-{i}', 1, '{severity}', now(), now(),
                 (now() AT TIME ZONE 'UTC')::date, 's', 50, 'm', '{{}}', now(), 'online', false);"
        ));
    }
    client.batch_execute(&sql).await.unwrap();

    let vulns = platform_store::vulns::summary(&client).await.unwrap();
    let vuln = |s: &str| {
        vulns
            .by_severity
            .iter()
            .find(|(k, _)| k == s)
            .map_or(0, |(_, n)| *n)
    };
    let compliance = platform_store::console_read::finding_summary(&client)
        .await
        .unwrap();
    let agents = platform_store::console_read::agent_summary(&client, Utc::now())
        .await
        .unwrap();
    let row = client
        .query_one(
            "SELECT count(*), count(*) FILTER (WHERE l.severity = 'critical'),
                    count(*) FILTER (WHERE l.severity = 'high'),
                    count(*) FILTER (WHERE l.severity = 'medium'),
                    count(*) FILTER (WHERE l.severity = 'low')
             FROM alarms l JOIN agents a USING (agent_id)
             WHERE l.state = 'open'",
            &[],
        )
        .await
        .unwrap();
    let alarms = |severity: &str| -> i64 {
        let i = ["", "critical", "high", "medium", "low"]
            .iter()
            .position(|s| *s == severity)
            .unwrap();
        row.get(i)
    };
    let expected = [
        (
            "all.open.critical",
            alarms("critical") + vuln("critical") + compliance.critical,
        ),
        (
            "all.open.high",
            alarms("high") + vuln("important") + compliance.high,
        ),
        ("alarms.active", alarms("")),
        ("alarms.active.critical", alarms("critical")),
        ("alarms.active.high", alarms("high")),
        ("alarms.active.medium", alarms("medium")),
        ("alarms.active.low", alarms("low")),
        ("vulns.open.critical", vuln("critical")),
        ("vulns.open.high", vuln("important")),
        ("vulns.open.medium", vuln("moderate")),
        ("vulns.open.low", vuln("low")),
        ("vulns.exploited", vulns.exploited),
        ("vulns.no_fix", vulns.no_fix),
        ("vulns.reboot_hosts", vulns.reboot_hosts),
        ("compliance.open.critical", compliance.critical),
        ("compliance.open.high", compliance.high),
        ("compliance.open.medium", compliance.medium),
        ("compliance.open.low", compliance.low),
        ("agents.active", agents.active),
        ("agents.stale", agents.stale),
        ("agents.revoked", agents.revoked),
    ];
    assert_eq!(
        alarms(""),
        10,
        "seed: 2 hosts x 5 severities x 1 active state (triage v2: open)"
    );
    let (vera, _) = login(&router, "vera").await;
    let mut mismatches = Vec::new();
    for (metric, want) in expected {
        let (status, body) = get(
            &router,
            &vera,
            &format!("/api/v1/metrics/history?metric={metric}&days=7"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{metric}");
        let got = body["points"].as_array().unwrap().last().unwrap()["value"]
            .as_i64()
            .unwrap();
        if got != want {
            mismatches.push(format!("{metric}: history {got}, summary {want}"));
        }
    }
    assert!(mismatches.is_empty(), "{mismatches:#?}");
    db.drop().await;
}

#[tokio::test]
async fn top_hosts_rank_across_kinds_within_the_callers_scope() {
    if std::env::var_os("OPENVIBES_TEST_DATABASE_URL").is_none() {
        return;
    }
    let (db, router) = setup().await;
    let client = db.pool.get().await.unwrap();
    client
        .batch_execute(&format!(
            "INSERT INTO host_vulnerability_counts
                 (agent_id, no_fix, critical, important, moderate, low, unrated, reboot, counted_at)
             VALUES ('{A}', 0, 0, 1, 0, 0, 0, 0, now()), ('{B}', 0, 2, 0, 0, 0, 0, 0, now());"
        ))
        .await
        .unwrap();
    drop(client);
    let (vera, _) = login(&router, "vera").await;
    let (status, body) = get(&router, &vera, "/api/v1/metrics/top-hosts?limit=5").await;
    assert_eq!(status, StatusCode::OK);
    let ids: Vec<_> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["agent_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, [B, A]);
    assert_eq!(body["items"][0]["serious"], 2);
    assert_eq!(body["items"][0]["hostname"], "host-b");
    let (sam, _) = login(&router, "sam").await;
    let (_, scoped) = get(&router, &sam, "/api/v1/metrics/top-hosts").await;
    assert_eq!(scoped["items"].as_array().unwrap().len(), 1);
    assert_eq!(scoped["items"][0]["agent_id"], A);
    for bad in ["0", "11", "x"] {
        let (status, body) = get(
            &router,
            &vera,
            &format!("/api/v1/metrics/top-hosts?limit={bad}"),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{bad}");
        assert_eq!(body["field_errors"][0]["code"], "invalid_limit");
    }
    let (status, _) = get(&router, "", "/api/v1/metrics/top-hosts").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // The 403 for kinds with different scopes is covered by `scopes_must_agree`;
    // every built-in role holds all three read permissions.
    db.drop().await;
}
