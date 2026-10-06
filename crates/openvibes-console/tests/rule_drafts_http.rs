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
use openvibes_console::{
    NormalizedPassword, TrustedPeer, authenticated_router, authenticated_router_with_signer,
    hash_password,
};
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

/// A stand-in for the rule signer: checks the password the console sends,
/// then signs with a fixed key like the real one.
async fn fake_signer(socket: std::path::PathBuf, key: ed25519_dalek::SigningKey) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let mut version = 0;
    loop {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).await.unwrap();
        let request: Value = serde_json::from_slice(&request).unwrap();
        let answer = if request["password"] != PASSWORD {
            json!({"result": "refused", "code": "credentials"})
        } else {
            version += 1;
            let signed = openvibes_signer::sign::sign(
                &key,
                "site-key",
                request["rule_set"].as_str().unwrap(),
                version,
                request["rules"].as_str().unwrap(),
                Utc::now().timestamp_millis(),
                365,
            )
            .unwrap();
            json!({
                "result": "signed",
                "envelope": signed.envelope,
                "version": version,
                "expires_at_unix_ms": signed.expires_at_unix_ms
            })
        };
        stream
            .write_all(answer.to_string().as_bytes())
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn drafts_publish_through_the_signer_and_show_what_changed() {
    if std::env::var_os("OPENVIBES_TEST_DATABASE_URL").is_none() {
        return;
    }
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    user(
        &mut client,
        "11111111-1111-4111-8111-111111111112",
        "21111111-1111-4111-8111-111111111112",
        "olga",
        "operator",
    )
    .await;
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    platform_store::rules::add_trust_key(
        &mut client,
        "site",
        "site-key",
        key.verifying_key().to_bytes(),
    )
    .await
    .unwrap();
    drop(client);
    let dir = std::env::temp_dir().join(format!("ov-signer-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let socket = dir.join("sign.sock");
    let _ = std::fs::remove_file(&socket);
    tokio::spawn(fake_signer(socket.clone(), key));
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let router =
        authenticated_router_with_signer(db.pool.clone(), "https://console.example", socket);
    let (cookie, csrf) = login(&router, "olga").await;
    let base = "/api/v1/rule-drafts/site";
    let publish = format!("{base}/publish");
    let ok = json!({"password": PASSWORD});

    let (status, none, _) = call(
        &router,
        "POST",
        &publish,
        &cookie,
        &csrf,
        Some(ok.clone()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{none}");

    let (status, _, _) = call(
        &router,
        "PUT",
        &format!("{base}/port.redis.exposed"),
        &cookie,
        &csrf,
        Some(rule("'6379' in facts['port.tcp.exposed']")),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, changes, _) = call(
        &router,
        "GET",
        &format!("{base}/changes"),
        &cookie,
        &csrf,
        None,
        None,
    )
    .await;
    assert_eq!(changes["added"], json!(["port.redis.exposed"]));
    assert!(changes["published_version"].is_null());

    let wrong = json!({"password": "not the password at all"});
    let (status, body, _) =
        call(&router, "POST", &publish, &cookie, &csrf, Some(wrong), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "wrong_password");

    let (status, done, _) = call(
        &router,
        "POST",
        &publish,
        &cookie,
        &csrf,
        Some(ok.clone()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{done}");
    assert_eq!(
        (done["version"].as_i64(), done["rules"].as_u64()),
        (Some(1), Some(1))
    );

    let (_, changes, _) = call(
        &router,
        "GET",
        &format!("{base}/changes"),
        &cookie,
        &csrf,
        None,
        None,
    )
    .await;
    assert_eq!(changes["published_version"], 1);
    assert_eq!(changes["unchanged"], 1);
    let (status, _, _) = call(
        &router,
        "POST",
        &publish,
        &cookie,
        &csrf,
        Some(ok.clone()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "nothing changed");

    let mut edited = rule("'6379' in facts['port.tcp.exposed']");
    edited["confidence"] = json!(70);
    call(
        &router,
        "PUT",
        &format!("{base}/port.redis.exposed"),
        &cookie,
        &csrf,
        Some(edited),
        None,
    )
    .await;
    let (_, changes, _) = call(
        &router,
        "GET",
        &format!("{base}/changes"),
        &cookie,
        &csrf,
        None,
        None,
    )
    .await;
    assert_eq!(changes["changed"], json!(["port.redis.exposed"]));
    let (status, done, _) = call(&router, "POST", &publish, &cookie, &csrf, Some(ok), None).await;
    assert_eq!(status, StatusCode::CREATED, "{done}");
    assert_eq!(done["version"], 2);

    let client = db.pool.get().await.unwrap();
    let published: i64 = client
        .query_one(
            "SELECT count(*) FROM audit_log WHERE action LIKE 'rule.%publish%' OR action LIKE 'rule_bundle%'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(published >= 2, "each publish is audited");
    drop(client);
    db.drop().await;
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn a_rule_is_tested_against_the_facts_the_platform_holds() {
    if std::env::var_os("OPENVIBES_TEST_DATABASE_URL").is_none() {
        return;
    }
    let (db, router) = setup().await;
    db.pool
        .get()
        .await
        .unwrap()
        .batch_execute(
            "INSERT INTO agents (agent_id, status, enrolled_at, hostname, last_seen_at)
                VALUES ('agent.00000000-0000-4000-8000-000000000401', 'active', now(), 'web-01', now()),
                       ('agent.00000000-0000-4000-8000-000000000402', 'active', now(), 'new-01', now());
             INSERT INTO package_versions (id, manager, name, epoch, version, release, arch) VALUES
                (1, 'rpm', 'redis', 0, '7.2', '1.fc44', 'x86_64'),
                (2, 'rpm', 'bash', 0, '5.2', '1.fc44', 'x86_64');
             INSERT INTO host_packages VALUES ('agent.00000000-0000-4000-8000-000000000401', 1), ('agent.00000000-0000-4000-8000-000000000401', 2);
             UPDATE agents SET services_at = now(), services_owners = 'complete'
                WHERE agent_id = 'agent.00000000-0000-4000-8000-000000000401';
             INSERT INTO host_listeners VALUES
                ('agent.00000000-0000-4000-8000-000000000401', 'tcp', '0.0.0.0', 6379, true, 'redis.service', 'redis'),
                ('agent.00000000-0000-4000-8000-000000000401', 'tcp', '127.0.0.1', 5432, false, NULL, NULL);",
        )
        .await
        .unwrap();
    let (cookie, csrf) = login(&router, "olga").await;
    let test = |agent: &str, rule: Value| json!({"agent_id": agent, "rule": rule});
    let url = "/api/v1/rule-drafts/site/port.redis.exposed/test";
    let post = |body: Value| {
        let (router, cookie, csrf) = (router.clone(), cookie.clone(), csrf.clone());
        async move { call(&router, "POST", url, &cookie, &csrf, Some(body), None).await }
    };

    let (status, hit, _) = post(test(
        "agent.00000000-0000-4000-8000-000000000401",
        rule("'6379' in facts['port.tcp.exposed']"),
    ))
    .await;
    assert_eq!(status, StatusCode::OK, "{hit}");
    assert_eq!(hit["outcome"], "match");
    assert_eq!(hit["facts"]["packages"], 2);
    assert_eq!(hit["facts"]["listeners"], 2);
    assert_eq!(hit["evidence"], json!(["port.tcp.exposed"]));

    let (_, miss, _) = post(test(
        "agent.00000000-0000-4000-8000-000000000401",
        rule("'22' in facts['port.tcp.exposed']"),
    ))
    .await;
    assert_eq!(miss["outcome"], "no_match");
    let (_, local, _) = post(test(
        "agent.00000000-0000-4000-8000-000000000401",
        rule("'5432' in facts['port.tcp.local']"),
    ))
    .await;
    assert_eq!(local["outcome"], "match");
    let (_, packages, _) = post(test(
        "agent.00000000-0000-4000-8000-000000000401",
        rule("'redis' in facts['package.names']"),
    ))
    .await;
    assert_eq!(packages["outcome"], "match");

    // Facts the platform doesn't rebuild, or a host that never reported
    // its ports, are unavailable, not "no match".
    let (_, unavailable, _) = post(test(
        "agent.00000000-0000-4000-8000-000000000401",
        rule("'sshd' in facts['process.names']"),
    ))
    .await;
    assert_eq!(unavailable["outcome"], "unavailable");
    let (_, silent, _) = post(test(
        "agent.00000000-0000-4000-8000-000000000402",
        rule("'6379' in facts['port.tcp.exposed']"),
    ))
    .await;
    assert_eq!(silent["outcome"], "unavailable");

    let (status, _, _) = post(test("nobody", rule("true"))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, _) = post(test(
        "agent.00000000-0000-4000-8000-000000000401",
        rule("this is not cel (("),
    ))
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let (status, body, _) = call(
        &router,
        "POST",
        "/api/v1/rule-drafts/site-alarms/a1/test",
        &cookie,
        &csrf,
        Some(test(
            "agent.00000000-0000-4000-8000-000000000401",
            rule("true"),
        )),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    let (viewer, viewer_csrf) = login(&router, "vera").await;
    let (status, _, _) = call(
        &router,
        "POST",
        url,
        &viewer,
        &viewer_csrf,
        Some(test(
            "agent.00000000-0000-4000-8000-000000000401",
            rule("true"),
        )),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    db.drop().await;
}
