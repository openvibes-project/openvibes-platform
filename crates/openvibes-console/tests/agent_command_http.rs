//! The Enrollment page's install command and package over HTTP: who may
//! get them, and what they carry (install walkthrough, 2026-10-08).

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
    AgentInstallConfig, NormalizedPassword, TrustedPeer, authenticated_router_with_agent_install,
    hash_password,
};
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
        let name = format!("ov_console_agent_command_{:016x}", hasher.finish());
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
    // GET requests only here: no CSRF token needed.
    (cookie, String::new())
}

async fn get(
    router: &axum::Router,
    uri: &str,
    cookie: &str,
) -> (StatusCode, String, Option<String>) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let cache = response
        .headers()
        .get(header::CACHE_CONTROL)
        .map(|v| v.to_str().unwrap().to_owned());
    let body = to_bytes(response.into_body(), 65_536).await.unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap(), cache)
}

#[tokio::test]
async fn admins_get_the_install_command_and_package_viewers_do_not() {
    if std::env::var_os("OPENVIBES_TEST_DATABASE_URL").is_none() {
        return;
    }
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
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
    let dir = std::env::temp_dir().join(format!("ov-agent-command-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let root = dir.join("root.crt");
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    std::fs::write(&root, params.self_signed(&key).unwrap().pem()).unwrap();
    let router = authenticated_router_with_agent_install(
        db.pool.clone(),
        "https://console.example",
        AgentInstallConfig {
            platform: "platform.example".into(),
            ingest_port: 18423,
            distribution_port: 18424,
            root_cert_file: root,
        },
    );
    let (admin, _) = login(&router, "alice").await;
    let (viewer, _) = login(&router, "vera").await;

    // No standing token yet: nothing to hand out.
    let (status, body, _) = get(&router, "/api/v1/agent-command", &admin).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body.contains("no_standing_token"), "{body}");

    const SECRET: &str = "StandingTokenSecret_0123456789-abcdefghijk";
    platform_store::tokens::create_standing(&client, SECRET, [7; 32], "test", Utc::now())
        .await
        .unwrap();
    let (status, body, cache) = get(&router, "/api/v1/agent-command", &admin).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(cache.as_deref(), Some("no-store"));
    let body: Value = serde_json::from_str(&body).unwrap();
    let command = body["command"].as_str().unwrap();
    assert!(
        command.starts_with(
            "curl -fsSL https://openvibes-project.github.io/install.sh | sudo sh -s -- \
             --agent --platform platform.example --token "
        ),
        "{command}"
    );
    assert!(
        command.contains(SECRET) && command.contains(" --ca-sha256 "),
        "{command}"
    );

    // The package carries the same token, read from a variable.
    let (status, script, _) = get(&router, "/api/v1/agent-package", &admin).await;
    assert_eq!(status, StatusCode::OK);
    assert!(script.contains(&format!("TOKEN='{SECRET}'")), "{script}");

    // Both carry the standing token: viewers get neither.
    for uri in ["/api/v1/agent-command", "/api/v1/agent-package"] {
        let (status, _, _) = get(&router, uri, &viewer).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{uri}");
    }
    let audited: i64 = client
        .query_one(
            "SELECT count(*) FROM audit_log WHERE action = 'agent_command.viewed'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        audited, 1,
        "showing the command is audited, like the package"
    );
    drop(client);
    std::fs::remove_dir_all(&dir).ok();
    db.drop().await;
}
