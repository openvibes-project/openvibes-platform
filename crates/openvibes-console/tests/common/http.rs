//! A throwaway database, sign-in and JSON requests for the console HTTP
//! tests that run against the authenticated router.

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
use openvibes_console::{NormalizedPassword, TrustedPeer, hash_password};
use platform_store::console_auth::{NewLocalUser, create_local_user};
use serde_json::Value;
use tower::ServiceExt;

pub const ORIGIN: &str = "https://console.example";
pub const PASSWORD: &str = "violet-satellite-mountain-otter-2026";

/// A migrated database of its own, dropped by [`TestDb::drop`].
pub struct TestDb {
    pub pool: platform_store::Pool,
    admin_url: String,
    name: String,
}

impl TestDb {
    /// `None` (the test skips) when `OPENVIBES_TEST_DATABASE_URL` is unset.
    pub async fn create(prefix: &str) -> Option<Self> {
        let Ok(admin_url) = std::env::var("OPENVIBES_TEST_DATABASE_URL") else {
            eprintln!("skipping: OPENVIBES_TEST_DATABASE_URL is unset");
            return None;
        };
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u64(std::process::id().into());
        let name = format!("ov_console_{prefix}_{:016x}", hasher.finish());
        let admin = platform_store::connect(&admin_url).await.unwrap();
        admin
            .get()
            .await
            .unwrap()
            .batch_execute(&format!("CREATE DATABASE {name}"))
            .await
            .unwrap();
        let (head, query) = admin_url
            .split_once('?')
            .map_or((admin_url.as_str(), None), |(h, q)| (h, Some(q)));
        let head = &head[..head.rfind('/').unwrap()];
        let url = match query {
            Some(query) => format!("{head}/{name}?{query}"),
            None => format!("{head}/{name}"),
        };
        let pool = platform_store::connect(&url).await.unwrap();
        platform_store::migrate(&mut pool.get().await.unwrap())
            .await
            .unwrap();
        Some(Self {
            pool,
            admin_url,
            name,
        })
    }

    pub async fn drop(self) {
        self.pool.close();
        let admin = platform_store::connect(&self.admin_url).await.unwrap();
        let client = admin.get().await.unwrap();
        client
            .batch_execute("SET statement_timeout = 0")
            .await
            .unwrap();
        client
            .batch_execute(&format!("DROP DATABASE {} WITH (FORCE)", self.name))
            .await
            .unwrap();
    }

    /// Creates enabled user `username` (password [`PASSWORD`]) holding
    /// `role_id`; `index` keeps ids unique within a test.
    pub async fn user(&self, username: &str, role_id: &str, index: u8) {
        let phc = hash_password(&NormalizedPassword::new(PASSWORD).unwrap()).unwrap();
        let mut client = self.pool.get().await.unwrap();
        super::ensure_role(&client, role_id).await;
        create_local_user(
            &mut client,
            &NewLocalUser {
                user_id: &format!("11111111-1111-4111-8111-1111111111{index:02}"),
                binding_id: &format!("22222222-2222-4222-8222-2222222222{index:02}"),
                username,
                display_name: username,
                password_phc: phc.as_str(),
                role_id,
                actor_id: "test-bootstrap",
                actor_kind: "local_admin",
                password_must_change: false,
                now: Utc::now(),
            },
        )
        .await
        .unwrap();
    }

    /// The audit actions, oldest first.
    pub async fn audit_actions(&self) -> Vec<String> {
        let client = self.pool.get().await.unwrap();
        client
            .query("SELECT action FROM audit_log ORDER BY id", &[])
            .await
            .unwrap()
            .iter()
            .map(|row| row.get(0))
            .collect()
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

pub async fn body(response: axum::response::Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 1 << 20).await.unwrap())
        .unwrap_or(Value::Null)
}

/// A signed-in browser: its session cookie and CSRF token.
pub type Session = (String, String);

/// Signs `username` in with [`PASSWORD`].
pub async fn sign_in(router: &axum::Router, username: &str) -> Session {
    let preauth = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/auth/v1/preauth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let preauth_cookie = cookie_pair(&preauth, "__Host-openvibes-preauth=");
    let browser_cookie = cookie_pair(&preauth, "__Host-openvibes-browser=");
    let csrf = body(preauth).await["csrf_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let address: SocketAddr = "127.0.0.1:4242".parse().unwrap();
    let login = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/v1/login")
                .header(header::ORIGIN, ORIGIN)
                .header("sec-fetch-site", "same-origin")
                .header("x-csrf-token", csrf)
                .header(
                    header::COOKIE,
                    format!("{preauth_cookie}; {browser_cookie}"),
                )
                .header(header::CONTENT_TYPE, "application/json")
                .extension(ConnectInfo(TrustedPeer::new(address)))
                .body(Body::from(
                    serde_json::json!({"username": username, "password": PASSWORD}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK, "sign-in as {username}");
    let cookie = cookie_pair(&login, "__Host-openvibes-session=");
    let session = send(
        router,
        "GET",
        "/api/v1/session",
        &(cookie.clone(), String::new()),
        None,
        &[],
    )
    .await;
    let csrf = body(session).await["csrf_token"]
        .as_str()
        .unwrap()
        .to_owned();
    (cookie, csrf)
}

/// Sends `method uri` as `who`, with a JSON body when given; returns the
/// status and the JSON answer (`Null` when there is none).
pub async fn call(
    router: &axum::Router,
    method: &str,
    uri: &str,
    who: &Session,
    json: Option<Value>,
) -> (StatusCode, Value) {
    call_with(router, method, uri, who, json, &[]).await
}

/// [`call`] with extra request headers.
pub async fn call_with(
    router: &axum::Router,
    method: &str,
    uri: &str,
    who: &Session,
    json: Option<Value>,
    extra: &[(&str, &str)],
) -> (StatusCode, Value) {
    let response = send(router, method, uri, who, json, extra).await;
    (response.status(), body(response).await)
}

async fn send(
    router: &axum::Router,
    method: &str,
    uri: &str,
    (cookie, csrf): &Session,
    json: Option<Value>,
    extra: &[(&str, &str)],
) -> axum::response::Response {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::COOKIE, cookie)
        .header(header::ORIGIN, ORIGIN)
        .header("sec-fetch-site", "same-origin")
        .header("x-csrf-token", csrf)
        .header(header::CONTENT_TYPE, "application/json");
    for (name, value) in extra {
        request = request.header(*name, *value);
    }
    router
        .clone()
        .oneshot(
            request
                .body(json.map_or_else(Body::empty, |json| Body::from(json.to_string())))
                .unwrap(),
        )
        .await
        .unwrap()
}
