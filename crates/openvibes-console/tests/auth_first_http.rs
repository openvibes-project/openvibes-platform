//! Every console API route authenticates before it looks at the request
//! (#97): with a malformed body and no session it is 401, and for a user
//! who must still set their own password it is 403, whatever the route.
//! The routes come from the OpenAPI document, so a new one is covered.

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
    NormalizedPassword, TrustedPeer, authenticated_router, hash_password, openapi_json,
};
use platform_store::console_auth::{NewLocalUser, create_local_user};
use serde_json::Value;
use tower::ServiceExt;

const ORIGIN: &str = "https://console.example";
const PASSWORD: &str = "violet-satellite-mountain-otter-2026";

/// (method, path with every `{param}` filled in), from the OpenAPI document.
fn routes() -> Vec<(String, String)> {
    let doc: Value = serde_json::from_str(&openapi_json().unwrap()).unwrap();
    let mut routes = Vec::new();
    for (path, item) in doc["paths"].as_object().unwrap() {
        // `/auth/…` (pre-auth, sign-in, sign-out) is outside the API.
        if !path.starts_with("/api/") {
            continue;
        }
        for method in ["get", "post", "put", "delete", "patch"] {
            if item.get(method).is_some() {
                let mut concrete = String::new();
                let mut inside = false;
                for c in path.chars() {
                    match c {
                        '{' => inside = true,
                        '}' => {
                            inside = false;
                            concrete.push_str("00000000-0000-4000-8000-000000000001");
                        }
                        _ if inside => {}
                        _ => concrete.push(c),
                    }
                }
                routes.push((method.to_uppercase(), concrete));
            }
        }
    }
    routes
}

async fn send(
    router: &axum::Router,
    method: &str,
    uri: &str,
    cookie: Option<&str>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::ORIGIN, ORIGIN)
        .header("sec-fetch-site", "same-origin")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    // A malformed body: whatever the route expects, it is not this.
    let body = if method == "GET" {
        Body::empty()
    } else {
        Body::from("{\"bad\": ")
    };
    let response = router
        .clone()
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
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
        .unwrap()
}

#[tokio::test]
async fn every_route_authenticates_before_it_reads_the_request() {
    let Some(admin_url) = std::env::var_os("OPENVIBES_TEST_DATABASE_URL") else {
        eprintln!("skipping: OPENVIBES_TEST_DATABASE_URL is unset");
        return;
    };
    let admin_url = admin_url.into_string().unwrap();
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(std::process::id().into());
    let name = format!("ov_console_auth_first_{:016x}", hasher.finish());
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
    let url = query.map_or_else(
        || format!("{head}/{name}"),
        |q| format!("{head}/{name}?{q}"),
    );
    let pool = platform_store::connect(&url).await.unwrap();
    let mut client = pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    // A user who must still replace a one-time password.
    let phc = hash_password(&NormalizedPassword::new(PASSWORD).unwrap()).unwrap();
    create_local_user(
        &mut client,
        &NewLocalUser {
            user_id: "11111111-1111-4111-8111-111111111111",
            binding_id: "22222222-2222-4222-8222-222222222222",
            username: "fresh",
            display_name: "Fresh",
            password_phc: phc.as_str(),
            role_id: "admin",
            actor_id: "test",
            actor_kind: "local_admin",
            password_must_change: true,
            now: Utc::now(),
        },
    )
    .await
    .unwrap();
    drop(client);
    let router = authenticated_router(pool.clone(), ORIGIN);

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
    let cookies = format!(
        "{}; {}",
        cookie_pair(&preauth, "__Host-openvibes-preauth="),
        cookie_pair(&preauth, "__Host-openvibes-browser=")
    );
    let csrf: Value =
        serde_json::from_slice(&to_bytes(preauth.into_body(), 4096).await.unwrap()).unwrap();
    let address: SocketAddr = "127.0.0.1:4242".parse().unwrap();
    let login = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/v1/login")
                .header(header::ORIGIN, ORIGIN)
                .header("sec-fetch-site", "same-origin")
                .header("x-csrf-token", csrf["csrf_token"].as_str().unwrap())
                .header(header::COOKIE, cookies)
                .header(header::CONTENT_TYPE, "application/json")
                .extension(ConnectInfo(TrustedPeer::new(address)))
                .body(Body::from(format!(
                    "{{\"username\":\"fresh\",\"password\":\"{PASSWORD}\"}}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    let session = cookie_pair(&login, "__Host-openvibes-session=");

    let routes = routes();
    assert!(
        routes.len() > 40,
        "the OpenAPI document lists the routes: {}",
        routes.len()
    );
    let mut wrong = Vec::new();
    for (method, uri) in &routes {
        // The OpenAPI paths are the full ones, `/api/v1/…`.
        let full = uri.clone();
        assert!(full.starts_with("/api/v1/"), "{full}");
        let (anonymous, _) = send(&router, method, &full, None).await;
        if anonymous != StatusCode::UNAUTHORIZED {
            wrong.push(format!("{method} {full} without a session: {anonymous}"));
        }
        let (forced, body) = send(&router, method, &full, Some(&session)).await;
        let open = (method.as_str(), uri.as_str()) == ("GET", "/api/v1/session")
            || (method.as_str(), uri.as_str()) == ("POST", "/api/v1/session/password");
        if !open && (forced != StatusCode::FORBIDDEN || body["code"] != "password_change_required")
        {
            wrong.push(format!(
                "{method} {full} before the password change: {forced} {}",
                body["code"]
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} routes answer before authenticating:\n{}",
        wrong.len(),
        wrong.join("\n")
    );

    pool.close();
    let client = admin.get().await.unwrap();
    client
        .batch_execute("SET statement_timeout = 0")
        .await
        .unwrap();
    client
        .batch_execute(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .await
        .unwrap();
}
