//! New user with a one-time password, the forced password change, and
//! self-service password change (#85).

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

const ORIGIN: &str = "https://console.example";
const ADMIN_PASSWORD: &str = "violet-satellite-mountain-otter-2026";

struct TestDb {
    pool: platform_store::Pool,
    admin_url: String,
    name: String,
}

impl TestDb {
    async fn create() -> Self {
        let admin_url = std::env::var("OPENVIBES_TEST_DATABASE_URL").unwrap();
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u64(std::process::id().into());
        let name = format!("ov_console_users_{:016x}", hasher.finish());
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
        Self {
            pool,
            admin_url,
            name,
        }
    }

    async fn drop(self) {
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

async fn body(response: axum::response::Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 65_536).await.unwrap())
        .unwrap_or(Value::Null)
}

/// Signs in; returns the session cookie and its CSRF token.
async fn sign_in(router: &axum::Router, username: &str, password: &str) -> (String, String) {
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
                    serde_json::json!({"username": username, "password": password}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK, "sign-in as {username}");
    let cookie = cookie_pair(&login, "__Host-openvibes-session=");
    let session = get(router, "/api/v1/session", &cookie).await;
    let csrf = body(session).await["csrf_token"]
        .as_str()
        .unwrap()
        .to_owned();
    (cookie, csrf)
}

async fn get(router: &axum::Router, uri: &str, cookie: &str) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn post(
    router: &axum::Router,
    uri: &str,
    (cookie, csrf): &(String, String),
    json: Value,
) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::COOKIE, cookie)
                .header(header::ORIGIN, ORIGIN)
                .header("sec-fetch-site", "same-origin")
                .header("x-csrf-token", csrf)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn local_user(db: &TestDb, username: &str, role_id: &str, index: u8) {
    let phc = hash_password(&NormalizedPassword::new(ADMIN_PASSWORD).unwrap()).unwrap();
    let mut client = db.pool.get().await.unwrap();
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

async fn audit_actions(db: &TestDb) -> Vec<(String, String)> {
    let client = db.pool.get().await.unwrap();
    client
        .query(
            "SELECT action, COALESCE(actor_kind, '') FROM audit_log ORDER BY id",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect()
}

#[tokio::test]
async fn a_new_user_must_set_their_own_password_before_anything_else() {
    if std::env::var_os("OPENVIBES_TEST_DATABASE_URL").is_none() {
        eprintln!("skipping: OPENVIBES_TEST_DATABASE_URL is unset");
        return;
    }
    let db = TestDb::create().await;
    platform_store::migrate(&mut db.pool.get().await.unwrap())
        .await
        .unwrap();
    local_user(&db, "alice", "admin", 1).await;
    local_user(&db, "carol", "analyst", 2).await;
    let router = authenticated_router(db.pool.clone(), ORIGIN);
    let admin = sign_in(&router, "alice", ADMIN_PASSWORD).await;

    // Only rbac.manage creates users: an analyst is refused.
    let analyst = sign_in(&router, "carol", ADMIN_PASSWORD).await;
    let new_user =
        serde_json::json!({"username": "Bob", "display_name": "Bob B", "role_id": "analyst"});
    let refused = post(
        &router,
        "/api/v1/access-control/users",
        &analyst,
        new_user.clone(),
    )
    .await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    // Bad input is 400 before anything is stored.
    let bad = post(
        &router,
        "/api/v1/access-control/users",
        &admin,
        serde_json::json!({"username": "b b", "display_name": "x", "role_id": "analyst"}),
    )
    .await;
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);

    let created = post(
        &router,
        "/api/v1/access-control/users",
        &admin,
        new_user.clone(),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    assert_eq!(
        created.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let created = body(created).await;
    assert_eq!(created["username"], "bob");
    let one_time = created["one_time_password"].as_str().unwrap().to_owned();
    assert!(one_time.len() >= 15);
    let again = post(&router, "/api/v1/access-control/users", &admin, new_user).await;
    assert_eq!(again.status(), StatusCode::CONFLICT);

    // Bob signs in with it: the session says so, carries no capability,
    // and every other route answers 403 password_change_required.
    let bob = sign_in(&router, "bob", &one_time).await;
    let session = body(get(&router, "/api/v1/session", &bob.0).await).await;
    assert_eq!(session["password_must_change"], true);
    assert_eq!(session["capabilities"], serde_json::json!([]));
    for uri in [
        "/api/v1/findings/groups",
        "/api/v1/agents",
        "/api/v1/dashboards",
        "/api/v1/me/home",
    ] {
        let blocked = get(&router, uri, &bob.0).await;
        assert_eq!(blocked.status(), StatusCode::FORBIDDEN, "{uri}");
        assert_eq!(
            body(blocked).await["code"],
            "password_change_required",
            "{uri}"
        );
    }

    // The current password is required, the new one must be long and new.
    let change = |current: &str, new: &str| serde_json::json!({"current_password": current, "new_password": new});
    let path = "/api/v1/session/password";
    let wrong = post(
        &router,
        path,
        &bob,
        change("not-the-one-time-password", "a-fine-long-new-password"),
    )
    .await;
    assert_eq!(body(wrong).await["code"], "invalid_current_password");
    let short = post(&router, path, &bob, change(&one_time, "short")).await;
    assert_eq!(body(short).await["code"], "weak_password");
    let same = post(&router, path, &bob, change(&one_time, &one_time)).await;
    assert_eq!(body(same).await["code"], "password_unchanged");
    // Another session of Bob's is signed out by the change.
    let other = sign_in(&router, "bob", &one_time).await;
    let new_password = "copper-lantern-river-sparrow-7";
    let done = post(&router, path, &bob, change(&one_time, new_password)).await;
    assert_eq!(done.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        get(&router, "/api/v1/session", &other.0).await.status(),
        StatusCode::UNAUTHORIZED
    );

    let session = body(get(&router, "/api/v1/session", &bob.0).await).await;
    assert_eq!(session["password_must_change"], false);
    assert_eq!(
        get(&router, "/api/v1/findings/groups", &bob.0)
            .await
            .status(),
        StatusCode::OK
    );
    sign_in(&router, "bob", new_password).await;

    // Self-service later needs the current password too.
    let stale = post(
        &router,
        path,
        &bob,
        change(&one_time, "yet-another-long-password"),
    )
    .await;
    assert_eq!(body(stale).await["code"], "invalid_current_password");

    let actions = audit_actions(&db).await;
    assert!(
        actions.contains(&("user.created".into(), "user".into())),
        "{actions:?}"
    );
    assert!(
        actions
            .iter()
            .any(|(action, _)| action == "auth.password.changed"),
        "{actions:?}"
    );
    db.drop().await;
}

#[tokio::test]
async fn guessing_the_current_password_is_throttled_like_sign_in() {
    if std::env::var_os("OPENVIBES_TEST_DATABASE_URL").is_none() {
        eprintln!("skipping: OPENVIBES_TEST_DATABASE_URL is unset");
        return;
    }
    let db = TestDb::create().await;
    platform_store::migrate(&mut db.pool.get().await.unwrap())
        .await
        .unwrap();
    local_user(&db, "dave", "viewer", 3).await;
    let router = authenticated_router(db.pool.clone(), ORIGIN);
    let dave = sign_in(&router, "dave", ADMIN_PASSWORD).await;
    let path = "/api/v1/session/password";
    let change = |current: &str| serde_json::json!({"current_password": current, "new_password": "a-long-enough-new-password"});
    // Five wrong guesses are refused one by one, as at sign-in ...
    for guess in 0..5 {
        let wrong = post(
            &router,
            path,
            &dave,
            change(&format!("guess-number-{guess}-wrong")),
        )
        .await;
        assert_eq!(
            body(wrong).await["code"],
            "invalid_current_password",
            "guess {guess}"
        );
    }
    // ... then the account is locked: even the right one is 429 now.
    let locked = post(&router, path, &dave, change(ADMIN_PASSWORD)).await;
    assert_eq!(locked.status(), StatusCode::TOO_MANY_REQUESTS);
    db.drop().await;
}
