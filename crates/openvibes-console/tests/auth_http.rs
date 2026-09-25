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
use platform_store::{
    self,
    console_auth::{NewLocalUser, create_local_user},
    ingest::{self, StoredFinding},
};
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
        let name = format!("ov_console_http_{:016x}", hasher.finish());
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
        admin
            .get()
            .await
            .unwrap()
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

async fn api_json(
    router: &axum::Router,
    method: &str,
    uri: &str,
    cookie: &str,
    csrf: &str,
    body: &str,
) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header(header::COOKIE, cookie)
                .header(header::ORIGIN, "https://console.example")
                .header("sec-fetch-site", "same-origin")
                .header("x-csrf-token", csrf)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn api_json_idempotent(
    router: &axum::Router,
    uri: &str,
    cookie: &str,
    csrf: &str,
    key: &str,
    body: &str,
) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::COOKIE, cookie)
                .header(header::ORIGIN, "https://console.example")
                .header("sec-fetch-site", "same-origin")
                .header("x-csrf-token", csrf)
                .header("idempotency-key", key)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn local_login_uses_one_use_preauth_and_returns_an_active_session() {
    if std::env::var_os("OPENVIBES_TEST_DATABASE_URL").is_none() {
        eprintln!("skipping PostgreSQL auth journey: OPENVIBES_TEST_DATABASE_URL is unset");
        return;
    }
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    let enrolled_at = Utc::now();
    for id in [
        "agent.00000000-0000-4000-8000-000000000101",
        "agent.00000000-0000-4000-8000-000000000102",
    ] {
        client
            .execute(
                "INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at)
                 VALUES ($1, 'active', $2, $2)",
                &[&id, &enrolled_at],
            )
            .await
            .unwrap();
    }
    for (serial, issued_at) in [(1_u8, enrolled_at), (2_u8, enrolled_at)] {
        client
            .execute(
                "INSERT INTO certificates (serial, agent_id, spki_sha256, not_before,
                    not_after, issued_at, chain_pem)
                 VALUES ($1, 'agent.00000000-0000-4000-8000-000000000101',
                    $2, $3, $4, $3, 'private certificate chain')",
                &[
                    &&[serial; 16][..],
                    &&[serial; 32][..],
                    &issued_at,
                    &(issued_at + chrono::Duration::days(90)),
                ],
            )
            .await
            .unwrap();
    }
    platform_store::ensure_partitions(&client, enrolled_at.date_naive(), 1)
        .await
        .unwrap();
    for (index, severity) in [(101, "critical"), (102, "high")] {
        let agent_id = format!("agent.00000000-0000-4000-8000-000000000{index}");
        ingest::store_findings(
            &mut client,
            &agent_id,
            &[StoredFinding {
                finding_id: format!("finding-{index}"),
                scan_id: format!("scan-{index}"),
                rule_set_id: "base".into(),
                rule_id: "credential".into(),
                rule_version: 1,
                observed_at: enrolled_at,
                severity: severity.into(),
                confidence: 95,
                message: format!("fixture finding {index}"),
                evidence: vec!["package=fixture".into()],
            }],
            enrolled_at,
        )
        .await
        .unwrap();
    }
    let password = "violet-satellite-mountain-otter-2026";
    let normalized = NormalizedPassword::new(password).unwrap();
    let phc = hash_password(&normalized).unwrap();
    create_local_user(
        &mut client,
        &NewLocalUser {
            user_id: "11111111-1111-4111-8111-111111111111",
            binding_id: "22222222-2222-4222-8222-222222222222",
            username: "alice",
            display_name: "Alice Example",
            password_phc: phc.as_str(),
            role_id: "admin",
            actor_id: "test-bootstrap",
            now: Utc::now(),
        },
    )
    .await
    .unwrap();
    drop(client);

    let router = authenticated_router(db.pool.clone(), "https://console.example");
    let (preauth_cookie, browser_cookie, csrf) = new_preauth(&router).await;
    let address: SocketAddr = "127.0.0.1:4242".parse().unwrap();
    let login = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/v1/login")
                .header(header::ORIGIN, "https://console.example")
                .header("sec-fetch-site", "same-origin")
                .header("x-csrf-token", csrf)
                .header(
                    header::COOKIE,
                    format!("{preauth_cookie}; {browser_cookie}"),
                )
                .header(header::CONTENT_TYPE, "application/json")
                .extension(ConnectInfo(TrustedPeer::new(address)))
                .body(Body::from(format!(
                    "{{\"username\":\"alice\",\"password\":\"{password}\"}}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    assert_eq!(
        cookie_pair(&login, "__Host-openvibes-session=")
            .split('=')
            .count(),
        2
    );
    assert_eq!(
        login.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let session_cookie = cookie_pair(&login, "__Host-openvibes-session=");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/session")
                .header(header::COOKIE, session_cookie.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let session: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 16_384).await.unwrap()).unwrap();
    assert_eq!(session["principal"]["username"], "alice");
    assert_eq!(session["authentication_method"], "local_password");
    assert!(
        session["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|capability| {
                capability["permission"] == "rbac.manage" && capability["scope"]["kind"] == "global"
            })
    );
    let create_group = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/access-control/asset-groups")
                .header(header::COOKIE, session_cookie.clone())
                .header(header::ORIGIN, "https://console.example")
                .header("sec-fetch-site", "same-origin")
                .header("x-csrf-token", session["csrf_token"].as_str().unwrap())
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"name":"Production","selectors":[{"key":"env","value":"prod"}]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_group.status(), StatusCode::CREATED);
    let group: Value =
        serde_json::from_slice(&to_bytes(create_group.into_body(), 8192).await.unwrap()).unwrap();
    let group_id = group["asset_group_id"].as_str().unwrap();
    let update_group=router.clone().oneshot(Request::builder()
        .method("PUT").uri(format!("/api/v1/access-control/asset-groups/{group_id}"))
        .header(header::COOKIE,session_cookie.clone()).header(header::ORIGIN,"https://console.example")
        .header("sec-fetch-site","same-origin").header("x-csrf-token",session["csrf_token"].as_str().unwrap())
        .header(header::CONTENT_TYPE,"application/json")
        .body(Body::from(r#"{"name":"Production Fleet","selectors":[{"key":"env","value":"prod"},{"key":"region","value":"north"}]}"#)).unwrap()).await.unwrap();
    assert_eq!(update_group.status(), StatusCode::OK);
    let updated: Value =
        serde_json::from_slice(&to_bytes(update_group.into_body(), 8192).await.unwrap()).unwrap();
    assert_eq!(updated["selectors"].as_array().unwrap().len(), 2);
    let access = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/access-control")
                .header(header::COOKIE, session_cookie.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(access.status(), StatusCode::OK);
    let access: Value =
        serde_json::from_slice(&to_bytes(access.into_body(), 16_384).await.unwrap()).unwrap();
    assert!(
        access["roles"]
            .as_array()
            .is_some_and(|roles| !roles.is_empty())
    );
    assert!(
        access["bindings"]
            .as_array()
            .is_some_and(|bindings| !bindings.is_empty())
    );
    assert!(access.get("credentials").is_none());
    let user_id = access["users"][0]["user_id"].as_str().unwrap();
    let binding_response = api_json(
        &router,
        "POST",
        "/api/v1/access-control/bindings",
        &session_cookie,
        session["csrf_token"].as_str().unwrap(),
        &format!(
            "{{\"user_id\":\"{user_id}\",\"role_id\":\"viewer\",\"asset_group_id\":\"{group_id}\"}}"
        ),
    )
    .await;
    assert_eq!(
        binding_response.status(),
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&to_bytes(binding_response.into_body(), 4096).await.unwrap())
    );
    let agent_id = "agent.00000000-0000-4000-8000-000000000101";
    let proposal_a = r#"{"tags":[{"key":"env","value":"prod"},{"key":"region","value":"north"}]}"#;
    let preview_a = api_json(
        &router,
        "POST",
        &format!("/api/v1/agents/{agent_id}/tags/preview"),
        &session_cookie,
        session["csrf_token"].as_str().unwrap(),
        proposal_a,
    )
    .await;
    assert_eq!(preview_a.status(), StatusCode::OK);
    let preview_a: Value =
        serde_json::from_slice(&to_bytes(preview_a.into_body(), 16_384).await.unwrap()).unwrap();
    assert_eq!(preview_a["gained_groups"][0]["name"], "Production Fleet");
    assert_eq!(preview_a["gained_bindings"][0]["role_id"], "viewer");
    let proposal_b = r#"{"tags":[{"key":"env","value":"test"}]}"#;
    let preview_b = api_json(
        &router,
        "POST",
        &format!("/api/v1/agents/{agent_id}/tags/preview"),
        &session_cookie,
        session["csrf_token"].as_str().unwrap(),
        proposal_b,
    )
    .await;
    assert_eq!(preview_b.status(), StatusCode::OK);
    let preview_b: Value =
        serde_json::from_slice(&to_bytes(preview_b.into_body(), 16_384).await.unwrap()).unwrap();
    let apply_b = api_json(
        &router,
        "PUT",
        &format!("/api/v1/agents/{agent_id}/tags"),
        &session_cookie,
        session["csrf_token"].as_str().unwrap(),
        &format!(
            "{{\"tags\":[{{\"key\":\"env\",\"value\":\"test\"}}],\"preview_token\":\"{}\"}}",
            preview_b["preview_token"].as_str().unwrap()
        ),
    )
    .await;
    assert_eq!(apply_b.status(), StatusCode::NO_CONTENT);
    let stale_a=api_json(&router,"PUT",&format!("/api/v1/agents/{agent_id}/tags"),&session_cookie,session["csrf_token"].as_str().unwrap(),&format!("{{\"tags\":[{{\"key\":\"env\",\"value\":\"prod\"}},{{\"key\":\"region\",\"value\":\"north\"}}],\"preview_token\":\"{}\"}}",preview_a["preview_token"].as_str().unwrap())).await;
    assert_eq!(stale_a.status(), StatusCode::CONFLICT);
    let refreshed: Value =
        serde_json::from_slice(&to_bytes(stale_a.into_body(), 16_384).await.unwrap()).unwrap();
    assert_eq!(refreshed["current"][0]["value"], "test");
    let apply_a=api_json(&router,"PUT",&format!("/api/v1/agents/{agent_id}/tags"),&session_cookie,session["csrf_token"].as_str().unwrap(),&format!("{{\"tags\":[{{\"key\":\"env\",\"value\":\"prod\"}},{{\"key\":\"region\",\"value\":\"north\"}}],\"preview_token\":\"{}\"}}",refreshed["preview_token"].as_str().unwrap())).await;
    assert_eq!(apply_a.status(), StatusCode::NO_CONTENT);
    let audit_client = db.pool.get().await.unwrap();
    let audited: i64 = audit_client
        .query_one(
            "SELECT count(*) FROM audit_log WHERE action='agent.tags.changed' AND target_id=$1",
            &[&agent_id],
        )
        .await
        .unwrap()
        .get(0);
    assert!(
        audited >= 2,
        "both successful tag replacements must be audited"
    );
    let token_creation_body = r#"{"label":"http journey","expires_in_hours":24,"max_uses":2}"#;
    let idempotency_key = "console-http-token-create-key-01";
    let created_token = api_json_idempotent(
        &router,
        "/api/v1/enrollment-tokens",
        &session_cookie,
        session["csrf_token"].as_str().unwrap(),
        idempotency_key,
        token_creation_body,
    )
    .await;
    assert_eq!(created_token.status(), StatusCode::CREATED);
    assert_eq!(
        created_token.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let created_token: Value =
        serde_json::from_slice(&to_bytes(created_token.into_body(), 8192).await.unwrap()).unwrap();
    let token_secret = created_token["token"].as_str().unwrap();
    assert_eq!(token_secret.len(), 43);
    let token_id = created_token["token_id"].as_str().unwrap();
    let replay = api_json_idempotent(
        &router,
        "/api/v1/enrollment-tokens",
        &session_cookie,
        session["csrf_token"].as_str().unwrap(),
        idempotency_key,
        token_creation_body,
    )
    .await;
    assert_eq!(replay.status(), StatusCode::OK);
    let replay: Value =
        serde_json::from_slice(&to_bytes(replay.into_body(), 8192).await.unwrap()).unwrap();
    assert_eq!(replay["replayed"], true);
    assert_eq!(replay["secret_available"], false);
    assert!(replay["token"].is_null());
    assert_eq!(replay["token_id"], token_id);
    let conflict = api_json_idempotent(
        &router,
        "/api/v1/enrollment-tokens",
        &session_cookie,
        session["csrf_token"].as_str().unwrap(),
        idempotency_key,
        r#"{"label":"other","expires_in_hours":24,"max_uses":2}"#,
    )
    .await;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    let token_list = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/enrollment-tokens")
                .header(header::COOKIE, session_cookie.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(token_list.status(), StatusCode::OK);
    assert_eq!(
        token_list.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let token_list: Value =
        serde_json::from_slice(&to_bytes(token_list.into_body(), 8192).await.unwrap()).unwrap();
    assert_eq!(token_list["items"][0]["token_id"], token_id);
    assert!(token_list["items"][0].get("token").is_none());
    let token_detail = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/enrollment-tokens/{token_id}"))
                .header(header::COOKIE, session_cookie.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(token_detail.status(), StatusCode::OK);
    assert_eq!(
        token_detail.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let token_detail: Value =
        serde_json::from_slice(&to_bytes(token_detail.into_body(), 8192).await.unwrap()).unwrap();
    assert_eq!(token_detail["token_id"], token_id);
    assert!(token_detail.get("token").is_none());
    let revoked_token = api_json(
        &router,
        "POST",
        &format!("/api/v1/enrollment-tokens/{token_id}/revoke"),
        &session_cookie,
        session["csrf_token"].as_str().unwrap(),
        "",
    )
    .await;
    assert_eq!(revoked_token.status(), StatusCode::NO_CONTENT);
    let admin_binding_id = access["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|binding| binding["role_id"] == "admin" && binding["asset_group_id"].is_null())
        .unwrap()["binding_id"]
        .as_str()
        .unwrap();
    let last_admin_revoke = router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/api/v1/access-control/bindings/{admin_binding_id}"
                ))
                .header(header::COOKIE, session_cookie.clone())
                .header(header::ORIGIN, "https://console.example")
                .header("sec-fetch-site", "same-origin")
                .header("x-csrf-token", session["csrf_token"].as_str().unwrap())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(last_admin_revoke.status(), StatusCode::CONFLICT);
    let new_binding = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/access-control/bindings")
                .header(header::COOKIE, session_cookie.clone())
                .header(header::ORIGIN, "https://console.example")
                .header("sec-fetch-site", "same-origin")
                .header("x-csrf-token", session["csrf_token"].as_str().unwrap())
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(
                    r#"{{"user_id":"{}","role_id":"viewer"}}"#,
                    session["principal"]["id"].as_str().unwrap()
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(new_binding.status(), StatusCode::CREATED);
    let new_binding: Value =
        serde_json::from_slice(&to_bytes(new_binding.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(new_binding["role_id"], "viewer");
    assert_eq!(new_binding["asset_group_id"], Value::Null);
    let revoke_binding = router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/api/v1/access-control/bindings/{}",
                    new_binding["binding_id"].as_str().unwrap()
                ))
                .header(header::COOKIE, session_cookie.clone())
                .header(header::ORIGIN, "https://console.example")
                .header("sec-fetch-site", "same-origin")
                .header("x-csrf-token", session["csrf_token"].as_str().unwrap())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(revoke_binding.status(), StatusCode::NO_CONTENT);
    let binding_events = db
        .pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT count(*) FROM audit_log WHERE action IN ('rbac.binding.created', 'rbac.binding.revoked')",
            &[],
        )
        .await
        .unwrap()
        .get::<_, i64>(0);
    assert_eq!(binding_events, 3);
    let unauthenticated_summary = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/agents/summary")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthenticated_summary.status(), StatusCode::UNAUTHORIZED);
    let summary = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/agents/summary")
                .header(header::COOKIE, session_cookie.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(summary.status(), StatusCode::OK);
    let summary: Value =
        serde_json::from_slice(&to_bytes(summary.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(summary["total"], 2);
    let first_page = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/agents?limit=1")
                .header(header::COOKIE, session_cookie.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first_page.status(), StatusCode::OK);
    let first_page: Value =
        serde_json::from_slice(&to_bytes(first_page.into_body(), 8192).await.unwrap()).unwrap();
    assert_eq!(
        first_page["items"][0]["id"],
        "agent.00000000-0000-4000-8000-000000000101"
    );
    let cursor = first_page["next_cursor"].as_str().unwrap();
    let second_page = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/agents?limit=1&cursor={cursor}"))
                .header(header::COOKIE, session_cookie.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second_page.status(), StatusCode::OK);
    let second_page: Value =
        serde_json::from_slice(&to_bytes(second_page.into_body(), 8192).await.unwrap()).unwrap();
    assert_eq!(
        second_page["items"][0]["id"],
        "agent.00000000-0000-4000-8000-000000000102"
    );
    let mismatched_cursor = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/agents?state=active&limit=1&cursor={cursor}"
                ))
                .header(header::COOKIE, session_cookie.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(mismatched_cursor.status(), StatusCode::BAD_REQUEST);
    let agent_detail = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/agents/agent.00000000-0000-4000-8000-000000000101")
                .header(header::COOKIE, session_cookie.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(agent_detail.status(), StatusCode::OK);
    let agent_detail: Value =
        serde_json::from_slice(&to_bytes(agent_detail.into_body(), 16_384).await.unwrap()).unwrap();
    assert_eq!(agent_detail["certificates"].as_array().unwrap().len(), 2);
    assert!(
        !agent_detail
            .to_string()
            .contains("private certificate chain")
    );
    let certificate_page = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/agents/agent.00000000-0000-4000-8000-000000000101/certificates?limit=1")
                .header(header::COOKIE, session_cookie.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(certificate_page.status(), StatusCode::OK);
    let certificate_page: Value =
        serde_json::from_slice(&to_bytes(certificate_page.into_body(), 8192).await.unwrap())
            .unwrap();
    assert_eq!(certificate_page["items"].as_array().unwrap().len(), 1);
    let certificate_cursor = certificate_page["next_cursor"].as_str().unwrap();
    let next_certificates = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/agents/agent.00000000-0000-4000-8000-000000000101/certificates?limit=1&cursor={certificate_cursor}"
                ))
                .header(header::COOKIE, session_cookie.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(next_certificates.status(), StatusCode::OK);
    let next_certificates: Value =
        serde_json::from_slice(&to_bytes(next_certificates.into_body(), 8192).await.unwrap())
            .unwrap();
    assert_eq!(next_certificates["items"].as_array().unwrap().len(), 1);
    let wrong_agent_cursor = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/agents/agent.00000000-0000-4000-8000-000000000102/certificates?cursor={certificate_cursor}"
                ))
                .header(header::COOKIE, session_cookie.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wrong_agent_cursor.status(), StatusCode::BAD_REQUEST);
    let findings_summary = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/findings/summary")
                .header(header::COOKIE, session_cookie.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(findings_summary.status(), StatusCode::OK);
    let findings_summary: Value =
        serde_json::from_slice(&to_bytes(findings_summary.into_body(), 4096).await.unwrap())
            .unwrap();
    assert_eq!(findings_summary["total"], 2);
    assert_eq!(findings_summary["critical"], 1);
    let first_findings = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/findings/latest?limit=1")
                .header(header::COOKIE, session_cookie.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first_findings.status(), StatusCode::OK);
    let first_findings: Value =
        serde_json::from_slice(&to_bytes(first_findings.into_body(), 8192).await.unwrap()).unwrap();
    assert_eq!(first_findings["items"].as_array().unwrap().len(), 1);
    let findings_cursor = first_findings["next_cursor"].as_str().unwrap();
    let second_findings = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/findings/latest?limit=1&cursor={findings_cursor}"
                ))
                .header(header::COOKIE, session_cookie.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second_findings.status(), StatusCode::OK);
    let second_findings: Value =
        serde_json::from_slice(&to_bytes(second_findings.into_body(), 8192).await.unwrap())
            .unwrap();
    assert_eq!(second_findings["items"].as_array().unwrap().len(), 1);
    let severity_mismatch = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/findings/latest?severity=critical&cursor={findings_cursor}"
                ))
                .header(header::COOKIE, session_cookie.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(severity_mismatch.status(), StatusCode::BAD_REQUEST);
    let latest_detail = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(
                    "/api/v1/findings/latest/agent.00000000-0000-4000-8000-000000000101/base/credential",
                )
                .header(header::COOKIE, session_cookie.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(latest_detail.status(), StatusCode::OK);
    let latest_detail: Value =
        serde_json::from_slice(&to_bytes(latest_detail.into_body(), 8192).await.unwrap()).unwrap();
    assert_eq!(latest_detail["severity"], "critical");
    assert_eq!(latest_detail["rule_set_id"], "base");
    let since = enrolled_at.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    let first_history = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/findings/history?since={since}&limit=1"))
                .header(header::COOKIE, session_cookie.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first_history.status(), StatusCode::OK);
    let first_history: Value =
        serde_json::from_slice(&to_bytes(first_history.into_body(), 8192).await.unwrap()).unwrap();
    assert_eq!(first_history["items"][0]["id"], "finding-101");
    let history_cursor = first_history["next_cursor"].as_str().unwrap();
    let second_history = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/findings/history?since={since}&limit=1&cursor={history_cursor}"
                ))
                .header(header::COOKIE, session_cookie.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second_history.status(), StatusCode::OK);
    let second_history: Value =
        serde_json::from_slice(&to_bytes(second_history.into_body(), 8192).await.unwrap()).unwrap();
    assert_eq!(second_history["items"][0]["id"], "finding-102");
    let first_event_day = first_history["items"][0]["observed_day"].as_str().unwrap();
    let history_detail = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/findings/history/{first_event_day}/finding-101"
                ))
                .header(header::COOKIE, session_cookie.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(history_detail.status(), StatusCode::OK);
    let history_without_bound = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/findings/history")
                .header(header::COOKIE, session_cookie.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(history_without_bound.status(), StatusCode::BAD_REQUEST);
    let retention = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/audit-retention")
                .header(header::COOKIE, session_cookie.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(retention.status(), StatusCode::OK);
    assert_eq!(retention.headers().get(header::ETAG).unwrap(), "\"1\"");
    let retention: Value =
        serde_json::from_slice(&to_bytes(retention.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(retention["retention_days"], 365);
    let audit_events = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/audit-events?since=2000-01-01T00%3A00%3A00Z&limit=1")
                .header(header::COOKIE, session_cookie.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(audit_events.status(), StatusCode::OK);
    let audit_events: Value =
        serde_json::from_slice(&to_bytes(audit_events.into_body(), 16_384).await.unwrap()).unwrap();
    assert_eq!(audit_events["items"].as_array().unwrap().len(), 1);
    assert!(audit_events["items"][0].get("detail").is_none());
    assert!(audit_events["items"][0].get("source_address").is_none());
    assert!(audit_events["items"][0].get("user_agent").is_none());
    assert!(audit_events["next_cursor"].is_string());
    db.pool
        .get()
        .await
        .unwrap()
        .execute(
            "INSERT INTO audit_log(actor, action, target, result, detail)
         VALUES ('=1+1', 'audit.test', 'csv-check', 'success', '{\"private\":true}'::jsonb)",
            &[],
        )
        .await
        .unwrap();
    let spool_prefix = format!("openvibes-audit-{}-", std::process::id());
    let export = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/audit-export.csv?since=2000-01-01T00%3A00%3A00Z&actor=%3D1%2B1")
                .header(header::COOKIE, session_cookie.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(export.status(), StatusCode::OK);
    assert_eq!(
        export.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(
        export.headers().get(header::CONTENT_TYPE).unwrap(),
        "text/csv; charset=utf-8"
    );
    let csv = to_bytes(export.into_body(), 1024 * 1024).await.unwrap();
    assert!(
        std::fs::read_dir(std::env::temp_dir())
            .unwrap()
            .filter_map(Result::ok)
            .all(|entry| !entry
                .file_name()
                .to_string_lossy()
                .starts_with(&spool_prefix))
    );
    let csv_text = std::str::from_utf8(&csv).unwrap();
    assert!(csv_text.contains("\"'=1+1\""));
    assert!(!csv_text.contains("private"));
    let export_audit = db
        .pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT detail->>'actor', detail->>'row_count', detail->>'sha256', detail::text
         FROM audit_log WHERE action = 'audit.exported'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(export_audit.get::<_, &str>(0), "=1+1");
    assert_eq!(export_audit.get::<_, &str>(1), "1");
    assert_eq!(export_audit.get::<_, &str>(2).len(), 64);
    assert!(!export_audit.get::<_, &str>(3).contains("private"));
    let retention_update = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/audit-retention")
                .header(header::COOKIE, session_cookie.clone())
                .header(header::ORIGIN, "https://console.example")
                .header("sec-fetch-site", "same-origin")
                .header("x-csrf-token", session["csrf_token"].as_str().unwrap())
                .header(header::IF_MATCH, "\"1\"")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"retention_days":180}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(retention_update.status(), StatusCode::OK);
    assert_eq!(
        retention_update.headers().get(header::ETAG).unwrap(),
        "\"2\""
    );
    let retention_update: Value =
        serde_json::from_slice(&to_bytes(retention_update.into_body(), 4096).await.unwrap())
            .unwrap();
    assert_eq!(retention_update["retention_days"], 180);
    let stale_retention = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/audit-retention")
                .header(header::COOKIE, session_cookie.clone())
                .header(header::ORIGIN, "https://console.example")
                .header("sec-fetch-site", "same-origin")
                .header("x-csrf-token", session["csrf_token"].as_str().unwrap())
                .header(header::IF_MATCH, "\"1\"")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"retention_days":30}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(stale_retention.status(), StatusCode::PRECONDITION_FAILED);
    let missing_csrf = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/audit-retention")
                .header(header::COOKIE, session_cookie.clone())
                .header(header::ORIGIN, "https://console.example")
                .header("sec-fetch-site", "same-origin")
                .header(header::IF_MATCH, "\"2\"")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"retention_days":30}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_csrf.status(), StatusCode::FORBIDDEN);
    let audit_count = db
        .pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT count(*) FROM audit_log WHERE action = 'audit.retention.updated'",
            &[],
        )
        .await
        .unwrap()
        .get::<_, i64>(0);
    assert_eq!(audit_count, 1);
    let old_session_cookie = session_cookie.clone();
    let (preauth_cookie, browser_cookie, csrf) = new_preauth(&router).await;
    let rotated_login = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/v1/login")
                .header(header::ORIGIN, "https://console.example")
                .header("sec-fetch-site", "same-origin")
                .header("x-csrf-token", &csrf)
                .header(
                    header::COOKIE,
                    format!("{preauth_cookie}; {browser_cookie}; {old_session_cookie}"),
                )
                .header(header::CONTENT_TYPE, "application/json")
                .extension(ConnectInfo(TrustedPeer::new(address)))
                .body(Body::from(format!(
                    "{{\"username\":\"alice\",\"password\":\"{password}\"}}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rotated_login.status(), StatusCode::OK);
    let session_cookie = cookie_pair(&rotated_login, "__Host-openvibes-session=");
    assert_ne!(session_cookie, old_session_cookie);
    let old_session = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/session")
                .header(header::COOKIE, old_session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(old_session.status(), StatusCode::UNAUTHORIZED);
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/session")
                .header(header::COOKIE, session_cookie.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let session: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 16_384).await.unwrap()).unwrap();

    let revoke_agent = api_json(
        &router,
        "POST",
        "/api/v1/agents/agent.00000000-0000-4000-8000-000000000101/revoke",
        &session_cookie,
        session["csrf_token"].as_str().unwrap(),
        r#"{"reason":"retired by operator"}"#,
    )
    .await;
    assert_eq!(revoke_agent.status(), StatusCode::NO_CONTENT);
    let revoke_audit: i64 = db
        .pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT count(*) FROM audit_log WHERE action='agent.revoked' AND target_id=$1",
            &[&"agent.00000000-0000-4000-8000-000000000101"],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(revoke_audit, 1);

    let logout = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/v1/logout")
                .header(header::ORIGIN, "https://console.example")
                .header("sec-fetch-site", "same-origin")
                .header("x-csrf-token", session["csrf_token"].as_str().unwrap())
                .header(header::COOKIE, session_cookie.clone())
                .extension(ConnectInfo(TrustedPeer::new(address)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(logout.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        logout.headers().get_all(header::SET_COOKIE).iter().count(),
        1
    );
    let after_logout = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/session")
                .header(header::COOKIE, session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(after_logout.status(), StatusCode::UNAUTHORIZED);

    let (preauth_cookie, browser_cookie, csrf) = new_preauth(&router).await;
    let failed_login = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/v1/login")
                .header(header::ORIGIN, "https://console.example")
                .header("sec-fetch-site", "same-origin")
                .header("x-csrf-token", &csrf)
                .header(
                    header::COOKIE,
                    format!("{preauth_cookie}; {browser_cookie}"),
                )
                .header(header::CONTENT_TYPE, "application/json")
                .extension(ConnectInfo(TrustedPeer::new(address)))
                .body(Body::from(
                    r#"{"username":"alice","password":"wrong password"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(failed_login.status(), StatusCode::UNAUTHORIZED);
    assert!(!failed_login.headers().contains_key(header::SET_COOKIE));
    let failed_body: Value =
        serde_json::from_slice(&to_bytes(failed_login.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(failed_body["code"], "authentication_failed");

    let (preauth_cookie, browser_cookie, csrf) = new_preauth(&router).await;
    let missing_login = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/v1/login")
                .header(header::ORIGIN, "https://console.example")
                .header("sec-fetch-site", "same-origin")
                .header("x-csrf-token", &csrf)
                .header(
                    header::COOKIE,
                    format!("{preauth_cookie}; {browser_cookie}"),
                )
                .header(header::CONTENT_TYPE, "application/json")
                .extension(ConnectInfo(TrustedPeer::new(address)))
                .body(Body::from(
                    r#"{"username":"nobody","password":"wrong password"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_login.status(), StatusCode::UNAUTHORIZED);
    let missing_body: Value =
        serde_json::from_slice(&to_bytes(missing_login.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(missing_body["code"], failed_body["code"]);
    assert_eq!(missing_body["title"], failed_body["title"]);
    let client = db.pool.get().await.unwrap();
    let failures: i64 = client
        .query_one(
            "SELECT count(*) FROM audit_log WHERE action = 'auth.login.failed'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(failures, 2);
    let logouts: i64 = client
        .query_one(
            "SELECT count(*) FROM audit_log WHERE action = 'auth.logout.succeeded'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(logouts, 1);
    let throttles: i64 = client
        .query_one(
            "SELECT count(*) FROM console_auth_throttle WHERE failures = 1",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(throttles, 2);
    drop(client);
    db.drop().await;
}
