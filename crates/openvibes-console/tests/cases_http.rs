//! Cases over HTTP, access: sessions, permissions, bearer tokens, CSRF,
//! cases.assign and the cases.read reach of a change.
//! Shared harness: `common/cases.rs`.

mod common;
use common::cases::*;

#[tokio::test]
async fn every_route_needs_a_session() {
    let fx = fixture!();
    let case = "00000000-0000-4000-8000-000000000000";
    let item = "00000000-0000-4000-8000-000000000001";
    for (method, uri) in [
        ("GET", "/api/v1/cases".to_owned()),
        ("GET", "/api/v1/case-list".to_owned()),
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
        ("GET", "/api/v1/case-list".to_owned(), None),
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
        &["admin".to_owned()],
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
            ("GET", "/api/v1/case-list"),
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

/// `cases.write` without `cases.assign`: setting or changing the assignee
/// is refused, every other change works. `cases.assign` is held or not,
/// whatever its reach: the case itself is already limited by the scope of
/// `cases.write` (roles step 3 decision).
#[tokio::test]
async fn writing_cases_without_cases_assign_cannot_set_the_assignee() {
    let fx = fixture!();
    let mut client = fx.db.pool.get().await.unwrap();
    let role = common::create_role(
        &mut client,
        "Case writer",
        &["cases.read", "cases.write", "alarms.read", "hosts.read"],
        platform_store::console_roles::Reach::All,
    )
    .await;
    const CARL: &str = "99999999-9999-4999-8999-99999999999c";
    user(
        &mut client,
        CARL,
        "99999999-9999-4999-8999-99999999999d",
        "carl",
        &role,
    )
    .await;
    drop(client);
    let carl = fx.session("carl").await;
    let alarm = json!([{"kind": "alarm", "ref": fx.web_alarm}]);
    let (status, _, _) = fx
        .send(
            &carl,
            "POST",
            "/api/v1/cases",
            Some(json!({"title": "Assigned", "items": alarm, "assignee_user_id": DAVE})),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "creating with an assignee");
    let case = fx.open(&carl, "Unassigned", alarm).await;
    let uri = case_uri(&case);
    let (status, _, _) = fx
        .send(
            &carl,
            "PUT",
            &uri,
            Some(put_body(&case, json!({"assignee_user_id": DAVE}))),
            Some(&version(&case)),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "changing the assignee");
    let (status, saved, _) = fx
        .send(
            &carl,
            "PUT",
            &uri,
            Some(put_body(
                &case,
                json!({"title": "Renamed", "severity": "high"}),
            )),
            Some(&version(&case)),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    assert_eq!(saved["title"], "Renamed");
    assert!(saved["assignee"].is_null());
    fx.db.drop().await;
}

/// A change is limited to what the caller can read: `cases.write` on every
/// host with `cases.read` on production only changes nothing outside it.
#[tokio::test]
async fn a_change_stays_inside_the_cases_read_scope() {
    let fx = fixture!();
    let mut client = fx.db.pool.get().await.unwrap();
    use platform_store::console_roles::Reach;
    let writer =
        common::create_role(&mut client, "Case writer", &["cases.write"], Reach::All).await;
    let reader = common::create_role(
        &mut client,
        "Prod case reader",
        &["cases.read"],
        Reach::Groups(vec![PROD.to_owned()]),
    )
    .await;
    let erin = "99999999-9999-4999-8999-999999999999";
    user(
        &mut client,
        erin,
        "aaaaaaaa-0000-4000-8000-000000000001",
        "erin",
        &writer,
    )
    .await;
    client
        .execute(
            "INSERT INTO console_role_bindings (binding_id, user_id, role_id, created_at, created_by)
             VALUES ('aaaaaaaa-0000-4000-8000-000000000002', $1::text::uuid, $2, now(), 'test')",
            &[&erin, &reader],
        )
        .await
        .unwrap();
    drop(client);
    let alice = fx.session("alice").await;
    let erin = fx.session("erin").await;
    // An empty case of Alice's: a global write scope would see it.
    let empty = fx.open(&alice, "Alice's", json!([])).await;
    let uri = case_uri(&empty);
    let (status, _) = fx.get(&erin, &uri).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, problem, _) = fx
        .send(
            &erin,
            "PUT",
            &uri,
            Some(put_body(&empty, json!({"title": "Mine now"}))),
            Some(&version(&empty)),
        )
        .await;
    assert_eq!(
        (status, problem["code"].clone()),
        (StatusCode::NOT_FOUND, json!("case_not_found"))
    );
    // Her own case takes no item from a host she cannot read.
    let own = fx
        .open(&erin, "Erin's", json!([{"kind": "host", "ref": WEB}]))
        .await;
    let (status, problem, _) = fx
        .send(
            &erin,
            "POST",
            &format!("{}/items", case_uri(&own)),
            Some(json!({"kind": "host", "ref": DB})),
            None,
        )
        .await;
    assert_eq!(
        (status, problem["code"].clone()),
        (StatusCode::NOT_FOUND, json!("item_not_found"))
    );
    fx.db.drop().await;
}
