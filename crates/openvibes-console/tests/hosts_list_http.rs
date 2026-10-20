//! `GET /api/v1/hosts`: validation, shape and counts, reach, and problem
//! counts that follow the caller's permissions.

use axum::http::StatusCode;
use platform_store::console_roles::Reach;
use serde_json::Value;

mod common;
use common::people::{Fx, WIN};

const W1: &str = "agent.00000000-0000-4000-8000-0000000000a1";
const W2: &str = "agent.00000000-0000-4000-8000-0000000000a2";
const L1: &str = "agent.00000000-0000-4000-8000-0000000000b1";
const URL: &str = "/api/v1/hosts";

/// Two Windows hosts in `win` (W1 has an open alarm and two critical
/// vulnerabilities) and one Linux host in `other`; returns the id of `other`.
async fn seed(fx: &Fx) -> String {
    let client = fx.db.pool.get().await.unwrap();
    platform_store::ensure_partitions(
        &client,
        chrono::Utc::now().date_naive() - chrono::Duration::days(1),
        2,
    )
    .await
    .unwrap();
    client
        .batch_execute(&format!(
            "INSERT INTO agents (agent_id, status, enrolled_at, hostname, last_seen_at, os_id, os_version, scanner_version) VALUES
                ('{W1}', 'active', now(), 'win-01', now(), 'windows', '11', '0.4.1'),
                ('{W2}', 'active', now(), 'win-02', now() - interval '3 days', 'windows', '11', '0.4.2'),
                ('{L1}', 'active', now(), 'lin-01', now(), 'debian', '12', '0.4.2');
             INSERT INTO console_host_group_members (asset_group_id, agent_id, added_at, added_by)
                VALUES ('{WIN}', '{W1}', now(), 't'), ('{WIN}', '{W2}', now(), 't');
             INSERT INTO host_vulnerability_counts (agent_id, no_fix, critical, important, moderate, low, unrated, reboot, counted_at)
                VALUES ('{W1}', 0, 2, 0, 0, 0, 0, 0, now());
             INSERT INTO alarms (first_seen_day, agent_id, alarm_id, rule_set_id, rule_set_version, rule_id, rule_version,
                                 severity, confidence, message, first_seen, last_seen, count, process, ancestors,
                                 received_at, state, note)
                VALUES ((now() AT TIME ZONE 'UTC')::date, '{W1}', 'a1', 'rs', 1, 'r', 1, 'high', 50, 'm',
                        now(), now(), 1, '{{}}', '[]', now(), 'open', 'n')"
        ))
        .await
        .unwrap();
    common::manual_group(&client, "Other", &[L1]).await
}

fn ids(body: &Value) -> Vec<&str> {
    body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_str().unwrap())
        .collect()
}

#[tokio::test]
async fn every_parameter_is_validated_and_named() {
    let Some(fx) = Fx::new().await else { return };
    let long = "x".repeat(201);
    let bad = [
        ("status=up", "status"),
        ("os=mac", "os"),
        ("group=nope", "group"),
        ("problems=some", "problems"),
        ("agent=newer", "agent"),
        ("sort=colour", "sort"),
        ("dir=up", "dir"),
        ("offset=-1", "offset"),
        ("offset=100001", "offset"),
        ("offset=x", "offset"),
        ("limit=0", "limit"),
        ("limit=101", "limit"),
        ("limit=x", "limit"),
        ("label=%00", "label"),
        (
            "label=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "label",
        ),
    ];
    for (query, field) in bad {
        let (status, body) = fx
            .call(&fx.admin, "GET", &format!("{URL}?{query}"), None)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}");
        assert_eq!(body["code"], "invalid_query", "{query}");
        assert_eq!(body["field_errors"][0]["field"], field, "{query}");
    }
    let (status, body) = fx
        .call(&fx.admin, "GET", &format!("{URL}?q={long}"), None)
        .await;
    assert_eq!(
        (status, &body["field_errors"][0]["field"]),
        (StatusCode::BAD_REQUEST, &"q".into())
    );
    let (status, _) = fx
        .call(&fx.admin, "GET", &format!("{URL}?surprise=1"), None)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    for ok in [
        "limit=100&offset=100000",
        "status=online&os=windows&problems=none&agent=older&sort=problems&dir=desc",
    ] {
        let (status, _) = fx
            .call(&fx.admin, "GET", &format!("{URL}?{ok}"), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{ok}");
    }
    // An unknown group is an empty result, not an error.
    let (status, body) = fx
        .call(
            &fx.admin,
            "GET",
            &format!("{URL}?group=99999999-9999-4999-8999-999999999999"),
            None,
        )
        .await;
    assert_eq!((status, body["total"].clone()), (StatusCode::OK, 0.into()));
    // No session, no list.
    let request = axum::http::Request::builder()
        .uri(URL)
        .body(axum::body::Body::empty())
        .unwrap();
    let response = tower::ServiceExt::oneshot(fx.router.clone(), request)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    fx.db.drop().await;
}

#[tokio::test]
async fn an_administrator_sees_rows_counts_and_a_summary() {
    let Some(fx) = Fx::new().await else { return };
    let other = seed(&fx).await;
    let (status, body) = fx.call(&fx.admin, "GET", URL, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ids(&body), [L1, W1, W2]);
    assert_eq!(body["total"], 3);
    assert!(body["latest_agent_version"].is_null());
    assert!(body["generated_at"].is_string());
    let w1 = &body["items"][1];
    assert_eq!(w1["hostname"], "win-01");
    assert_eq!(w1["os"]["family"], "windows");
    assert_eq!(w1["status"], "online");
    assert_eq!(w1["groups"][0]["name"], "win");
    assert_eq!(w1["groups"][0]["kind"], "manual");
    assert_eq!(w1["group_count"], 1);
    assert_eq!(w1["problems"]["open_alarms"], 1);
    assert_eq!(w1["problems"]["critical"], 2);
    assert_eq!(w1["agent"]["version"], "0.4.1");
    assert_eq!(w1["alarms_off"], false);
    assert!(w1["agent"]["older"].is_null());
    assert_eq!(body["summary"]["online"], 2);
    let status_count = |v: &str| {
        body["counts"]["status"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["value"] == v)
            .unwrap()["count"]
            .clone()
    };
    assert_eq!(
        (status_count("online"), status_count("offline")),
        (2.into(), 1.into())
    );
    // Count values are the URL's spelling, so a chosen value filters.
    let problems: Vec<(&str, i64)> = body["counts"]["problems"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| (c["value"].as_str().unwrap(), c["count"].as_i64().unwrap()))
        .collect();
    assert_eq!(problems, [("critical", 1), ("alarms", 1), ("none", 2)]);
    let groups = body["counts"]["group"].as_array().unwrap();
    assert!(
        groups
            .iter()
            .any(|g| g["value"] == other.as_str() && g["name"] == "Other" && g["count"] == 1)
    );

    let (_, body) = fx
        .call(
            &fx.admin,
            "GET",
            &format!("{URL}?os=windows&problems=critical"),
            None,
        )
        .await;
    assert_eq!(ids(&body), [W1]);
    let (_, body) = fx
        .call(&fx.admin, "GET", &format!("{URL}?problems=alarms"), None)
        .await;
    assert_eq!(ids(&body), [W1]);
    let (_, body) = fx
        .call(
            &fx.admin,
            "GET",
            &format!("{URL}?sort=host&dir=desc&limit=1&offset=1"),
            None,
        )
        .await;
    assert_eq!((ids(&body), body["total"].clone()), (vec![W1], 3.into()));
    fx.db.drop().await;
}

#[tokio::test]
async fn a_scoped_viewer_sees_only_their_hosts_and_their_problem_kinds() {
    let Some(fx) = Fx::new().await else { return };
    let other = seed(&fx).await;
    let role = fx
        .role(
            "Win alarms",
            &["hosts.read", "alarms.read"],
            Reach::Groups(vec![WIN.into()]),
        )
        .await;
    fx.db.user("wa", &role, 3).await;
    let wa = common::http::sign_in(&fx.router, "wa").await;

    let (status, body) = fx.call(&wa, "GET", URL, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ids(&body), [W1, W2]);
    assert_eq!(body["total"], 2);
    // alarms.read reaches them; vulnerabilities and compliance do not.
    assert_eq!(body["items"][0]["problems"]["open_alarms"], 1);
    assert!(body["items"][0]["problems"]["critical"].is_null());
    assert!(body["items"][0]["problems"]["failing"].is_null());
    assert!(
        body["counts"]["group"]
            .as_array()
            .unwrap()
            .iter()
            .all(|g| g["value"] != other.as_str())
    );

    // Another team's group id names no group and finds no host.
    let (status, body) = fx
        .call(&wa, "GET", &format!("{URL}?group={other}"), None)
        .await;
    assert_eq!((status, body["total"].clone()), (StatusCode::OK, 0.into()));
    assert!(ids(&body).is_empty());
    assert!(
        body["counts"]["group"]
            .as_array()
            .unwrap()
            .iter()
            .all(|g| g["value"] != other.as_str() && g["name"] != "Other")
    );

    // Without alarms.read the count is null.
    let (status, body) = fx.call(&fx.admin, "GET", URL, None).await;
    assert_eq!(status, StatusCode::OK);
    let plain = fx.windows_lead().await; // hosts.read only among these kinds
    let (_, body2) = fx.call(&plain, "GET", URL, None).await;
    assert_eq!(ids(&body2), [W1, W2]);
    assert!(body2["items"][0]["problems"]["open_alarms"].is_null());
    assert_eq!(body["items"][1]["problems"]["open_alarms"], 1);
    fx.db.drop().await;
}

#[tokio::test]
async fn a_role_without_hosts_read_is_refused() {
    let Some(fx) = Fx::new().await else { return };
    let role = fx.role("Alarms only", &["alarms.read"], Reach::All).await;
    fx.db.user("ao", &role, 3).await;
    let ao = common::http::sign_in(&fx.router, "ao").await;
    let (status, _) = fx.call(&ao, "GET", URL, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    fx.db.drop().await;
}

#[tokio::test]
async fn a_bearer_token_may_read_the_list() {
    use axum::{
        body::Body,
        http::{Request, header},
    };
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;
    let Some(fx) = Fx::new().await else { return };
    seed(&fx).await;
    let secret = "ovst_0123456789abcdef0123456789abcdef0123456789a";
    let mut client = fx.db.pool.get().await.unwrap();
    let account = platform_store::console_auth::create_service_account(
        &mut client,
        "ci",
        &["admin".to_owned()],
        &common::people::uid(1),
        chrono::Utc::now(),
    )
    .await
    .unwrap()
    .unwrap();
    client
        .execute(
            "INSERT INTO console_service_tokens (token_id, service_account_id, token_sha256, label,
                created_at, expires_at, created_by)
             VALUES (gen_random_uuid(), $1::text::uuid, $2, 'test', now(), now() + interval '1 day', 'test')",
            &[&account, &Sha256::digest(secret.as_bytes()).as_slice()],
        )
        .await
        .unwrap();
    drop(client);
    let request = Request::builder()
        .uri(URL)
        .header(header::AUTHORIZATION, format!("Bearer {secret}"))
        .body(Body::empty())
        .unwrap();
    let response = fx.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = common::http::body(response).await;
    assert_eq!(body["total"], 3);
    fx.db.drop().await;
}
