//! Rule permissions are platform-wide, but the hosts they show are not:
//! testing a rule, the site fleet view and a host's rule sets keep to the
//! caller's `hosts.read` reach (roles spec §3, §6).

use axum::http::StatusCode;
use openvibes_console::authenticated_router;
use platform_store::console_roles::Reach;
use serde_json::json;

mod common;
use common::http::{TestDb, call, sign_in};

const LAB: &str = "41111111-1111-4111-8111-111111111111";
const PROD: &str = "42222222-2222-4222-8222-222222222222";
const LAB_HOST: &str = "agent.00000000-0000-4000-8000-000000000601";
const PROD_HOST: &str = "agent.00000000-0000-4000-8000-000000000602";
const PERMISSIONS: [&str; 4] = [
    "site_rules.read",
    "site_rules.write",
    "site_rules.test",
    "hosts.read",
];

#[tokio::test]
async fn a_role_reaching_one_group_tests_and_sees_only_its_hosts() {
    let Some(db) = TestDb::create("site_reach").await else {
        return;
    };
    db.pool
        .get()
        .await
        .unwrap()
        .batch_execute(&format!(
            "INSERT INTO console_asset_groups VALUES ('{LAB}', 'lab', now(), 'test'),
                                                     ('{PROD}', 'prod', now(), 'test');
             INSERT INTO console_asset_group_selectors VALUES ('{LAB}', 'env', 'lab', now()),
                                                              ('{PROD}', 'env', 'prod', now());
             INSERT INTO agents (agent_id, status, enrolled_at, hostname, last_seen_at) VALUES
                ('{LAB_HOST}', 'active', now(), 'lab-01', now()),
                ('{PROD_HOST}', 'active', now(), 'prod-01', now());
             INSERT INTO console_agent_tags VALUES ('{LAB_HOST}', 'env', 'lab', now(), 'test'),
                                                   ('{PROD_HOST}', 'env', 'prod', now(), 'test');
             UPDATE agents SET health_at = now(), health = '{{\"rule_sets\":[]}}';"
        ))
        .await
        .unwrap();
    let mut client = db.pool.get().await.unwrap();
    let lab = common::create_role(
        &mut client,
        "Lab",
        &PERMISSIONS,
        Reach::Groups(vec![LAB.into()]),
    )
    .await;
    let all = common::create_role(&mut client, "All", &PERMISSIONS, Reach::All).await;
    drop(client);
    db.user("lena", &lab, 1).await;
    db.user("abe", &all, 2).await;
    let router = authenticated_router(db.pool.clone(), common::http::ORIGIN);
    let url = "/api/v1/rule-drafts/site/port.redis.exposed/test";
    let rule = json!({
        "title": "Redis is exposed",
        "severity": "high",
        "confidence": 90,
        "expression": "true",
        "finding_message": "Redis listens beyond loopback."
    });
    let test = |agent: &str| Some(json!({"agent_id": agent, "rule": rule}));

    let lena = sign_in(&router, "lena").await;
    let (status, body) = call(&router, "POST", url, &lena, test(LAB_HOST)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = call(&router, "POST", url, &lena, test(PROD_HOST)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["code"], "host_not_found");
    let (_, fleet) = call(&router, "GET", "/api/v1/site-rules/fleet", &lena, None).await;
    let names: Vec<&str> = fleet["hosts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|host| host["hostname"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["lab-01"], "{fleet}");
    assert_eq!(fleet["reporting"], 1, "{fleet}");
    assert_eq!(fleet["sets"][0]["missing"], 1, "{fleet}");

    let abe = sign_in(&router, "abe").await;
    let (status, body) = call(&router, "POST", url, &abe, test(PROD_HOST)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, fleet) = call(&router, "GET", "/api/v1/site-rules/fleet", &abe, None).await;
    assert_eq!(fleet["hosts"].as_array().unwrap().len(), 2, "{fleet}");
    assert_eq!(fleet["reporting"], 2, "{fleet}");
    db.drop().await;
}

#[tokio::test]
async fn the_host_rule_set_view_stays_within_the_callers_groups() {
    let Some(db) = TestDb::create("host_sets").await else {
        return;
    };
    db.pool
        .get()
        .await
        .unwrap()
        .batch_execute(&format!(
            "INSERT INTO console_asset_groups VALUES ('{LAB}', 'lab', now(), 'test');
             INSERT INTO console_asset_group_selectors VALUES ('{LAB}', 'env', 'lab', now());
             INSERT INTO agents (agent_id, status, enrolled_at) VALUES
                ('{LAB_HOST}', 'active', now()), ('{PROD_HOST}', 'active', now());
             INSERT INTO console_agent_tags VALUES ('{LAB_HOST}', 'env', 'lab', now(), 'test');"
        ))
        .await
        .unwrap();
    // bob (analyst) holds hosts.read for the lab group only.
    db.user("bob", "analyst", 1).await;
    common::scope_bindings(
        &mut db.pool.get().await.unwrap(),
        "user_id = '11111111-1111-4111-8111-111111111101'",
        LAB,
    )
    .await;
    let router = authenticated_router(db.pool.clone(), common::http::ORIGIN);
    let bob = sign_in(&router, "bob").await;
    let view = |agent: &str| format!("/api/v1/agents/{agent}/rule-set-assignments");
    let (status, body) = call(&router, "GET", &view(LAB_HOST), &bob, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = call(&router, "GET", &view(PROD_HOST), &bob, None).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("agent_not_found"))
    );
    db.drop().await;
}
