//! `GET /api/v1/alarms/{id}/summary`: an alarm's page above the fold,
//! inside the viewer's reach, with its actions per permission on the host.

use axum::http::StatusCode;
use platform_store::console_roles::Reach;
use serde_json::Value;

mod common;
use common::people::{Fx, WIN};

const W1: &str = "agent.00000000-0000-4000-8000-0000000000a1";
const L1: &str = "agent.00000000-0000-4000-8000-0000000000b1";

/// W1 (in `win`): `a` (nginx < systemd, count 3), its sibling `b` (count 7)
/// and `c` (another program, count 1); L1 (outside `win`): `d` from the
/// same rule. Hourly starts: 2 for `a` and 5 for `b` this hour.
async fn seed(fx: &Fx) {
    let client = fx.db.pool.get().await.unwrap();
    platform_store::ensure_partitions(
        &client,
        chrono::Utc::now().date_naive() - chrono::Duration::days(3),
        4,
    )
    .await
    .unwrap();
    client
        .batch_execute(&format!(
            "INSERT INTO agents (agent_id, status, enrolled_at, hostname, last_seen_at, os_id, os_version) VALUES
                ('{W1}', 'active', now(), 'web-01', now(), 'debian', '12'),
                ('{L1}', 'active', now(), 'lin-01', now(), 'debian', '12');
             INSERT INTO console_host_group_members (asset_group_id, agent_id, added_at, added_by)
                VALUES ('{WIN}', '{W1}', now(), 't');
             INSERT INTO alarms (first_seen_day, agent_id, alarm_id, rule_set_id, rule_set_version, rule_id,
                                 rule_version, severity, confidence, message, first_seen, last_seen, count,
                                 process, ancestors, received_at, state)
             SELECT ((now() - v.first::interval) AT TIME ZONE 'UTC')::date, v.agent, v.msg, 'rs', 1, 'r', 1,
                    'high', 80, v.msg, now() - v.first::interval, now(), v.n,
                    jsonb_build_object('exe', v.exe, 'args', jsonb_build_array(v.exe, '-' || v.msg)),
                    jsonb_build_array(jsonb_build_object('exe', '/usr/lib/systemd/systemd')), now(), 'open'
             FROM (VALUES ('a', '{W1}', '/usr/sbin/nginx', 3, '1 hour'),
                          ('b', '{W1}', '/usr/sbin/nginx', 7, '2 days'),
                          ('c', '{W1}', '/usr/bin/other', 1, '1 hour'),
                          ('d', '{L1}', '/usr/sbin/nginx', 2, '1 hour')) AS v(msg, agent, exe, n, first);
             INSERT INTO alarm_hourly_starts (alarm_row_id, hour, starts)
             SELECT id, date_trunc('hour', now()), CASE message WHEN 'a' THEN 2 ELSE 5 END
             FROM alarms WHERE message IN ('a', 'b');"
        ))
        .await
        .unwrap();
}

async fn id(fx: &Fx, name: &str) -> i64 {
    fx.db
        .pool
        .get()
        .await
        .unwrap()
        .query_one("SELECT id FROM alarms WHERE message = $1", &[&name])
        .await
        .unwrap()
        .get(0)
}

async fn url(fx: &Fx, name: &str) -> String {
    format!("/api/v1/alarms/{}/summary", id(fx, name).await)
}

async fn user(
    fx: &Fx,
    name: &str,
    n: u8,
    permissions: &[&str],
    reach: Reach,
) -> common::http::Session {
    let role = fx.role(name, permissions, reach).await;
    fx.db.user(name, &role, n).await;
    common::http::sign_in(&fx.router, name).await
}

#[tokio::test]
async fn an_administrator_sees_the_whole_page() {
    let Some(fx) = Fx::new().await else { return };
    seed(&fx).await;
    let (status, body) = fx.call(&fx.admin, "GET", &url(&fx, "a").await, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let a = &body["alarm"];
    assert_eq!(a["message"], "a");
    assert_eq!(a["host"]["id"], W1);
    assert_eq!(a["program"], "/usr/sbin/nginx");
    assert_eq!(a["parent_program"], "/usr/lib/systemd/systemd");
    assert_eq!(a["confidence"], 80);
    assert_eq!(a["rule_set_version"], 1);
    assert!(a["process"].is_object() && a["ancestors"].is_array());
    assert!(a["triage"]["version"].is_i64());
    assert!(a["received_at"].is_string());
    let t = &body["tiles"];
    assert_eq!(t["starts"], 10);
    assert_eq!(t["different_commands"], 2);
    assert_eq!(t["confidence"], 80);
    assert_eq!(t["first_seen"], body["commands"][0]["first_seen"]);
    // Not indexed: the alarm's message stands in.
    assert_eq!(body["rule"]["title"], "a");
    assert_eq!(body["rule"]["message"], "a");
    assert!(body["rule"]["explain"].is_null());
    assert_eq!(body["rule"]["techniques"], serde_json::json!([]));
    // The usual command first.
    assert_eq!(
        body["commands"][0]["args"],
        serde_json::json!(["/usr/sbin/nginx", "-b"])
    );
    assert_eq!(body["commands"][0]["count"], 7);
    assert_eq!(body["commands"][1]["id"], id(&fx, "a").await);
    let hourly = body["hourly"].as_array().unwrap();
    assert_eq!(hourly.len(), 24);
    assert_eq!(hourly[23], 7);
    let r = &body["related"];
    assert_eq!(r["host_alarms"]["total"], 2);
    assert_eq!(r["host_vulnerabilities"]["total"], 0);
    assert_eq!(
        r["same_rule_elsewhere"],
        serde_json::json!({"hosts": 1, "open": 1})
    );
    let can = &body["can"];
    for key in ["triage", "assign", "suppress", "add_to_case", "export"] {
        assert_eq!(can[key], true, "{key}");
    }
    // The assistant is off in tests.
    assert_eq!(can["ask"], false);
    fx.db.drop().await;
}

#[tokio::test]
async fn summary_stays_inside_the_scope() {
    let Some(fx) = Fx::new().await else { return };
    seed(&fx).await;
    let win = user(
        &fx,
        "wr",
        3,
        &["alarms.read"],
        Reach::Groups(vec![WIN.into()]),
    )
    .await;
    let (status, body) = fx.call(&win, "GET", &url(&fx, "a").await, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // L1 is out of reach: not counted, not named.
    assert_eq!(
        body["related"]["same_rule_elsewhere"],
        serde_json::json!({"hosts": 0, "open": 0})
    );
    assert!(!body.to_string().contains(L1));
    // No vulnerabilities.read: no vulnerabilities.
    assert!(body["related"]["host_vulnerabilities"].is_null());
    // An alarm out of reach is the same 404 as a missing one or a bad id.
    let (status, mut outside) = fx.call(&win, "GET", &url(&fx, "d").await, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(outside["code"], "alarm_not_found");
    outside["request_id"] = Value::Null;
    for missing in ["/api/v1/alarms/999999/summary", "/api/v1/alarms/x/summary"] {
        let (status, mut body) = fx.call(&win, "GET", missing, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        body["request_id"] = Value::Null;
        assert_eq!(body, outside);
    }
    // No alarms.read at all.
    let (status, _) = fx
        .call(&fx.windows_lead().await, "GET", &url(&fx, "a").await, None)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    fx.db.drop().await;
}

#[tokio::test]
async fn actions_need_their_permission_on_this_host() {
    let Some(fx) = Fx::new().await else { return };
    seed(&fx).await;
    let other = {
        let client = fx.db.pool.get().await.unwrap();
        common::manual_group(&client, "Other", &[L1]).await
    };
    let triager = user(
        &fx,
        "tr",
        3,
        &["alarms.read", "alarms.triage"],
        Reach::Groups(vec![WIN.into()]),
    )
    .await;
    let changers = fx
        .role(
            "Other changers",
            &[
                "alarms.read",
                "alarms.suppress",
                "alarms.suppressions.read",
                "alarms.export",
                "cases.read",
                "cases.write",
                "cases.assign",
                "assistant.use",
            ],
            Reach::Groups(vec![other]),
        )
        .await;
    fx.db
        .pool
        .get()
        .await
        .unwrap()
        .execute(
            "INSERT INTO console_role_bindings (binding_id, user_id, role_id, created_at, created_by)
             VALUES (gen_random_uuid(), $1::text::uuid, $2, now(), 'test')",
            &[&common::people::uid(3), &changers],
        )
        .await
        .unwrap();
    let can = |body: &Value| -> Vec<bool> {
        [
            "triage",
            "assign",
            "suppress",
            "add_to_case",
            "ask",
            "export",
        ]
        .iter()
        .map(|k| body["can"][k].as_bool().unwrap())
        .collect()
    };
    let (status, body) = fx.call(&triager, "GET", &url(&fx, "a").await, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(can(&body), [true, false, false, false, false, false]);
    let (status, body) = fx.call(&triager, "GET", &url(&fx, "d").await, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // Assigning goes through triage, which the Other group lacks.
    assert_eq!(can(&body), [false, false, true, true, false, true]);
    fx.db.drop().await;
}
