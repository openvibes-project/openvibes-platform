//! `GET /api/v1/case-list`: validation naming the parameter, the row and
//! count shapes, "me" from the session, a team lead's reach, and the
//! saved-views page "cases".

use axum::http::StatusCode;
use platform_store::console_roles::Reach;
use serde_json::{Value, json};

mod common;
use common::people::{Fx, WIN, uid};

const W1: &str = "agent.00000000-0000-4000-8000-0000000000a1";
const L1: &str = "agent.00000000-0000-4000-8000-0000000000b1";
const URL: &str = "/api/v1/case-list";

fn case_id(n: u8) -> String {
    format!("00000000-0000-4000-8000-0000000000{n:02}")
}

/// W1 (in `win`) and L1 (not); Bea (user 3) reads cases on `win` only.
/// 1 "Web vuln" open high by Alice for Bea: vulnerability W1 (no outcome),
///   host W1; a note; an hour ago.
/// 2 "Lin vuln" investigating critical by Alice: vulnerability L1 (false
///   positive); 10 days ago.
/// 3 "Empty" open low by Alice; just now.
/// 4 "Done" closed medium by Alice: host W1; 2 days ago.
async fn seed(fx: &Fx) {
    let bea = fx
        .role(
            "Win cases",
            &["cases.read"],
            Reach::Groups(vec![WIN.into()]),
        )
        .await;
    fx.db.user("bea", &bea, 3).await;
    let (alice, bea) = (uid(1), uid(3));
    let client = fx.db.pool.get().await.unwrap();
    client
        .batch_execute(&format!(
            "INSERT INTO agents (agent_id, status, enrolled_at, hostname, last_seen_at) VALUES
                ('{W1}', 'active', now(), 'web-01', now()), ('{L1}', 'active', now(), 'lin-01', now());
             INSERT INTO console_host_group_members (asset_group_id, agent_id, added_at, added_by)
                VALUES ('{WIN}', '{W1}', now(), 't');
             INSERT INTO cases (case_id, title, status, resolution_note, closed_at, severity,
                                assignee_user_id, opened_by_user_id, created_at, updated_at)
             SELECT v.id::uuid, v.title, v.status, CASE WHEN v.status = 'closed' THEN 'done' END,
                    CASE WHEN v.status = 'closed' THEN now() END, v.sev, v.assignee::uuid,
                    '{alice}'::uuid, now() - interval '20 days', now() - v.ago::interval
             FROM (VALUES (1, '{c1}', 'Web vuln', 'open', 'high', '{bea}', '1 hour'),
                          (2, '{c2}', 'Lin vuln', 'investigating', 'critical', NULL, '10 days'),
                          (3, '{c3}', 'Empty', 'open', 'low', NULL, '0 seconds'),
                          (4, '{c4}', 'Done', 'closed', 'medium', NULL, '2 days'))
                  v(n, id, title, status, sev, assignee, ago)
             ORDER BY v.n;
             INSERT INTO case_items (item_id, case_id, kind, ref, agent_id, active, outcome,
                                     outcome_note, added_by_user_id, added_at)
             SELECT gen_random_uuid(), v.c::uuid, v.kind, v.ref, v.agent, v.c <> '{c4}', v.outcome,
                    CASE WHEN v.outcome IS NOT NULL THEN 'why' END, '{alice}'::uuid, now()
             FROM (VALUES ('{c1}', 'vulnerability', '{W1}/FEDORA-1', '{W1}', NULL),
                          ('{c1}', 'host', '{W1}', '{W1}', NULL),
                          ('{c2}', 'vulnerability', '{L1}/FEDORA-1', '{L1}', 'false_positive'),
                          ('{c4}', 'host', '{W1}', '{W1}', NULL)) v(c, kind, ref, agent, outcome);
             INSERT INTO case_events (case_id, at, actor_user_id, kind, body)
                VALUES ('{c1}', now() - interval '1 hour', '{alice}', 'note', 'first look');",
            c1 = case_id(1),
            c2 = case_id(2),
            c3 = case_id(3),
            c4 = case_id(4),
        ))
        .await
        .unwrap();
}

fn titles(body: &Value) -> Vec<&str> {
    body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["title"].as_str().unwrap())
        .collect()
}

fn count(body: &Value, facet: &str, v: &str) -> Value {
    body["counts"][facet]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["value"] == v)
        .unwrap_or_else(|| panic!("no {facet}={v} in {body}"))["count"]
        .clone()
}

#[tokio::test]
async fn every_parameter_is_validated_and_named() {
    let Some(fx) = Fx::new().await else { return };
    let long = "x".repeat(201);
    let bad = [
        ("status=gone", "status"),
        ("severity=info", "severity"),
        ("assignee=nobody", "assignee"),
        ("assignee=none", "assignee"),
        ("contains=hosts", "contains"),
        ("host=%00", "host"),
        ("group=nope", "group"),
        ("updated=month", "updated"),
        ("sort=title", "sort"),
        ("dir=up", "dir"),
        ("offset=-1", "offset"),
        ("offset=100001", "offset"),
        ("limit=0", "limit"),
        ("limit=101", "limit"),
        ("limit=x", "limit"),
        ("q=%00", "q"),
        ("cursor=abc", "query"),
        ("surprise=1", "query"),
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
    for ok in [
        "limit=100&offset=100000",
        "status=all&severity=low&sort=severity&dir=asc",
        "status=closed&contains=findings&updated=quiet&sort=opened",
        "status=open&contains=alarms&updated=today&sort=number",
        "status=investigating&contains=vulnerabilities&updated=week",
        "assignee=me&q=C-1",
        "assignee=unassigned&status=",
        "assignee=11111111-1111-4111-8111-111111111101",
        "group=31111111-1111-4111-8111-111111111111&host=agent.x",
    ] {
        let (status, body) = fx
            .call(&fx.admin, "GET", &format!("{URL}?{ok}"), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{ok}: {body}");
    }
    fx.db.drop().await;
}

#[tokio::test]
async fn the_list_has_rows_counts_and_a_summary() {
    let Some(fx) = Fx::new().await else { return };
    seed(&fx).await;
    let (status, body) = fx.call(&fx.admin, "GET", URL, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(titles(&body), ["Empty", "Web vuln", "Lin vuln"]);
    assert_eq!(body["total"], 3);
    assert!(body["generated_at"].is_string());
    let r = &body["items"][1];
    assert_eq!(r["case_id"], case_id(1));
    assert!(r["number"].is_i64());
    assert_eq!(
        (&r["status"], &r["severity"]),
        (&json!("open"), &json!("high"))
    );
    assert_eq!(r["opened_by"]["display_name"], "alice");
    assert_eq!(r["assignee"]["user_id"], uid(3));
    assert_eq!(r["latest_note"]["text"], "first look");
    assert!(r["latest_note"]["at"].is_string());
    assert_eq!(r["hosts"], json!([{"agent_id": W1, "hostname": "web-01"}]));
    assert_eq!(r["host_count"], 1);
    assert_eq!(
        r["kinds"],
        json!({"alarms": 0, "findings": 0, "vulnerabilities": 1, "hosts": 1, "software": 0})
    );
    assert_eq!(
        (&r["with_outcome"], &r["takes_outcome"]),
        (&json!(0), &json!(1))
    );
    assert_eq!(r["ready"], false);
    assert!(r["updated_at"].is_string());
    let empty = &body["items"][0];
    assert_eq!(empty["assignee"], Value::Null);
    assert_eq!(empty["latest_note"], Value::Null);
    assert_eq!(empty["hosts"], json!([]));
    assert_eq!(
        body["summary"],
        json!({"open": 2, "investigating": 1, "unassigned": 2, "ready_to_close": 2})
    );
    for (v, n) in [
        ("active", 3),
        ("open", 2),
        ("investigating", 1),
        ("closed", 1),
        ("all", 4),
    ] {
        assert_eq!(count(&body, "status", v), n, "status {v}");
    }
    assert_eq!(count(&body, "severity", "critical"), 1);
    assert_eq!(count(&body, "contains", "vulnerabilities"), 2);
    assert_eq!(count(&body, "updated", "quiet"), 1);
    assert_eq!(body["counts"]["assignee"]["unassigned"], 2);
    assert_eq!(
        body["counts"]["assignee"]["people"],
        json!([{"value": uid(3), "name": "bea", "count": 1}])
    );
    assert_eq!(count(&body, "group", WIN), 1);
    // filters, search and paging
    for (query, expected) in [
        ("status=closed", vec!["Done"]),
        ("updated=quiet", vec!["Lin vuln"]),
        (
            "contains=vulnerabilities&sort=number&dir=asc",
            vec!["Web vuln", "Lin vuln"],
        ),
        (&format!("host={L1}"), vec!["Lin vuln"]),
        (
            &format!("group={WIN}&status=all&sort=number&dir=asc"),
            vec!["Web vuln", "Done"],
        ),
        ("q=EMPTY", vec!["Empty"]),
        ("q=C-2", vec!["Lin vuln"]),
        (
            "q=alice&sort=severity",
            vec!["Lin vuln", "Web vuln", "Empty"],
        ),
        (
            "status=all&sort=number&dir=asc&limit=1&offset=3",
            vec!["Done"],
        ),
    ] {
        let (status, body) = fx
            .call(&fx.admin, "GET", &format!("{URL}?{query}"), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{query}");
        assert_eq!(titles(&body), expected, "{query}");
    }
    fx.db.drop().await;
}

#[tokio::test]
async fn me_is_the_signed_in_person_and_a_team_lead_sees_only_their_hosts() {
    let Some(fx) = Fx::new().await else { return };
    seed(&fx).await;
    let (_, body) = fx
        .call(&fx.admin, "GET", &format!("{URL}?assignee=me"), None)
        .await;
    assert_eq!(body["total"], 0, "nothing is assigned to Alice");
    let (_, body) = fx
        .call(
            &fx.admin,
            "GET",
            &format!("{URL}?assignee={}", uid(3)),
            None,
        )
        .await;
    assert_eq!(titles(&body), ["Web vuln"]);
    let bea = common::http::sign_in(&fx.router, "bea").await;
    let (status, body) = fx
        .call(&bea, "GET", &format!("{URL}?assignee=me"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(titles(&body), ["Web vuln"]);
    assert_eq!(body["counts"]["assignee"]["me"], 1);
    // Not the empty case (her scope is not every host), not L1's.
    let (_, body) = fx
        .call(
            &bea,
            "GET",
            &format!("{URL}?status=all&sort=number&dir=asc"),
            None,
        )
        .await;
    assert_eq!(titles(&body), ["Web vuln", "Done"]);
    let (_, body) = fx
        .call(&bea, "GET", &format!("{URL}?host={L1}"), None)
        .await;
    assert_eq!(body["total"], 0);
    // cases.read is required
    let role = fx.role("Hosts only", &["hosts.read"], Reach::All).await;
    fx.db.user("ho", &role, 5).await;
    let ho = common::http::sign_in(&fx.router, "ho").await;
    let (status, _) = fx.call(&ho, "GET", URL, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    fx.db.drop().await;
}

#[tokio::test]
async fn the_cases_page_keeps_saved_views_and_hidden_columns() {
    let Some(fx) = Fx::new().await else { return };
    let a = &fx.admin;
    let (status, _) = fx
        .call(
            a,
            "POST",
            "/api/v1/saved-views",
            Some(json!({"page": "cases", "name": "Mine", "query": "assignee=me"})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let cols = "/api/v1/list-columns/cases";
    let all = [
        "severity", "status", "assignee", "hosts", "items", "updated",
    ];
    let (status, body) = fx.call(a, "PUT", cols, Some(json!({"hidden": all}))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    for never in ["case", "title"] {
        let (status, body) = fx
            .call(a, "PUT", cols, Some(json!({"hidden": [never]})))
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{never} {body}");
    }
    fx.db.drop().await;
}
