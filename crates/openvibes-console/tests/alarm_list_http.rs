//! `GET /api/v1/alarm-list`: validation, shape and counts, "me" from the
//! session, a team lead's reach, and the saved-views page "alarms".

use axum::http::StatusCode;
use platform_store::console_roles::Reach;
use serde_json::{Value, json};

mod common;
use common::people::{Fx, WIN, uid};

const W1: &str = "agent.00000000-0000-4000-8000-0000000000a1";
const L1: &str = "agent.00000000-0000-4000-8000-0000000000b1";
const URL: &str = "/api/v1/alarm-list";

/// W1 (in `win`): x1 high open (Alice), x2 low open, x3 medium mitigated;
/// L1 (in `Other`): y1 critical open (user 3). Returns the id of `Other`.
async fn seed(fx: &Fx) -> String {
    let client = fx.db.pool.get().await.unwrap();
    platform_store::ensure_partitions(
        &client,
        chrono::Utc::now().date_naive() - chrono::Duration::days(1),
        2,
    )
    .await
    .unwrap();
    let (alice, third) = (uid(1), uid(3));
    fx.db
        .user(
            "third",
            &fx.role("Third", &["alarms.read"], Reach::All).await,
            3,
        )
        .await;
    client
        .batch_execute(&format!(
            "INSERT INTO agents (agent_id, status, enrolled_at, hostname, last_seen_at, os_id, os_version) VALUES
                ('{W1}', 'active', now(), 'win-01', now(), 'windows', '11'),
                ('{L1}', 'active', now(), 'lin-01', now(), 'debian', '12');
             INSERT INTO console_host_group_members (asset_group_id, agent_id, added_at, added_by)
                VALUES ('{WIN}', '{W1}', now(), 't');
             INSERT INTO alarms (first_seen_day, agent_id, alarm_id, rule_set_id, rule_set_version, rule_id, rule_version,
                                 severity, confidence, message, first_seen, last_seen, count, process, ancestors,
                                 received_at, state, note, assigned_to)
                SELECT (now() AT TIME ZONE 'UTC')::date, v.agent, v.msg, 'rs', 1, 'r', 1, v.sev, 50, v.msg,
                       now(), now(), 2, '{{\"exe\": \"/bin/sh\"}}', '[]', now(), v.state,
                       CASE WHEN v.state <> 'open' THEN 'n' END, v.who::uuid
                FROM (VALUES
                  ('x1', '{W1}', 'high', 'open', '{alice}'),
                  ('x2', '{W1}', 'low', 'open', NULL),
                  ('x3', '{W1}', 'medium', 'mitigated', NULL),
                  ('y1', '{L1}', 'critical', 'open', '{third}')) AS v(msg, agent, sev, state, who)"
        ))
        .await
        .unwrap();
    common::manual_group(&client, "Other", &[L1]).await
}

fn messages(body: &Value) -> Vec<&str> {
    let mut m: Vec<_> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["message"].as_str().unwrap())
        .collect();
    m.sort_unstable();
    m
}

#[tokio::test]
async fn every_parameter_is_validated_and_named() {
    let Some(fx) = Fx::new().await else { return };
    let long = "x".repeat(201);
    let bad = [
        ("state=gone", "state"),
        ("severity=huge", "severity"),
        ("suppressed=yes", "suppressed"),
        ("group=nope", "group"),
        ("technique=%00", "technique"),
        ("case=maybe", "case"),
        ("assignee=nobody", "assignee"),
        ("assignee=ABC", "assignee"),
        ("sort=colour", "sort"),
        ("dir=up", "dir"),
        ("offset=-1", "offset"),
        ("offset=100001", "offset"),
        ("offset=x", "offset"),
        ("limit=0", "limit"),
        ("limit=101", "limit"),
        ("limit=x", "limit"),
        ("host=%00", "host"),
        ("q=%00", "q"),
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
        "state=all&severity=high&suppressed=shown&case=no&sort=count&dir=asc",
        "assignee=me",
        "assignee=unassigned&state=",
        "assignee=11111111-1111-4111-8111-111111111101&technique=T1059.004",
    ] {
        let (status, _) = fx
            .call(&fx.admin, "GET", &format!("{URL}?{ok}"), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{ok}");
    }
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
async fn the_list_has_rows_counts_and_a_summary() {
    let Some(fx) = Fx::new().await else { return };
    let other = seed(&fx).await;
    // the default view is open alarms
    let (status, body) = fx.call(&fx.admin, "GET", URL, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(messages(&body), ["x1", "x2", "y1"]);
    assert_eq!(body["total"], 3);
    assert!(body["generated_at"].is_string());
    let x1 = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["message"] == "x1")
        .unwrap();
    assert_eq!(x1["host"]["name"], "win-01");
    assert_eq!(x1["host"]["id"], W1);
    assert_eq!(x1["severity"], "high");
    assert_eq!(x1["state"], "open");
    assert_eq!(x1["count"], 2);
    assert_eq!(x1["program"], "/bin/sh");
    assert_eq!(x1["assignee"]["id"], uid(1));
    assert!(x1["case"].is_null());
    assert_eq!(x1["suppressed"], false);
    assert_eq!(body["summary"]["open"], 3);
    assert_eq!(body["summary"]["critical_or_high"], 2);
    assert_eq!(body["summary"]["on_alarms_off_hosts"], 0);
    let c = &body["counts"];
    let count = |facet: &str, v: &str| {
        c[facet]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["value"] == v)
            .unwrap()["count"]
            .clone()
    };
    assert_eq!(count("state", "open"), 3);
    assert_eq!(count("state", "mitigated"), 1);
    assert_eq!(count("severity", "critical"), 1);
    assert_eq!(count("suppressed", "hidden"), 3);
    assert_eq!(count("case", "no"), 3);
    assert_eq!(c["assignee"]["me"], 1);
    assert_eq!(c["assignee"]["unassigned"], 1);
    assert_eq!(c["assignee"]["people"].as_array().unwrap().len(), 2);
    assert!(
        c["group"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g["value"] == other.as_str() && g["name"] == "Other" && g["count"] == 1)
    );

    // state=all shows every state; the summary still counts the open ones
    let (_, body) = fx
        .call(&fx.admin, "GET", &format!("{URL}?state=all"), None)
        .await;
    assert_eq!(body["total"], 4);
    let (_, body) = fx
        .call(&fx.admin, "GET", &format!("{URL}?state=mitigated"), None)
        .await;
    assert_eq!(
        (messages(&body), body["summary"]["open"].clone()),
        (vec!["x3"], 3.into())
    );
    // filters combine; sort and paging
    let (_, body) = fx
        .call(
            &fx.admin,
            "GET",
            &format!("{URL}?sort=severity&dir=desc&limit=1&offset=1"),
            None,
        )
        .await;
    assert_eq!(
        (messages(&body), body["total"].clone()),
        (vec!["x1"], 3.into())
    );
    let (_, body) = fx
        .call(
            &fx.admin,
            "GET",
            &format!("{URL}?q=LIN-01&severity=critical"),
            None,
        )
        .await;
    assert_eq!(messages(&body), ["y1"]);
    fx.db.drop().await;
}

#[tokio::test]
async fn me_is_the_signed_in_person_and_unassigned_is_not_a_name() {
    let Some(fx) = Fx::new().await else { return };
    seed(&fx).await;
    let (_, body) = fx
        .call(&fx.admin, "GET", &format!("{URL}?assignee=me"), None)
        .await;
    assert_eq!(messages(&body), ["x1"]);
    let third = common::http::sign_in(&fx.router, "third").await;
    let (_, body) = fx
        .call(&third, "GET", &format!("{URL}?assignee=me"), None)
        .await;
    assert_eq!(messages(&body), ["y1"]);
    let (_, body) = fx
        .call(
            &fx.admin,
            "GET",
            &format!("{URL}?assignee=unassigned"),
            None,
        )
        .await;
    assert_eq!(messages(&body), ["x2"]);
    let id = uid(3);
    let (_, body) = fx
        .call(&fx.admin, "GET", &format!("{URL}?assignee={id}"), None)
        .await;
    assert_eq!(messages(&body), ["y1"]);
    fx.db.drop().await;
}

#[tokio::test]
async fn a_team_lead_sees_only_their_groups_and_hosts_read_gates_one_number() {
    let Some(fx) = Fx::new().await else { return };
    let other = seed(&fx).await;
    let role = fx
        .role(
            "Win alarms",
            &["alarms.read"],
            Reach::Groups(vec![WIN.into()]),
        )
        .await;
    fx.db.user("wa", &role, 4).await;
    let wa = common::http::sign_in(&fx.router, "wa").await;
    let (status, body) = fx.call(&wa, "GET", &format!("{URL}?state=all"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(messages(&body), ["x1", "x2", "x3"]);
    assert_eq!(body["summary"]["open"], 2);
    assert!(body["summary"]["on_alarms_off_hosts"].is_null());
    let people = body["counts"]["assignee"]["people"].as_array().unwrap();
    assert_eq!(people.len(), 1);
    assert!(
        body["counts"]["group"]
            .as_array()
            .unwrap()
            .iter()
            .all(|g| g["value"] != other.as_str())
    );
    // another team's host, group, and a search naming it find nothing
    for q in [
        format!("host={L1}"),
        format!("group={other}"),
        "q=lin-01".into(),
    ] {
        let (status, body) = fx.call(&wa, "GET", &format!("{URL}?{q}"), None).await;
        assert_eq!(
            (status, body["total"].clone()),
            (StatusCode::OK, 0.into()),
            "{q}"
        );
    }
    // alarms.read is required
    let role = fx.role("Hosts only", &["hosts.read"], Reach::All).await;
    fx.db.user("ho", &role, 5).await;
    let ho = common::http::sign_in(&fx.router, "ho").await;
    let (status, _) = fx.call(&ho, "GET", URL, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    fx.db.drop().await;
}

#[tokio::test]
async fn the_alarms_page_keeps_saved_views_and_hidden_columns() {
    let Some(fx) = Fx::new().await else { return };
    let a = &fx.admin;
    let (status, _) = fx
        .call(
            a,
            "POST",
            "/api/v1/saved-views",
            Some(json!({"page": "alarms", "name": "Mine", "query": "assignee=me"})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let cols = "/api/v1/list-columns/alarms";
    let (status, _) = fx
        .call(
            a,
            "PUT",
            cols,
            Some(
                json!({"hidden": ["alarm", "host", "count", "seen", "state", "assignee", "case"]}),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = fx
        .call(a, "PUT", cols, Some(json!({"hidden": ["severity"]})))
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    fx.db.drop().await;
}
