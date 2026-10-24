//! `GET /api/v1/compliance-list`: validation, shape and counts, "me" from
//! the session, a team lead's reach, and the saved-views page "compliance".

use axum::http::StatusCode;
use platform_store::console_roles::Reach;
use serde_json::{Value, json};

mod common;
use common::people::{Fx, WIN, uid};

const W1: &str = "agent.00000000-0000-4000-8000-0000000000a1";
const L1: &str = "agent.00000000-0000-4000-8000-0000000000b1";
const URL: &str = "/api/v1/compliance-list";
const HEALTH: &str = r#"{"rule_sets":[{"id":"baseline","version":1}],
  "last_scan":{"collectors":{"ports":"ok","packages":"ok","hardening":"ok","processes":"ok"}}}"#;

/// W1 (in `win`) and L1 (in `Other`), both healthy on baseline 1.
/// - baseline/port.ssh.exposed (high): W1 open (Alice), L1 open (user 3).
/// - baseline/package.telnet_server.installed (medium): W1's finding ended.
/// - baseline/port.redis.exposed (indexed only, high): no finding.
async fn seed(fx: &Fx) -> String {
    let client = fx.db.pool.get().await.unwrap();
    let (alice, third) = (uid(1), uid(3));
    fx.db
        .user(
            "third",
            &fx.role("Third", &["compliance.read"], Reach::All).await,
            3,
        )
        .await;
    let k = "07".repeat(32);
    client
        .batch_execute(&format!(
            "INSERT INTO agents (agent_id, status, enrolled_at, hostname, last_seen_at, health, health_at) VALUES
                ('{W1}', 'active', now(), 'win-01', now(), '{HEALTH}', now()),
                ('{L1}', 'active', now(), 'lin-01', now(), '{HEALTH}', now());
             INSERT INTO console_host_group_members (asset_group_id, agent_id, added_at, added_by)
                VALUES ('{WIN}', '{W1}', now(), 't');
             INSERT INTO rule_sets (rule_set_id) VALUES ('baseline');
             INSERT INTO rule_trust_keys (rule_set_id, issuer_key_id, public_key) VALUES ('baseline', 'k', '\\x{k}');
             INSERT INTO rule_bundles (rule_set_id, version, envelope, envelope_sha256, issuer_key_id,
                                       created_at_ms, expires_at_ms, published_by)
                VALUES ('baseline', 1, '{{}}', sha256('b1'::bytea), 'k', 1, 9e15, 't');
             INSERT INTO console_rule_meta (rule_set_id, rule_set_version, rule_id, rule_version, title, message, attack, techniques, severity) VALUES
                ('baseline', 1, 'port.ssh.exposed', 1, 'SSH port exposed', 'm', '[]', '{{}}', 'high'),
                ('baseline', 1, 'package.telnet_server.installed', 1, 'Telnet server installed', 'm', '[]', '{{}}', 'medium'),
                ('baseline', 1, 'port.redis.exposed', 1, 'Redis exposed', 'm', '[]', '{{}}', 'high');
             INSERT INTO current_findings (agent_id, rule_set_id, rule_id, last_finding_id, rule_version, severity,
                    first_observed_at, last_observed_at, last_observed_day, scan_id, confidence, message, evidence,
                    received_at, origin, authenticated, source, ended_at) VALUES
                ('{W1}', 'baseline', 'port.ssh.exposed', 'f', 1, 'high', now() - interval '3 days', now(), current_date, 's', 90, 'm', '{{}}', now(), 'online', true, 'changes', NULL),
                ('{L1}', 'baseline', 'port.ssh.exposed', 'f', 1, 'high', now() - interval '2 days', now(), current_date, 's', 90, 'm', '{{}}', now(), 'online', true, 'changes', NULL),
                ('{W1}', 'baseline', 'package.telnet_server.installed', 'f', 1, 'medium', now() - interval '5 days', now(), current_date, 's', 90, 'm', '{{}}', now(), 'online', true, 'changes', now() - interval '1 hour');
             INSERT INTO console_finding_triage (agent_id, rule_set_id, rule_id, state, rule_version, assigned_to,
                    note, accepted_until, version, updated_at, updated_by) VALUES
                ('{W1}', 'baseline', 'port.ssh.exposed', 'open', 1, '{alice}', NULL, NULL, 1, now(), 't'),
                ('{L1}', 'baseline', 'port.ssh.exposed', 'open', 1, '{third}', NULL, NULL, 1, now(), 't');"
        ))
        .await
        .unwrap();
    common::manual_group(&client, "Other", &[L1]).await
}

fn keys(body: &Value) -> Vec<&str> {
    body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["rule_id"].as_str().unwrap())
        .collect()
}

fn row<'a>(body: &'a Value, rule_id: &str) -> &'a Value {
    body["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["rule_id"] == rule_id)
        .unwrap()
}

fn count(body: &Value, facet: &str, v: &str) -> Value {
    body["counts"][facet]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["value"] == v)
        .unwrap()["count"]
        .clone()
}

#[tokio::test]
async fn every_parameter_is_validated_and_named() {
    let Some(fx) = Fx::new().await else { return };
    let long = "x".repeat(201);
    let bad = [
        ("state=gone", "state"),
        ("state=resolved", "state"),
        ("severity=important", "severity"),
        ("rule_set=%00", "rule_set"),
        ("area=%00", "area"),
        ("group=nope", "group"),
        ("host=%00", "host"),
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
    // unknown parameters (the old list's window, say) are the web's to map
    for old in ["window=7d", "since=1", "surprise=1"] {
        let (status, _) = fx
            .call(&fx.admin, "GET", &format!("{URL}?{old}"), None)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{old}");
    }
    for ok in [
        "limit=100&offset=100000",
        "state=all&severity=info&sort=since&dir=asc",
        "state=passing&rule_set=baseline&area=SSH&sort=title",
        "sort=failing&assignee=me",
        "assignee=unassigned&state=",
        "assignee=11111111-1111-4111-8111-111111111101",
        "host=agent.x&q=ssh",
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
    let (status, body) = fx.call(&fx.admin, "GET", URL, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(keys(&body), ["port.ssh.exposed"]);
    assert_eq!(body["total"], 1);
    assert!(body["generated_at"].is_string());
    let r = row(&body, "port.ssh.exposed");
    assert_eq!(r["rule_set_id"], "baseline");
    assert_eq!(r["title"], "SSH port exposed");
    assert_eq!(r["severity"], "high");
    assert_eq!(r["area"], "Network exposure");
    assert_eq!(
        (r["failing"].clone(), r["passing"].clone()),
        (2.into(), 0.into())
    );
    assert_eq!(
        (r["open"].clone(), r["mitigated"].clone()),
        (2.into(), 0.into())
    );
    assert!(r["since"].is_string());
    assert_eq!(r["assignee"], json!({"kind": "several", "count": 2}));
    let s = &body["summary"];
    assert_eq!(
        (
            s["failing_checks"].clone(),
            s["hosts"].clone(),
            s["critical"].clone(),
            s["unassigned"].clone()
        ),
        (1.into(), 2.into(), 0.into(), 0.into())
    );
    assert_eq!(s["rule_sets"], json!([{"value": "baseline", "count": 1}]));
    assert_eq!(count(&body, "state", "open"), 1);
    assert_eq!(count(&body, "state", "passing"), 2);
    assert_eq!(count(&body, "state", "all"), 3);
    assert_eq!(count(&body, "severity", "high"), 1);
    assert_eq!(count(&body, "rule_set", "baseline"), 1);
    assert_eq!(count(&body, "area", "Network exposure"), 1);
    assert_eq!(body["counts"]["assignee"]["me"], 1);
    assert_eq!(body["counts"]["assignee"]["unassigned"], 0);
    assert_eq!(
        body["counts"]["assignee"]["people"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert!(
        body["counts"]["group"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g["value"] == other.as_str() && g["name"] == "Other" && g["count"] == 1)
    );

    // passing-only and ended-finding checks
    let (_, body) = fx
        .call(
            &fx.admin,
            "GET",
            &format!("{URL}?state=passing&sort=title&dir=asc"),
            None,
        )
        .await;
    assert_eq!(
        keys(&body),
        ["port.redis.exposed", "package.telnet_server.installed"]
    );
    let r = row(&body, "port.redis.exposed");
    assert_eq!(
        (r["failing"].clone(), r["passing"].clone()),
        (0.into(), 2.into())
    );
    assert_eq!(r["severity"], "high", "the indexed severity, no finding");
    assert_eq!(r["assignee"], json!({"kind": "none"}));
    assert!(r["since"].is_null());
    let (_, body) = fx
        .call(&fx.admin, "GET", &format!("{URL}?state=all"), None)
        .await;
    assert_eq!(body["total"], 3);
    let (_, body) = fx
        .call(
            &fx.admin,
            "GET",
            &format!("{URL}?state=all&q=TELNET&area=Packages"),
            None,
        )
        .await;
    assert_eq!(keys(&body), ["package.telnet_server.installed"]);
    let (_, body) = fx
        .call(
            &fx.admin,
            "GET",
            &format!("{URL}?state=all&sort=title&dir=asc&limit=1&offset=1"),
            None,
        )
        .await;
    assert_eq!(
        (keys(&body), body["total"].clone()),
        (vec!["port.ssh.exposed"], 3.into())
    );
    fx.db.drop().await;
}

#[tokio::test]
async fn me_is_the_signed_in_person_and_unassigned_is_not_a_name() {
    let Some(fx) = Fx::new().await else { return };
    seed(&fx).await;
    let (_, body) = fx
        .call(&fx.admin, "GET", &format!("{URL}?assignee=me"), None)
        .await;
    assert_eq!(keys(&body), ["port.ssh.exposed"]);
    assert_eq!(body["items"][0]["failing"], 2, "the row, not only the pair");
    let third = common::http::sign_in(&fx.router, "third").await;
    let (_, body) = fx
        .call(&third, "GET", &format!("{URL}?assignee=me"), None)
        .await;
    assert_eq!(keys(&body), ["port.ssh.exposed"]);
    let (_, body) = fx
        .call(
            &fx.admin,
            "GET",
            &format!("{URL}?assignee=unassigned&state=all"),
            None,
        )
        .await;
    assert_eq!(
        body["total"], 0,
        "passing hosts have no assignee, nor do they match"
    );
    let id = uid(3);
    let (_, body) = fx
        .call(&fx.admin, "GET", &format!("{URL}?assignee={id}"), None)
        .await;
    assert_eq!(keys(&body), ["port.ssh.exposed"]);
    fx.db.drop().await;
}

#[tokio::test]
async fn a_team_lead_sees_only_their_groups() {
    let Some(fx) = Fx::new().await else { return };
    let other = seed(&fx).await;
    let role = fx
        .role(
            "Win checks",
            &["compliance.read"],
            Reach::Groups(vec![WIN.into()]),
        )
        .await;
    fx.db.user("wa", &role, 4).await;
    let wa = common::http::sign_in(&fx.router, "wa").await;
    let (status, body) = fx.call(&wa, "GET", &format!("{URL}?state=all"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"], 3);
    let r = row(&body, "port.ssh.exposed");
    assert_eq!(
        (r["failing"].clone(), r["passing"].clone()),
        (1.into(), 0.into())
    );
    assert_eq!(r["assignee"]["kind"], "one");
    assert_eq!(r["assignee"]["id"], uid(1));
    assert_eq!(
        body["counts"]["assignee"]["people"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(body["summary"]["hosts"], 1);
    assert!(
        body["counts"]["group"]
            .as_array()
            .unwrap()
            .iter()
            .all(|g| g["value"] != other.as_str())
    );
    for q in [format!("host={L1}"), format!("group={other}")] {
        let (status, body) = fx.call(&wa, "GET", &format!("{URL}?{q}"), None).await;
        assert_eq!(
            (status, body["total"].clone()),
            (StatusCode::OK, 0.into()),
            "{q}"
        );
    }
    // compliance.read is required
    let role = fx.role("Hosts only", &["hosts.read"], Reach::All).await;
    fx.db.user("ho", &role, 5).await;
    let ho = common::http::sign_in(&fx.router, "ho").await;
    let (status, _) = fx.call(&ho, "GET", URL, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    fx.db.drop().await;
}

#[tokio::test]
async fn the_compliance_page_keeps_saved_views_and_hidden_columns() {
    let Some(fx) = Fx::new().await else { return };
    let a = &fx.admin;
    let (status, _) = fx
        .call(
            a,
            "POST",
            "/api/v1/saved-views",
            Some(json!({"page": "compliance", "name": "Mine", "query": "assignee=me"})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let cols = "/api/v1/list-columns/compliance";
    let (status, _) = fx
        .call(
            a,
            "PUT",
            cols,
            Some(json!({"hidden": ["area", "failing", "hosts", "since", "assignee"]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    for never in ["severity", "check"] {
        let (status, body) = fx
            .call(a, "PUT", cols, Some(json!({"hidden": [never]})))
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{never} {body}");
    }
    fx.db.drop().await;
}

#[tokio::test]
async fn triage_states_are_counted_and_an_expired_acceptance_is_open() {
    let Some(fx) = Fx::new().await else { return };
    let client = fx.db.pool.get().await.unwrap();
    let host = |n: u8| format!("agent.00000000-0000-4000-8000-0000000000c{n}");
    let mut sql = String::new();
    for (n, state, until) in [
        (1, "mitigated", "NULL"),
        (2, "accepted_risk", "now() + interval '30 days'"),
        (3, "accepted_risk", "now() - interval '1 day'"),
        (4, "open", "NULL"),
    ] {
        let a = host(n);
        sql += &format!(
            "INSERT INTO agents (agent_id, status, enrolled_at, hostname, last_seen_at)
                VALUES ('{a}', 'active', now(), 'h{n}', now());
             INSERT INTO current_findings (agent_id, rule_set_id, rule_id, last_finding_id, rule_version, severity,
                    first_observed_at, last_observed_at, last_observed_day, scan_id, confidence, message, evidence,
                    received_at, origin, authenticated, source)
                VALUES ('{a}', 'site', 'x.check', 'f', 1, 'low', now() - interval '2 days', now(), current_date,
                        's', 90, 'm', '{{}}', now(), 'online', true, 'changes');
             INSERT INTO console_finding_triage (agent_id, rule_set_id, rule_id, state, rule_version, assigned_to,
                    note, accepted_until, version, updated_at, updated_by)
                VALUES ('{a}', 'site', 'x.check', '{state}', 1, NULL, 'n', {until}, 1, now(), 't');"
        );
    }
    client.batch_execute(&sql).await.unwrap();
    for (state, want) in [("open", 2), ("mitigated", 1), ("accepted_risk", 1)] {
        let (_, body) = fx
            .call(&fx.admin, "GET", &format!("{URL}?state={state}"), None)
            .await;
        assert_eq!(keys(&body), ["x.check"], "{state}");
        assert_eq!(count(&body, "state", state), 1, "{state}");
        let r = row(&body, "x.check");
        assert_eq!(r["failing"], 4);
        let field = if state == "accepted_risk" {
            "accepted_risk"
        } else {
            state
        };
        assert_eq!(r[field], want, "{state}: the expired acceptance is open");
        assert_eq!(r["false_positive"], 0);
    }
    fx.db.drop().await;
}
