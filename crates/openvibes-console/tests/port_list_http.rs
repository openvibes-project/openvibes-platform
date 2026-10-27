//! `GET /api/v1/port-list`: validation, shape and counts, a team lead's
//! reach, and the saved-views page "ports".

use axum::http::StatusCode;
use serde_json::{Value, json};

mod common;
use common::lists::{self, count};
use common::people::{Fx, WIN};

const W1: &str = "agent.00000000-0000-4000-8000-0000000000a1";
const L1: &str = "agent.00000000-0000-4000-8000-0000000000b1";
const URL: &str = "/api/v1/port-list";

/// W1 (in `win`) and L1 (outside it).
/// - tcp/22: both, exposed; W1 stopped and restarted it (change log).
/// - tcp/5432: W1 on loopback only, L1 exposed.
/// - tcp/9999: L1 only, no owner, started this week.
async fn seed(fx: &Fx) -> String {
    let client = fx.db.pool.get().await.unwrap();
    client
        .batch_execute(&format!(
            "INSERT INTO agents (agent_id, status, enrolled_at, hostname, last_seen_at, services_at, services_owners) VALUES
                ('{W1}', 'active', now(), 'win-01', now(), now(), 'partial'),
                ('{L1}', 'active', now(), 'lin-01', now(), now(), 'partial');
             INSERT INTO console_host_group_members (asset_group_id, agent_id, added_at, added_by)
                VALUES ('{WIN}', '{W1}', now(), 't');
             INSERT INTO host_listeners (agent_id, protocol, address, port, exposed, service, program) VALUES
                ('{W1}', 'tcp', '0.0.0.0', 22, true, 'sshd.service', NULL),
                ('{L1}', 'tcp', '0.0.0.0', 22, true, 'sshd.service', NULL),
                ('{W1}', 'tcp', '127.0.0.1', 5432, false, 'postgresql.service', NULL),
                ('{L1}', 'tcp', '0.0.0.0', 5432, true, 'postgresql.service', NULL),
                ('{L1}', 'tcp', '0.0.0.0', 9999, true, NULL, NULL);
             INSERT INTO change_log (at, agent_id, kind, key, change) VALUES
                (now() - interval '1 day', '{W1}', 'listener', 'tcp/22', 'appeared'),
                (now() - interval '1 day', '{L1}', 'listener', 'tcp/9999', 'appeared');"
        ))
        .await
        .unwrap();
    common::manual_group(&client, "Other", &[L1]).await
}

fn keys(body: &Value) -> Vec<String> {
    body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| format!("{}/{}", r["protocol"].as_str().unwrap(), r["port"]))
        .collect()
}

fn row<'a>(body: &'a Value, key: &str) -> &'a Value {
    body["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| format!("{}/{}", r["protocol"].as_str().unwrap(), r["port"]) == key)
        .unwrap()
}

#[tokio::test]
async fn every_parameter_is_validated_and_named() {
    let Some(fx) = Fx::new().await else { return };
    let bad = [
        ("exposure=gone", "exposure"),
        ("protocol=icmp", "protocol"),
        ("group=nope", "group"),
        ("changes=old", "changes"),
        ("host=%00", "host"),
        ("service=%00", "service"),
        ("sort=colour", "sort"),
        ("dir=up", "dir"),
        ("offset=-1", "offset"),
        ("offset=100001", "offset"),
        ("limit=0", "limit"),
        ("limit=101", "limit"),
        ("q=%00", "q"),
    ];
    // The old list's `exposed=true` is the web's to map.
    let (status, _) = fx
        .call(&fx.admin, "GET", &format!("{URL}?exposed=true"), None)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    lists::assert_queries_validated(
        &fx,
        URL,
        &bad,
        &[
            "limit=100&offset=100000",
            "exposure=exposed&protocol=tcp&changes=look&sort=week&dir=desc",
            "service=~none&sort=hosts",
            "service=sshd.service&exposure=local&q=22%2Ftcp",
            "host=agent.x&exposure=",
        ],
    )
    .await;
    fx.db.drop().await;
}

#[tokio::test]
async fn the_list_has_rows_counts_and_a_summary() {
    let Some(fx) = Fx::new().await else { return };
    let other = seed(&fx).await;
    let (status, body) = fx.call(&fx.admin, "GET", URL, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(keys(&body), ["tcp/22", "tcp/5432", "tcp/9999"]);
    assert_eq!(body["total"], 3);
    assert!(body["generated_at"].is_string());
    let ssh = row(&body, "tcp/22");
    assert_eq!(ssh["name"], "SSH");
    assert_eq!(
        (ssh["hosts"].clone(), ssh["exposed_hosts"].clone()),
        (2.into(), 2.into())
    );
    assert_eq!(ssh["services"], json!(["sshd.service"]));
    assert_eq!(ssh["week_added"], 1);
    assert_eq!(ssh["look"], json!([]));
    assert_eq!(ssh["groups"], json!([]), "the manual group is left out");
    let pg = row(&body, "tcp/5432");
    assert_eq!(pg["look"], json!(["database_exposed"]));
    assert_eq!(pg["exposed_hosts"], 1);
    let odd = row(&body, "tcp/9999");
    assert!(odd.get("name").is_none());
    assert_eq!(odd["owners_missing"], true);
    assert_eq!(odd["look"], json!(["new_unusual"]));
    assert_eq!(
        body["summary"],
        json!({"exposed": 3, "new_this_week": 2, "need_a_look": 2, "reporting_hosts": 2})
    );
    assert_eq!(count(&body, "exposure", "exposed"), 3);
    assert_eq!(count(&body, "exposure", "local"), 0);
    assert_eq!(count(&body, "protocol", "tcp"), 3);
    assert_eq!(count(&body, "changes", "new"), 2);
    assert_eq!(count(&body, "service", "sshd.service"), 1);
    assert_eq!(count(&body, "service", "~none"), 1);
    assert!(
        body["counts"]["group"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g["value"] == other.as_str() && g["name"] == "Other" && g["count"] == 3)
    );

    let (_, body) = fx
        .call(
            &fx.admin,
            "GET",
            &format!("{URL}?changes=look&sort=port&dir=desc"),
            None,
        )
        .await;
    assert_eq!(keys(&body), ["tcp/9999", "tcp/5432"]);
    let (_, body) = fx
        .call(&fx.admin, "GET", &format!("{URL}?service=~none"), None)
        .await;
    assert_eq!(keys(&body), ["tcp/9999"]);
    let (_, body) = fx
        .call(&fx.admin, "GET", &format!("{URL}?q=postgres"), None)
        .await;
    assert_eq!(keys(&body), ["tcp/5432"]);
    let (_, body) = fx
        .call(&fx.admin, "GET", &format!("{URL}?limit=1&offset=1"), None)
        .await;
    assert_eq!(
        (keys(&body), body["total"].clone()),
        (vec!["tcp/5432".to_string()], 3.into())
    );
    fx.db.drop().await;
}

#[tokio::test]
async fn a_team_lead_sees_only_their_groups() {
    let Some(fx) = Fx::new().await else { return };
    let other = seed(&fx).await;
    let (status, body) = fx.call(&fx.admin, "GET", URL, None).await;
    assert_eq!((status, body["total"].clone()), (StatusCode::OK, 3.into()));
    let lead = fx.windows_lead().await;
    let (status, body) = fx.call(&lead, "GET", URL, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(keys(&body), ["tcp/22", "tcp/5432"], "9999 is only on L1");
    assert_eq!(row(&body, "tcp/22")["hosts"], 1);
    assert_eq!(
        row(&body, "tcp/5432")["exposed_hosts"],
        0,
        "only W1's loopback"
    );
    assert_eq!(body["summary"]["reporting_hosts"], 1);
    let queries = [format!("host={L1}"), format!("group={other}")];
    lists::assert_out_of_reach(&fx, &lead, URL, &other, &queries).await;
    fx.db.drop().await;
}

#[tokio::test]
async fn the_ports_page_keeps_saved_views_and_hidden_columns() {
    let Some(fx) = Fx::new().await else { return };
    lists::assert_views_and_columns(
        &fx,
        "ports",
        ("Exposed", "exposure=exposed"),
        &["hosts", "exposed", "services", "groups", "week", "look"],
        "port",
    )
    .await;
    fx.db.drop().await;
}
