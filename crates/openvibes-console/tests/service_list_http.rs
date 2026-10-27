//! `GET /api/v1/service-list`: validation, shape and counts, a team lead's
//! reach, and the saved-views page "services".

use axum::http::StatusCode;
use serde_json::{Value, json};

mod common;
use common::lists::{self, count};
use common::people::{Fx, WIN};

const W1: &str = "agent.00000000-0000-4000-8000-0000000000a1";
const L1: &str = "agent.00000000-0000-4000-8000-0000000000b1";
const URL: &str = "/api/v1/service-list";

/// W1 (in `win`) and L1 (outside it).
/// - sshd.service: both, root, exposed on tcp/22; from `openssh-server` on W1.
/// - postgresql.service: W1 loopback only, L1 exposed; `postgres`.
/// - mystery.service: L1 only, root, no package, no port, started this week.
async fn seed(fx: &Fx) -> String {
    let client = fx.db.pool.get().await.unwrap();
    client
        .batch_execute(&format!(
            "INSERT INTO agents (agent_id, status, enrolled_at, hostname, last_seen_at, services_at, services_owners) VALUES
                ('{W1}', 'active', now(), 'win-01', now(), now(), 'complete'),
                ('{L1}', 'active', now(), 'lin-01', now(), now(), 'complete');
             INSERT INTO console_host_group_members (asset_group_id, agent_id, added_at, added_by)
                VALUES ('{WIN}', '{W1}', now(), 't');
             INSERT INTO host_services (agent_id, unit, programs, processes, run_as) VALUES
                ('{W1}', 'sshd.service', '{{sshd}}', 1, 'root'),
                ('{L1}', 'sshd.service', '{{sshd}}', 1, 'root'),
                ('{W1}', 'postgresql.service', '{{postgres}}', 4, 'postgres'),
                ('{L1}', 'postgresql.service', '{{postgres}}', 4, 'postgres'),
                ('{L1}', 'mystery.service', '{{mystery}}', 1, 'root');
             INSERT INTO host_listeners (agent_id, protocol, address, port, exposed, service, program) VALUES
                ('{W1}', 'tcp', '0.0.0.0', 22, true, 'sshd.service', 'sshd'),
                ('{L1}', 'tcp', '0.0.0.0', 22, true, 'sshd.service', 'sshd'),
                ('{W1}', 'tcp', '127.0.0.1', 5432, false, 'postgresql.service', NULL),
                ('{L1}', 'tcp', '0.0.0.0', 5432, true, 'postgresql.service', NULL);
             INSERT INTO package_versions (manager, name, version, arch) VALUES ('deb', 'openssh-server', '9.2', 'amd64');
             INSERT INTO host_packages (agent_id, package_version_id)
                SELECT '{W1}', id FROM package_versions WHERE name = 'openssh-server';
             INSERT INTO change_log (at, agent_id, kind, key, change) VALUES
                (now() - interval '1 day', '{L1}', 'service', 'mystery.service', 'appeared');"
        ))
        .await
        .unwrap();
    common::manual_group(&client, "Other", &[L1]).await
}

fn units(body: &Value) -> Vec<String> {
    body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["unit"].as_str().unwrap().to_owned())
        .collect()
}

fn row<'a>(body: &'a Value, unit: &str) -> &'a Value {
    body["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["unit"] == unit)
        .unwrap()
}

#[tokio::test]
async fn every_parameter_is_validated_and_named() {
    let Some(fx) = Fx::new().await else { return };
    let bad = [
        ("runs_as=gone", "runs_as"),
        ("listens=sometimes", "listens"),
        ("packaged=maybe", "packaged"),
        ("group=nope", "group"),
        ("changes=old", "changes"),
        ("host=%00", "host"),
        ("sort=colour", "sort"),
        ("dir=up", "dir"),
        ("offset=-1", "offset"),
        ("offset=100001", "offset"),
        ("limit=0", "limit"),
        ("limit=101", "limit"),
        ("q=%00", "q"),
    ];
    lists::assert_queries_validated(
        &fx,
        URL,
        &bad,
        &[
            "limit=100&offset=100000",
            "runs_as=root&listens=exposed&packaged=no&changes=look&sort=week&dir=desc",
            "listens=none&sort=hosts",
            "host=agent.x&runs_as=",
            "q=sshd.service",
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
    assert_eq!(
        units(&body),
        ["mystery.service", "postgresql.service", "sshd.service"]
    );
    assert_eq!(body["total"], 3);
    assert!(body["generated_at"].is_string());
    let ssh = row(&body, "sshd.service");
    assert_eq!(ssh["name"], "OpenSSH server");
    assert_eq!(
        (
            ssh["hosts"].clone(),
            ssh["root_hosts"].clone(),
            ssh["package_hosts"].clone()
        ),
        (2.into(), 2.into(), 1.into())
    );
    assert_eq!(ssh["package"], "openssh-server");
    assert_eq!(
        ssh["ports"],
        json!([{"protocol": "tcp", "port": 22, "exposed": true, "hosts": 2}])
    );
    assert_eq!(ssh["look"], json!(["root_unpackaged"]), "L1 has no package");
    assert_eq!(ssh["groups"], json!([]), "the manual group is left out");
    let pg = row(&body, "postgresql.service");
    assert_eq!(pg["look"], json!(["database_exposed"]));
    assert_eq!(pg["exposed_hosts"], 1);
    let odd = row(&body, "mystery.service");
    assert!(odd.get("name").is_none());
    assert_eq!(odd["look"], json!(["root_unpackaged", "new_unusual"]));
    assert_eq!(odd["week_added"], 1);
    assert_eq!(
        body["summary"],
        json!({"root": 2, "exposed": 2, "not_packaged": 3, "new_this_week": 1, "need_a_look": 3, "reporting_hosts": 2})
    );
    assert_eq!(count(&body, "runs_as", "root"), 2);
    assert_eq!(count(&body, "listens", "none"), 1);
    assert_eq!(count(&body, "packaged", "no"), 3);
    assert_eq!(count(&body, "changes", "new"), 1);
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
            &format!("{URL}?changes=look&sort=service&dir=desc"),
            None,
        )
        .await;
    assert_eq!(
        units(&body),
        ["sshd.service", "postgresql.service", "mystery.service"]
    );
    let (_, body) = fx
        .call(&fx.admin, "GET", &format!("{URL}?listens=none"), None)
        .await;
    assert_eq!(units(&body), ["mystery.service"]);
    let (_, body) = fx
        .call(&fx.admin, "GET", &format!("{URL}?q=22%2Ftcp"), None)
        .await;
    assert_eq!(units(&body), ["sshd.service"]);
    let (_, body) = fx
        .call(&fx.admin, "GET", &format!("{URL}?limit=1&offset=1"), None)
        .await;
    assert_eq!(
        (units(&body), body["total"].clone()),
        (vec!["postgresql.service".to_string()], 3.into())
    );
    fx.db.drop().await;
}

#[tokio::test]
async fn a_team_lead_sees_only_their_groups() {
    let Some(fx) = Fx::new().await else { return };
    let other = seed(&fx).await;
    let lead = fx.windows_lead().await;
    let (status, body) = fx.call(&lead, "GET", URL, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        units(&body),
        ["postgresql.service", "sshd.service"],
        "mystery is only on L1"
    );
    assert_eq!(row(&body, "sshd.service")["hosts"], 1);
    assert_eq!(
        row(&body, "sshd.service")["look"],
        json!([]),
        "W1 has the package"
    );
    assert_eq!(
        row(&body, "postgresql.service")["exposed_hosts"],
        0,
        "only W1's loopback"
    );
    assert_eq!(body["summary"]["reporting_hosts"], 1);
    let queries = [format!("host={L1}"), format!("group={other}")];
    lists::assert_out_of_reach(&fx, &lead, URL, &other, &queries).await;
    fx.db.drop().await;
}

#[tokio::test]
async fn the_services_page_keeps_saved_views_and_hidden_columns() {
    let Some(fx) = Fx::new().await else { return };
    lists::assert_views_and_columns(
        &fx,
        "services",
        ("Root", "runs_as=root"),
        &["hosts", "runs_as", "ports", "package", "week", "look"],
        "service",
    )
    .await;
    fx.db.drop().await;
}
