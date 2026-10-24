//! `GET /api/v1/hosts/{agent_id}/summary`: the host page above the fold,
//! each section present only with its permission on this host.

use axum::http::StatusCode;
use platform_store::console_roles::Reach;
use serde_json::Value;

mod common;
use common::people::{Fx, WIN};

const W1: &str = "agent.00000000-0000-4000-8000-0000000000a1";
const L1: &str = "agent.00000000-0000-4000-8000-0000000000b1";
const R1: &str = "agent.00000000-0000-4000-8000-0000000000c1";

fn url(id: &str) -> String {
    format!("/api/v1/hosts/{id}/summary")
}

/// W1 (in `win`) with two open alarms and a failing check, L1 elsewhere,
/// R1 revoked.
async fn seed(fx: &Fx) {
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
            "INSERT INTO agents (agent_id, status, enrolled_at, revoked_at, hostname, last_seen_at, os_id, os_version, scanner_version) VALUES
                ('{W1}', 'active', now(), NULL, 'win-01', now(), 'windows', '11', '0.4.1'),
                ('{L1}', 'active', now(), NULL, 'lin-01', now(), 'debian', '12', '0.4.2'),
                ('{R1}', 'revoked', now(), now(), 'old-01', now() - interval '1 day', 'debian', '12', '0.4.2');
             INSERT INTO console_host_group_members (asset_group_id, agent_id, added_at, added_by)
                VALUES ('{WIN}', '{W1}', now(), 't');
             INSERT INTO console_host_labels (agent_id, label, added_at, added_by) VALUES ('{W1}', 'prod', now(), 't');
             INSERT INTO alarms (first_seen_day, agent_id, alarm_id, rule_set_id, rule_set_version, rule_id, rule_version,
                                 severity, confidence, message, first_seen, last_seen, count, process, ancestors,
                                 received_at, state, note)
                VALUES ((now() AT TIME ZONE 'UTC')::date, '{W1}', 'a1', 'rs', 1, 'low-rule', 1, 'low', 50, 'm',
                        now(), now(), 1, '{{}}', '[]', now(), 'open', 'n'),
                       ((now() AT TIME ZONE 'UTC')::date, '{W1}', 'a2', 'rs', 1, 'crit-rule', 1, 'critical', 50, 'm',
                        now(), now(), 1, '{{}}', '[]', now(), 'open', 'n');
             INSERT INTO current_findings (agent_id, rule_set_id, rule_id, last_finding_id, rule_version, severity,
                                           first_observed_at, last_observed_at, last_observed_day, scan_id,
                                           confidence, message, evidence, received_at, origin, authenticated)
                VALUES ('{W1}', 'set', 'ssh-root', 'f-1', 1, 'high', now(), now(), (now() AT TIME ZONE 'UTC')::date,
                        's', 50, 'Root login over SSH', '{{}}', now(), 'online', false)"
        ))
        .await
        .unwrap();
}

#[tokio::test]
async fn an_administrator_sees_every_section() {
    let Some(fx) = Fx::new().await else { return };
    seed(&fx).await;
    let (status, body) = fx.call(&fx.admin, "GET", &url(W1), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["host"]["id"], W1);
    assert_eq!(body["host"]["hostname"], "win-01");
    assert_eq!(body["host"]["status"], "online");
    assert_eq!(body["host"]["os"]["family"], "windows");
    assert_eq!(body["tiles"]["open_alarms"], 2);
    assert_eq!(body["tiles"]["compliance_failing"], 1);
    assert_eq!(body["tiles"]["compliance_stale"], false);
    assert_eq!(body["tiles"]["vulnerabilities"], 0);
    assert_eq!(body["tiles"]["software"], 0);
    assert_eq!(body["top_alarms"]["total"], 2);
    assert_eq!(body["top_alarms"]["items"][0]["rule_id"], "crit-rule");
    assert_eq!(body["top_alarms"]["items"][0]["severity"], "critical");
    assert!(body["top_alarms"]["items"][0]["id"].is_i64());
    assert_eq!(body["top_failing"]["items"][0]["rule_id"], "ssh-root");
    assert_eq!(body["top_failing"]["items"][0]["rule_set_id"], "set");
    assert_eq!(body["top_vulnerabilities"]["total"], 0);
    assert_eq!(body["groups"][0]["name"], "win");
    assert_eq!(body["groups"][0]["id"], WIN);
    assert_eq!(body["labels"], serde_json::json!(["prod"]));
    assert_eq!(body["certificate_count"], 0);
    assert_eq!(body["inventory"]["packages"], 0);
    assert!(body["protection"]["last_test"].is_object());
    let can = &body["can"];
    for key in ["label", "revoke", "export", "add_to_case"] {
        assert_eq!(can[key], true, "{key}");
    }
    // The assistant is off in tests, so "Ask" is not offered.
    assert_eq!(can["ask"], false);
    fx.db.drop().await;
}

#[tokio::test]
async fn summary_sections_follow_permissions() {
    let Some(fx) = Fx::new().await else { return };
    seed(&fx).await;
    let role = fx
        .role(
            "Win no alarms",
            &["hosts.read", "compliance.read", "vulnerabilities.read"],
            Reach::Groups(vec![WIN.into()]),
        )
        .await;
    fx.db.user("wn", &role, 3).await;
    let wn = common::http::sign_in(&fx.router, "wn").await;
    let (status, body) = fx.call(&wn, "GET", &url(W1), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["tiles"]["open_alarms"].is_null());
    assert!(body["top_alarms"].is_null());
    assert_eq!(body["tiles"]["compliance_failing"], 1);
    assert_eq!(body["top_failing"]["total"], 1);
    assert_eq!(body["tiles"]["vulnerabilities"], 0);
    assert_eq!(body["tiles"]["software"], 0);
    assert_eq!(body["labels"], serde_json::json!(["prod"]));
    assert!(body["protection"].is_object());
    let can = &body["can"];
    for key in ["label", "revoke", "export", "add_to_case", "ask"] {
        assert_eq!(can[key], false, "{key}");
    }

    // hosts.read only: no compliance either.
    let lead = fx.windows_lead().await;
    let (status, body) = fx.call(&lead, "GET", &url(W1), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["tiles"]["compliance_failing"].is_null());
    assert!(body["top_failing"].is_null());
    assert!(body["tiles"]["vulnerabilities"].is_null());
    assert!(body["top_vulnerabilities"].is_null());
    assert_eq!(body["tiles"]["software"], 0);
    fx.db.drop().await;
}

#[tokio::test]
async fn out_of_reach_and_missing_hosts_are_the_same_404() {
    let Some(fx) = Fx::new().await else { return };
    seed(&fx).await;
    let lead = fx.windows_lead().await;
    let (status, mut outside) = fx.call(&lead, "GET", &url(L1), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, mut missing) = fx.call(&lead, "GET", &url("agent.nope"), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(outside["code"], "host_not_found");
    outside["request_id"] = Value::Null;
    missing["request_id"] = Value::Null;
    assert_eq!(outside, missing);
    let role = fx.role("Alarms only", &["alarms.read"], Reach::All).await;
    fx.db.user("ao", &role, 4).await;
    let ao = common::http::sign_in(&fx.router, "ao").await;
    let (status, _) = fx.call(&ao, "GET", &url(W1), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    fx.db.drop().await;
}

#[tokio::test]
async fn a_revoked_host_still_answers_and_cannot_be_revoked_again() {
    let Some(fx) = Fx::new().await else { return };
    seed(&fx).await;
    let (status, body): (_, Value) = fx.call(&fx.admin, "GET", &url(R1), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["host"]["status"], "revoked");
    assert!(body["host"]["revoked_at"].is_string());
    assert_eq!(body["can"]["revoke"], false);
    assert_eq!(body["can"]["label"], false);
    assert_eq!(body["can"]["export"], true);
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
    let readers = fx
        .role(
            "Win readers",
            &["hosts.read"],
            Reach::Groups(vec![WIN.into()]),
        )
        .await;
    let changers = fx
        .role(
            "Other changers",
            &["hosts.read", "hosts.label", "hosts.revoke"],
            Reach::Groups(vec![other]),
        )
        .await;
    fx.db.user("mixed", &readers, 5).await;
    fx.db
        .pool
        .get()
        .await
        .unwrap()
        .execute(
            "INSERT INTO console_role_bindings (binding_id, user_id, role_id, created_at, created_by)
             VALUES (gen_random_uuid(), $1::text::uuid, $2, now(), 'test')",
            &[&common::people::uid(5), &changers],
        )
        .await
        .unwrap();
    let mixed = common::http::sign_in(&fx.router, "mixed").await;
    let (status, body) = fx.call(&mixed, "GET", &url(W1), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["can"]["revoke"], false);
    assert_eq!(body["can"]["label"], false);
    let (status, body) = fx.call(&mixed, "GET", &url(L1), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["can"]["revoke"], true);
    assert_eq!(body["can"]["label"], true);

    // The list sends the group's `id` too.
    let (_, list) = fx.call(&fx.admin, "GET", "/api/v1/hosts", None).await;
    let w1 = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == W1)
        .unwrap();
    assert_eq!(w1["groups"][0]["id"], WIN);
    fx.db.drop().await;
}

/// `/compliance?host=` reads `GET /api/v1/compliance/groups?agent_id=`:
/// one host's findings, still inside the caller's scope, with their triage;
/// a finding triaged away is not failing on the host page either.
#[tokio::test]
async fn compliance_groups_filter_by_host_inside_the_scope() {
    let Some(fx) = Fx::new().await else { return };
    seed(&fx).await;
    let client = fx.db.pool.get().await.unwrap();
    client
        .batch_execute(&format!(
            "INSERT INTO current_findings (agent_id, rule_set_id, rule_id, last_finding_id, rule_version, severity,
                                           first_observed_at, last_observed_at, last_observed_day, scan_id,
                                           confidence, message, evidence, received_at, origin, authenticated)
                VALUES ('{L1}', 'set', 'ssh-root', 'f-2', 1, 'high', now(), now(), (now() AT TIME ZONE 'UTC')::date,
                        's', 50, 'Root login over SSH', '{{}}', now(), 'online', false),
                       ('{L1}', 'set', 'tmp-noexec', 'f-3', 1, 'low', now(), now(), (now() AT TIME ZONE 'UTC')::date,
                        's', 50, '/tmp allows exec', '{{}}', now(), 'online', false)"
        ))
        .await
        .unwrap();
    let groups = |body: &Value| -> Vec<(String, u64, u64)> {
        body["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| {
                (
                    g["rule_id"].as_str().unwrap().to_owned(),
                    g["endpoint_count"].as_u64().unwrap(),
                    g["triage_counts"]["open"].as_u64().unwrap(),
                )
            })
            .collect()
    };
    let (status, all) = fx
        .call(&fx.admin, "GET", "/api/v1/compliance/groups", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{all}");
    assert!(groups(&all).contains(&("ssh-root".into(), 2, 2)));
    let (_, one) = fx
        .call(
            &fx.admin,
            "GET",
            &format!("/api/v1/compliance/groups?agent_id={L1}"),
            None,
        )
        .await;
    let mut got = groups(&one);
    got.sort();
    assert_eq!(
        got,
        [("ssh-root".into(), 1, 1), ("tmp-noexec".into(), 1, 1)]
    );

    // A person reaching only `win` asking for L1 gets nothing, not L1's findings.
    let role = fx
        .role(
            "Win compliance",
            &["hosts.read", "compliance.read"],
            Reach::Groups(vec![WIN.into()]),
        )
        .await;
    fx.db.user("wc", &role, 3).await;
    let wc = common::http::sign_in(&fx.router, "wc").await;
    let (status, body) = fx
        .call(
            &wc,
            "GET",
            &format!("/api/v1/compliance/groups?agent_id={L1}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(groups(&body), []);
    let (status, _) = fx
        .call(
            &fx.admin,
            "GET",
            "/api/v1/compliance/groups?agent_id=bad%01id",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // A host silent for days: its page asks for every current finding.
    client
        .batch_execute(&format!(
            "UPDATE current_findings SET last_observed_at = now() - interval '200 days'
             WHERE agent_id = '{L1}' AND rule_id = 'tmp-noexec'"
        ))
        .await
        .unwrap();
    let all_time = "since=1970-01-01T00:00:00Z";
    let (_, recent) = fx
        .call(
            &fx.admin,
            "GET",
            &format!("/api/v1/compliance/groups?agent_id={L1}"),
            None,
        )
        .await;
    assert_eq!(groups(&recent), [("ssh-root".into(), 1, 1)]);
    let (status, all) = fx
        .call(
            &fx.admin,
            "GET",
            &format!("/api/v1/compliance/groups?agent_id={L1}&{all_time}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{all}");
    let mut got = groups(&all);
    got.sort();
    assert_eq!(
        got,
        [("ssh-root".into(), 1, 1), ("tmp-noexec".into(), 1, 1)]
    );
    let (status, _) = fx
        .call(
            &fx.admin,
            "GET",
            &format!("/api/v1/compliance/groups?{all_time}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Mitigated on W1: the host's group shows it closed, the page counts 0.
    client
        .batch_execute(&format!(
            "INSERT INTO console_finding_triage (agent_id, rule_set_id, rule_id, state, rule_version, note,
                                                 version, updated_at, updated_by)
                VALUES ('{W1}', 'set', 'ssh-root', 'mitigated', 1, 'patched', 1, now(), 'test')"
        ))
        .await
        .unwrap();
    let (_, w1) = fx
        .call(
            &fx.admin,
            "GET",
            &format!("/api/v1/compliance/groups?agent_id={W1}"),
            None,
        )
        .await;
    assert_eq!(groups(&w1), [("ssh-root".into(), 1, 0)]);
    let (_, summary) = fx.call(&fx.admin, "GET", &url(W1), None).await;
    assert_eq!(summary["tiles"]["compliance_failing"], 0);
    assert_eq!(summary["top_failing"]["total"], 0);
    fx.db.drop().await;
}

/// A host with no report in the last day (the Compliance list's window)
/// says so instead of a failing count the list would not show.
#[tokio::test]
async fn a_host_silent_for_a_day_is_compliance_stale() {
    let Some(fx) = Fx::new().await else { return };
    seed(&fx).await;
    let client = fx.db.pool.get().await.unwrap();
    client
        .execute(
            "UPDATE agents SET last_seen_at = now() - interval '2 days' WHERE agent_id = $1",
            &[&W1],
        )
        .await
        .unwrap();
    client
        .execute(
            "UPDATE current_findings SET last_observed_at = now() - interval '2 days' WHERE agent_id = $1",
            &[&W1],
        )
        .await
        .unwrap();
    let (status, body) = fx.call(&fx.admin, "GET", &url(W1), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["tiles"]["compliance_stale"], true);
    assert_eq!(body["tiles"]["compliance_failing"], 0);
    fx.db.drop().await;
}
