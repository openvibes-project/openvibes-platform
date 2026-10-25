//! `GET /api/v1/cases/{id}/summary` (step 5d rulings 12–14): the page's
//! shape, a team member's reach (Review Focus 1), names only with
//! `access.read`, problems only per readable kind, and the `can` flags.

use axum::http::StatusCode;
use platform_store::console_roles::Reach;
use serde_json::{Value, json};

mod common;
use common::{
    http::sign_in,
    people::{Fx, WIN, uid},
};

const W1: &str = "agent.00000000-0000-4000-8000-0000000000a1";
const L1: &str = "agent.00000000-0000-4000-8000-0000000000b1";
const OPEN: &str = "00000000-0000-4000-8000-000000000001";
const HIDDEN: &str = "00000000-0000-4000-8000-000000000002";
const CLOSED: &str = "00000000-0000-4000-8000-000000000003";
const LIN: &str = "41111111-1111-4111-8111-111111111111";

fn url(id: &str) -> String {
    format!("/api/v1/cases/{id}/summary")
}

/// W1 (web-01, in `win`, 2 open alarms) and L1 (lin-01, not). Alice opens
/// OPEN (alarm W1, vulnerability L1), HIDDEN (vulnerability L1) and
/// CLOSED (host W1, closed with a note).
async fn seed(fx: &Fx) {
    let client = fx.db.pool.get().await.unwrap();
    let alice = uid(1);
    let yesterday = chrono::Utc::now().date_naive() - chrono::Duration::days(1);
    platform_store::ensure_partitions(&client, yesterday, 2)
        .await
        .unwrap();
    client
        .batch_execute(&format!(
            "INSERT INTO agents (agent_id, status, enrolled_at, hostname, os_id, last_seen_at) VALUES
                ('{W1}', 'active', now(), 'web-01', 'debian', now()),
                ('{L1}', 'active', now(), 'lin-01', 'fedora', now());
             INSERT INTO console_host_group_members (asset_group_id, agent_id, added_at, added_by)
                VALUES ('{WIN}', '{W1}', now(), 't');
             INSERT INTO alarms (first_seen_day, agent_id, alarm_id, rule_set_id, rule_set_version,
                                 rule_id, rule_version, severity, confidence, message, first_seen,
                                 last_seen, count, process, ancestors, received_at, state, note)
             SELECT (now() AT TIME ZONE 'UTC')::date, '{W1}', md5(n::text), 'rs', 1, 'r', 1, 'high',
                    50, 'm', now(), now(), 1, '{{}}', '[]', now(), 'open', 'n'
             FROM generate_series(1, 2) n;
             INSERT INTO cases (case_id, title, status, severity, opened_by_user_id, created_at,
                                updated_at, closed_at, resolution_note)
             VALUES ('{OPEN}', 'Open one', 'open', 'high', '{alice}', now() - interval '2 hours', now(), NULL, NULL),
                    ('{HIDDEN}', 'Hidden', 'open', 'low', '{alice}', now(), now(), NULL, NULL),
                    ('{CLOSED}', 'Closed one', 'closed', 'low', '{alice}', now() - interval '24 hours',
                     now(), now() - interval '23 hours', 'fixed');
             INSERT INTO case_items (item_id, case_id, kind, ref, agent_id, active, added_by_user_id, added_at)
             VALUES (gen_random_uuid(), '{OPEN}', 'alarm', '7', '{W1}', true, '{alice}', now()),
                    (gen_random_uuid(), '{OPEN}', 'vulnerability', '{L1}/CVE-1', '{L1}', true, '{alice}', now()),
                    (gen_random_uuid(), '{HIDDEN}', 'vulnerability', '{L1}/CVE-2', '{L1}', true, '{alice}', now()),
                    (gen_random_uuid(), '{CLOSED}', 'host', '{W1}', '{W1}', false, '{alice}', now());"
        ))
        .await
        .unwrap();
}

async fn get(fx: &Fx, who: &common::http::Session, id: &str) -> (StatusCode, Value) {
    fx.call(who, "GET", &url(id), None).await
}

#[tokio::test]
async fn the_page_has_header_tiles_details_hosts_people_and_can() {
    let Some(fx) = Fx::new().await else { return };
    seed(&fx).await;
    let (status, b) = get(&fx, &fx.admin, OPEN).await;
    assert_eq!(status, StatusCode::OK, "{b}");
    assert_eq!(b["header"]["case_id"], OPEN);
    assert_eq!(b["header"]["title"], "Open one");
    assert_eq!(b["header"]["opened_by"]["user_id"], uid(1));
    assert_eq!(b["header"]["assignee"], Value::Null);
    assert!(b["header"]["number"].is_i64() && b["header"]["created_at"].is_string());
    assert_eq!(b["tiles"]["items"], 2);
    assert_eq!(b["tiles"]["need_outcome"], 2);
    assert_eq!(b["tiles"]["hosts"], 2);
    assert_eq!(b["tiles"]["ready"], false);
    let open_for = b["tiles"]["open_for_seconds"].as_i64().unwrap();
    assert!((7190..7300).contains(&open_for), "{open_for}");
    assert_eq!(b["details"]["status"], "open");
    assert_eq!(b["details"]["resolution_note"], Value::Null);
    assert_eq!(b["hosts"][0]["agent_id"], L1, "lin-01 before web-01");
    assert_eq!(b["hosts"][1]["hostname"], "web-01");
    assert_eq!(b["hosts"][1]["os"]["id"], "debian");
    assert_eq!(
        b["hosts"][1]["problems"],
        json!({"alarms": 2, "critical_vulns": 0, "failing_checks": 0, "compliance_stale": false})
    );
    assert_eq!(b["people"]["names"][0]["username"], "alice");
    assert_eq!(b["people"]["total"], 1);
    assert_eq!(b["people"]["complete"], true);
    assert_eq!(
        b["can"],
        json!({"edit": true, "assign": true, "close": true, "reopen": false, "note": true,
               "outcome": true, "ask": false, "export": true})
    );

    let (_, b) = get(&fx, &fx.admin, CLOSED).await;
    assert_eq!(b["details"]["resolution_note"], "fixed");
    assert!(b["details"]["closed_at"].is_string());
    assert_eq!(b["tiles"]["open_for_seconds"], 3600);
    assert_eq!(b["tiles"]["ready"], false);
    assert_eq!(
        (
            &b["can"]["close"],
            &b["can"]["reopen"],
            &b["can"]["outcome"],
            &b["can"]["note"]
        ),
        (&json!(false), &json!(true), &json!(false), &json!(true))
    );
    fx.db.drop().await;
}

#[tokio::test]
async fn case_summary_stays_inside_a_team_members_reach() {
    let Some(fx) = Fx::new().await else { return };
    seed(&fx).await;
    let reader = fx
        .role(
            "Win cases",
            &["cases.read"],
            Reach::Groups(vec![WIN.into()]),
        )
        .await;
    fx.db.user("bea", &reader, 3).await;
    let bea = sign_in(&fx.router, "bea").await;
    let (status, b) = get(&fx, &bea, OPEN).await;
    assert_eq!(status, StatusCode::OK, "{b}");
    assert_eq!(
        (
            &b["tiles"]["items"],
            &b["tiles"]["need_outcome"],
            &b["tiles"]["hosts"]
        ),
        (&json!(1), &json!(1), &json!(1)),
        "lin-01's vulnerability is out of reach"
    );
    assert_eq!(b["hosts"].as_array().unwrap().len(), 1);
    assert_eq!(b["hosts"][0]["agent_id"], W1);
    assert_eq!(
        b["hosts"][0]["problems"],
        json!({"alarms": null, "critical_vulns": null, "failing_checks": null, "compliance_stale": false}),
        "no alarms, vulnerabilities or compliance read"
    );
    assert_eq!(b["people"]["names"], Value::Null, "no access.read");
    assert_eq!(b["people"]["total"], 2, "alice and bea");
    assert_eq!(
        b["people"]["complete"], false,
        "a scoped reader may not know everyone"
    );
    assert_eq!(
        b["can"],
        json!({"edit": false, "assign": false, "close": false, "reopen": false, "note": false,
               "outcome": false, "ask": false, "export": true})
    );
    for id in [HIDDEN, "00000000-0000-4000-8000-000000000099", "nope"] {
        let (status, b) = get(&fx, &bea, id).await;
        assert_eq!(
            (status, &b["code"]),
            (StatusCode::NOT_FOUND, &json!("case_not_found")),
            "{id}"
        );
    }
    fx.db.drop().await;
}

#[tokio::test]
async fn writes_count_only_inside_the_cases_read_reach() {
    let Some(fx) = Fx::new().await else { return };
    seed(&fx).await;
    let client = fx.db.pool.get().await.unwrap();
    client
        .batch_execute(&format!(
            "INSERT INTO console_asset_groups (asset_group_id, name, created_at, created_by)
             VALUES ('{LIN}', 'lin', now(), 'test')"
        ))
        .await
        .unwrap();
    let read = fx
        .role(
            "Win cases",
            &["cases.read", "alarms.read"],
            Reach::Groups(vec![WIN.into()]),
        )
        .await;
    // Cy writes on lin only, Dee everywhere: changes stay inside what each reads.
    let lin = fx
        .role(
            "Lin writer",
            &["cases.write"],
            Reach::Groups(vec![LIN.into()]),
        )
        .await;
    let all = fx.role("Writer", &["cases.write"], Reach::All).await;
    for (name, index, write) in [("cy", 4, &lin), ("dee", 5, &all)] {
        fx.db.user(name, &read, index).await;
        client
            .execute(
                "INSERT INTO console_role_bindings (binding_id, user_id, role_id, created_at, created_by)
                 VALUES (gen_random_uuid(), $1::text::uuid, $2, now(), 't')",
                &[&uid(index), write],
            )
            .await
            .unwrap();
    }
    let (_, b) = get(&fx, &sign_in(&fx.router, "cy").await, OPEN).await;
    assert_eq!(
        (&b["can"]["edit"], &b["can"]["note"]),
        (&json!(false), &json!(false))
    );
    let (_, b) = get(&fx, &sign_in(&fx.router, "dee").await, OPEN).await;
    assert_eq!(
        (&b["can"]["edit"], &b["can"]["close"]),
        (&json!(true), &json!(true))
    );
    assert_eq!(b["can"]["assign"], false, "no cases.assign");
    assert_eq!(b["hosts"][0]["problems"]["alarms"], 2, "alarms.read on win");
    fx.db.drop().await;
}

#[tokio::test]
async fn callers_without_cases_read_are_refused() {
    let Some(fx) = Fx::new().await else { return };
    seed(&fx).await;
    fx.db.user("vic", &fx.win_viewers, 6).await;
    let vic = sign_in(&fx.router, "vic").await;
    let (status, _) = get(&fx, &vic, OPEN).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    fx.db.drop().await;
}
