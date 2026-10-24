//! `GET /api/v1/compliance/checks/{rule_set_id}/{rule_id}/summary` and
//! `/hosts`: a check's page inside the viewer's reach, evidence with its
//! file and never a masked value, the Hosts segments, and the actions per
//! permission.

use axum::http::StatusCode;
use platform_store::console_roles::Reach;
use serde_json::{Value, json};

mod common;
use common::people::{Fx, WIN, uid};

const W1: &str = "agent.00000000-0000-4000-8000-0000000000a1";
const W2: &str = "agent.00000000-0000-4000-8000-0000000000a2";
const L1: &str = "agent.00000000-0000-4000-8000-0000000000b1";
const HEALTH: &str = r#"{"rule_sets":[{"id":"hardening-linux-l1","version":1}],
  "last_scan":{"collectors":{"ports":"ok","packages":"ok","hardening":"ok","processes":"ok"}}}"#;
const ROOT: &str = "hardening-linux-l1/harden.ssh.permit_root_login";
const ASLR: &str = "hardening-linux-l1/harden.kernel.aslr";

/// W1 and W2 (in `win`) and L1 (in `Other`, returned), healthy on
/// hardening-linux-l1 1.
/// - harden.ssh.permit_root_login: W1 open (Alice) with detection, L1 open;
///   W2 passes.
/// - harden.kernel.aslr: L1 only.
async fn seed(fx: &Fx) -> String {
    let client = fx.db.pool.get().await.unwrap();
    let alice = uid(1);
    let k = "07".repeat(32);
    let detection = json!({"inputs": [
        {"key": "sshd.permitrootlogin", "status": "complete", "value": "yes"},
        {"key": "sshd.secret", "status": "masked"},
        {"key": "port.tcp.exposed", "status": "summarized", "item_count": 3}
    ]});
    client
        .batch_execute(&format!(
            "INSERT INTO agents (agent_id, status, enrolled_at, hostname, last_seen_at, health, health_at) VALUES
                ('{W1}', 'active', now(), 'win-01', now(), '{HEALTH}', now()),
                ('{W2}', 'active', now(), 'win-02', now(), '{HEALTH}', now()),
                ('{L1}', 'active', now(), 'lin-01', now(), '{HEALTH}', now());
             INSERT INTO console_host_group_members (asset_group_id, agent_id, added_at, added_by)
                VALUES ('{WIN}', '{W1}', now(), 't'), ('{WIN}', '{W2}', now(), 't');
             INSERT INTO rule_sets (rule_set_id) VALUES ('hardening-linux-l1');
             INSERT INTO rule_trust_keys (rule_set_id, issuer_key_id, public_key)
                VALUES ('hardening-linux-l1', 'k', '\\x{k}');
             INSERT INTO rule_bundles (rule_set_id, version, envelope, envelope_sha256, issuer_key_id,
                                       created_at_ms, expires_at_ms, published_by)
                VALUES ('hardening-linux-l1', 1, '{{}}', sha256('h1'::bytea), 'k', 1, 9e15, 't');
             INSERT INTO console_rule_meta (rule_set_id, rule_set_version, rule_id, rule_version, title, message,
                                            explain, \"check\", attack, techniques, severity) VALUES
                ('hardening-linux-l1', 1, 'harden.ssh.permit_root_login', 3, 'Root login over SSH', 'msg',
                 'why', 'how', '[]', '{{T1078}}', 'critical'),
                ('hardening-linux-l1', 1, 'harden.kernel.aslr', 1, 'ASLR off', 'm', NULL, NULL, '[]', '{{}}', 'medium');
             INSERT INTO current_findings (agent_id, rule_set_id, rule_id, last_finding_id, rule_version, severity,
                    first_observed_at, last_observed_at, last_observed_day, scan_id, confidence, message, evidence,
                    received_at, origin, authenticated, source, detection) VALUES
                ('{W1}', 'hardening-linux-l1', 'harden.ssh.permit_root_login', 'f', 3, 'critical', now() - interval '3 days',
                 now(), current_date, 's', 90, 'm', '{{}}', now(), 'online', true, 'changes', '{detection}'),
                ('{L1}', 'hardening-linux-l1', 'harden.ssh.permit_root_login', 'f', 3, 'critical', now() - interval '2 days',
                 now(), current_date, 's', 90, 'm', '{{}}', now(), 'online', true, 'changes', NULL),
                ('{L1}', 'hardening-linux-l1', 'harden.kernel.aslr', 'f', 1, 'medium', now(), now(), current_date, 's',
                 90, 'm', '{{}}', now(), 'online', true, 'changes', NULL);
             INSERT INTO console_finding_triage (agent_id, rule_set_id, rule_id, state, rule_version, assigned_to,
                    note, accepted_until, version, updated_at, updated_by) VALUES
                ('{W1}', 'hardening-linux-l1', 'harden.ssh.permit_root_login', 'open', 3, '{alice}', NULL, NULL, 2, now(), 't');"
        ))
        .await
        .unwrap();
    common::manual_group(&client, "Other", &[L1]).await
}

fn summary(key: &str) -> String {
    format!("/api/v1/compliance/checks/{key}/summary")
}

fn hosts(key: &str, query: &str) -> String {
    format!("/api/v1/compliance/checks/{key}/hosts?{query}")
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
async fn the_summary_has_every_card() {
    let Some(fx) = Fx::new().await else { return };
    seed(&fx).await;
    let (status, body) = fx.call(&fx.admin, "GET", &summary(ROOT), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let h = &body["header"];
    assert_eq!(h["title"], "Root login over SSH");
    assert_eq!(h["severity"], "critical");
    assert_eq!(
        (h["rule_set_version"].clone(), h["rule_version"].clone()),
        (json!(1), json!(3))
    );
    assert_eq!(h["area"], "SSH");
    assert_eq!(
        (h["failing"].clone(), h["checked"].clone()),
        (json!(2), json!(3))
    );
    assert_eq!(h["assignee"]["kind"], "one");
    assert_eq!(body["tiles"]["passing"], 1);
    assert_eq!(body["tiles"]["days"].as_array().unwrap().len(), 14);
    assert_eq!(body["tiles"]["first_seen"]["hostname"], "win-01");
    assert_eq!(
        body["text"],
        json!({"explain": "why", "check": "how", "message": "msg"})
    );
    assert_eq!(
        body["details"],
        json!({"applies_to": "Linux hosts", "techniques": ["T1078"]})
    );
    assert_eq!(body["related"]["same_area"]["checks"], 0);
    assert!(body["related"]["port"].is_null());
    let kinds: Vec<&str> = body["history"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds.iter().filter(|k| **k == "failing").count(), 2);
    assert!(kinds.contains(&"published"));
    assert_eq!(body["can"]["triage"], true);
    assert_eq!(body["can"]["ask"], false, "the assistant is off");
    for bad in [
        "/api/v1/compliance/checks/hardening-linux-l1/no.such/summary",
        "/api/v1/compliance/checks/nope/harden.kernel.aslr/hosts",
        "/api/v1/compliance/checks/x%01/y/summary",
    ] {
        let (status, body) = fx.call(&fx.admin, "GET", bad, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{bad}");
        assert_eq!(body["code"], "check_not_found", "{bad}");
    }
    fx.db.drop().await;
}

#[tokio::test]
async fn a_team_lead_sees_only_their_hosts() {
    let Some(fx) = Fx::new().await else { return };
    seed(&fx).await;
    let lead = user(
        &fx,
        "lead",
        4,
        &["compliance.read"],
        Reach::Groups(vec![WIN.into()]),
    )
    .await;
    let (status, body) = fx.call(&lead, "GET", &summary(ROOT), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["header"]["failing"], 1);
    assert!(
        body["history"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["agent_id"] != L1)
    );
    assert_eq!(
        body["can"],
        json!({"triage": false, "assign": false, "add_to_case": false, "ask": false, "export": false})
    );
    let (_, body) = fx.call(&lead, "GET", &hosts(ROOT, ""), None).await;
    assert_eq!(body["total"], 2);
    assert!(
        body["rows"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["agent_id"] != L1)
    );
    // ASLR fails only on L1, but W1 and W2 pass it: the lead sees passing.
    let (status, body) = fx
        .call(&lead, "GET", &hosts(ASLR, "segment=failing"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        (body["total"].clone(), body["segments"]["passing"].clone()),
        (json!(0), json!(2))
    );
    let none = user(&fx, "none", 5, &["hosts.read"], Reach::All).await;
    for url in [summary(ROOT), hosts(ROOT, "")] {
        let (status, _) = fx.call(&none, "GET", &url, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{url}");
    }
    fx.db.drop().await;
}

#[tokio::test]
async fn the_hosts_table_has_segments_evidence_and_pages() {
    let Some(fx) = Fx::new().await else { return };
    seed(&fx).await;
    let (status, body) = fx.call(&fx.admin, "GET", &hosts(ROOT, ""), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["segments"],
        json!({"all": 3, "failing": 2, "passing": 1})
    );
    let rows = body["rows"].as_array().unwrap();
    let names: Vec<&str> = rows
        .iter()
        .map(|r| r["hostname"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["lin-01", "win-01", "win-02"]);
    let w1 = &rows[1];
    assert_eq!(w1["state"], "open");
    assert_eq!(w1["triage_version"], 2);
    assert_eq!(w1["assignee"]["id"], uid(1));
    assert_eq!(
        w1["evidence"],
        json!([
            {"fact": "sshd.permitrootlogin", "value": "yes", "file": "/etc/ssh/sshd_config"},
            {"fact": "sshd.secret", "status": "masked", "file": "/etc/ssh/sshd_config"},
            {"fact": "port.tcp.exposed", "status": "summarized"}
        ])
    );
    assert!(!body.to_string().contains("item_count"));
    assert_eq!(rows[0]["evidence"], json!([]), "no detection");
    let w2 = &rows[2];
    assert_eq!(
        (w2["state"].clone(), w2["evidence"].clone()),
        (json!("passing"), json!([]))
    );
    assert!(
        w2["triage_version"].is_null() && w2["assignee"].is_null() && w2["checked_at"].is_string()
    );
    let (_, body) = fx
        .call(&fx.admin, "GET", &hosts(ROOT, "segment=passing"), None)
        .await;
    assert_eq!(body["total"], 1);
    let (_, body) = fx
        .call(&fx.admin, "GET", &hosts(ROOT, "limit=1&offset=2"), None)
        .await;
    assert_eq!(
        (body["total"].clone(), body["rows"][0]["hostname"].clone()),
        (json!(3), json!("win-02"))
    );
    for (query, field) in [
        ("segment=open", "segment"),
        ("offset=-1", "offset"),
        ("limit=101", "limit"),
        ("other=1", "query"),
    ] {
        let (status, body) = fx.call(&fx.admin, "GET", &hosts(ROOT, query), None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}");
        assert_eq!(body["field_errors"][0]["field"], field, "{query}");
    }
    fx.db.drop().await;
}

#[tokio::test]
async fn each_action_is_allowed_by_its_permission_on_a_host_in_reach() {
    let Some(fx) = Fx::new().await else { return };
    let other = seed(&fx).await;
    let viewer = user(&fx, "vw", 3, &["compliance.read"], Reach::All).await;
    let changers = fx
        .role(
            "Other changers",
            &[
                "compliance.read",
                "compliance.triage",
                "compliance.export",
                "cases.read",
                "cases.write",
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
            &[&uid(3), &changers],
        )
        .await
        .unwrap();
    let can = |body: &Value| -> Vec<bool> {
        ["triage", "assign", "add_to_case", "ask", "export"]
            .iter()
            .map(|k| body["can"][k].as_bool().unwrap())
            .collect()
    };
    // Root login fails on L1, in Other: the changers' reach.
    let (status, body) = fx.call(&viewer, "GET", &summary(ROOT), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(can(&body), [true, true, true, false, true]);
    // With L1's ASLR finding gone and its heartbeat stale, ASLR's pairs
    // are W1 and W2 passing, out of the changers' reach.
    fx.db
        .pool
        .get()
        .await
        .unwrap()
        .batch_execute(&format!("DELETE FROM current_findings WHERE agent_id = '{L1}' AND rule_id = 'harden.kernel.aslr'"))
        .await
        .unwrap();
    fx.db
        .pool
        .get()
        .await
        .unwrap()
        .batch_execute(&format!(
            "UPDATE agents SET health_at = now() - interval '2 days' WHERE agent_id = '{L1}'"
        ))
        .await
        .unwrap();
    let (status, body) = fx.call(&viewer, "GET", &summary(ASLR), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        can(&body),
        [false; 5],
        "only W1 and W2 pass, out of the changers' reach"
    );
    fx.db.drop().await;
}
