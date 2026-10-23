//! `GET /api/v1/vulnerabilities/{key}/summary` and `/{key}/hosts`: a
//! vulnerability's page inside the viewer's reach, how a key resolves, the
//! Hosts table's segments and paging, and the actions per permission.

use axum::http::StatusCode;
use platform_store::console_roles::Reach;
use serde_json::{Value, json};

mod common;
use common::people::{Fx, WIN, uid};

const W1: &str = "agent.00000000-0000-4000-8000-0000000000a1";
const L1: &str = "agent.00000000-0000-4000-8000-0000000000b1";

/// W1 (in `win`) and L1 (in `Other`, returned).
/// - ADV-1 (critical, CVE-1, curl fixed in 2): W1 open (Alice), L1 mitigated.
/// - ADV-2 (moderate, CVE-2): W1 only.
/// - ADV-3 (low, no CVE): W1, reboot pending.
/// - ADV-4 (CVE-4a and CVE-4b): W1. ADV-5 (CVE-5): L1 only.
async fn seed(fx: &Fx) -> String {
    let client = fx.db.pool.get().await.unwrap();
    let alice = uid(1);
    client
        .batch_execute(&format!(
            "INSERT INTO agents (agent_id, status, enrolled_at, hostname, last_seen_at, os_id, os_version, last_address) VALUES
                ('{W1}', 'active', now(), 'win-01', now(), 'debian', '12', '10.0.0.1'),
                ('{L1}', 'active', now(), 'lin-01', now(), 'debian', '12', '10.0.0.2');
             INSERT INTO console_host_group_members (asset_group_id, agent_id, added_at, added_by)
                VALUES ('{WIN}', '{W1}', now(), 't');
             INSERT INTO advisories (advisory_id, source, os_id, os_version, severity, title, url) VALUES
                ('ADV-1', 'debian-12', 'debian', '12', 'critical', 'curl: flaw', 'https://a/1'),
                ('ADV-2', 'debian-12', 'debian', '12', 'moderate', 'bash: flaw', 'u'),
                ('ADV-3', 'debian-12', 'debian', '12', 'low', 'openssl hardening', 'u'),
                ('ADV-4', 'debian-12', 'debian', '12', 'low', 'two flaws', 'u'),
                ('ADV-5', 'debian-12', 'debian', '12', 'low', 'lin only', 'u');
             INSERT INTO advisory_cves VALUES ('ADV-1', 'CVE-1'), ('ADV-2', 'CVE-2'), ('ADV-4', 'CVE-4a'),
                ('ADV-4', 'CVE-4b'), ('ADV-5', 'CVE-5');
             INSERT INTO cve_enrichment (cve_id, kev_added, kev_due, epss, epss_percentile, cvss_score, cvss_version) VALUES
                ('CVE-1', current_date - 60, current_date + 10, 0.5, 0.9, 9.8, '3.1');
             INSERT INTO vulnerabilities (agent_id, advisory_id, packages, first_seen_at, fixed_at, last_evaluated_at, reboot_needed)
             SELECT h, a, jsonb_build_array(jsonb_build_object('name', n, 'installed', '1', 'fixed', '2')), now(), NULL, now(), a = 'ADV-3'
             FROM (VALUES ('{W1}', 'ADV-1', 'curl'), ('{L1}', 'ADV-1', 'curl'), ('{W1}', 'ADV-2', 'bash'),
                          ('{W1}', 'ADV-3', 'openssl'), ('{W1}', 'ADV-4', 'vim'), ('{L1}', 'ADV-5', 'tar')) x(h, a, n);
             INSERT INTO vulnerability_triage (agent_id, advisory_id, state, assigned_to, note, accepted_until, version, updated_at, updated_by) VALUES
                ('{W1}', 'ADV-1', 'open', '{alice}', NULL, NULL, 2, now(), 't'),
                ('{L1}', 'ADV-1', 'mitigated', NULL, 'n', NULL, 1, now(), 't');
             INSERT INTO vulnerability_triage_history (agent_id, advisory_id, from_state, to_state, note, changed_at, changed_by) VALUES
                ('{W1}', 'ADV-1', 'open', 'open', NULL, now(), '{alice}'),
                ('{L1}', 'ADV-1', 'open', 'mitigated', 'lin note', now(), '{alice}');"
        ))
        .await
        .unwrap();
    common::manual_group(&client, "Other", &[L1]).await
}

fn summary(key: &str) -> String {
    format!("/api/v1/vulnerabilities/{key}/summary")
}

fn hosts(key: &str, query: &str) -> String {
    format!("/api/v1/vulnerabilities/{key}/hosts?{query}")
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
    let (status, body) = fx.call(&fx.admin, "GET", &summary("CVE-1"), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["key"], "CVE-1");
    let h = &body["header"];
    assert_eq!(h["title"], "curl: flaw");
    assert_eq!(h["severity"], "critical");
    assert_eq!(h["packages"], json!(["curl"]));
    assert_eq!(h["fixed"], json!({"kind": "one", "version": "2"}));
    assert_eq!(
        (h["open"].clone(), h["total"].clone()),
        (1.into(), 2.into())
    );
    assert_eq!(h["assignee"]["kind"], "one");
    assert!(h["kev_due"].is_string());
    assert_eq!(h["ransomware"], false);
    let t = &body["tiles"];
    assert_eq!(t["fix"], json!({"kind": "all"}));
    assert_eq!(t["cvss_version"], "3.1");
    assert_eq!(t["epss_percentile"].as_f64().unwrap() as f32, 0.9);
    assert_eq!(
        body["what_to_do"],
        json!([{"os_id": "debian", "os_version": "12", "advisory_id": "ADV-1", "url": "https://a/1",
                "packages": [{"name": "curl", "fixed": "2"}], "hosts": 2, "reboot": false}])
    );
    let d = &body["details"];
    assert_eq!(
        d["advisories"],
        json!([{"id": "ADV-1", "url": "https://a/1", "source": "debian-12"}])
    );
    assert_eq!(d["confidence"]["min"], 95);
    assert_eq!(body["history"].as_array().unwrap().len(), 2);
    assert!(body["history"][0]["actor"].is_string());
    assert_eq!(body["also_covers"], json!([]));
    assert!(body["related"]["alarms"].is_object());
    assert_eq!(body["related"]["cases"], json!([]));
    assert_eq!(body["related"]["same_package"]["cves"], 0);
    assert_eq!(body["can"]["triage"], true);
    assert_eq!(body["can"]["ask"], false, "the assistant is off");
    fx.db.drop().await;
}

#[tokio::test]
async fn keys_resolve_and_bad_keys_are_not_found() {
    let Some(fx) = Fx::new().await else { return };
    seed(&fx).await;
    let a = &fx.admin;
    let (_, body) = fx.call(a, "GET", &summary("ADV-1"), None).await;
    assert_eq!(body["key"], "CVE-1", "an advisory with one CVE");
    let (_, body) = fx.call(a, "GET", &summary("ADV-3"), None).await;
    assert_eq!(body["key"], "ADV-3", "an advisory without CVEs");
    for url in [summary("ADV-4"), hosts("ADV-4", "")] {
        let (status, body) = fx.call(a, "GET", &url, None).await;
        assert_eq!(status, StatusCode::CONFLICT, "{url}");
        assert_eq!(body["code"], "advisory_has_several_cves");
        let cves: Vec<_> = body["field_errors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| (e["field"].as_str().unwrap(), e["message"].as_str().unwrap()))
            .collect();
        assert_eq!(cves, [("key", "CVE-4a"), ("key", "CVE-4b")]);
    }
    let long = "C".repeat(257);
    for key in ["CVE-NONE", "CPE:CVE-1:curl", "CVE%01", long.as_str()] {
        for url in [summary(key), hosts(key, "")] {
            let (status, body) = fx.call(a, "GET", &url, None).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{url}");
            assert_eq!(body["code"], "vulnerability_not_found");
        }
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
        &["vulnerabilities.read"],
        Reach::Groups(vec![WIN.into()]),
    )
    .await;
    let (status, body) = fx.call(&lead, "GET", &summary("CVE-1"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["header"]["total"], 1);
    assert_eq!(body["what_to_do"][0]["hosts"], 1);
    let history = body["history"].as_array().unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0]["agent_id"], W1);
    assert!(body["related"]["alarms"].is_null(), "no alarms.read");
    assert!(body["related"]["cases"].is_null(), "no cases.read");
    assert_eq!(
        body["can"],
        json!({"triage": false, "assign": false, "add_to_case": false, "ask": false, "export": false})
    );
    let (_, body) = fx.call(&lead, "GET", &hosts("CVE-1", ""), None).await;
    assert_eq!(body["total"], 1);
    assert_eq!(body["rows"][0]["agent_id"], W1);
    for url in [summary("CVE-5"), hosts("CVE-5", "")] {
        let (status, _) = fx.call(&lead, "GET", &url, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{url}: out of reach");
    }
    let none = user(&fx, "none", 5, &["hosts.read"], Reach::All).await;
    for url in [summary("CVE-1"), hosts("CVE-1", "")] {
        let (status, _) = fx.call(&none, "GET", &url, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{url}");
    }
    fx.db.drop().await;
}

#[tokio::test]
async fn the_hosts_table_has_segments_and_pages() {
    let Some(fx) = Fx::new().await else { return };
    seed(&fx).await;
    let a = &fx.admin;
    let (status, body) = fx.call(a, "GET", &hosts("CVE-1", ""), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["segments"],
        json!({"all": 2, "open": 1, "mitigated": 1, "resolved": 0})
    );
    assert_eq!(body["total"], 2);
    let first = &body["rows"][0];
    assert_eq!(first["hostname"], "lin-01");
    assert_eq!(first["address"], "10.0.0.2");
    assert_eq!(first["installed"], "1");
    assert_eq!(first["state"], "mitigated");
    assert_eq!(first["advisory_id"], "ADV-1");
    assert_eq!(first["triage_version"], 1);
    assert_eq!(first["reboot_needed"], false);
    assert!(
        first["first_seen"]
            .as_str()
            .is_some_and(|s| s.ends_with('Z'))
    );
    assert!(first["assignee"].is_null());
    assert_eq!(body["rows"][1]["assignee"]["id"], uid(1));
    let (_, body) = fx
        .call(a, "GET", &hosts("CVE-1", "segment=open"), None)
        .await;
    assert_eq!(
        (body["total"].clone(), body["rows"][0]["agent_id"].clone()),
        (1.into(), W1.into())
    );
    let (_, body) = fx
        .call(a, "GET", &hosts("CVE-1", "offset=1&limit=1"), None)
        .await;
    assert_eq!(body["rows"].as_array().unwrap().len(), 1);
    assert_eq!(body["rows"][0]["hostname"], "win-01");
    for (query, field) in [
        ("segment=fixed", "segment"),
        ("offset=-1", "offset"),
        ("offset=100001", "offset"),
        ("limit=0", "limit"),
        ("limit=101", "limit"),
        ("sort=host", "query"),
    ] {
        let (status, body) = fx.call(a, "GET", &hosts("CVE-1", query), None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}");
        assert_eq!(body["field_errors"][0]["field"], field, "{query}");
    }
    fx.db.drop().await;
}

#[tokio::test]
async fn each_action_is_allowed_by_its_permission_on_a_host_in_reach() {
    let Some(fx) = Fx::new().await else { return };
    let other = seed(&fx).await;
    let viewer = user(&fx, "vw", 3, &["vulnerabilities.read"], Reach::All).await;
    let changers = fx
        .role(
            "Other changers",
            &[
                "vulnerabilities.read",
                "vulnerabilities.triage",
                "vulnerabilities.export",
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
    // CVE-1 is also on L1, in Other.
    let (status, body) = fx.call(&viewer, "GET", &summary("CVE-1"), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(can(&body), [true, true, true, false, true]);
    assert!(body["related"]["cases"].is_array());
    // CVE-2 is only on W1.
    let (_, body) = fx.call(&viewer, "GET", &summary("CVE-2"), None).await;
    assert_eq!(can(&body), [false; 5]);
    fx.db.drop().await;
}
