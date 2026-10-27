//! `GET /api/v1/ports/{protocol}/{port}/summary` and `/hosts`: path and
//! query validation, shape, a team lead's reach, the actions and the
//! Related card's permissions.

use axum::http::StatusCode;
use platform_store::console_roles::Reach;
use serde_json::{Value, json};

mod common;
use common::people::{Fx, WIN};

const W1: &str = "agent.00000000-0000-4000-8000-0000000000a1";
const L1: &str = "agent.00000000-0000-4000-8000-0000000000b1";

/// W1 (in `win`) and L1 (outside it) both listen on tcp/22 (W1 exposed on
/// two addresses); only L1 on tcp/9999, which has no owner.
async fn seed(fx: &Fx) {
    let client = fx.db.pool.get().await.unwrap();
    client
        .batch_execute(&format!(
            "INSERT INTO agents (agent_id, status, enrolled_at, hostname, last_seen_at, services_at, services_owners) VALUES
                ('{W1}', 'active', now(), 'win-01', now(), now(), 'partial'),
                ('{L1}', 'active', now(), 'lin-01', now(), now(), 'partial');
             INSERT INTO console_host_group_members (asset_group_id, agent_id, added_at, added_by)
                VALUES ('{WIN}', '{W1}', now(), 't');
             INSERT INTO host_listeners (agent_id, protocol, address, port, exposed, service, program) VALUES
                ('{W1}', 'tcp', '0.0.0.0', 22, true, 'sshd.service', 'sshd'),
                ('{W1}', 'tcp', '::', 22, true, 'sshd.service', 'sshd'),
                ('{L1}', 'tcp', '127.0.0.1', 22, false, 'sshd.service', 'sshd'),
                ('{L1}', 'tcp', '0.0.0.0', 9999, true, NULL, NULL);
             INSERT INTO change_log (at, agent_id, kind, key, change) VALUES
                (now() - interval '1 day', '{W1}', 'listener', 'tcp/22', 'appeared');"
        ))
        .await
        .unwrap();
}

fn summary(port: &str) -> String {
    format!("/api/v1/ports/tcp/{port}/summary")
}

fn hosts(port: &str, query: &str) -> String {
    format!("/api/v1/ports/tcp/{port}/hosts{query}")
}

#[tokio::test]
async fn paths_and_queries_are_validated() {
    let Some(fx) = Fx::new().await else { return };
    seed(&fx).await;
    for uri in [
        "/api/v1/ports/icmp/22/summary",
        "/api/v1/ports/tcp/0/summary",
        "/api/v1/ports/tcp/65536/summary",
        "/api/v1/ports/tcp/022/summary",
        "/api/v1/ports/tcp/ssh/hosts",
    ] {
        let (status, body) = fx.call(&fx.admin, "GET", uri, None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
        assert_eq!(body["code"], "invalid_port", "{uri}");
    }
    for (query, field) in [
        ("segment=gone", "segment"),
        ("offset=-1", "offset"),
        ("offset=100001", "offset"),
        ("limit=0", "limit"),
        ("limit=101", "limit"),
    ] {
        let (status, body) = fx
            .call(&fx.admin, "GET", &hosts("22", &format!("?{query}")), None)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}");
        assert_eq!(body["field_errors"][0]["field"], field, "{query}");
    }
    let (status, _) = fx
        .call(&fx.admin, "GET", &hosts("22", "?surprise=1"), None)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, body) = fx.call(&fx.admin, "GET", &summary("4444"), None).await;
    assert_eq!(
        (status, body["code"].clone()),
        (StatusCode::NOT_FOUND, json!("port_not_found"))
    );
    let request = axum::http::Request::builder()
        .uri(summary("22"))
        .body(axum::body::Body::empty())
        .unwrap();
    let response = tower::ServiceExt::oneshot(fx.router.clone(), request)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    fx.db.drop().await;
}

#[tokio::test]
async fn the_page_has_a_header_tiles_hosts_and_actions() {
    let Some(fx) = Fx::new().await else { return };
    seed(&fx).await;
    let (status, body) = fx.call(&fx.admin, "GET", &summary("22"), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["header"]["name"], "SSH");
    assert_eq!(
        (
            body["header"]["listening"].clone(),
            body["header"]["of"].clone()
        ),
        (2.into(), 2.into())
    );
    assert_eq!(
        body["tiles"],
        json!({"listening": 2, "exposed": 1, "local": 1, "week": {"added": 1, "removed": 0}})
    );
    assert_eq!(body["details"]["programs"], json!(["sshd"]));
    assert_eq!(body["details"]["owners"], json!({"collected": 2, "of": 2}));
    assert_eq!(body["changes"][0]["change"], "appeared");
    assert_eq!(body["changes"][0]["hostname"], "win-01");
    // The administrator holds every permission; the assistant is not wired in tests.
    assert_eq!(body["can"]["export"], true);
    assert_eq!(body["can"]["ask"], false);
    assert!(body["related"]["compliance"].is_object());
    assert!(body["related"]["alarms"].is_object());

    let (status, page) = fx.call(&fx.admin, "GET", &hosts("22", ""), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page["total"], 2);
    assert_eq!(
        page["segments"],
        json!({"all": 2, "exposed": 1, "local": 1})
    );
    let win = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["hostname"] == "win-01")
        .unwrap();
    assert_eq!(win["bound"].as_array().unwrap().len(), 2);
    assert_eq!(win["exposed"], true);
    let (_, local) = fx
        .call(
            &fx.admin,
            "GET",
            &hosts("22", "?segment=local&limit=1"),
            None,
        )
        .await;
    assert_eq!(local["total"], 1);
    assert_eq!(local["items"][0]["hostname"], "lin-01");
    fx.db.drop().await;
}

#[tokio::test]
async fn a_team_lead_sees_only_their_hosts_and_a_reader_without_the_rest_gets_less() {
    let Some(fx) = Fx::new().await else { return };
    seed(&fx).await;
    let lead = fx.windows_lead().await;
    let (status, body) = fx.call(&lead, "GET", &summary("22"), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["tiles"]["listening"], 1);
    assert_eq!(body["can"]["export"], false, "no hosts.export");
    assert_eq!(body["can"]["add_to_case"], false);
    for section in ["compliance", "vulnerabilities", "alarms"] {
        assert!(
            body["related"].get(section).is_none(),
            "{section} needs its own permission"
        );
    }
    let (_, page) = fx.call(&lead, "GET", &hosts("22", ""), None).await;
    assert_eq!(page["total"], 1);
    // 9999 is only on L1, which the lead does not reach: 404, not 403.
    let (status, body) = fx.call(&lead, "GET", &summary("9999"), None).await;
    assert_eq!(
        (status, body["code"].clone()),
        (StatusCode::NOT_FOUND, json!("port_not_found"))
    );
    let (_, page) = fx.call(&lead, "GET", &hosts("9999", ""), None).await;
    assert_eq!(page["total"], 0);
    // hosts.read is required.
    let role = fx.role("Cases only", &["cases.read"], Reach::All).await;
    fx.db.user("co", &role, 5).await;
    let co = common::http::sign_in(&fx.router, "co").await;
    for uri in [summary("22"), hosts("22", "")] {
        let (status, _) = fx.call(&co, "GET", &uri, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{uri}");
    }
    // Export and cases are separate permissions that need a host in reach.
    let role = fx
        .role(
            "Export and cases",
            &["hosts.read", "hosts.export", "cases.read", "cases.write"],
            Reach::Groups(vec![WIN.into()]),
        )
        .await;
    fx.db.user("ec", &role, 6).await;
    let ec = common::http::sign_in(&fx.router, "ec").await;
    let (_, body) = fx.call(&ec, "GET", &summary("22"), None).await;
    assert_eq!(
        (
            body["can"]["export"].clone(),
            body["can"]["add_to_case"].clone()
        ),
        (json!(true), json!(true))
    );
    let _: Value = body;
    fx.db.drop().await;
}
