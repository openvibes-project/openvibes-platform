//! `GET /api/v1/services/{unit}/summary` and `/hosts`: path and query
//! validation, shape, a team lead's reach, the actions and the Related
//! card's permissions.

use axum::http::StatusCode;
use platform_store::console_roles::Reach;
use serde_json::json;

mod common;
use common::people::{Fx, WIN};

const W1: &str = "agent.00000000-0000-4000-8000-0000000000a1";
const L1: &str = "agent.00000000-0000-4000-8000-0000000000b1";

/// W1 (in `win`) and L1 (outside it) both run nginx (W1 as www-data with a
/// package, exposed on 443; L1 as root without one, loopback only); only L1
/// runs mystery.service.
async fn seed(fx: &Fx) {
    let client = fx.db.pool.get().await.unwrap();
    client
        .batch_execute(&format!(
            "INSERT INTO agents (agent_id, status, enrolled_at, hostname, last_seen_at, services_at, services_owners) VALUES
                ('{W1}', 'active', now(), 'win-01', now(), now(), 'complete'),
                ('{L1}', 'active', now(), 'lin-01', now(), now(), 'complete');
             INSERT INTO console_host_group_members (asset_group_id, agent_id, added_at, added_by)
                VALUES ('{WIN}', '{W1}', now(), 't');
             INSERT INTO host_services (agent_id, unit, programs, processes, run_as) VALUES
                ('{W1}', 'nginx.service', '{{nginx}}', 3, 'www-data'),
                ('{L1}', 'nginx.service', '{{nginx}}', 1, 'root'),
                ('{L1}', 'mystery.service', '{{mystery}}', 1, 'root');
             INSERT INTO host_listeners (agent_id, protocol, address, port, exposed, service, program) VALUES
                ('{W1}', 'tcp', '0.0.0.0', 443, true, 'nginx.service', 'nginx'),
                ('{L1}', 'tcp', '127.0.0.1', 443, false, 'nginx.service', 'nginx');
             INSERT INTO package_versions (manager, name, version, arch) VALUES ('deb', 'nginx', '1.22.1', 'amd64');
             INSERT INTO host_packages (agent_id, package_version_id)
                SELECT '{W1}', id FROM package_versions WHERE name = 'nginx';
             INSERT INTO change_log (at, agent_id, kind, key, change) VALUES
                (now() - interval '1 day', '{W1}', 'service', 'nginx.service', 'appeared');"
        ))
        .await
        .unwrap();
}

fn summary(unit: &str) -> String {
    format!("/api/v1/services/{unit}/summary")
}

fn hosts(unit: &str, query: &str) -> String {
    format!("/api/v1/services/{unit}/hosts{query}")
}

#[tokio::test]
async fn paths_and_queries_are_validated() {
    let Some(fx) = Fx::new().await else { return };
    seed(&fx).await;
    let long = "x".repeat(201);
    for uri in [summary("%00"), summary(&long), hosts("%0A", "")] {
        let (status, body) = fx.call(&fx.admin, "GET", &uri, None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
        assert_eq!(body["code"], "invalid_unit", "{uri}");
    }
    for (query, field) in [
        ("segment=gone", "segment"),
        ("offset=-1", "offset"),
        ("offset=100001", "offset"),
        ("limit=0", "limit"),
        ("limit=101", "limit"),
    ] {
        let (status, body) = fx
            .call(
                &fx.admin,
                "GET",
                &hosts("nginx.service", &format!("?{query}")),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}");
        assert_eq!(body["field_errors"][0]["field"], field, "{query}");
    }
    let (status, _) = fx
        .call(
            &fx.admin,
            "GET",
            &hosts("nginx.service", "?surprise=1"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, body) = fx
        .call(&fx.admin, "GET", &summary("nothing.service"), None)
        .await;
    assert_eq!(
        (status, body["code"].clone()),
        (StatusCode::NOT_FOUND, json!("service_not_found"))
    );
    let request = axum::http::Request::builder()
        .uri(summary("nginx.service"))
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
    let (status, body) = fx
        .call(&fx.admin, "GET", &summary("nginx.service"), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["header"]["name"], "nginx");
    assert_eq!(
        (
            body["header"]["running"].clone(),
            body["header"]["of"].clone(),
            body["header"]["root"].clone()
        ),
        (2.into(), 2.into(), 1.into())
    );
    // The administrator holds every permission.
    assert_eq!(body["tiles"]["running"], 2);
    assert_eq!(body["tiles"]["alarms"], 0);
    assert_eq!(body["tiles"]["vulnerabilities"], 0);
    assert_eq!(body["tiles"]["versions"], 1);
    assert_eq!(body["details"]["programs"], json!(["nginx"]));
    assert_eq!(body["details"]["processes"], 4);
    assert_eq!(
        body["details"]["packages"],
        json!([{"name": "nginx", "hosts": 1}])
    );
    assert_eq!(body["details"]["week"], json!({"added": 1, "removed": 0}));
    assert_eq!(
        body["ports"],
        json!([{"protocol": "tcp", "port": 443, "exposed": true, "hosts": 2}])
    );
    assert_eq!(body["changes"][0]["change"], "appeared");
    assert_eq!(body["can"]["export"], true);
    assert_eq!(body["can"]["add_to_case"], true);
    assert!(body["related"]["compliance"].is_object());
    assert!(body["related"]["vulnerabilities"].is_object());
    assert!(body["related"]["alarms"].is_object());

    let (status, page) = fx
        .call(&fx.admin, "GET", &hosts("nginx.service", ""), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page["total"], 2);
    assert_eq!(page["segments"], json!({"all": 2, "exposed": 1, "root": 1}));
    let win = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["hostname"] == "win-01")
        .unwrap();
    assert_eq!(
        win["package"],
        json!({"name": "nginx", "version": "1.22.1"})
    );
    assert_eq!(win["processes"], 3);
    assert_eq!(
        win["ports"],
        json!([{"protocol": "tcp", "port": 443, "exposed": true}])
    );
    assert_eq!(win["problems"], json!({"alarms": 0, "vulnerabilities": 0}));
    let (_, root) = fx
        .call(
            &fx.admin,
            "GET",
            &hosts("nginx.service", "?segment=root&limit=1"),
            None,
        )
        .await;
    assert_eq!(root["total"], 1);
    assert_eq!(root["items"][0]["hostname"], "lin-01");
    assert!(root["items"][0].get("package").is_none());
    fx.db.drop().await;
}

#[tokio::test]
async fn a_team_lead_sees_only_their_hosts_and_a_reader_without_the_rest_gets_less() {
    let Some(fx) = Fx::new().await else { return };
    seed(&fx).await;
    let lead = fx.windows_lead().await;
    let (status, body) = fx.call(&lead, "GET", &summary("nginx.service"), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["tiles"]["running"], 1);
    assert!(
        body["tiles"].get("alarms").is_none() && body["tiles"].get("vulnerabilities").is_none()
    );
    assert_eq!(body["can"]["export"], false, "no hosts.export");
    assert_eq!(body["can"]["add_to_case"], false);
    for section in ["compliance", "vulnerabilities", "alarms"] {
        assert!(
            body["related"].get(section).is_none(),
            "{section} needs its own permission"
        );
    }
    let (_, page) = fx
        .call(&lead, "GET", &hosts("nginx.service", ""), None)
        .await;
    assert_eq!(page["total"], 1);
    assert_eq!(page["items"][0]["problems"], json!({}));
    // mystery.service is only on L1, which the lead does not reach: 404, not 403.
    let (status, body) = fx
        .call(&lead, "GET", &summary("mystery.service"), None)
        .await;
    assert_eq!(
        (status, body["code"].clone()),
        (StatusCode::NOT_FOUND, json!("service_not_found"))
    );
    let (_, page) = fx
        .call(&lead, "GET", &hosts("mystery.service", ""), None)
        .await;
    assert_eq!(page["total"], 0);
    // hosts.read is required.
    let role = fx.role("Cases only", &["cases.read"], Reach::All).await;
    fx.db.user("co", &role, 5).await;
    let co = common::http::sign_in(&fx.router, "co").await;
    for uri in [summary("nginx.service"), hosts("nginx.service", "")] {
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
    let (_, body) = fx.call(&ec, "GET", &summary("nginx.service"), None).await;
    assert_eq!(
        (
            body["can"]["export"].clone(),
            body["can"]["add_to_case"].clone()
        ),
        (json!(true), json!(true))
    );
    fx.db.drop().await;
}
