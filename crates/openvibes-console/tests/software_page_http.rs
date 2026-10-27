//! `GET /api/v1/software-pages/{name}/summary` and `/hosts`: path and query
//! validation, shape, a team lead's reach, and the actions.

use axum::http::StatusCode;
use serde_json::json;

mod common;
use common::lists;
use common::people::{Fx, WIN};

const W1: &str = "agent.00000000-0000-4000-8000-0000000000a1";
const L1: &str = "agent.00000000-0000-4000-8000-0000000000b1";

/// W1 (in `win`) has openssl 3.0.11 and L1 has 3.0.9; OS-1 (critical) is
/// fixable on L1 (fixed in 3.0.12) and OS-2 has no fix for 3.0.9; only L1
/// has secretpkg.
async fn seed(fx: &Fx) {
    let client = fx.db.pool.get().await.unwrap();
    client
        .batch_execute(&format!(
            "INSERT INTO agents (agent_id, status, enrolled_at, hostname, last_seen_at, inventory_at) VALUES
                ('{W1}', 'active', now(), 'win-01', now(), now()),
                ('{L1}', 'active', now(), 'lin-01', now(), now());
             INSERT INTO console_host_group_members (asset_group_id, agent_id, added_at, added_by)
                VALUES ('{WIN}', '{W1}', now(), 't');
             INSERT INTO package_versions (manager, name, version, arch) VALUES
                ('dpkg', 'openssl', '3.0.11', 'amd64'), ('dpkg', 'openssl', '3.0.9', 'amd64'),
                ('dpkg', 'secretpkg', '1.0', 'amd64');
             INSERT INTO host_packages (agent_id, package_version_id)
                SELECT '{W1}', id FROM package_versions WHERE version = '3.0.11';
             INSERT INTO host_packages (agent_id, package_version_id)
                SELECT '{L1}', id FROM package_versions WHERE version IN ('3.0.9', '1.0');
             INSERT INTO advisories (advisory_id, source, os_id, os_version, severity, title, url) VALUES
                ('OS-1', 'debian-12', 'debian', '12', 'critical', 'openssl: flaw', 'u'),
                ('OS-2', 'debian-12', 'debian', '12', 'low', 'openssl: no fix', 'u');
             INSERT INTO vulnerabilities (agent_id, advisory_id, packages, first_seen_at, last_evaluated_at, reboot_needed)
                VALUES ('{L1}', 'OS-1', '[{{\"name\": \"openssl\", \"fixed\": \"3.0.12\"}}]', now(), now(), false);
             INSERT INTO version_vulnerabilities (package_version_id, advisory_id, package, first_seen_at)
                SELECT id, 'OS-2', 'openssl', now() FROM package_versions WHERE version = '3.0.9';
             INSERT INTO change_log (at, agent_id, kind, key, change, detail) VALUES
                (now() - interval '1 day', '{W1}', 'package', 'openssl', 'appeared', '{{\"version\": \"0:3.0.11-1\"}}');"
        ))
        .await
        .unwrap();
}

fn summary(name: &str) -> String {
    format!("/api/v1/software-pages/{name}/summary")
}

fn hosts(name: &str, query: &str) -> String {
    format!("/api/v1/software-pages/{name}/hosts{query}")
}

#[tokio::test]
async fn paths_and_queries_are_validated() {
    let Some(fx) = Fx::new().await else { return };
    seed(&fx).await;
    let long = "x".repeat(257);
    for uri in [summary("%00"), summary(&long), hosts("%0A", "")] {
        let (status, body) = fx.call(&fx.admin, "GET", &uri, None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
        assert_eq!(body["code"], "invalid_package", "{uri}");
    }
    lists::assert_hosts_queries_refused(&fx, |query| hosts("openssl", query)).await;
    let (status, body) = fx.call(&fx.admin, "GET", &summary("nothing"), None).await;
    assert_eq!(
        (status, body["code"].clone()),
        (StatusCode::NOT_FOUND, json!("package_not_found"))
    );
    lists::assert_unauthorized(&fx, &summary("openssl")).await;
    fx.db.drop().await;
}

#[tokio::test]
async fn the_page_has_a_header_tiles_versions_advisories_hosts_and_actions() {
    let Some(fx) = Fx::new().await else { return };
    seed(&fx).await;
    let (status, body) = fx.call(&fx.admin, "GET", &summary("openssl"), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["header"]["name"], "openssl");
    assert_eq!(body["header"]["managers"], json!(["dpkg"]));
    assert_eq!(
        (body["header"]["hosts"].clone(), body["header"]["of"].clone()),
        (2.into(), 2.into())
    );
    assert_eq!(
        body["tiles"],
        json!({"hosts": 2, "vulnerabilities": 2, "update_hosts": 1, "versions": 2})
    );
    assert_eq!(body["week"], json!({"added": 1, "updated": 0, "removed": 0}));
    assert_eq!(body["no_fix"], 1);
    let versions = body["versions"].as_array().unwrap();
    assert_eq!(versions.len(), 2);
    let old = versions.iter().find(|v| v["version"] == "3.0.9").unwrap();
    assert_eq!(old["advisories"], 2);
    let advisories = body["advisories"].as_array().unwrap();
    assert_eq!(advisories[0]["advisory_id"], "OS-1");
    assert_eq!(advisories[0]["fixed_in"], "3.0.12");
    assert!(advisories[1].get("fixed_in").is_none());
    assert_eq!(body["changes"][0]["version"], "3.0.11-1");
    assert_eq!(body["can"]["export"], true);
    assert_eq!(body["can"]["add_to_case"], true);

    let (status, page) = fx.call(&fx.admin, "GET", &hosts("openssl", ""), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page["total"], 2);
    assert_eq!(page["segments"], json!({"all": 2, "update": 1, "current": 1}));
    let lin = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["hostname"] == "lin-01")
        .unwrap();
    assert_eq!(lin["update_to"], "3.0.12");
    assert_eq!(lin["versions"][0]["version"], "3.0.9");
    let (_, update) = fx
        .call(&fx.admin, "GET", &hosts("openssl", "?segment=current&limit=1"), None)
        .await;
    assert_eq!(update["total"], 1);
    assert_eq!(update["items"][0]["hostname"], "win-01");
    assert!(update["items"][0].get("update_to").is_none());
    fx.db.drop().await;
}

#[tokio::test]
async fn a_team_lead_sees_only_their_hosts() {
    let Some(fx) = Fx::new().await else { return };
    seed(&fx).await;
    let lead = fx.windows_lead().await;
    let (status, body) = fx.call(&lead, "GET", &summary("openssl"), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["tiles"]["hosts"], 1);
    assert_eq!(body["tiles"]["vulnerabilities"], 0, "both advisories are on L1");
    assert_eq!(body["can"]["export"], false, "no hosts.export");
    assert_eq!(body["can"]["add_to_case"], false);
    let (_, page) = fx.call(&lead, "GET", &hosts("openssl", ""), None).await;
    assert_eq!(page["total"], 1);
    // secretpkg is only on L1, which the lead does not reach: 404, not 403.
    let (status, body) = fx.call(&lead, "GET", &summary("secretpkg"), None).await;
    assert_eq!(
        (status, body["code"].clone()),
        (StatusCode::NOT_FOUND, json!("package_not_found"))
    );
    let (_, page) = fx.call(&lead, "GET", &hosts("secretpkg", ""), None).await;
    assert_eq!(page["total"], 0);
    lists::assert_page_permissions(
        &fx,
        &[summary("openssl"), hosts("openssl", "")],
        &summary("openssl"),
    )
    .await;
    fx.db.drop().await;
}
