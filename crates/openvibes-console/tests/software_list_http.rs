//! `GET /api/v1/software-list`: validation, shape and counts, a team lead's
//! reach, and the saved-views page "software".

use axum::http::StatusCode;
use serde_json::{Value, json};

mod common;
use common::lists::{self, count};
use common::people::{Fx, WIN};

const W1: &str = "agent.00000000-0000-4000-8000-0000000000a1";
const L1: &str = "agent.00000000-0000-4000-8000-0000000000b1";
const URL: &str = "/api/v1/software-list";

/// W1 (in `win`) and L1 (outside it).
/// - openssl: dpkg 3.0.11 on W1, 3.0.9 on L1; OS-1 (critical) fixable on L1.
/// - nginx: dpkg 1.22.1 on W1; used by nginx.service.
/// - bash: rpm 5.2 on L1 and dpkg 5.2 on W1 (one row, both types).
/// - secretpkg: only L1; installed this week.
async fn seed(fx: &Fx) -> String {
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
                ('dpkg', 'nginx', '1.22.1', 'amd64'), ('rpm', 'bash', '5.2', 'x86_64'),
                ('dpkg', 'bash', '5.2', 'amd64'), ('dpkg', 'secretpkg', '1.0', 'amd64');
             INSERT INTO host_packages (agent_id, package_version_id)
                SELECT '{W1}', id FROM package_versions WHERE (name, version) IN
                    (('openssl', '3.0.11'), ('nginx', '1.22.1')) OR (name = 'bash' AND manager = 'dpkg');
             INSERT INTO host_packages (agent_id, package_version_id)
                SELECT '{L1}', id FROM package_versions WHERE (name, version) IN
                    (('openssl', '3.0.9'), ('secretpkg', '1.0')) OR (name = 'bash' AND manager = 'rpm');
             INSERT INTO host_services (agent_id, unit, programs, processes, run_as) VALUES
                ('{W1}', 'nginx.service', '{{nginx}}', 2, 'www-data');
             INSERT INTO advisories (advisory_id, source, os_id, os_version, severity, title, url)
                VALUES ('OS-1', 'debian-12', 'debian', '12', 'critical', 'openssl: flaw', 'u');
             INSERT INTO vulnerabilities (agent_id, advisory_id, packages, first_seen_at, last_evaluated_at, reboot_needed)
                VALUES ('{L1}', 'OS-1', '[{{\"name\": \"openssl\", \"fixed\": \"3.0.12\"}}]', now(), now(), false);
             INSERT INTO change_log (at, agent_id, kind, key, change) VALUES
                (now() - interval '1 day', '{L1}', 'package', 'secretpkg', 'appeared');"
        ))
        .await
        .unwrap();
    common::manual_group(&client, "Other", &[L1]).await
}

fn names(body: &Value) -> Vec<String> {
    body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap().to_owned())
        .collect()
}

fn row<'a>(body: &'a Value, name: &str) -> &'a Value {
    body["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == name)
        .unwrap()
}

#[tokio::test]
async fn every_parameter_is_validated_and_named() {
    let Some(fx) = Fx::new().await else { return };
    let bad = [
        ("vulns=bad", "vulns"),
        ("fix=maybe", "fix"),
        ("versions=two", "versions"),
        ("type=msi", "type"),
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
            "vulns=critical_high&fix=available&versions=several&type=rpm&changes=updated&sort=vulnerabilities&dir=desc",
            "vulns=none&fix=none&versions=one&type=dpkg&sort=week",
            "host=agent.x&vulns=",
            "q=openssl&sort=versions",
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
    assert_eq!(names(&body), ["bash", "nginx", "openssl", "secretpkg"]);
    assert_eq!(body["total"], 4);
    assert!(body["generated_at"].is_string());
    let openssl = row(&body, "openssl");
    assert_eq!(
        (openssl["hosts"].clone(), openssl["versions"].clone()),
        (2.into(), 2.into())
    );
    assert_eq!(
        (openssl["oldest"].clone(), openssl["newest"].clone()),
        ("3.0.9".into(), "3.0.11".into())
    );
    assert_eq!(openssl["advisories"], 1);
    assert_eq!(openssl["worst_severity"], "critical");
    assert_eq!(openssl["update_hosts"], 1);
    assert_eq!(openssl["no_fix"], 0);
    let bash = row(&body, "bash");
    assert_eq!(
        (bash["dpkg"].clone(), bash["rpm"].clone()),
        (true.into(), true.into())
    );
    assert_eq!(bash["hosts"], 2, "one row for both managers");
    assert!(row(&body, "nginx")["used_by"][0]["unit"] == "nginx.service");
    assert!(row(&body, "bash").get("worst_severity").is_none());
    assert_eq!(row(&body, "secretpkg")["week_added"], 1);
    assert_eq!(
        body["summary"],
        json!({"exploited": 0, "fixable": 1, "several_versions": 1, "new_this_week": 1, "reporting_hosts": 2})
    );
    assert_eq!(count(&body, "vulns", "any"), 1);
    assert_eq!(count(&body, "fix", "available"), 1);
    assert_eq!(count(&body, "versions", "several"), 1);
    assert_eq!(count(&body, "type", "rpm"), 1);
    assert_eq!(count(&body, "changes", "new"), 1);
    assert!(
        body["counts"]["group"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g["value"] == other.as_str() && g["name"] == "Other" && g["count"] == 1),
        "a group's count is its hosts in reach"
    );
    for (query, expected) in [
        ("fix=available", vec!["openssl"]),
        ("versions=several&dir=desc", vec!["openssl"]),
        ("type=rpm", vec!["bash"]),
        ("changes=new", vec!["secretpkg"]),
        ("q=NGINX", vec!["nginx"]),
        ("sort=hosts&dir=desc&limit=2", vec!["openssl", "bash"]),
        ("limit=1&offset=1", vec!["nginx"]),
    ] {
        let (_, body) = fx
            .call(&fx.admin, "GET", &format!("{URL}?{query}"), None)
            .await;
        assert_eq!(names(&body), expected, "{query}");
    }
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
        names(&body),
        ["bash", "nginx", "openssl"],
        "secretpkg is only on L1"
    );
    assert_eq!(row(&body, "openssl")["hosts"], 1);
    assert_eq!(
        row(&body, "openssl")["advisories"],
        0,
        "OS-1 is open on L1 only"
    );
    assert_eq!(row(&body, "bash")["rpm"], false, "the rpm bash is L1's");
    assert_eq!(body["summary"]["reporting_hosts"], 1);
    let queries = [format!("host={L1}"), format!("group={other}")];
    lists::assert_out_of_reach(&fx, &lead, URL, &other, &queries).await;
    fx.db.drop().await;
}

#[tokio::test]
async fn the_software_page_keeps_saved_views_and_hidden_columns() {
    let Some(fx) = Fx::new().await else { return };
    lists::assert_views_and_columns(
        &fx,
        "software",
        ("Fixable", "fix=available"),
        &[
            "hosts",
            "versions",
            "vulnerabilities",
            "fix",
            "used_by",
            "week",
        ],
        "package",
    )
    .await;
    fx.db.drop().await;
}
