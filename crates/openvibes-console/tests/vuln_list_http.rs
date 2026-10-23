//! `GET /api/v1/vulnerability-list`: validation, shape and counts, "me" from
//! the session, a team lead's reach, and the saved-views page
//! "vulnerabilities".

use axum::http::StatusCode;
use platform_store::console_roles::Reach;
use serde_json::{Value, json};

mod common;
use common::people::{Fx, WIN, uid};

const W1: &str = "agent.00000000-0000-4000-8000-0000000000a1";
const L1: &str = "agent.00000000-0000-4000-8000-0000000000b1";
const URL: &str = "/api/v1/vulnerability-list";

/// W1 (in `win`) and L1 (in `Other`).
/// - ADV-1 (critical, CVE-1, KEV due in 10 days, curl fixed in 2): W1 open
///   (Alice), L1 open (user 3).
/// - ADV-2 (moderate, CVE-2): W1 mitigated.
/// - ADV-3 (low, no CVE, reboot pending): W1 open.
async fn seed(fx: &Fx) -> String {
    let client = fx.db.pool.get().await.unwrap();
    let (alice, third) = (uid(1), uid(3));
    fx.db
        .user(
            "third",
            &fx.role("Third", &["vulnerabilities.read"], Reach::All)
                .await,
            3,
        )
        .await;
    let due = (chrono::Utc::now().date_naive() + chrono::Duration::days(10)).to_string();
    client
        .batch_execute(&format!(
            "INSERT INTO agents (agent_id, status, enrolled_at, hostname, last_seen_at, os_id, os_version) VALUES
                ('{W1}', 'active', now(), 'win-01', now(), 'debian', '12'),
                ('{L1}', 'active', now(), 'lin-01', now(), 'debian', '12');
             INSERT INTO console_host_group_members (asset_group_id, agent_id, added_at, added_by)
                VALUES ('{WIN}', '{W1}', now(), 't');
             INSERT INTO advisories (advisory_id, source, os_id, os_version, severity, title, url) VALUES
                ('ADV-1', 'debian-12', 'debian', '12', 'critical', 'curl: flaw', 'u'),
                ('ADV-2', 'debian-12', 'debian', '12', 'moderate', 'bash: flaw', 'u'),
                ('ADV-3', 'debian-12', 'debian', '12', 'low', 'openssl hardening', 'u');
             INSERT INTO advisory_cves VALUES ('ADV-1', 'CVE-1'), ('ADV-2', 'CVE-2');
             INSERT INTO cve_enrichment (cve_id, kev_added, kev_due, epss, epss_percentile, cvss_score) VALUES
                ('CVE-1', current_date - 60, '{due}', 0.5, 0.9, 9.8);
             INSERT INTO vulnerabilities (agent_id, advisory_id, packages, first_seen_at, fixed_at, last_evaluated_at, reboot_needed) VALUES
                ('{W1}', 'ADV-1', '[{{\"name\":\"curl\",\"installed\":\"1\",\"fixed\":\"2\"}}]', now(), NULL, now(), false),
                ('{L1}', 'ADV-1', '[{{\"name\":\"curl\",\"installed\":\"1\",\"fixed\":\"2\"}}]', now(), NULL, now(), false),
                ('{W1}', 'ADV-2', '[{{\"name\":\"bash\",\"installed\":\"5\",\"fixed\":\"5.1\"}}]', now(), NULL, now(), false),
                ('{W1}', 'ADV-3', '[{{\"name\":\"openssl\",\"installed\":\"3\",\"fixed\":\"3.1\"}}]', now(), NULL, now(), true);
             INSERT INTO vulnerability_triage (agent_id, advisory_id, state, assigned_to, note, accepted_until, version, updated_at, updated_by) VALUES
                ('{W1}', 'ADV-1', 'open', '{alice}', NULL, NULL, 1, now(), 't'),
                ('{L1}', 'ADV-1', 'open', '{third}', NULL, NULL, 1, now(), 't'),
                ('{W1}', 'ADV-2', 'mitigated', NULL, 'n', NULL, 1, now(), 't');
             INSERT INTO package_versions (manager, name, version, arch, source)
                SELECT 'dpkg', n, '1', 'amd64', n FROM unnest(ARRAY['curl', 'bash', 'openssl']) n;
             INSERT INTO host_packages SELECT h, (SELECT id FROM package_versions WHERE name = n)
                FROM (VALUES ('{W1}', 'curl'), ('{L1}', 'curl'), ('{W1}', 'bash'), ('{W1}', 'openssl')) x(h, n);
             INSERT INTO advisory_packages (advisory_id, name, arch, scheme, match_on, fixed) VALUES
                ('ADV-1', 'curl', '', 'dpkg', 'source', '2'), ('ADV-2', 'bash', '', 'dpkg', 'source', '5.1'),
                ('ADV-3', 'openssl', '', 'dpkg', 'source', '3.1');"
        ))
        .await
        .unwrap();
    common::manual_group(&client, "Other", &[L1]).await
}

fn keys(body: &Value) -> Vec<&str> {
    body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["key"].as_str().unwrap())
        .collect()
}

fn row<'a>(body: &'a Value, key: &str) -> &'a Value {
    body["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["key"] == key)
        .unwrap()
}

#[tokio::test]
async fn every_parameter_is_validated_and_named() {
    let Some(fx) = Fx::new().await else { return };
    let long = "x".repeat(201);
    let bad = [
        ("state=gone", "state"),
        ("severity=high", "severity"),
        ("signal=loud", "signal"),
        ("package=%00", "package"),
        ("group=nope", "group"),
        ("host=%00", "host"),
        ("advisory=%00", "advisory"),
        ("assignee=nobody", "assignee"),
        ("assignee=ABC", "assignee"),
        ("sort=colour", "sort"),
        ("dir=up", "dir"),
        ("offset=-1", "offset"),
        ("offset=100001", "offset"),
        ("offset=x", "offset"),
        ("limit=0", "limit"),
        ("limit=101", "limit"),
        ("limit=x", "limit"),
        ("q=%00", "q"),
    ];
    for (query, field) in bad {
        let (status, body) = fx
            .call(&fx.admin, "GET", &format!("{URL}?{query}"), None)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}");
        assert_eq!(body["code"], "invalid_query", "{query}");
        assert_eq!(body["field_errors"][0]["field"], field, "{query}");
    }
    let (status, body) = fx
        .call(&fx.admin, "GET", &format!("{URL}?q={long}"), None)
        .await;
    assert_eq!(
        (status, &body["field_errors"][0]["field"]),
        (StatusCode::BAD_REQUEST, &"q".into())
    );
    // the old list's flags are the web's to map, not this route's
    for old in ["exploited=true", "reboot=true", "surprise=1"] {
        let (status, _) = fx
            .call(&fx.admin, "GET", &format!("{URL}?{old}"), None)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{old}");
    }
    for ok in [
        "limit=100&offset=100000",
        "state=all&severity=unrated&signal=lowconf&sort=due&dir=asc",
        "state=resolved&signal=due30&package=curl&advisory=CPE:CVE-1:nginx",
        "sort=open&assignee=me",
        "assignee=unassigned&state=",
        "assignee=11111111-1111-4111-8111-111111111101&sort=epss",
        "sort=cvss&host=agent.x",
    ] {
        let (status, _) = fx
            .call(&fx.admin, "GET", &format!("{URL}?{ok}"), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{ok}");
    }
    let request = axum::http::Request::builder()
        .uri(URL)
        .body(axum::body::Body::empty())
        .unwrap();
    let response = tower::ServiceExt::oneshot(fx.router.clone(), request)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    fx.db.drop().await;
}

#[tokio::test]
async fn the_list_has_rows_counts_and_a_summary() {
    let Some(fx) = Fx::new().await else { return };
    let other = seed(&fx).await;
    let (status, body) = fx.call(&fx.admin, "GET", URL, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(keys(&body), ["CVE-1", "ADV-3"]);
    assert_eq!(body["total"], 2);
    assert!(body["generated_at"].is_string());
    let r = row(&body, "CVE-1");
    assert_eq!(r["title"], "curl: flaw");
    assert_eq!(r["severity"], "critical");
    assert_eq!(r["exploited"], true);
    assert_eq!(r["cvss"].as_f64().unwrap(), 9.8);
    assert!(r["due"].is_string());
    assert_eq!(
        (r["open"].clone(), r["total"].clone()),
        (2.into(), 2.into())
    );
    assert_eq!(r["packages"], json!(["curl"]));
    assert_eq!(r["fixed"], json!({"kind": "one", "version": "2"}));
    assert_eq!(r["advisories"], json!(["ADV-1"]));
    assert_eq!(r["assignee"], json!({"kind": "several", "count": 2}));
    assert_eq!(r["reboot"], false);
    let r = row(&body, "ADV-3");
    assert_eq!(r["reboot"], true);
    assert_eq!(r["assignee"], json!({"kind": "none"}));
    assert_eq!(body["summary"]["open_rows"], 2);
    assert_eq!(body["summary"]["hosts"], 2);
    assert_eq!(body["summary"]["exploited"], 1);
    assert_eq!(body["summary"]["with_due"], 1);
    assert_eq!(body["summary"]["no_fix"], 0);
    assert_eq!(body["summary"]["unassigned"], 1);
    let c = &body["counts"];
    let count = |facet: &str, v: &str| {
        c[facet]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["value"] == v)
            .unwrap()["count"]
            .clone()
    };
    assert_eq!(count("state", "open"), 2);
    assert_eq!(count("state", "mitigated"), 1);
    assert_eq!(count("severity", "critical"), 1);
    assert_eq!(count("signal", "exploited"), 1);
    assert_eq!(count("package", "curl"), 1);
    assert_eq!(c["assignee"]["me"], 1);
    assert_eq!(c["assignee"]["unassigned"], 1);
    assert_eq!(c["assignee"]["people"].as_array().unwrap().len(), 2);
    assert!(
        c["group"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g["value"] == other.as_str() && g["name"] == "Other" && g["count"] == 1)
    );

    let (_, body) = fx
        .call(&fx.admin, "GET", &format!("{URL}?state=all"), None)
        .await;
    assert_eq!(body["total"], 3);
    let (_, body) = fx
        .call(&fx.admin, "GET", &format!("{URL}?state=mitigated"), None)
        .await;
    assert_eq!(keys(&body), ["CVE-2"]);
    // the "also covers" and fixed shapes, search, sort and paging
    let (_, body) = fx
        .call(
            &fx.admin,
            "GET",
            &format!("{URL}?q=LIN&signal=exploited"),
            None,
        )
        .await;
    assert_eq!(body["total"], 0, "host names are not searched");
    let (_, body) = fx
        .call(&fx.admin, "GET", &format!("{URL}?q=openssl"), None)
        .await;
    assert_eq!(keys(&body), ["ADV-3"]);
    let (_, body) = fx
        .call(
            &fx.admin,
            "GET",
            &format!("{URL}?sort=severity&dir=asc&limit=1&offset=1"),
            None,
        )
        .await;
    assert_eq!(
        (keys(&body), body["total"].clone()),
        (vec!["CVE-1"], 2.into())
    );
    fx.db.drop().await;
}

#[tokio::test]
async fn me_is_the_signed_in_person_and_unassigned_is_not_a_name() {
    let Some(fx) = Fx::new().await else { return };
    seed(&fx).await;
    let (_, body) = fx
        .call(&fx.admin, "GET", &format!("{URL}?assignee=me"), None)
        .await;
    assert_eq!(keys(&body), ["CVE-1"]);
    assert_eq!(body["items"][0]["open"], 2, "the row, not only the pair");
    let third = common::http::sign_in(&fx.router, "third").await;
    let (_, body) = fx
        .call(&third, "GET", &format!("{URL}?assignee=me"), None)
        .await;
    assert_eq!(keys(&body), ["CVE-1"]);
    let (_, body) = fx
        .call(
            &fx.admin,
            "GET",
            &format!("{URL}?assignee=unassigned"),
            None,
        )
        .await;
    assert_eq!(keys(&body), ["ADV-3"]);
    let id = uid(3);
    let (_, body) = fx
        .call(&fx.admin, "GET", &format!("{URL}?assignee={id}"), None)
        .await;
    assert_eq!(keys(&body), ["CVE-1"]);
    fx.db.drop().await;
}

#[tokio::test]
async fn a_team_lead_sees_only_their_groups() {
    let Some(fx) = Fx::new().await else { return };
    let other = seed(&fx).await;
    let role = fx
        .role(
            "Win vulns",
            &["vulnerabilities.read"],
            Reach::Groups(vec![WIN.into()]),
        )
        .await;
    fx.db.user("wa", &role, 4).await;
    let wa = common::http::sign_in(&fx.router, "wa").await;
    let (status, body) = fx.call(&wa, "GET", &format!("{URL}?state=all"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(keys(&body), ["CVE-1", "CVE-2", "ADV-3"]);
    let r = row(&body, "CVE-1");
    assert_eq!(
        (r["open"].clone(), r["total"].clone()),
        (1.into(), 1.into())
    );
    assert_eq!(r["assignee"]["kind"], "one");
    assert_eq!(r["assignee"]["id"], uid(1));
    assert_eq!(
        body["counts"]["assignee"]["people"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(
        body["counts"]["group"]
            .as_array()
            .unwrap()
            .iter()
            .all(|g| g["value"] != other.as_str())
    );
    for q in [format!("host={L1}"), format!("group={other}")] {
        let (status, body) = fx.call(&wa, "GET", &format!("{URL}?{q}"), None).await;
        assert_eq!(
            (status, body["total"].clone()),
            (StatusCode::OK, 0.into()),
            "{q}"
        );
    }
    // vulnerabilities.read is required
    let role = fx.role("Hosts only", &["hosts.read"], Reach::All).await;
    fx.db.user("ho", &role, 5).await;
    let ho = common::http::sign_in(&fx.router, "ho").await;
    let (status, _) = fx.call(&ho, "GET", URL, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    fx.db.drop().await;
}

#[tokio::test]
async fn the_vulnerabilities_page_keeps_saved_views_and_hidden_columns() {
    let Some(fx) = Fx::new().await else { return };
    let a = &fx.admin;
    let (status, _) = fx
        .call(
            a,
            "POST",
            "/api/v1/saved-views",
            Some(json!({"page": "vulnerabilities", "name": "Mine", "query": "assignee=me"})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let cols = "/api/v1/list-columns/vulnerabilities";
    let (status, _) = fx
        .call(
            a,
            "PUT",
            cols,
            Some(json!({"hidden": ["package", "cvss", "epss", "hosts", "due", "assignee"]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    for never in ["severity", "advisory"] {
        let (status, body) = fx
            .call(a, "PUT", cols, Some(json!({"hidden": [never]})))
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{never} {body}");
    }
    fx.db.drop().await;
}
