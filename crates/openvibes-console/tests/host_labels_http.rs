//! Host labels over HTTP (spec §5.2): `hosts.label` on that host, 404
//! outside reach, the 32-label cap, and the host's groups.

use axum::http::StatusCode;
use openvibes_console::authenticated_router;
use platform_store::console_roles::Reach;
use serde_json::json;

mod common;
use common::http::{TestDb, call, sign_in};

const IN: &str = "agent.00000000-0000-4000-8000-0000000000c1";
const OUT: &str = "agent.00000000-0000-4000-8000-0000000000c2";

#[tokio::test]
async fn labels_need_hosts_label_on_that_host() {
    let Some(db) = TestDb::create("hostlabels").await else {
        return;
    };
    db.user("alice", "admin", 1).await;
    let mut client = db.pool.get().await.unwrap();
    client
        .batch_execute(&format!(
            "INSERT INTO agents (agent_id, status, enrolled_at, hostname) VALUES
                ('{IN}', 'active', now(), 'in-01'), ('{OUT}', 'active', now(), 'out-01')"
        ))
        .await
        .unwrap();
    let win = common::manual_group(&client, "WindowsServers", &[IN]).await;
    let labeler = common::create_role(
        &mut client,
        "Labelers",
        &["hosts.read", "hosts.label"],
        Reach::Groups(vec![win]),
    )
    .await;
    db.user("lab", &labeler, 2).await;
    let reader = common::create_role(&mut client, "Readers", &["hosts.read"], Reach::All).await;
    db.user("reader", &reader, 3).await;
    let router = authenticated_router(db.pool.clone(), common::http::ORIGIN);
    let (admin, lab, reader) = (
        sign_in(&router, "alice").await,
        sign_in(&router, "lab").await,
        sign_in(&router, "reader").await,
    );
    let labels = |agent: &str| format!("/api/v1/hosts/{agent}/labels");

    let (status, _) = call(
        &router,
        "PUT",
        &format!("{}/web%20tier", labels(IN)),
        &lab,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = call(
        &router,
        "PUT",
        &format!("{}/web%20tier", labels(IN)),
        &lab,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "adding twice is fine");
    let (status, got) = call(&router, "GET", &labels(IN), &lab, None).await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert_eq!(got["labels"], json!(["web tier"]));
    assert_eq!(got["groups"][0]["name"], "WindowsServers");
    assert_eq!(got["groups"][0]["kind"], "manual");

    let (status, refused) = call(&router, "PUT", &format!("{}/web", labels(OUT)), &lab, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{refused}");
    assert_eq!(refused["code"], "host_not_found");
    let (status, _) = call(&router, "GET", &labels(OUT), &lab, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = call(
        &router,
        "PUT",
        &format!("{}/x", labels("agent.nope")),
        &admin,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "missing reads the same as out of reach"
    );
    let (status, _) = call(
        &router,
        "PUT",
        &format!("{}/web", labels(IN)),
        &reader,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = call(&router, "GET", &labels(OUT), &reader, None).await;
    assert_eq!(status, StatusCode::OK);

    for n in 1..32 {
        let (status, _) = call(
            &router,
            "PUT",
            &format!("{}/l{n}", labels(IN)),
            &admin,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }
    let (status, full) = call(
        &router,
        "PUT",
        &format!("{}/one-more", labels(IN)),
        &admin,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(full["code"], "too_many_labels");

    let (status, _) = call(
        &router,
        "DELETE",
        &format!("{}/web%20tier", labels(IN)),
        &lab,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, got) = call(&router, "GET", &labels(IN), &lab, None).await;
    assert!(
        !got["labels"]
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l == "web tier")
    );
    let actions = db.audit_actions().await;
    assert!(actions.iter().any(|a| a == "host.label_added"));
    assert!(actions.iter().any(|a| a == "host.label_removed"));
    db.drop().await;
}
