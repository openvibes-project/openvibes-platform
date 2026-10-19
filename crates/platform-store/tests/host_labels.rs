//! Host labels: trimmed, bounded, audited, and never part of membership.
mod common;

use chrono::Utc;
use common::{manual_group, migrated, rule_group};
use platform_store::{
    Client,
    console_read::AgentScope,
    host_groups,
    host_labels::{self, LabelWrite},
};

const A1: &str = "agent.00000000-0000-4000-8000-000000000001";
const A2: &str = "agent.00000000-0000-4000-8000-000000000002";
const A3: &str = "agent.00000000-0000-4000-8000-000000000003";

async fn fleet(c: &Client) {
    c.batch_execute(&format!(
        "INSERT INTO agents (agent_id, status, enrolled_at, revoked_at, hostname, os_id, os_version) VALUES
           ('{A1}','active',now(),NULL,'web-01','debian','12'),
           ('{A2}','active',now(),NULL,'db-02','fedora','44'),
           ('{A3}','revoked',now(),now(),'old-03','debian','12');"
    ))
    .await
    .unwrap();
}

async fn count(c: &Client, sql: &str) -> i64 {
    c.query_one(sql, &[]).await.unwrap().get(0)
}

#[tokio::test]
async fn labels_are_capped_at_32_and_deduplicated() {
    let (db, mut c) = migrated().await;
    fleet(&c).await;
    let now = Utc::now();
    assert_eq!(
        host_labels::add_label(&mut c, A1, " web ", "ann", now)
            .await
            .unwrap(),
        LabelWrite::Added
    );
    assert_eq!(host_labels::labels(&c, A1).await.unwrap(), ["web"]);
    assert_eq!(
        host_labels::add_label(&mut c, A1, "web", "ann", now)
            .await
            .unwrap(),
        LabelWrite::AlreadyThere
    );
    for n in 0..31 {
        let label = format!("l{n:02}");
        assert_eq!(
            host_labels::add_label(&mut c, A1, &label, "ann", now)
                .await
                .unwrap(),
            LabelWrite::Added
        );
    }
    assert_eq!(
        host_labels::add_label(&mut c, A1, "one-too-many", "ann", now)
            .await
            .unwrap(),
        LabelWrite::TooMany
    );
    assert_eq!(host_labels::labels(&c, A1).await.unwrap().len(), 32);
    let long = "x".repeat(65);
    for bad in ["", "   ", "a\nb", long.as_str()] {
        assert_eq!(
            host_labels::add_label(&mut c, A2, bad, "ann", now)
                .await
                .unwrap(),
            LabelWrite::Invalid,
            "{bad:?}"
        );
    }
    let fits = "é".repeat(64);
    assert_eq!(
        host_labels::add_label(&mut c, A2, &fits, "ann", now)
            .await
            .unwrap(),
        LabelWrite::Added
    );
    for gone in [A3, "agent.00000000-0000-4000-8000-00000000ffff"] {
        assert_eq!(
            host_labels::add_label(&mut c, gone, "x", "ann", now)
                .await
                .unwrap(),
            LabelWrite::NotFound
        );
    }
    assert!(
        host_labels::remove_label(&mut c, A1, " web", "ann", now)
            .await
            .unwrap()
    );
    assert!(
        !host_labels::remove_label(&mut c, A1, "web", "ann", now)
            .await
            .unwrap()
    );
    assert_eq!(
        count(
            &c,
            "SELECT count(*) FROM audit_log WHERE action = 'host.label_added'"
        )
        .await,
        33
    );
    let removed: serde_json::Value = c
        .query_one(
            "SELECT detail FROM audit_log WHERE action = 'host.label_removed'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(removed, serde_json::json!({"label": "web"}));
    db.drop().await;
}

#[tokio::test]
async fn labels_never_change_membership() {
    let (db, mut c) = migrated().await;
    fleet(&c).await;
    rule_group(&c, "Web", &[("hostname", false, &["web-*"])]).await;
    let picked = manual_group(&c, "Picked", &[A1]).await;
    let membership = "SELECT string_agg(g.name || '/' || a.agent_id, ',' ORDER BY g.name, a.agent_id)
                      FROM console_asset_groups g, agents a WHERE console_host_in_group(a.agent_id, g.asset_group_id)";
    let before: String = c.query_one(membership, &[]).await.unwrap().get(0);
    for agent in [A1, A2] {
        for label in ["web-01", "hostname:web-01", "os_family:windows", "Picked"] {
            host_labels::add_label(&mut c, agent, label, "ann", Utc::now())
                .await
                .unwrap();
        }
    }
    let after: String = c.query_one(membership, &[]).await.unwrap().get(0);
    assert_eq!(before, after);
    let hosts = host_groups::hosts(&c, &picked, &AgentScope::Global, None, 10)
        .await
        .unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(
        hosts[0].labels,
        ["Picked", "hostname:web-01", "os_family:windows", "web-01"]
    );
    db.drop().await;
}
