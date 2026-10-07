//! Migration 43 renames findings to compliance in stored IDs.
mod common;

use common::TestDb;

#[tokio::test]
async fn migration_43_renames_permissions_dashboards_and_case_items() {
    let db = TestDb::create().await;
    let client = common::at_version(&db, 42).await;
    client.batch_execute(
        "INSERT INTO console_roles (role_id, display_name, builtin) VALUES ('custom', 'Custom', false);
         INSERT INTO console_role_permissions VALUES ('custom', 'findings.read');
         INSERT INTO console_users (user_id, username, display_name, created_at)
              VALUES ('00000000-0000-0000-0000-000000000001', 'u', 'U', now());
         INSERT INTO console_dashboards (dashboard_id, owner_user_id, name, layout, created_at, updated_at)
         VALUES ('00000000-0000-0000-0000-0000000000d1', '00000000-0000-0000-0000-000000000001', 'Mine',
           '{\"schema\":1,\"widgets\":[
              {\"id\":\"a\",\"type\":\"number\",\"x\":0,\"y\":0,\"w\":3,\"h\":2,\"config\":{\"metric\":\"findings.open.high\"}},
              {\"id\":\"b\",\"type\":\"breakdown\",\"x\":3,\"y\":0,\"w\":3,\"h\":2,\"config\":{\"source\":\"findings\"}},
              {\"id\":\"c\",\"type\":\"attention\",\"x\":6,\"y\":0,\"w\":3,\"h\":2,\"config\":{\"include\":[\"alarms\",\"findings\"]}},
              {\"id\":\"d\",\"type\":\"list\",\"x\":9,\"y\":0,\"w\":3,\"h\":2,\"config\":{\"view\":\"/findings\",\"query\":\"severity=high\"}},
              {\"id\":\"e\",\"type\":\"note\",\"x\":0,\"y\":2,\"w\":3,\"h\":2,\"config\":{}}]}', now(), now());",
    ).await.unwrap();
    common::insert_case_with_item(&client, "finding", "agent-1/site/R-1").await;
    drop(client);
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();

    let perms: Vec<String> = client
        .query(
            "SELECT permission_id FROM console_role_permissions WHERE role_id = 'custom'",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(perms, ["compliance.read"]);
    let old: i64 = client
        .query_one(
            "SELECT count(*) FROM console_permissions WHERE permission_id LIKE 'findings.%'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(old, 0);
    let analyst: i64 = client
        .query_one(
            "SELECT count(*) FROM console_role_permissions WHERE role_id = 'analyst'
                    AND permission_id IN ('compliance.read', 'compliance.triage')",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(analyst, 2);

    let layout: serde_json::Value = client
        .query_one("SELECT layout FROM console_dashboards", &[])
        .await
        .unwrap()
        .get(0);
    let w = &layout["widgets"];
    assert_eq!(w[0]["config"]["metric"], "compliance.open.high");
    assert_eq!(w[1]["config"]["source"], "compliance");
    assert_eq!(
        w[2]["config"]["include"],
        serde_json::json!(["alarms", "compliance"])
    );
    assert_eq!(w[3]["config"]["view"], "/compliance");
    assert_eq!(w[3]["config"]["query"], "severity=high");
    assert_eq!(w[4]["config"], serde_json::json!({}));

    let kind: String = client
        .query_one("SELECT kind FROM case_items", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(kind, "compliance_finding");

    // A compliance finding is in at most one open case.
    let err = client
        .batch_execute(
            "INSERT INTO cases (case_id, title, status, severity, opened_by_user_id, created_at, updated_at)
             VALUES ('00000000-0000-0000-0000-0000000000c2', 'T2', 'open', 'high',
                     '00000000-0000-0000-0000-000000000001', now(), now());
             INSERT INTO case_items (item_id, case_id, kind, ref, agent_id, added_by_user_id, added_at)
             VALUES ('00000000-0000-0000-0000-0000000000e2', '00000000-0000-0000-0000-0000000000c2',
                     'compliance_finding', 'agent-1/site/R-1', 'agent-1',
                     '00000000-0000-0000-0000-000000000001', now());",
        )
        .await
        .unwrap_err();
    assert_eq!(
        err.code(),
        Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION)
    );
    drop(client);
    db.drop().await;
}
