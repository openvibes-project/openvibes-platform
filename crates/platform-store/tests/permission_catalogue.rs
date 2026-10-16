//! Migration 51 maps the old permission ids to the 48-permission catalogue
//! (spec 2026-10-16-roles-permissions-design.md §3, §12 part 1).
mod common;

use std::collections::BTreeSet;

#[tokio::test]
async fn old_ids_map_to_the_new_catalogue_and_roles_gain_their_needs() {
    let db = common::TestDb::create().await;
    let client = common::at_version(&db, 50).await;
    let before = role_permissions(&client).await;
    assert!(before.contains(&("operator".into(), "rules.upload".into())));
    drop(client);
    let mut client = db.pool.get().await.unwrap();
    assert_eq!(platform_store::migrate(&mut client).await.unwrap(), 51);
    let after = role_permissions(&client).await;
    for (role, old, new) in [
        ("operator", "agents.read", "hosts.read"),
        ("operator", "rules.upload", "rules.publish"),
        ("operator", "rules.upload", "rules.coverage.read"),
        ("operator", "rules.write", "site_rules.read"),
        ("analyst", "cases.manage", "cases.assign"),
        ("analyst", "alarms.read", "alarms.suppressions.read"),
        ("analyst", "alarms.read", "alarms.export"),
        ("admin", "rbac.manage", "access.grant"),
    ] {
        assert!(
            before.contains(&(role.into(), old.into())),
            "{role} had {old}"
        );
        assert!(
            after.contains(&(role.into(), new.into())),
            "{role} gets {new}"
        );
    }
    let ids: Vec<String> = client
        .query("SELECT permission_id FROM console_permissions", &[])
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(ids.len(), 48);
    assert!(
        !ids.iter()
            .any(|i| i.starts_with("agents.") || i.starts_with("rbac."))
    );
    let admin: i64 = client
        .query_one(
            "SELECT count(*) FROM console_role_permissions WHERE role_id = 'admin'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(admin, 48);
    // Viewers gain nothing beyond the exports and views of what they read.
    let viewer: BTreeSet<&str> = after
        .iter()
        .filter(|(role, _)| role == "viewer")
        .map(|(_, p)| p.as_str())
        .collect();
    assert_eq!(
        viewer,
        BTreeSet::from([
            "alarms.read",
            "alarms.suppressions.read",
            "alarms.export",
            "compliance.read",
            "compliance.export",
            "vulnerabilities.read",
            "vulnerabilities.export",
            "hosts.read",
            "hosts.export",
        ])
    );
    db.drop().await;
}

async fn role_permissions(c: &tokio_postgres::Client) -> BTreeSet<(String, String)> {
    c.query(
        "SELECT role_id, permission_id FROM console_role_permissions",
        &[],
    )
    .await
    .unwrap()
    .iter()
    .map(|r| (r.get(0), r.get(1)))
    .collect()
}
