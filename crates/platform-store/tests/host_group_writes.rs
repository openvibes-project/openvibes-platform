//! Host-group writes: names, versions, kinds, deletes and their checks.
mod common;

use chrono::Utc;
use common::groups::*;
use common::{manual_group, migrated};
use platform_store::{
    console_read::AgentScope,
    host_group_facts::ensure_automatic_groups,
    host_group_writes::{self, GroupContent, GroupWrite, HostRef},
    host_groups::{self, Condition, GroupKind},
};

#[tokio::test]
async fn group_names_are_unique_regardless_of_case() {
    let (db, mut c) = migrated().await;
    let now = Utc::now();
    let web = saved(
        host_group_writes::create(&mut c, &input("Web", GroupContent::Manual(&[])), "ann", now)
            .await
            .unwrap(),
    );
    assert_eq!((web.kind, web.version), (GroupKind::Manual, 1));
    let clash =
        host_group_writes::create(&mut c, &input("WEB", GroupContent::Manual(&[])), "ann", now)
            .await
            .unwrap();
    assert!(matches!(clash, GroupWrite::NameTaken), "{clash:?}");
    let other = saved(
        host_group_writes::create(&mut c, &input("Other", GroupContent::Rule(&[])), "ann", now)
            .await
            .unwrap(),
    );
    let clash = host_group_writes::update(
        &mut c,
        &other.asset_group_id,
        1,
        None,
        &input("web", GroupContent::Rule(&[])),
        "ann",
        now,
    )
    .await
    .unwrap();
    assert!(matches!(clash, GroupWrite::NameTaken), "{clash:?}");
    let renamed = saved(
        host_group_writes::update(
            &mut c,
            &web.asset_group_id,
            1,
            None,
            &input("WEB", GroupContent::Manual(&[])),
            "ann",
            now,
        )
        .await
        .unwrap(),
    );
    assert_eq!((renamed.name.as_str(), renamed.version), ("WEB", 2));
    assert_eq!(
        count(
            &c,
            "SELECT count(*) FROM audit_log WHERE action = 'host_group.created'"
        )
        .await,
        2
    );
    db.drop().await;
}

#[tokio::test]
async fn editing_an_automatic_group_makes_it_a_rule_group() {
    let (db, mut c) = migrated().await;
    fleet(&c).await;
    ensure_automatic_groups(&c, "linux", "debian 12", Utc::now())
        .await
        .unwrap();
    let id: String = c
        .query_one("SELECT asset_group_id::text FROM console_asset_groups WHERE auto_key = 'distribution:debian 12'", &[])
        .await
        .unwrap()
        .get(0);
    let rule = [
        cond("distribution", false, &["debian 12"]),
        cond("hostname", true, &["*test*"]),
    ];
    let edited = saved(
        host_group_writes::update(
            &mut c,
            &id,
            1,
            None,
            &input("Debian 12", GroupContent::Rule(&rule)),
            "ann",
            Utc::now(),
        )
        .await
        .unwrap(),
    );
    assert_eq!(
        (edited.kind, edited.version, edited.hosts),
        (GroupKind::Rule, 2, 1)
    );
    assert_eq!(edited.conditions, rule);
    assert_eq!(edited.changed_by.as_deref(), Some("ann"));
    assert_eq!(
        count(
            &c,
            "SELECT count(*) FROM console_asset_groups WHERE auto_key IS NOT NULL"
        )
        .await,
        1
    );
    assert_eq!(
        count(&c, "SELECT count(*) FROM console_host_group_dismissed").await,
        0
    );
    let detail: serde_json::Value = c
        .query_one(
            "SELECT detail FROM audit_log WHERE action = 'host_group.updated'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(detail["kind"], "rule");
    assert_eq!(detail["conditions"][1]["negate"], true);
    let changes = host_groups::recent_changes(&c, &id, &AgentScope::Global, 10)
        .await
        .unwrap();
    let actions: Vec<&str> = changes.iter().map(|l| l.action.as_str()).collect();
    assert_eq!(
        actions,
        ["host_group.updated", "host_group.created_automatically"]
    );
    db.drop().await;
}

#[tokio::test]
async fn deleting_an_automatic_group_is_remembered() {
    let (db, mut c) = migrated().await;
    ensure_automatic_groups(&c, "linux", "debian 12", Utc::now())
        .await
        .unwrap();
    let id: String = c
        .query_one("SELECT asset_group_id::text FROM console_asset_groups WHERE auto_key = 'os_family:linux'", &[])
        .await
        .unwrap()
        .get(0);
    saved(
        host_group_writes::delete(&mut c, &id, 1, "ann", Utc::now())
            .await
            .unwrap(),
    );
    ensure_automatic_groups(&c, "linux", "debian 12", Utc::now())
        .await
        .unwrap();
    assert_eq!(
        count(
            &c,
            "SELECT count(*) FROM console_asset_groups WHERE auto_key = 'os_family:linux'"
        )
        .await,
        0
    );
    assert_eq!(
        count(
            &c,
            "SELECT count(*) FROM console_host_group_dismissed WHERE auto_key = 'os_family:linux'"
        )
        .await,
        1
    );
    let detail: serde_json::Value = c
        .query_one(
            "SELECT detail FROM audit_log WHERE action = 'host_group.deleted'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        detail,
        serde_json::json!({"name": "Linux", "kind": "automatic", "overrides_removed": 0})
    );
    db.drop().await;
}

#[tokio::test]
async fn deleting_a_group_in_use_names_the_roles() {
    let (db, mut c) = migrated().await;
    let id = manual_group(&c, "Web", &[]).await;
    group_role(&c, "beta", &id).await;
    group_role(&c, "alpha", &id).await;
    let refused = host_group_writes::delete(&mut c, &id, 1, "ann", Utc::now())
        .await
        .unwrap();
    match refused {
        GroupWrite::InUse(roles) => assert_eq!(roles, ["Alpha", "Beta"]),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        count(&c, "SELECT count(*) FROM console_asset_groups").await,
        1
    );
    db.drop().await;
}

#[tokio::test]
async fn deleting_removes_rule_set_overrides_and_the_preview_counts_them() {
    let (db, mut c) = migrated().await;
    fleet(&c).await;
    let id = manual_group(&c, "Web", &[A1]).await;
    c.batch_execute(&format!(
        "INSERT INTO rule_set_assignment VALUES ('rs1', true), ('rs2', true);
         INSERT INTO rule_set_group_assignment VALUES ('rs1', '{id}', false), ('rs2', '{id}', true);"
    ))
    .await
    .unwrap();
    let preview = host_group_writes::preview(&c, Some(&id), None)
        .await
        .unwrap()
        .ready();
    assert_eq!(preview.overrides_removed, 2);
    assert_eq!(
        preview.leaves,
        [HostRef {
            agent_id: A1.into(),
            hostname: Some("web-01".into())
        }]
    );
    assert!(preview.joins.is_empty());
    saved(
        host_group_writes::delete(&mut c, &id, 1, "ann", Utc::now())
            .await
            .unwrap(),
    );
    assert_eq!(
        count(&c, "SELECT count(*) FROM rule_set_group_assignment").await,
        0
    );
    let removed: serde_json::Value = c
        .query_one(
            "SELECT detail->'overrides_removed' FROM audit_log WHERE action = 'host_group.deleted'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(removed, 2);
    db.drop().await;
}
#[tokio::test]
async fn stale_versions_are_refused() {
    let (db, mut c) = migrated().await;
    let now = Utc::now();
    let g = saved(
        host_group_writes::create(&mut c, &input("Web", GroupContent::Manual(&[])), "ann", now)
            .await
            .unwrap(),
    );
    let id = g.asset_group_id.as_str();
    saved(
        host_group_writes::update(
            &mut c,
            id,
            1,
            None,
            &input("Web 2", GroupContent::Manual(&[])),
            "ann",
            now,
        )
        .await
        .unwrap(),
    );
    let stale = host_group_writes::update(
        &mut c,
        id,
        1,
        None,
        &input("Web 3", GroupContent::Manual(&[])),
        "ann",
        now,
    )
    .await
    .unwrap();
    assert!(matches!(stale, GroupWrite::Stale), "{stale:?}");
    let stale = host_group_writes::delete(&mut c, id, 1, "ann", now)
        .await
        .unwrap();
    assert!(matches!(stale, GroupWrite::Stale), "{stale:?}");
    for missing in ["00000000-0000-4000-8000-00000000ffff", "not-a-uuid"] {
        let gone = host_group_writes::update(
            &mut c,
            missing,
            1,
            None,
            &input("X", GroupContent::Manual(&[])),
            "ann",
            now,
        )
        .await
        .unwrap();
        assert!(matches!(gone, GroupWrite::NotFound), "{gone:?}");
        let gone = host_group_writes::delete(&mut c, missing, 1, "ann", now)
            .await
            .unwrap();
        assert!(matches!(gone, GroupWrite::NotFound), "{gone:?}");
    }
    db.drop().await;
}

#[tokio::test]
async fn a_membership_change_checked_against_other_roles_is_stale() {
    let (db, mut c) = migrated().await;
    let id = manual_group(&c, "Web", &[]).await;
    group_role(&c, "alpha", &id).await;
    group_role(&c, "beta", &id).await;
    let now = Utc::now();
    for checked in [&["alpha".to_owned()][..], &[]] {
        let stale = host_group_writes::update(
            &mut c,
            &id,
            1,
            Some(checked),
            &input("Web 2", GroupContent::Manual(&[])),
            "ann",
            now,
        )
        .await
        .unwrap();
        assert!(matches!(stale, GroupWrite::Stale), "{stale:?}");
    }
    assert_eq!(
        count(
            &c,
            "SELECT count(*) FROM console_asset_groups WHERE name = 'Web' AND version = 1"
        )
        .await,
        1,
        "nothing written"
    );
    let both = ["beta".to_owned(), "alpha".to_owned()];
    let saved = host_group_writes::update(
        &mut c,
        &id,
        1,
        Some(&both),
        &input("Web 2", GroupContent::Manual(&[])),
        "ann",
        now,
    )
    .await
    .unwrap();
    assert!(matches!(saved, GroupWrite::Saved(_)), "{saved:?}");
    db.drop().await;
}

#[tokio::test]
async fn unknown_or_revoked_hosts_cannot_be_picked() {
    let (db, mut c) = migrated().await;
    fleet(&c).await;
    let now = Utc::now();
    for bad in [A3, "agent.00000000-0000-4000-8000-00000000ffff"] {
        let picked = [A1.to_string(), bad.to_string()];
        let refused = host_group_writes::create(
            &mut c,
            &input("Web", GroupContent::Manual(&picked)),
            "ann",
            now,
        )
        .await
        .unwrap();
        assert!(
            matches!(&refused, GroupWrite::UnknownHost(id) if id == bad),
            "{refused:?}"
        );
    }
    let picked = [A1.to_string(), A1.to_string()];
    let g = saved(
        host_group_writes::create(
            &mut c,
            &input("Web", GroupContent::Manual(&picked)),
            "ann",
            now,
        )
        .await
        .unwrap(),
    );
    assert_eq!((g.picked, g.hosts), (1, 1));
    let detail: serde_json::Value = c
        .query_one(
            "SELECT detail FROM audit_log WHERE action = 'host_group.created'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        detail,
        serde_json::json!({"name": "Web", "kind": "manual", "picked": [A1]})
    );
    // a scoped viewer's history never names picked hosts
    let id = g.asset_group_id.as_str();
    let global = host_groups::recent_changes(&c, id, &AgentScope::Global, 10)
        .await
        .unwrap();
    assert_eq!(global[0].detail["picked"], serde_json::json!([A1]));
    let scope = AgentScope::AssetGroups(vec![id.to_string()]);
    let scoped = host_groups::recent_changes(&c, id, &scope, 10)
        .await
        .unwrap();
    assert_eq!(
        scoped[0].detail,
        serde_json::json!({"name": "Web", "kind": "manual"})
    );
    db.drop().await;
}

#[tokio::test]
async fn bad_conditions_are_refused_before_the_database() {
    let (db, mut c) = migrated().await;
    let now = Utc::now();
    let too_many: Vec<Condition> = (0..17).map(|_| cond("hostname", false, &["a"])).collect();
    let cases: [(Vec<Condition>, &str); 6] = [
        (vec![cond("ip", false, &["10.0.0.0/33"])], "ip"),
        (vec![cond("ip", false, &["web"])], "ip"),
        (vec![cond("os_family", false, &["bsd"])], "os_family"),
        (vec![cond("hostname", false, &[])], "hostname"),
        (vec![cond("labels", false, &["x"])], "labels"),
        (too_many, "conditions"),
    ];
    for (rule, field) in cases {
        let refused =
            host_group_writes::create(&mut c, &input("G", GroupContent::Rule(&rule)), "ann", now)
                .await
                .unwrap();
        assert!(
            matches!(&refused, GroupWrite::Invalid(f) if f == field),
            "{field}: {refused:?}"
        );
    }
    let ok = [cond("ip", false, &["10.0.0.0/8", "2001:db8::1"])];
    saved(
        host_group_writes::create(&mut c, &input("G", GroupContent::Rule(&ok)), "ann", now)
            .await
            .unwrap(),
    );
    db.drop().await;
}
