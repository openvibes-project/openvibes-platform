//! Rule-set assignment (spec 2026-10-14): defaults, group overrides, audit,
//! run as the roles that use them.

mod common;

use common::TestDb;
use platform_store::{
    Client,
    rule_assignment::{self, Change, GroupOverride},
};

const L1: &str = "hardening-linux-l1";
const L2: &str = "hardening-linux-l2";

/// The migrated database and an admin client (kept for the whole test, so
/// pooled connections with a role set are never handed back as admin).
async fn setup() -> (TestDb, Client) {
    let db = TestDb::create().await;
    let mut admin = db.pool.get().await.unwrap();
    platform_store::migrate(&mut admin).await.unwrap();
    (db, admin)
}

async fn as_role(db: &TestDb, role: &str) -> Client {
    let client = db.pool.get().await.unwrap();
    client
        .batch_execute(&format!("SET ROLE \"{role}\""))
        .await
        .unwrap();
    client
}

/// An asset group whose hosts carry every `selectors` tag; its id.
async fn group(admin: &Client, name: &str, selectors: &[(&str, &str)]) -> String {
    let id: String = admin
        .query_one(
            "INSERT INTO console_asset_groups (asset_group_id, name, created_at, created_by)
             VALUES (gen_random_uuid(), $1, now(), 'test') RETURNING asset_group_id::text",
            &[&name],
        )
        .await
        .unwrap()
        .get(0);
    for (key, value) in selectors {
        admin
            .execute(
                "INSERT INTO console_asset_group_selectors (asset_group_id, tag_key, tag_value, created_at)
                 VALUES ($1::text::uuid, $2, $3, now())",
                &[&id, key, value],
            )
            .await
            .unwrap();
    }
    id
}

async fn audits(admin: &Client) -> Vec<serde_json::Value> {
    admin
        .query(
            "SELECT detail FROM audit_log WHERE action = 'rules.assignment.change' ORDER BY id",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect()
}

fn done(change: Change) -> rule_assignment::Assignment {
    match change {
        Change::Done(assignment) => assignment,
        other => panic!("expected Done, got {other:?}"),
    }
}

#[tokio::test]
async fn the_defaults_are_l1_on_and_l2_off() {
    let (db, admin) = setup().await;
    let web = group(&admin, "web", &[("env", "web")]).await;
    let console = as_role(&db, "openvibes-console").await;
    let overview = rule_assignment::overview(&console).await.unwrap();
    let sets: Vec<_> = overview
        .sets
        .iter()
        .map(|s| {
            (
                s.rule_set_id.as_str(),
                s.default_enabled,
                s.published,
                s.groups.len(),
            )
        })
        .collect();
    assert_eq!(sets, [(L1, true, false, 0), (L2, false, false, 0)]);
    assert_eq!(overview.groups.len(), 1);
    assert_eq!(overview.groups[0].asset_group_id, web);
    // A live bundle makes the set published; retiring it unpublishes it.
    let mut admin = admin;
    platform_store::rules::add_trust_key(&mut admin, L1, "openvibes-1", [9; 32])
        .await
        .unwrap();
    platform_store::rules::publish(
        &mut admin,
        &platform_store::rules::NewBundle {
            rule_set_id: L1,
            version: 1,
            envelope: b"{}",
            envelope_sha256: [0; 32],
            issuer_key_id: "openvibes-1",
            created_at_ms: 0,
            expires_at_ms: i64::MAX,
            published_by: "test",
        },
    )
    .await
    .unwrap();
    let published = |o: &rule_assignment::Overview| o.sets[0].published;
    assert!(published(
        &rule_assignment::overview(&console).await.unwrap()
    ));
    platform_store::rules::retire(&admin, L1).await.unwrap();
    assert!(!published(
        &rule_assignment::overview(&console).await.unwrap()
    ));
    drop((console, admin));
    db.drop().await;
}

#[tokio::test]
async fn a_default_change_is_audited_with_old_and_new() {
    let (db, admin) = setup().await;
    let mut console = as_role(&db, "openvibes-console").await;
    let l2 = done(
        rule_assignment::set_default(&mut console, "alice", L2, true)
            .await
            .unwrap(),
    );
    assert!(l2.default_enabled);
    // The same value again changes nothing and is not audited.
    done(
        rule_assignment::set_default(&mut console, "alice", L2, true)
            .await
            .unwrap(),
    );
    assert_eq!(
        rule_assignment::set_default(&mut console, "alice", "baseline", false)
            .await
            .unwrap(),
        Change::UnknownSet
    );
    let rows = audits(&admin).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0],
        serde_json::json!({"rule_set_id": L2, "asset_group_id": null,
            "asset_group_name": null, "old": false, "new": true})
    );
    let actor: String = admin
        .query_one(
            "SELECT actor FROM audit_log WHERE action = 'rules.assignment.change'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(actor, "alice");
    drop((console, admin));
    db.drop().await;
}

#[tokio::test]
async fn group_overrides_are_set_changed_removed_and_audited() {
    let (db, admin) = setup().await;
    let web = group(&admin, "web", &[("env", "web")]).await;
    let mut console = as_role(&db, "openvibes-console").await;
    let c = &mut console;
    let l1 = done(
        rule_assignment::set_group(c, "alice", L1, &web, Some(false))
            .await
            .unwrap(),
    );
    assert_eq!(
        l1.groups,
        [GroupOverride {
            asset_group_id: web.clone(),
            name: "web".into(),
            enabled: false
        }]
    );
    let l1 = done(
        rule_assignment::set_group(c, "alice", L1, &web, Some(true))
            .await
            .unwrap(),
    );
    assert!(l1.groups[0].enabled);
    let l1 = done(
        rule_assignment::set_group(c, "alice", L1, &web, None)
            .await
            .unwrap(),
    );
    assert!(l1.groups.is_empty());
    // Removing what is not there changes nothing.
    let l1 = done(
        rule_assignment::set_group(c, "alice", L1, &web, None)
            .await
            .unwrap(),
    );
    assert!(l1.groups.is_empty());
    assert_eq!(
        rule_assignment::set_group(
            &mut console,
            "alice",
            L1,
            "00000000-0000-4000-8000-000000000000",
            Some(true)
        )
        .await
        .unwrap(),
        Change::UnknownGroup
    );
    assert_eq!(
        rule_assignment::set_group(&mut console, "alice", L1, "not-a-uuid", Some(true))
            .await
            .unwrap(),
        Change::UnknownGroup
    );
    assert_eq!(
        rule_assignment::set_group(&mut console, "alice", "baseline", &web, Some(true))
            .await
            .unwrap(),
        Change::UnknownSet
    );
    let olds_news: Vec<_> = audits(&admin)
        .await
        .iter()
        .map(|d| {
            (
                d["old"].clone(),
                d["new"].clone(),
                d["asset_group_name"].clone(),
            )
        })
        .collect();
    assert_eq!(
        olds_news,
        [
            (serde_json::Value::Null, false.into(), "web".into()),
            (false.into(), true.into(), "web".into()),
            (true.into(), serde_json::Value::Null, "web".into()),
        ]
    );
    drop((console, admin));
    db.drop().await;
}

#[tokio::test]
async fn deleting_a_group_deletes_its_overrides() {
    let (db, admin) = setup().await;
    let web = group(&admin, "web", &[("env", "web")]).await;
    let mut console = as_role(&db, "openvibes-console").await;
    done(
        rule_assignment::set_group(&mut console, "alice", L1, &web, Some(false))
            .await
            .unwrap(),
    );
    admin
        .execute(
            "DELETE FROM console_asset_groups WHERE asset_group_id::text = $1",
            &[&web],
        )
        .await
        .unwrap();
    let overview = rule_assignment::overview(&console).await.unwrap();
    assert!(overview.sets[0].groups.is_empty() && overview.groups.is_empty());
    drop((console, admin));
    db.drop().await;
}
