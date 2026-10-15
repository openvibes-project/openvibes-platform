//! Rule-set assignment (spec 2026-10-14): defaults, group overrides, audit,
//! run as the roles that use them.

mod common;

use common::TestDb;
use platform_store::{
    Client,
    console_read::AgentScope,
    rule_assignment::{self, Change, GroupOverride, HostAssignment, Source},
};

const L1: &str = "hardening-linux-l1";
const L2: &str = "hardening-linux-l2";
/// The console user who makes the changes (audited by id, shown by name).
const ALICE: &str = "00000000-0000-4000-8000-000000000001";

/// The migrated database and an admin client (kept for the whole test, so
/// pooled connections with a role set are never handed back as admin).
async fn setup() -> (TestDb, Client) {
    let db = TestDb::create().await;
    let mut admin = db.pool.get().await.unwrap();
    platform_store::migrate(&mut admin).await.unwrap();
    admin
        .execute(
            "INSERT INTO console_users (user_id, username, display_name, created_at)
             VALUES ($1::text::uuid, 'alice', 'Alice', now())",
            &[&ALICE],
        )
        .await
        .unwrap();
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
async fn a_change_by_an_unknown_user_fails_and_changes_nothing() {
    let (db, admin) = setup().await;
    let web = group(&admin, "web", &[("env", "web")]).await;
    let mut console = as_role(&db, "openvibes-console").await;
    let nobody = "00000000-0000-4000-8000-000000000099";
    for actor in [nobody, "not-a-uuid"] {
        assert!(
            rule_assignment::set_default(&mut console, actor, L2, true)
                .await
                .is_err()
        );
        assert!(
            rule_assignment::set_group(&mut console, actor, L1, &web, Some(false))
                .await
                .is_err()
        );
    }
    let overview = rule_assignment::overview(&console).await.unwrap();
    assert!(
        !overview
            .sets
            .iter()
            .find(|a| a.rule_set_id == L2)
            .unwrap()
            .default_enabled
    );
    assert!(overview.sets.iter().all(|a| a.groups.is_empty()));
    assert!(audits(&admin).await.is_empty());
    drop((console, admin));
    db.drop().await;
}

#[tokio::test]
async fn a_default_change_is_audited_with_old_and_new() {
    let (db, admin) = setup().await;
    let mut console = as_role(&db, "openvibes-console").await;
    let l2 = done(
        rule_assignment::set_default(&mut console, ALICE, L2, true)
            .await
            .unwrap(),
    );
    assert!(l2.default_enabled);
    // The same value again changes nothing and is not audited.
    done(
        rule_assignment::set_default(&mut console, ALICE, L2, true)
            .await
            .unwrap(),
    );
    assert_eq!(
        rule_assignment::set_default(&mut console, ALICE, "baseline", false)
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
    let actor = admin
        .query_one(
            "SELECT actor, actor_id, actor_display FROM audit_log
             WHERE action = 'rules.assignment.change'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        (
            actor.get::<_, &str>(0),
            actor.get::<_, &str>(1),
            actor.get::<_, &str>(2)
        ),
        (ALICE, ALICE, "Alice")
    );
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
        rule_assignment::set_group(c, ALICE, L1, &web, Some(false))
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
        rule_assignment::set_group(c, ALICE, L1, &web, Some(true))
            .await
            .unwrap(),
    );
    assert!(l1.groups[0].enabled);
    let l1 = done(
        rule_assignment::set_group(c, ALICE, L1, &web, None)
            .await
            .unwrap(),
    );
    assert!(l1.groups.is_empty());
    // Removing what is not there changes nothing.
    let l1 = done(
        rule_assignment::set_group(c, ALICE, L1, &web, None)
            .await
            .unwrap(),
    );
    assert!(l1.groups.is_empty());
    assert_eq!(
        rule_assignment::set_group(
            &mut console,
            ALICE,
            L1,
            "00000000-0000-4000-8000-000000000000",
            Some(true)
        )
        .await
        .unwrap(),
        Change::UnknownGroup
    );
    assert_eq!(
        rule_assignment::set_group(&mut console, ALICE, L1, "not-a-uuid", Some(true))
            .await
            .unwrap(),
        Change::UnknownGroup
    );
    assert_eq!(
        rule_assignment::set_group(&mut console, ALICE, "baseline", &web, Some(true))
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
        rule_assignment::set_group(&mut console, ALICE, L1, &web, Some(false))
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

const A: &str = "agent.00000000-0000-4000-8000-000000000001";
const B: &str = "agent.00000000-0000-4000-8000-000000000002";
const NOBODY: &str = "agent.00000000-0000-4000-8000-000000000099";

async fn agent(admin: &Client, id: &str, tags: &[(&str, &str)]) {
    admin
        .execute(
            "INSERT INTO agents (agent_id, status, enrolled_at) VALUES ($1, 'active', now())",
            &[&id],
        )
        .await
        .unwrap();
    for (key, value) in tags {
        admin
            .execute(
                "INSERT INTO console_agent_tags (agent_id, tag_key, tag_value, changed_at, changed_by)
                 VALUES ($1, $2, $3, now(), 'test')",
                &[&id, key, value],
            )
            .await
            .unwrap();
    }
}

async fn assigned(dist: &Client, agent: &str, set: &str) -> bool {
    rule_assignment::assigned(dist, agent, set).await.unwrap()
}

#[tokio::test]
async fn a_host_in_no_group_gets_the_default() {
    let (db, admin) = setup().await;
    agent(&admin, A, &[("env", "web")]).await;
    // A group without selectors matches nobody, so its "off" does not apply.
    let empty = group(&admin, "empty", &[]).await;
    let mut console = as_role(&db, "openvibes-console").await;
    done(
        rule_assignment::set_group(&mut console, ALICE, L1, &empty, Some(false))
            .await
            .unwrap(),
    );
    let dist = as_role(&db, "openvibes-distribution").await;
    assert!(assigned(&dist, A, L1).await);
    assert!(!assigned(&dist, A, L2).await);
    // Not assignable: always served as before.
    assert!(assigned(&dist, A, "baseline").await);
    let host = rule_assignment::for_agent(&console, &AgentScope::Global, A)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        host,
        [
            HostAssignment {
                rule_set_id: L1.into(),
                enabled: true,
                source: Source::Default,
                group: None,
                published: false,
            },
            HostAssignment {
                rule_set_id: L2.into(),
                enabled: false,
                source: Source::Default,
                group: None,
                published: false,
            },
        ]
    );
    drop((console, dist, admin));
    db.drop().await;
}

#[tokio::test]
async fn on_wins_and_a_deleted_group_falls_back() {
    let (db, admin) = setup().await;
    agent(&admin, A, &[("env", "web"), ("tier", "db")]).await;
    agent(&admin, B, &[("env", "web"), ("tier", "web")]).await;
    let web = group(&admin, "web", &[("env", "web")]).await;
    // Needs both tags: B has the tier key but another value, so is not a member.
    let web_db = group(&admin, "web-db", &[("env", "web"), ("tier", "db")]).await;
    let mut console = as_role(&db, "openvibes-console").await;
    done(
        rule_assignment::set_group(&mut console, ALICE, L2, &web, Some(false))
            .await
            .unwrap(),
    );
    done(
        rule_assignment::set_group(&mut console, ALICE, L2, &web_db, Some(true))
            .await
            .unwrap(),
    );
    done(
        rule_assignment::set_group(&mut console, ALICE, L1, &web, Some(false))
            .await
            .unwrap(),
    );
    let dist = as_role(&db, "openvibes-distribution").await;
    assert!(assigned(&dist, A, L2).await, "one group on, one off: on");
    assert!(!assigned(&dist, B, L2).await, "only the off group");
    assert!(
        !assigned(&dist, A, L1).await,
        "an off group beats the on default"
    );
    let source = |host: Vec<HostAssignment>| {
        host.into_iter()
            .map(|h| (h.enabled, h.source))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        source(
            rule_assignment::for_agent(&console, &AgentScope::Global, A)
                .await
                .unwrap()
                .unwrap()
        ),
        [(false, Source::Group), (true, Source::Group)]
    );
    admin
        .execute(
            "DELETE FROM console_asset_groups WHERE asset_group_id::text = $1",
            &[&web_db],
        )
        .await
        .unwrap();
    assert!(!assigned(&dist, A, L2).await, "back to web's off");
    drop((console, dist, admin));
    db.drop().await;
}

#[tokio::test]
async fn the_host_view_is_scoped_and_distribution_reads_no_more_than_it_needs() {
    let (db, admin) = setup().await;
    agent(&admin, A, &[("env", "web")]).await;
    let other = group(&admin, "other", &[("env", "db")]).await;
    let console = as_role(&db, "openvibes-console").await;
    let web = group(&admin, "web", &[("env", "web")]).await;
    assert!(
        rule_assignment::for_agent(&console, &AgentScope::AssetGroups(vec![web]), A)
            .await
            .unwrap()
            .is_some()
    );
    let scoped = AgentScope::AssetGroups(vec![other]);
    assert_eq!(
        rule_assignment::for_agent(&console, &scoped, A)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        rule_assignment::for_agent(&console, &AgentScope::Global, NOBODY)
            .await
            .unwrap(),
        None
    );
    let privileges: Vec<bool> = admin
        .query_one(
            "SELECT ARRAY[
                has_column_privilege('openvibes-distribution', 'console_agent_tags', 'tag_value', 'SELECT'),
                has_column_privilege('openvibes-distribution', 'console_agent_tags', 'changed_by', 'SELECT'),
                has_table_privilege('openvibes-distribution', 'rule_set_group_assignment', 'UPDATE'),
                has_column_privilege('openvibes-distribution', 'console_asset_group_selectors', 'created_at', 'SELECT')]",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(privileges, [true, false, false, false]);
    drop((console, admin));
    db.drop().await;
}
