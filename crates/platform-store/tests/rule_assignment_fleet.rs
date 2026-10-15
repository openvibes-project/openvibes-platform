//! Rule-set assignment, the console's figures (plan 2026-10-15, part 3):
//! Linux host counts per set and per group, group selectors, the group that
//! decides a host's state, whether the set is published, and (Task 2) when
//! hardening facts were last usable.

mod common;

use common::TestDb;
use platform_store::{
    Client,
    console_read::AgentScope,
    rule_assignment::{self, Change, HostAssignment, Source},
};

const L1: &str = "hardening-linux-l1";
const L2: &str = "hardening-linux-l2";
const ALICE: &str = "00000000-0000-4000-8000-000000000001";
const A: &str = "agent.00000000-0000-4000-8000-000000000001";
const B: &str = "agent.00000000-0000-4000-8000-000000000002";
const C: &str = "agent.00000000-0000-4000-8000-000000000003";
const D: &str = "agent.00000000-0000-4000-8000-000000000004";
const E: &str = "import.lab-9";

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

/// An agent; `linux` sets `os_id` as an inventory from os-release does.
async fn agent(admin: &Client, id: &str, status: &str, linux: bool, tags: &[(&str, &str)]) {
    admin
        .execute(
            "INSERT INTO agents (agent_id, status, enrolled_at, os_id) VALUES ($1, $2, now(), $3)",
            &[&id, &status, &linux.then_some("fedora")],
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

async fn switch(console: &mut Client, set: &str, group: &str, on: bool) {
    let change = rule_assignment::set_group(console, ALICE, set, group, Some(on))
        .await
        .unwrap();
    assert!(matches!(change, Change::Done(_)), "{change:?}");
}

#[tokio::test]
async fn hosts_are_counted_per_set_and_per_group_on_linux_hosts_only() {
    let (db, admin) = setup().await;
    agent(&admin, A, "active", true, &[("env", "prod")]).await;
    agent(&admin, B, "active", true, &[("env", "lab")]).await;
    // Not counted: no os-release reported yet, revoked, imported.
    agent(&admin, C, "active", false, &[("env", "prod")]).await;
    agent(&admin, D, "revoked", true, &[("env", "prod")]).await;
    agent(&admin, E, "imported", true, &[("env", "prod")]).await;
    let prod = group(&admin, "prod", &[("env", "prod")]).await;
    let lab = group(&admin, "lab", &[("env", "lab")]).await;
    group(&admin, "empty", &[]).await;
    let mut console = as_role(&db, "openvibes-console").await;
    switch(&mut console, L1, &prod, false).await;
    switch(&mut console, L2, &lab, true).await;
    let overview = rule_assignment::overview(&console).await.unwrap();
    let sets: Vec<_> = overview
        .sets
        .iter()
        .map(|s| (s.rule_set_id.as_str(), s.hosts_on, s.hosts_off))
        .collect();
    assert_eq!(sets, [(L1, 1, 1), (L2, 1, 1)]);
    let groups: Vec<_> = overview
        .groups
        .iter()
        .map(|g| (g.name.as_str(), g.selectors.clone(), g.hosts))
        .collect();
    assert_eq!(
        groups,
        [
            ("empty", vec![], 0),
            ("lab", vec!["env=lab".to_owned()], 1),
            ("prod", vec!["env=prod".to_owned()], 1),
        ]
    );
    drop((console, admin));
    db.drop().await;
}

#[tokio::test]
async fn no_linux_host_counts_zero() {
    let (db, admin) = setup().await;
    let console = as_role(&db, "openvibes-console").await;
    let overview = rule_assignment::overview(&console).await.unwrap();
    assert!(
        overview
            .sets
            .iter()
            .all(|s| (s.hosts_on, s.hosts_off) == (0, 0))
    );
    drop((console, admin));
    db.drop().await;
}

#[tokio::test]
async fn the_host_view_names_the_deciding_group_and_says_whether_the_set_is_published() {
    let (db, admin) = setup().await;
    agent(&admin, A, "active", true, &[("env", "web"), ("tier", "db")]).await;
    let zeta = group(&admin, "zeta", &[("env", "web")]).await;
    let alpha = group(&admin, "alpha", &[("tier", "db")]).await;
    let mid = group(&admin, "mid", &[("env", "web"), ("tier", "db")]).await;
    let mut console = as_role(&db, "openvibes-console").await;
    // L2: two groups say on, one says off. On wins; the first on group by name decides.
    switch(&mut console, L2, &zeta, true).await;
    switch(&mut console, L2, &alpha, true).await;
    switch(&mut console, L2, &mid, false).await;
    // L1: only an off group.
    switch(&mut console, L1, &mid, false).await;
    let host = rule_assignment::for_agent(&console, &AgentScope::Global, A)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        host,
        [
            HostAssignment {
                rule_set_id: L1.into(),
                enabled: false,
                source: Source::Group,
                group: Some("mid".into()),
                published: false,
            },
            HostAssignment {
                rule_set_id: L2.into(),
                enabled: true,
                source: Source::Group,
                group: Some("alpha".into()),
                published: false,
            },
        ]
    );
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
    let host = rule_assignment::for_agent(&console, &AgentScope::Global, A)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((host[0].published, host[1].published), (true, false));
    // Distribution reads no group names: the shared resolution still works for it.
    let dist = as_role(&db, "openvibes-distribution").await;
    assert!(!rule_assignment::assigned(&dist, A, L1).await.unwrap());
    assert!(rule_assignment::assigned(&dist, A, L2).await.unwrap());
    drop((console, dist, admin));
    db.drop().await;
}
