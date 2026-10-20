//! Rule-set assignment, the console's figures (plan 2026-10-15, part 3):
//! Linux host counts per set and per group, the group that
//! decides a host's state, whether the set is published, and (Task 2) when
//! hardening facts were last usable.

mod common;

use common::TestDb;
use platform_store::{
    Client,
    console_read::AgentScope,
    host_groups::GroupKind,
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

/// An agent; `linux` sets `os_id` as an inventory from os-release does.
async fn agent(admin: &Client, id: &str, status: &str, linux: bool) {
    admin
        .execute(
            "INSERT INTO agents (agent_id, status, enrolled_at, os_id) VALUES ($1, $2, now(), $3)",
            &[&id, &status, &linux.then_some("fedora")],
        )
        .await
        .unwrap();
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
    agent(&admin, A, "active", true).await;
    agent(&admin, B, "active", true).await;
    // Not counted: no os-release reported yet, revoked, imported (the last two
    // are in no group).
    agent(&admin, C, "active", false).await;
    agent(&admin, D, "revoked", true).await;
    agent(&admin, E, "imported", true).await;
    let prod = common::manual_group(&admin, "prod", &[A, C, D, E]).await;
    let lab = common::manual_group(&admin, "lab", &[B]).await;
    common::manual_group(&admin, "empty", &[]).await;
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
        .map(|g| (g.name.as_str(), g.kind, g.hosts))
        .collect();
    assert_eq!(
        groups,
        [
            ("empty", GroupKind::Manual, 0),
            ("lab", GroupKind::Manual, 1),
            ("prod", GroupKind::Manual, 1),
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
    agent(&admin, A, "active", true).await;
    let zeta = common::manual_group(&admin, "zeta", &[A]).await;
    let alpha = common::manual_group(&admin, "alpha", &[A]).await;
    let mid = common::manual_group(&admin, "mid", &[A]).await;
    let mut console = as_role(&db, "openvibes-console").await;
    // L2: two groups say on, one says off. On wins; the first on group by name decides.
    switch(&mut console, L2, &zeta, true).await;
    switch(&mut console, L2, &alpha, true).await;
    switch(&mut console, L2, &mid, false).await;
    // L1: only off groups; the first by name decides ("mid" before "zzz").
    let late = common::manual_group(&admin, "zzz", &[A]).await;
    switch(&mut console, L1, &late, false).await;
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

#[tokio::test]
async fn a_host_in_an_on_and_an_off_group_counts_as_on_like_distribution_says() {
    let (db, admin) = setup().await;
    agent(&admin, A, "active", true).await;
    let web = common::rule_group(&admin, "web", &[("os_family", false, &["linux"])]).await;
    let dbs = common::manual_group(&admin, "db", &[A]).await;
    let mut console = as_role(&db, "openvibes-console").await;
    switch(&mut console, L1, &web, false).await;
    switch(&mut console, L1, &dbs, true).await;
    let overview = rule_assignment::overview(&console).await.unwrap();
    let l1 = overview.sets.iter().find(|s| s.rule_set_id == L1).unwrap();
    assert_eq!((l1.hosts_on, l1.hosts_off), (1, 0));
    let dist = as_role(&db, "openvibes-distribution").await;
    assert!(rule_assignment::assigned(&dist, A, L1).await.unwrap());
    drop((console, dist, admin));
    db.drop().await;
}

#[tokio::test]
async fn the_hardening_facts_outcome_comes_from_the_latest_report() {
    let (db, admin) = setup().await;
    agent(&admin, A, "active", true).await;
    let console = as_role(&db, "openvibes-console").await;
    assert_eq!(
        rule_assignment::hardening_facts(&console, A).await.unwrap(),
        (None, None),
        "no report yet"
    );
    admin
        .execute(
            "UPDATE agents SET health = $2 WHERE agent_id = $1",
            &[
                &A,
                &serde_json::json!({"last_scan": {"collectors": {"hardening": "not_found", "packages": "ok"}}}),
            ],
        )
        .await
        .unwrap();
    let (outcome, ok_at) = rule_assignment::hardening_facts(&console, A).await.unwrap();
    assert_eq!(
        (outcome.as_deref(), ok_at),
        (Some("not_found"), None),
        "never ok: since enrollment"
    );
    drop((console, admin));
    db.drop().await;
}

#[tokio::test]
async fn ingest_records_when_hardening_facts_were_last_usable() {
    let (db, admin) = setup().await;
    agent(&admin, A, "active", true).await;
    let ingest = as_role(&db, "openvibes-ingest").await;
    let t0 = chrono::Utc::now();
    // Ten minutes apart: past the five-minute heartbeat write throttle.
    for (outcome, at) in [
        ("ok", t0),
        ("not_found", t0 + chrono::Duration::minutes(10)),
    ] {
        let health = serde_json::json!({"last_scan": {"collectors": {"hardening": outcome}}});
        platform_store::ingest::heartbeat(&ingest, A, "0.5.0", None, &[], Some(&health), None, at)
            .await
            .unwrap();
    }
    // A report without the hardening collector, and one without a health
    // report at all, leave the time where it was.
    let packages_only = serde_json::json!({"last_scan": {"collectors": {"packages": "ok"}}});
    for (n, health) in [(20, Some(&packages_only)), (30, None)] {
        let at = t0 + chrono::Duration::minutes(n);
        platform_store::ingest::heartbeat(&ingest, A, "0.5.0", None, &[], health, None, at)
            .await
            .unwrap();
    }
    let console = as_role(&db, "openvibes-console").await;
    let (outcome, ok_at) = rule_assignment::hardening_facts(&console, A).await.unwrap();
    assert_eq!(
        outcome.as_deref(),
        None,
        "the latest report has no hardening collector"
    );
    assert_eq!(
        ok_at.map(|t| t.timestamp_millis()),
        Some(t0.timestamp_millis()),
        "the last stored report with usable facts"
    );
    drop((ingest, console, admin));
    db.drop().await;
}
