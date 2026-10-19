//! Protocol P20: `410 Gone` for an assignable set switched off on the
//! asking host; every other answer unchanged.

mod support;

use support::{Agent, World, request};

const L1: &str = "hardening-linux-l1";
const L2: &str = "hardening-linux-l2";
const BUNDLE: &[u8] = b"{\"version\":1}";

async fn status(world: &World, agent: &Agent, set: &str, current: Option<u64>) -> u16 {
    world
        .raw(&request(set, current), Some(agent))
        .await
        .unwrap()
        .0
}

async fn set_default(world: &World, set: &str, enabled: bool) {
    world
        .db()
        .await
        .execute(
            "UPDATE rule_set_assignment SET default_enabled = $2 WHERE rule_set_id = $1",
            &[&set, &enabled],
        )
        .await
        .unwrap();
}

/// A host group with `set` switched to `enabled`: a manual group of
/// `members`, or with `members` empty a rule group of hosts named `web-*`.
async fn group(world: &World, name: &str, members: &[&Agent], set: &str, enabled: bool) -> String {
    let db = world.db().await;
    let kind = if members.is_empty() { "rule" } else { "manual" };
    let id: String = db
        .query_one(
            "INSERT INTO console_asset_groups (asset_group_id, name, created_at, created_by, kind)
             VALUES (gen_random_uuid(), $1, now(), 'test', $2) RETURNING asset_group_id::text",
            &[&name, &kind],
        )
        .await
        .unwrap()
        .get(0);
    let ids: Vec<&str> = members.iter().map(|a| a.id.as_str()).collect();
    db.execute(
        "INSERT INTO console_host_group_members (asset_group_id, agent_id, added_at, added_by)
         SELECT $1::text::uuid, unnest($2::text[]), now(), 'test'",
        &[&id, &ids],
    )
    .await
    .unwrap();
    if members.is_empty() {
        db.execute(
            "INSERT INTO console_host_group_conditions (asset_group_id, position, field, vals)
             VALUES ($1::text::uuid, 0, 'hostname', '{web-*}')",
            &[&id],
        )
        .await
        .unwrap();
    }
    db.execute(
        "INSERT INTO rule_set_group_assignment (rule_set_id, asset_group_id, enabled)
         VALUES ($1, $2::text::uuid, $3)",
        &[&set, &id, &enabled],
    )
    .await
    .unwrap();
    id
}

async fn name(world: &World, agent: &Agent, hostname: &str) {
    world
        .db()
        .await
        .execute(
            "UPDATE agents SET hostname = $2 WHERE agent_id = $1",
            &[&agent.id, &hostname],
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn a_set_switched_off_for_the_host_is_gone() {
    let world = World::start().await;
    world.publish(L1, 1, BUNDLE).await;
    let agent = world.agent(1).await;
    assert_eq!(
        status(&world, &agent, L1, None).await,
        200,
        "L1 is on by default"
    );
    set_default(&world, L1, false).await;
    let (code, _, body) = world.raw(&request(L1, None), Some(&agent)).await.unwrap();
    assert_eq!((code, body.len()), (410, 0));
    assert_eq!(
        status(&world, &agent, L1, Some(1)).await,
        410,
        "even when current"
    );
    set_default(&world, L1, true).await;
    assert_eq!(status(&world, &agent, L1, Some(1)).await, 204, "back on");
    world.stop().await;
}

#[tokio::test]
async fn on_wins_across_groups() {
    let world = World::start().await;
    world.publish(L2, 1, BUNDLE).await;
    let agent = world.agent(1).await;
    let other = world.agent(2).await;
    name(&world, &agent, "web-01").await;
    name(&world, &other, "web-02").await;
    group(&world, "web", &[], L2, false).await;
    let db_group = group(&world, "db", &[&agent], L2, true).await;
    assert_eq!(
        status(&world, &agent, L2, None).await,
        200,
        "one group on wins"
    );
    assert_eq!(status(&world, &other, L2, None).await, 410);
    world
        .db()
        .await
        .execute(
            "DELETE FROM console_asset_groups WHERE asset_group_id::text = $1",
            &[&db_group],
        )
        .await
        .unwrap();
    assert_eq!(
        status(&world, &agent, L2, None).await,
        410,
        "falls back to web's off"
    );
    world.stop().await;
}

/// Pinning test: passes before the change (404 is today's behaviour).
#[tokio::test]
async fn unpublished_or_retired_sets_stay_not_found() {
    let world = World::start().await;
    let agent = world.agent(1).await;
    // L2: assignable, off by default, nothing published.
    assert_eq!(status(&world, &agent, L2, None).await, 404);
    world.publish(L1, 1, BUNDLE).await;
    set_default(&world, L1, false).await;
    assert!(
        platform_store::rules::retire(&world.db().await, L1)
            .await
            .unwrap()
    );
    assert_eq!(status(&world, &agent, L1, None).await, 404);
    world.stop().await;
}

/// Pinning test: passes before the change.
#[tokio::test]
async fn other_sets_are_unchanged() {
    let world = World::start().await;
    world.publish("baseline", 1, BUNDLE).await;
    world.publish("baseline-alarms", 1, BUNDLE).await;
    set_default(&world, L1, false).await;
    set_default(&world, L2, false).await;
    let agent = world.agent(1).await;
    assert_eq!(status(&world, &agent, "baseline", None).await, 200);
    assert_eq!(status(&world, &agent, "baseline", Some(1)).await, 204);
    assert_eq!(status(&world, &agent, "baseline-alarms", None).await, 200);
    assert_eq!(status(&world, &agent, "site-rules", None).await, 404);
    world.stop().await;
}
