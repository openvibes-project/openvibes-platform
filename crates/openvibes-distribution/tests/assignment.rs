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

async fn tag(world: &World, agent: &Agent, key: &str, value: &str) {
    world
        .db()
        .await
        .execute(
            "INSERT INTO console_agent_tags (agent_id, tag_key, tag_value, changed_at, changed_by)
             VALUES ($1, $2, $3, now(), 'test')",
            &[&agent.id, &key, &value],
        )
        .await
        .unwrap();
}

/// A group of hosts tagged `key=value` with `set` switched to `enabled`.
async fn group(
    world: &World,
    name: &str,
    key: &str,
    value: &str,
    set: &str,
    enabled: bool,
) -> String {
    let db = world.db().await;
    let id: String = db
        .query_one(
            "INSERT INTO console_asset_groups (asset_group_id, name, created_at, created_by)
             VALUES (gen_random_uuid(), $1, now(), 'test') RETURNING asset_group_id::text",
            &[&name],
        )
        .await
        .unwrap()
        .get(0);
    db.execute(
        "INSERT INTO console_asset_group_selectors (asset_group_id, tag_key, tag_value, created_at)
         VALUES ($1::text::uuid, $2, $3, now())",
        &[&id, &key, &value],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO rule_set_group_assignment (rule_set_id, asset_group_id, enabled)
         VALUES ($1, $2::text::uuid, $3)",
        &[&set, &id, &enabled],
    )
    .await
    .unwrap();
    id
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
    tag(&world, &agent, "env", "web").await;
    tag(&world, &agent, "tier", "db").await;
    tag(&world, &other, "env", "web").await;
    group(&world, "web", "env", "web", L2, false).await;
    let db_group = group(&world, "db", "tier", "db", L2, true).await;
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
