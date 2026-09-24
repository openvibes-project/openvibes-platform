//! `POST /v1/rule-bundle`: 200 with the exact bytes, 204, 404, 400.

mod support;

use support::{World, request};

const V1: &[u8] = b"{ \"any\" : \"bytes\",\n  \"kept\": [1, 2] }";
const V2: &[u8] = b"{\"version\":2}";

#[tokio::test]
async fn first_fetch_returns_the_exact_bytes() {
    let world = World::start().await;
    world.publish("baseline", 1, V1).await;
    let agent = world.agent(1).await;
    assert_eq!(
        world.fetch(&agent, "baseline", None).await.unwrap(),
        Some(V1.to_vec())
    );
    let (status, head, body) = world
        .raw(&request("baseline", None), Some(&agent))
        .await
        .unwrap();
    assert_eq!((status, body.as_slice()), (200, V1));
    assert!(
        head.to_ascii_lowercase()
            .contains("content-type: application/json"),
        "{head}"
    );
    world.stop().await;
}

#[tokio::test]
async fn an_older_version_gets_the_current_bundle() {
    let world = World::start().await;
    world.publish("baseline", 1, V1).await;
    world.publish("baseline", 2, V2).await;
    let agent = world.agent(1).await;
    assert_eq!(
        world.fetch(&agent, "baseline", Some(1)).await.unwrap(),
        Some(V2.to_vec())
    );
    world.stop().await;
}

#[tokio::test]
async fn the_current_version_gets_no_content() {
    let world = World::start().await;
    world.publish("baseline", 2, V2).await;
    let agent = world.agent(1).await;
    assert_eq!(
        world.fetch(&agent, "baseline", Some(2)).await.unwrap(),
        None
    );
    let (status, _, body) = world
        .raw(&request("baseline", Some(2)), Some(&agent))
        .await
        .unwrap();
    assert_eq!((status, body.len()), (204, 0));
    world.stop().await;
}

#[tokio::test]
async fn a_newer_agent_version_gets_no_content() {
    let world = World::start().await;
    world.publish("baseline", 2, V2).await;
    let agent = world.agent(1).await;
    assert_eq!(
        world.fetch(&agent, "baseline", Some(99)).await.unwrap(),
        None
    );
    world.stop().await;
}

#[tokio::test]
async fn an_unknown_set_is_not_found() {
    let world = World::start().await;
    let agent = world.agent(1).await;
    let status = world
        .raw(&request("nobody", None), Some(&agent))
        .await
        .map(|r| r.0);
    assert_eq!(status, Some(404));
    world.stop().await;
}

#[tokio::test]
async fn a_set_without_bundles_is_not_found() {
    let world = World::start().await;
    let db = world.db().await;
    platform_store::rules::add_trust_key(&db, "baseline", "org.rules", [9; 32])
        .await
        .unwrap();
    let agent = world.agent(1).await;
    let status = world
        .raw(&request("baseline", None), Some(&agent))
        .await
        .map(|r| r.0);
    assert_eq!(status, Some(404));
    world.stop().await;
}

#[tokio::test]
async fn a_retired_set_is_not_found() {
    let world = World::start().await;
    world.publish("baseline", 1, V1).await;
    let agent = world.agent(1).await;
    assert!(
        platform_store::rules::retire(&world.db().await, "baseline")
            .await
            .unwrap()
    );
    let status = world
        .raw(&request("baseline", None), Some(&agent))
        .await
        .map(|r| r.0);
    assert_eq!(status, Some(404));
    world.stop().await;
}

#[tokio::test]
async fn malformed_requests_are_bad_requests() {
    let world = World::start().await;
    world.publish("baseline", 1, V1).await;
    let agent = world.agent(1).await;
    for body in [
        &b"{"[..],
        br#"{"schema_version":1,"rule_set_id":"baseline","current_version":0}"#,
        br#"{"schema_version":2,"rule_set_id":"baseline"}"#,
        br#"{"schema_version":1,"rule_set_id":"a/b"}"#,
        br#"{"schema_version":1}"#,
    ] {
        let status = world.raw(body, Some(&agent)).await.map(|r| r.0);
        assert_eq!(status, Some(400), "{}", String::from_utf8_lossy(body));
    }
    world.stop().await;
}
