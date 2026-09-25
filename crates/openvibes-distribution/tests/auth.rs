//! Agents authenticate exactly as at ingest.

mod support;

use chrono::{Duration, Utc};
use support::{Agent, World, request};

#[tokio::test]
async fn a_revoked_agent_is_told_identity_revoked() {
    let world = World::start().await;
    world.publish("baseline", 1, b"{}").await;
    let agent = world.agent(1).await;
    world.revoke(&agent).await;
    let (status, _, body) = world
        .raw(&request("baseline", None), Some(&agent))
        .await
        .unwrap();
    assert_eq!(status, 403);
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        body,
        serde_json::json!({"schema_version": 1, "code": "identity_revoked"})
    );
    world.stop().await;
}

#[tokio::test]
async fn an_unknown_certificate_is_unauthorized() {
    let world = World::start().await;
    world.publish("baseline", 1, b"{}").await;
    let id = "agent.00000000-0000-4000-8000-000000000009";
    let (issued, key) = world.certificate(id, Utc::now() - Duration::minutes(5), 30);
    let stranger = Agent {
        id: id.into(),
        chain: issued.chain_pem,
        key,
    };
    let status = world
        .raw(&request("baseline", None), Some(&stranger))
        .await
        .map(|r| r.0);
    assert_eq!(status, Some(401));
    world.stop().await;
}

#[tokio::test]
async fn an_expired_certificate_is_unauthorized() {
    let world = World::start().await;
    world.publish("baseline", 1, b"{}").await;
    let agent = world
        .agent_valid(1, Utc::now() - Duration::days(3), 1)
        .await;
    let status = world
        .raw(&request("baseline", None), Some(&agent))
        .await
        .map(|r| r.0);
    assert_eq!(status, Some(401), "an HTTP answer, not a failed handshake");
    world.stop().await;
}

#[tokio::test]
async fn no_client_certificate_is_unauthorized() {
    let world = World::start().await;
    world.publish("baseline", 1, b"{}").await;
    let status = world
        .raw(&request("baseline", None), None)
        .await
        .map(|r| r.0);
    assert_eq!(status, Some(401));
    // Authentication comes first: a malformed body without a certificate
    // is 401, not 400.
    assert_eq!(world.raw(b"{", None).await.map(|r| r.0), Some(401));
    world.stop().await;
}

#[tokio::test]
async fn a_foreign_ca_fails_the_handshake() {
    let world = World::start().await;
    let other = World::start().await;
    let foreign = other.agent(1).await;
    assert_eq!(
        world.raw(&request("baseline", None), Some(&foreign)).await,
        None
    );
    other.stop().await;
    world.stop().await;
}
