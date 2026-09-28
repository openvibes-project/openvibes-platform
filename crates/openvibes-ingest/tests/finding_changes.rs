//! `POST /v1/findings/changes` and the heartbeat's match digest (protocol
//! P13) through the agent's real client.

mod support;

use chrono::{Duration, Utc};
use openvibes_core::{
    Confidence, EnrollmentToken, Finding, FindingChanges, Heartbeat, Identifier, SchemaVersion,
    Severity, hex, match_digest,
};
use openvibes_transport::{ClientIdentity, HostKey, PlatformClient, TransportError};
use support::World;

async fn blocking<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(work).await.unwrap()
}

fn id(value: &str) -> Identifier {
    Identifier::new(value).unwrap()
}

struct Agent {
    id: String,
    chain: Vec<String>,
    key: String,
}

async fn enrolled(world: &World) -> Agent {
    let transport = world.transport();
    let token = EnrollmentToken::new(world.token(1, Duration::days(1)).await).unwrap();
    blocking(move || {
        let key = HostKey::generate().unwrap();
        let response = PlatformClient::new(&transport, None)
            .unwrap()
            .enroll(&token, &key)
            .unwrap();
        Agent {
            id: response.agent_id.as_str().to_owned(),
            chain: response.certificate_chain_pem,
            key: key.expose_key_pem().to_owned(),
        }
    })
    .await
}

fn client(world: &World, agent: &Agent) -> PlatformClient {
    let identity = ClientIdentity::from_pem(&agent.chain, &agent.key).unwrap();
    PlatformClient::new(&world.transport(), Some(&identity)).unwrap()
}

fn finding(rule: &str, observed_at_unix_ms: i64) -> Finding {
    Finding {
        schema_version: SchemaVersion::V1,
        finding_id: id(&format!("finding.{rule}.{observed_at_unix_ms}")),
        scan_id: id("scan.1"),
        rule_set_id: Some(id("base")),
        rule_id: id(rule),
        rule_version: 1,
        observed_at_unix_ms,
        severity: Severity::High,
        confidence: Confidence::new(100).unwrap(),
        message: format!("{rule} matched"),
        evidence: vec![id("port.tcp.exposed")],
    }
}

fn replace(agent: &str, started: Vec<Finding>) -> FindingChanges {
    FindingChanges {
        schema_version: SchemaVersion::V1,
        agent_id: id(agent),
        base_sha256: hex(&match_digest(&[])),
        sha256: hex(&match_digest(&started)),
        replace: true,
        scanned_at_unix_ms: Utc::now().timestamp_millis(),
        started,
        changed: Vec::new(),
        ended: Vec::new(),
        transient: Vec::new(),
        transient_dropped: 0,
    }
}

async fn send(world: &World, agent: &Agent, changes: FindingChanges) -> Result<(), TransportError> {
    let client = client(world, agent);
    blocking(move || client.report_finding_changes(&changes)).await
}

fn heartbeat(agent: &str, match_sha256: Option<String>) -> Heartbeat {
    Heartbeat {
        schema_version: SchemaVersion::V1,
        agent_id: id(agent),
        scanner_version: "0.1.0".into(),
        hostname: None,
        observed_at_unix_ms: Utc::now().timestamp_millis(),
        capabilities: Vec::new(),
        health: None,
        match_sha256,
    }
}

async fn beat(world: &World, agent: &Agent, digest: Option<String>) -> Result<(), TransportError> {
    let client = client(world, agent);
    let heartbeat = heartbeat(&agent.id, digest);
    blocking(move || client.heartbeat(&heartbeat)).await
}

/// (rule, ended) for the agent's P13 rows.
async fn rows(world: &World, agent: &str) -> Vec<(String, bool)> {
    world
        .db()
        .await
        .query(
            "SELECT rule_id, ended_at IS NOT NULL FROM current_findings
             WHERE agent_id = $1 AND source = 'changes' ORDER BY rule_id",
            &[&agent],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect()
}

#[tokio::test]
async fn a_replace_is_stored_and_a_wrong_base_is_a_resync() {
    let world = World::start().await;
    let agent = enrolled(&world).await;
    let now = Utc::now().timestamp_millis();
    let first = replace(&agent.id, vec![finding("a", now)]);
    send(&world, &agent, first.clone()).await.unwrap();
    assert_eq!(rows(&world, &agent.id).await, [("a".into(), false)]);
    let mut diff = first.clone();
    diff.replace = false;
    diff.base_sha256 = "0".repeat(64);
    diff.started = vec![finding("b", now)];
    diff.sha256 = hex(&match_digest(&[finding("a", now), finding("b", now)]));
    assert_eq!(
        send(&world, &agent, diff).await,
        Err(TransportError::FindingsResync)
    );
    assert_eq!(rows(&world, &agent.id).await, [("a".into(), false)]);
    world.stop().await;
}

#[tokio::test]
async fn another_agents_document_and_an_unstorable_value_are_refused() {
    let world = World::start().await;
    let agent = enrolled(&world).await;
    let other = replace("agent.00000000-0000-4000-8000-000000000999", Vec::new());
    assert_eq!(
        send(&world, &agent, other).await,
        Err(TransportError::Rejected)
    );
    let mut huge = finding("a", Utc::now().timestamp_millis());
    huge.rule_version = 1 << 63;
    assert_eq!(
        send(&world, &agent, replace(&agent.id, vec![huge])).await,
        Err(TransportError::Rejected),
        "a value the store cannot hold is 400, never 409"
    );
    world.stop().await;
}

#[tokio::test]
async fn a_start_outside_the_window_is_stored_at_receipt() {
    let world = World::start().await;
    let agent = enrolled(&world).await;
    let future = (Utc::now() + Duration::days(2)).timestamp_millis();
    send(
        &world,
        &agent,
        replace(&agent.id, vec![finding("a", future)]),
    )
    .await
    .unwrap();
    let observed: chrono::DateTime<Utc> = world
        .db()
        .await
        .query_one(
            "SELECT observed_at FROM findings WHERE agent_id = $1",
            &[&agent.id],
        )
        .await
        .unwrap()
        .get(0);
    assert!(
        observed <= Utc::now(),
        "stored at receipt, not in the future"
    );
    world.stop().await;
}

#[tokio::test]
async fn a_heartbeat_with_another_digest_is_stored_and_asks_for_the_set() {
    let world = World::start().await;
    let agent = enrolled(&world).await;
    let first = replace(&agent.id, vec![finding("a", Utc::now().timestamp_millis())]);
    send(&world, &agent, first.clone()).await.unwrap();
    assert_eq!(
        beat(&world, &agent, Some(first.sha256.clone())).await,
        Ok(())
    );
    assert_eq!(
        beat(&world, &agent, Some("0".repeat(64))).await,
        Err(TransportError::FindingsResync)
    );
    assert_eq!(
        beat(&world, &agent, None).await,
        Ok(()),
        "agents before P13"
    );
    let seen: Option<chrono::DateTime<Utc>> = world
        .db()
        .await
        .query_one(
            "SELECT last_seen_at FROM agents WHERE agent_id = $1",
            &[&agent.id],
        )
        .await
        .unwrap()
        .get(0);
    assert!(seen.is_some(), "the heartbeat was stored");
    world.stop().await;
}
