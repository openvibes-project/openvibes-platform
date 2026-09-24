//! Heartbeats and finding delivery through the agent's real client.

mod support;

use chrono::{Duration, Utc};
use openvibes_core::{
    Confidence, EnrollmentToken, Finding, Heartbeat, Identifier, SchemaVersion, Severity,
};
use openvibes_transport::{ClientIdentity, HostKey, PlatformClient, TransportError};
use support::World;

async fn blocking<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(work).await.unwrap()
}

/// Enrolls one agent; returns its id, chain, and key.
async fn enrolled(world: &World) -> (String, Vec<String>, String) {
    let transport = world.transport();
    let token = EnrollmentToken::new(world.token(1, Duration::days(1)).await).unwrap();
    blocking(move || {
        let key = HostKey::generate().unwrap();
        let response = PlatformClient::new(&transport, None)
            .unwrap()
            .enroll(&token, &key)
            .unwrap();
        (
            response.agent_id.as_str().to_owned(),
            response.certificate_chain_pem,
            key.expose_key_pem().to_owned(),
        )
    })
    .await
}

fn finding(id: &str, observed_ms: i64) -> Finding {
    Finding {
        schema_version: SchemaVersion::V1,
        finding_id: Identifier::new(id).unwrap(),
        scan_id: Identifier::new("scan.1").unwrap(),
        rule_id: Identifier::new(format!("rule.{id}")).unwrap(),
        rule_version: 1,
        observed_at_unix_ms: observed_ms,
        severity: Severity::Medium,
        confidence: Confidence::new(90).unwrap(),
        message: "synthetic".into(),
        evidence: vec![Identifier::new("process.names").unwrap()],
    }
}

fn heartbeat(agent_id: &str) -> Heartbeat {
    Heartbeat {
        schema_version: SchemaVersion::V1,
        agent_id: Identifier::new(agent_id).unwrap(),
        scanner_version: "0.1.0".into(),
        hostname: Some("metabox-lnx".into()),
        observed_at_unix_ms: Utc::now().timestamp_millis(),
        capabilities: Vec::new(),
    }
}

async fn count(world: &World) -> i64 {
    world
        .db()
        .await
        .query_one("SELECT count(*) FROM findings", &[])
        .await
        .unwrap()
        .get(0)
}

#[tokio::test]
async fn heartbeats_and_findings_are_idempotent_and_bounded() {
    let world = World::start().await;
    let (agent_id, chain, key) = enrolled(&world).await;
    let transport = world.transport();
    let now = Utc::now().timestamp_millis();
    let batch = vec![
        finding("f.1", now - 60_000),
        finding("f.2", now - 120_000),
        finding("f.3", now),
    ];
    let (first, second, other_agent) = blocking({
        let (agent_id, chain, key, batch) =
            (agent_id.clone(), chain.clone(), key.clone(), batch.clone());
        move || {
            let identity = ClientIdentity::from_pem(&chain, &key).unwrap();
            let client = PlatformClient::new(&transport, Some(&identity)).unwrap();
            client.heartbeat(&heartbeat(&agent_id)).unwrap();
            let other = client
                .heartbeat(&heartbeat("agent.00000000-0000-4000-8000-000000000009"))
                .err();
            (
                client.deliver(&batch).unwrap(),
                client.deliver(&batch).unwrap(),
                other,
            )
        }
    })
    .await;
    assert_eq!(
        other_agent,
        Some(TransportError::Rejected),
        "another agent's id is 400"
    );
    let ids = |ack: &openvibes_core::DeliveryAcknowledgement| {
        let mut ids: Vec<String> = ack
            .accepted_finding_ids
            .iter()
            .map(|id| id.as_str().to_owned())
            .collect();
        ids.sort();
        ids
    };
    assert_eq!(ids(&first), ["f.1", "f.2", "f.3"]);
    assert_eq!(ids(&second), ["f.1", "f.2", "f.3"]);
    assert_eq!(count(&world).await, 3);
    let seen: Option<chrono::DateTime<Utc>> = world
        .db()
        .await
        .query_one(
            "SELECT last_seen_at FROM agents WHERE agent_id = $1",
            &[&agent_id],
        )
        .await
        .unwrap()
        .get(0);
    assert!(seen.is_some());
    let hostname: Option<String> = world
        .db()
        .await
        .query_one(
            "SELECT hostname FROM agents WHERE agent_id = $1",
            &[&agent_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        hostname.as_deref(),
        Some("metabox-lnx"),
        "the heartbeat hostname is stored"
    );

    // One bad finding never fails its batch: each is stored or refused on
    // its own, and a refused one is acknowledged with a reason.
    let partition_gone = (Utc::now() - Duration::days(10)).date_naive();
    world
        .db()
        .await
        .batch_execute(&format!(
            "DROP TABLE findings_{}",
            partition_gone.format("%Y%m%d")
        ))
        .await
        .unwrap();
    let transport = world.transport();
    let ack = blocking(move || {
        let identity = ClientIdentity::from_pem(&chain, &key).unwrap();
        let client = PlatformClient::new(&transport, Some(&identity)).unwrap();
        let mut huge = finding("f.7", now);
        huge.rule_version = u64::MAX;
        client
            .deliver(&[
                finding("f.4", now),
                finding("f.5", now + 30 * 60_000),
                finding("f.6", now + 2 * 3_600_000),
                finding("f.8", now - 100 * 86_400_000),
                huge,
                finding("f.9", now - 10 * 86_400_000),
            ])
            .unwrap()
    })
    .await;
    let mut accepted: Vec<&str> = ack
        .accepted_finding_ids
        .iter()
        .map(|id| id.as_str())
        .collect();
    accepted.sort_unstable();
    assert_eq!(accepted, ["f.4", "f.5", "f.6", "f.7", "f.8", "f.9"]);
    let mut rejected: Vec<(&str, &str)> = ack
        .rejected_findings
        .iter()
        .map(|rejected| (rejected.finding_id.as_str(), rejected.reason.as_str()))
        .collect();
    rejected.sort_unstable();
    assert_eq!(
        rejected,
        [
            ("f.6", "future_observation"),
            ("f.7", "out_of_range"),
            ("f.8", "retention_expired"),
            ("f.9", "unstorable"),
        ]
    );
    assert_eq!(count(&world).await, 5, "f.4 and f.5 (30 min ahead) stored");
    world.stop().await;
}

#[tokio::test]
async fn revoked_agents_get_identity_revoked_and_outages_503() {
    let world = World::start().await;
    let (agent_id, chain, key) = enrolled(&world).await;
    let pem_chain = chain.concat();
    platform_store::agents::revoke(&world.db().await, &agent_id, Utc::now())
        .await
        .unwrap();
    let transport = world.transport();
    let errors = blocking({
        let (agent_id, chain, key) = (agent_id.clone(), chain.clone(), key.clone());
        move || {
            let identity = ClientIdentity::from_pem(&chain, &key).unwrap();
            let client = PlatformClient::new(&transport, Some(&identity)).unwrap();
            (
                client.heartbeat(&heartbeat(&agent_id)).err(),
                client.deliver(&[finding("f.9", 0)]).err(),
            )
        }
    })
    .await;
    assert_eq!(
        errors,
        (
            Some(TransportError::IdentityRevoked),
            Some(TransportError::IdentityRevoked)
        )
    );

    world.drop_database().await;
    let body = serde_json::to_vec(&heartbeat(&agent_id)).unwrap();
    for path in ["/v1/heartbeat", "/v1/findings", "/v1/renew"] {
        let status = world
            .raw(path, &body, Some((&pem_chain, &key)))
            .await
            .map(|r| r.0);
        assert_eq!(status, Some(503), "{path}");
    }
    let enroll = serde_json::json!({"schema_version": 1, "token": "A".repeat(43), "csr_pem": "x"});
    assert_eq!(
        world
            .raw("/v1/enroll", enroll.to_string().as_bytes(), None)
            .await
            .map(|r| r.0),
        Some(503)
    );
    assert_eq!(support::health_get(world.health, "/health").await, 200);
    world.stop().await;
}

/// Small responses must not wait for a delayed ACK (Nagle): without
/// TCP_NODELAY every request took about 40 ms on loopback. Only a release
/// build is fast enough to hit the stall; debug runs pass either way, and the
/// `accepted_sockets_disable_nagle` unit test covers them.
#[tokio::test]
async fn requests_are_not_delayed_by_nagle() {
    let world = World::start().await;
    let (agent_id, chain, key) = enrolled(&world).await;
    let transport = world.transport();
    let mut millis = blocking(move || {
        let identity = ClientIdentity::from_pem(&chain, &key).unwrap();
        (0..9)
            .map(|_| {
                // A fresh client per request, as the agent opens one per tick.
                let client = PlatformClient::new(&transport, Some(&identity)).unwrap();
                let started = std::time::Instant::now();
                client.heartbeat(&heartbeat(&agent_id)).unwrap();
                started.elapsed().as_millis()
            })
            .collect::<Vec<_>>()
    })
    .await;
    millis.sort_unstable();
    assert!(
        millis[4] < 20,
        "median heartbeat {} ms: {millis:?}",
        millis[4]
    );
    world.stop().await;
}
