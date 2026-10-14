//! P20: a heartbeat whose health reports an assignable set `not_assigned`
//! ends the host's open matches of that set; one without a state ends none.

mod support;

use chrono::{Duration, Utc};
use openvibes_core::{EnrollmentToken, Heartbeat, Identifier};
use openvibes_transport::{ClientIdentity, HostKey, PlatformClient};
use support::World;

async fn blocking<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(work).await.unwrap()
}

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

/// A valid heartbeat (the protocol fixture) whose health lists `rule_sets`.
fn beat(agent_id: &str, rule_sets: serde_json::Value) -> Heartbeat {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../protocol/fixtures/v1/heartbeat/valid-alarms-fallback.json");
    let mut beat: Heartbeat =
        serde_json::from_str(&std::fs::read_to_string(fixture).unwrap()).unwrap();
    beat.agent_id = Identifier::new(agent_id).unwrap();
    beat.observed_at_unix_ms = Utc::now().timestamp_millis();
    beat.match_sha256 = None;
    beat.health.as_mut().unwrap().rule_sets = serde_json::from_value(rule_sets).unwrap();
    beat
}

async fn send(world: &World, chain: &[String], key: &str, beat: Heartbeat) {
    let (transport, chain, key) = (world.transport(), chain.to_vec(), key.to_owned());
    blocking(move || {
        let identity = ClientIdentity::from_pem(&chain, &key).unwrap();
        PlatformClient::new(&transport, Some(&identity))
            .unwrap()
            .heartbeat(&beat)
            .unwrap();
    })
    .await;
}

async fn seed(world: &World, agent_id: &str) {
    world
        .db()
        .await
        .execute(
            "INSERT INTO current_findings (agent_id, rule_set_id, rule_id, last_finding_id,
                 rule_version, severity, first_observed_at, last_observed_at, last_observed_day,
                 scan_id, confidence, message, evidence, received_at, origin, authenticated, source)
             VALUES ($1, 'hardening-linux-l1', 'harden.ssh.x', 'finding.seed', 1, 'low', now(),
                 now(), current_date, 'scan.1', 100, 'm', '{}', now(), 'online', true, 'changes')",
            &[&agent_id],
        )
        .await
        .unwrap();
}

/// (match ended, history entries, triage rows).
async fn observed(world: &World) -> (bool, i64, i64) {
    let row = world
        .db()
        .await
        .query_one(
            "SELECT (SELECT ended_at IS NOT NULL FROM current_findings),
                    (SELECT count(*) FROM console_finding_triage_history),
                    (SELECT count(*) FROM console_finding_triage)",
            &[],
        )
        .await
        .unwrap();
    (row.get(0), row.get(1), row.get(2))
}

#[tokio::test]
async fn a_heartbeat_without_state_ends_nothing() {
    let world = World::start().await;
    let (agent_id, chain, key) = enrolled(&world).await;
    seed(&world, &agent_id).await;
    let sets = serde_json::json!([{"id": "hardening-linux-l1", "version": null}]);
    send(&world, &chain, &key, beat(&agent_id, sets)).await;
    assert_eq!(observed(&world).await, (false, 0, 0));
    world.stop().await;
}

#[tokio::test]
async fn a_not_assigned_report_ends_the_sets_matches() {
    let world = World::start().await;
    let (agent_id, chain, key) = enrolled(&world).await;
    seed(&world, &agent_id).await;
    let sets = serde_json::json!([{"id": "hardening-linux-l1", "state": "not_assigned"}]);
    send(&world, &chain, &key, beat(&agent_id, sets.clone())).await;
    assert_eq!(observed(&world).await, (true, 1, 0));
    send(&world, &chain, &key, beat(&agent_id, sets)).await;
    assert_eq!(
        observed(&world).await,
        (true, 1, 0),
        "the second report ends nothing more"
    );
    world.stop().await;
}

/// The lab's sequence (task 9): the agent ends the match itself through P13
/// in the scan that got the 410, then reports `not_assigned`: the match gets
/// the note once.
#[tokio::test]
async fn a_match_the_agent_ended_gets_the_note_once() {
    let world = World::start().await;
    let (agent_id, chain, key) = enrolled(&world).await;
    let before = serde_json::json!([{"id": "hardening-linux-l1", "version": 4}]);
    send(&world, &chain, &key, beat(&agent_id, before)).await;
    seed(&world, &agent_id).await;
    world
        .db()
        .await
        .execute("UPDATE current_findings SET ended_at = now()", &[])
        .await
        .unwrap();
    let sets = serde_json::json!([{"id": "hardening-linux-l1", "state": "not_assigned"}]);
    send(&world, &chain, &key, beat(&agent_id, sets.clone())).await;
    assert_eq!(observed(&world).await, (true, 1, 0));
    send(&world, &chain, &key, beat(&agent_id, sets)).await;
    assert_eq!(
        observed(&world).await,
        (true, 1, 0),
        "the second report notes nothing more"
    );
    world.stop().await;
}
