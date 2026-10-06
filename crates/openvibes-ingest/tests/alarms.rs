//! `POST /v1/alarms` (protocol P14) through the agent's real client.

mod support;

use chrono::{Duration, Utc};
use openvibes_core::{
    Alarm, AlarmBatch, AlarmProcess, Confidence, EnrollmentToken, Identifier, SchemaVersion,
    Severity,
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

fn alarm(n: u32, first_seen_unix_ms: i64) -> Alarm {
    let process = |exe: &str| AlarmProcess {
        pid: 4242,
        exe: exe.into(),
        args: vec!["sh".into(), "-c".into(), "id".into()],
        cwd: None,
        uid: 48,
        euid: 0,
        truncated: false,
        seeded: false,
    };
    Alarm {
        detection: None,
        alarm_id: id(&format!("alarm.{n:032x}")),
        rule_set_id: id("baseline"),
        rule_set_version: 4,
        rule_id: id("web-server-spawns-shell"),
        rule_version: 1,
        severity: Severity::High,
        confidence: Confidence::new(80).unwrap(),
        message: "A web server started a shell".into(),
        first_seen_unix_ms,
        last_seen_unix_ms: first_seen_unix_ms,
        count: 1,
        process: process("/usr/bin/sh"),
        ancestors: vec![process("/usr/sbin/nginx")],
    }
}

fn batch(agent: &str, alarms: Vec<Alarm>) -> AlarmBatch {
    AlarmBatch {
        schema_version: SchemaVersion::V1,
        agent_id: id(agent),
        dropped_total: 2,
        alarms,
    }
}

async fn stored(world: &World, agent: &str) -> Vec<(String, i64, i64)> {
    world
        .db()
        .await
        .query(
            "SELECT alarm_id, count, (process->>'euid')::bigint FROM alarms
             WHERE agent_id = $1 ORDER BY alarm_id",
            &[&agent],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .collect()
}

#[tokio::test]
async fn alarms_are_stored_once_and_skipped_ones_do_not_block_the_batch() {
    let world = World::start().await;
    let agent = enrolled(&world).await;
    let now = Utc::now().timestamp_millis();
    let expired = (Utc::now() - Duration::days(400)).timestamp_millis();
    let sent = batch(&agent.id, vec![alarm(1, now), alarm(2, expired)]);
    let platform = client(&world, &agent);
    let again = sent.clone();
    blocking(move || {
        platform.send_alarms(&sent).unwrap();
        // A retried batch stores nothing twice.
        platform.send_alarms(&again).unwrap();
    })
    .await;
    assert_eq!(
        stored(&world, &agent.id).await,
        [(format!("alarm.{:032x}", 1), 1, 0)],
        "the good alarm once, euid kept; the expired one skipped"
    );
    let dropped: Option<i64> = world
        .db()
        .await
        .query_one(
            "SELECT alarms_dropped_total FROM agents WHERE agent_id = $1",
            &[&agent.id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(dropped, Some(2));
    world.stop().await;
}

#[tokio::test]
async fn another_agents_batch_is_refused() {
    let world = World::start().await;
    let agent = enrolled(&world).await;
    let other = enrolled(&world).await;
    let sent = batch(&other.id, vec![alarm(3, Utc::now().timestamp_millis())]);
    let platform = client(&world, &agent);
    let result = blocking(move || platform.send_alarms(&sent)).await;
    assert!(
        matches!(result, Err(TransportError::Rejected)),
        "{result:?}"
    );
    assert!(stored(&world, &other.id).await.is_empty());
    world.stop().await;
}

#[tokio::test]
async fn a_batch_over_256_kib_is_413_and_gzip_is_accepted() {
    let world = World::start().await;
    let agent = enrolled(&world).await;
    let pem = (agent.chain.concat(), agent.key.clone());
    let client = Some((pem.0.as_str(), pem.1.as_str()));
    let mut big = serde_json::to_vec(&batch(
        &agent.id,
        vec![alarm(4, Utc::now().timestamp_millis())],
    ))
    .unwrap();
    big.extend(std::iter::repeat_n(b' ', 262_144));
    let (status, _) = world.raw("/v1/alarms", &big, client).await.unwrap();
    assert_eq!(status, 413);

    let body = serde_json::to_vec(&batch(
        &agent.id,
        vec![alarm(5, Utc::now().timestamp_millis())],
    ))
    .unwrap();
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut gzip, &body).unwrap();
    let (status, _) = world
        .raw_encoded("/v1/alarms", &gzip.finish().unwrap(), "gzip", client)
        .await
        .unwrap();
    assert_eq!(status, 204);
    assert_eq!(stored(&world, &agent.id).await.len(), 1);
    world.stop().await;
}
