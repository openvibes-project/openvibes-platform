//! `POST /v1/services` (protocol P15) through the agent's real client.

mod support;

use chrono::Duration;
use openvibes_core::{
    EnrollmentToken, HostService, HostServices, Identifier, ListenerProtocol, Owners,
    SchemaVersion, ServiceListener, hex, services_digest,
};
use openvibes_transport::{ClientIdentity, HostKey, PlatformClient, TransportError};
use support::World;

async fn blocking<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(work).await.unwrap()
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

fn report(agent: &str, ports: &[u16]) -> HostServices {
    let listeners: Vec<ServiceListener> = ports
        .iter()
        .map(|&port| ServiceListener {
            protocol: ListenerProtocol::Tcp,
            address: "0.0.0.0".parse().unwrap(),
            port,
            exposed: true,
            service: Some("nginx.service".into()),
            program: Some("nginx".into()),
        })
        .collect();
    let services = vec![HostService {
        unit: "nginx.service".into(),
        programs: vec!["nginx".into()],
        processes: 3,
        user: Some("root".into()),
    }];
    HostServices {
        schema_version: SchemaVersion::V1,
        agent_id: Identifier::new(agent).unwrap(),
        collected_at_unix_ms: 1_790_604_131_000,
        sha256: hex(&services_digest(&listeners, &services)),
        owners: Owners::Partial,
        truncated: false,
        listeners,
        services,
    }
}

/// (ports, sha256, refusal code) as stored.
async fn stored(world: &World, agent: &str) -> (Vec<i32>, Option<String>, Option<String>) {
    let db = world.db().await;
    let ports = db
        .query(
            "SELECT port FROM host_listeners WHERE agent_id = $1 ORDER BY port",
            &[&agent],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    let row = db
        .query_one(
            "SELECT services_sha256, services_refused FROM agents WHERE agent_id = $1",
            &[&agent],
        )
        .await
        .unwrap();
    (ports, row.get(0), row.get(1))
}

#[tokio::test]
async fn a_report_is_stored_and_an_unchanged_one_keeps_it() {
    let world = World::start().await;
    let agent = enrolled(&world).await;
    let first = report(&agent.id, &[443, 80]);
    let digest = first.sha256.clone();
    let platform = client(&world, &agent);
    blocking(move || {
        platform.report_services(&first).unwrap();
        // The same lists again (the daily resend): accepted, nothing changes.
        platform.report_services(&first).unwrap();
    })
    .await;
    assert_eq!(
        stored(&world, &agent.id).await,
        (vec![80, 443], Some(digest), None)
    );
    world.stop().await;
}

#[tokio::test]
async fn another_agents_report_is_refused_and_recorded() {
    let world = World::start().await;
    let agent = enrolled(&world).await;
    let other = enrolled(&world).await;
    let sent = report(&other.id, &[22]);
    let platform = client(&world, &agent);
    let result = blocking(move || platform.report_services(&sent)).await;
    assert!(
        matches!(result, Err(TransportError::Rejected)),
        "{result:?}"
    );
    assert_eq!(
        stored(&world, &agent.id).await,
        (vec![], None, Some("wrong_agent".into())),
        "nothing stored; the refusal recorded on the sender"
    );
    assert_eq!(stored(&world, &other.id).await, (vec![], None, None));
    world.stop().await;
}

#[tokio::test]
async fn over_512_kib_is_413_then_a_good_gzip_report_clears_the_refusal() {
    let world = World::start().await;
    let agent = enrolled(&world).await;
    let pem = (agent.chain.concat(), agent.key.clone());
    let raw = Some((pem.0.as_str(), pem.1.as_str()));
    let mut big = serde_json::to_vec(&report(&agent.id, &[443])).unwrap();
    big.extend(std::iter::repeat_n(b' ', 524_288));
    let (status, _) = world.raw("/v1/services", &big, raw).await.unwrap();
    assert_eq!(status, 413);
    assert_eq!(
        stored(&world, &agent.id).await,
        (vec![], None, Some("too_large".into()))
    );
    // Not JSON: 400, recorded as invalid.
    let (status, _) = world.raw("/v1/services", b"{", raw).await.unwrap();
    assert_eq!(status, 400);
    assert_eq!(
        stored(&world, &agent.id).await.2.as_deref(),
        Some("invalid")
    );

    // The agent's real client sends gzip; a good report clears it.
    let good = report(&agent.id, &[443]);
    let platform = client(&world, &agent);
    blocking(move || platform.report_services(&good).unwrap()).await;
    let (ports, digest, refused) = stored(&world, &agent.id).await;
    assert_eq!((ports, refused), (vec![443], None));
    assert!(digest.is_some());
    world.stop().await;
}
