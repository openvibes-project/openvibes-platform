//! TLS 1.3 only, client certificates optional at the handshake and checked
//! per request, loopback health, strict config.

mod support;

use support::{World, health_get, raw_tls};

const AGENT: &str = "agent.00000000-0000-4000-8000-000000000001";

#[tokio::test]
async fn only_tls13_and_only_our_client_certificates_complete() {
    let world = World::start().await;
    let tls12 = raw_tls(
        world.addr,
        &world.root.cert_pem,
        "/v1/heartbeat",
        b"{}",
        None,
        &rustls::version::TLS12,
    )
    .await;
    assert_eq!(tls12, None, "TLS 1.2 is refused");

    // No certificate: handshake completes; authenticated endpoints say 401.
    assert_eq!(
        world.raw("/v1/heartbeat", b"{}", None).await.map(|r| r.0),
        Some(401)
    );

    // Issued by our intermediate but never recorded: 401.
    let (chain, key) = world.unrecorded_client(AGENT);
    assert_eq!(
        world
            .raw("/v1/heartbeat", b"{}", Some((&chain, &key)))
            .await
            .map(|r| r.0),
        Some(401)
    );

    // From another CA: no HTTP response at all.
    let other = World::start().await;
    let (foreign_chain, foreign_key) = other.unrecorded_client(AGENT);
    assert_eq!(
        world
            .raw("/v1/heartbeat", b"{}", Some((&foreign_chain, &foreign_key)))
            .await,
        None
    );
    other.stop().await;
    world.stop().await;
}

#[tokio::test]
async fn health_is_local_and_readiness_follows_the_database() {
    let world = World::start().await;
    assert_eq!(health_get(world.health, "/health").await, 200);
    assert_eq!(health_get(world.health, "/ready").await, 200);
    world.drop_database().await;
    assert_eq!(health_get(world.health, "/ready").await, 503);
    assert_eq!(health_get(world.health, "/health").await, 200);
    world.stop().await;
}

#[test]
fn configuration_is_strict() {
    let dir = std::env::temp_dir().join(format!("ov-ingest-config-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let good = r#"
listen = "0.0.0.0:18423"
health_listen = "127.0.0.1:18480"
server_certificate_file = "/etc/openvibes/tls/ingest.crt"
server_key_file = "/etc/openvibes/tls/ingest.key"
client_ca_file = "/etc/openvibes/pki/intermediate.crt"
issuing_certificate_file = "/etc/openvibes/pki/intermediate.crt"
issuing_key_file = "/var/lib/openvibes-ingest/intermediate.key"
database_url = "postgresql:///openvibes?host=/run/postgresql&user=openvibes_ingest"
"#;
    let write = |name: &str, text: &str| {
        let path = dir.join(name);
        std::fs::write(&path, text).unwrap();
        path
    };
    let config = openvibes_ingest::load_config(&write("good.toml", good)).unwrap();
    assert_eq!(
        (
            config.client_certificate_days,
            config.max_in_flight,
            config.finding_retention_days
        ),
        (30, 4096, 90)
    );
    for (name, text) in [
        ("zero-days", format!("{good}client_certificate_days = 0\n")),
        (
            "long-days",
            format!("{good}client_certificate_days = 366\n"),
        ),
        ("no-flight", format!("{good}max_in_flight = 0\n")),
        (
            "relative",
            good.replace("/etc/openvibes/tls/ingest.crt", "ingest.crt"),
        ),
        ("unknown", format!("{good}listn = \"x\"\n")),
        (
            "public-health",
            good.replace("127.0.0.1:18480", "0.0.0.0:18480"),
        ),
        (
            "lan-health",
            good.replace("127.0.0.1:18480", "10.0.0.5:18480"),
        ),
    ] {
        assert!(
            openvibes_ingest::load_config(&write(&format!("{name}.toml"), &text)).is_err(),
            "{name}"
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn expired_certificates_get_an_http_answer() {
    use chrono::{Duration, Utc};
    let world = World::start().await;
    let expired = |agent: &str| {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.distinguished_name = rcgen::DistinguishedName::new();
        let csr = params.serialize_request(&key).unwrap().pem().unwrap();
        let checked = platform_pki::check_csr(&csr).unwrap();
        let issued = world
            .issuer
            .issue_client(&checked, agent, Utc::now() - Duration::days(3), 1)
            .unwrap();
        (issued, key.serialize_pem())
    };
    // Unrecorded and expired: 401, not a failed handshake.
    let (issued, key) = expired(AGENT);
    let chain = issued.chain_pem.concat();
    assert_eq!(
        world
            .raw("/v1/heartbeat", b"{}", Some((&chain, &key)))
            .await
            .map(|r| r.0),
        Some(401)
    );

    // Recorded, expired, and revoked: the agent still learns it is revoked.
    let revoked = "agent.00000000-0000-4000-8000-000000000002";
    let (issued, key) = expired(revoked);
    let db = world.db().await;
    db.execute(
        "INSERT INTO agents (agent_id, status, enrolled_at, revoked_at) VALUES ($1, 'revoked', now(), now())",
        &[&revoked],
    )
    .await
    .unwrap();
    platform_store::ingest::add_certificate(
        &db,
        revoked,
        &platform_store::ingest::IssuedCert {
            serial: issued.serial,
            spki_sha256: issued.spki_sha256,
            not_before: issued.not_before,
            not_after: issued.not_after,
            chain_pem: issued.chain_pem.clone(),
        },
        Utc::now(),
    )
    .await
    .unwrap();
    let response = world
        .raw(
            "/v1/heartbeat",
            b"{}",
            Some((&issued.chain_pem.concat(), &key)),
        )
        .await;
    assert_eq!(response.as_ref().map(|r| r.0), Some(403));
    assert!(response.unwrap().1.contains("identity_revoked"));
    world.stop().await;
}
