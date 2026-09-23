//! Enrollment and renewal through the agent's real client.

mod support;

use chrono::{Duration, Utc};
use openvibes_core::EnrollmentToken;
use openvibes_transport::{ClientIdentity, HostKey, PlatformClient, TransportError};
use support::World;

async fn blocking<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(work).await.unwrap()
}

#[tokio::test]
async fn enrollment_is_idempotent_per_key_and_renewal_keeps_the_identity() {
    let world = World::start().await;
    let transport = world.transport();
    let token = EnrollmentToken::new(world.token(1, Duration::days(1)).await).unwrap();
    let key = HostKey::generate().unwrap();

    let (first, again, other) = blocking({
        let transport = transport.clone();
        move || {
            let client = PlatformClient::new(&transport, None).unwrap();
            let first = client.enroll(&token, &key).unwrap();
            let again = client.enroll(&token, &key).unwrap();
            let other = client.enroll(&token, &HostKey::generate().unwrap());
            (first, again, (other.err(), key))
        }
    })
    .await;
    let (other_error, key) = other;
    assert!(platform_pki::is_agent_id(first.agent_id.as_str()));
    assert_eq!(first.certificate_chain_pem.len(), 2);
    platform_pki::verify_signed_by(&first.certificate_chain_pem[0], world.issuer.cert_pem())
        .unwrap();
    let thirty_days = (Utc::now() + Duration::days(30)).timestamp_millis();
    assert!((first.expires_at_unix_ms - thirty_days).abs() < 120_000);
    assert_eq!(
        (again.agent_id.clone(), again.certificate_chain_pem.clone()),
        (first.agent_id.clone(), first.certificate_chain_pem.clone())
    );
    assert_eq!(other_error, Some(TransportError::Unauthorized));

    let renewed = blocking({
        let transport = transport.clone();
        let chain = first.certificate_chain_pem.clone();
        move || {
            let identity = ClientIdentity::from_pem(&chain, key.expose_key_pem()).unwrap();
            let client = PlatformClient::new(&transport, Some(&identity)).unwrap();
            let renewed = client.renew(&HostKey::generate().unwrap()).unwrap();
            // The old certificate still authenticates until it expires.
            let again = client.renew(&HostKey::generate().unwrap()).unwrap();
            (renewed, again)
        }
    })
    .await;
    assert_eq!(renewed.0.agent_id, first.agent_id);
    assert_eq!(renewed.1.agent_id, first.agent_id);
    let certificates: i64 = world
        .db()
        .await
        .query_one(
            "SELECT count(*) FROM certificates WHERE agent_id = $1",
            &[&first.agent_id.as_str()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(certificates, 3);
    world.stop().await;
}

#[tokio::test]
async fn bad_tokens_are_401_and_bad_csrs_400() {
    let world = World::start().await;
    let transport = world.transport();
    let expired = world.token(5, Duration::hours(-1)).await;
    let revoked = world.token(5, Duration::days(1)).await;
    let db = world.db().await;
    db.execute(
        "UPDATE enrollment_tokens SET revoked_at = now() WHERE expires_at > now()",
        &[],
    )
    .await
    .unwrap();
    let unknown = "A".repeat(43);
    let results = blocking(move || {
        let client = PlatformClient::new(&transport, None).unwrap();
        [
            unknown.as_str(),
            expired.as_str(),
            revoked.as_str(),
            "not-a-token",
        ]
        .map(|token| {
            client
                .enroll(
                    &EnrollmentToken::new(token).unwrap(),
                    &HostKey::generate().unwrap(),
                )
                .err()
        })
    })
    .await;
    assert_eq!(results, [Some(TransportError::Unauthorized); 4]);

    let good = world.token(5, Duration::days(1)).await;
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "evil");
    let csr = params.serialize_request(&key).unwrap().pem().unwrap();
    let body = serde_json::json!({ "schema_version": 1, "token": good, "csr_pem": csr });
    let response = world
        .raw("/v1/enroll", body.to_string().as_bytes(), None)
        .await;
    assert_eq!(response.map(|r| r.0), Some(400));
    world.stop().await;
}

#[tokio::test]
async fn a_revoked_agent_cannot_renew() {
    let world = World::start().await;
    let transport = world.transport();
    let token = EnrollmentToken::new(world.token(1, Duration::days(1)).await).unwrap();
    let (enrolled, key) = blocking({
        let transport = transport.clone();
        move || {
            let key = HostKey::generate().unwrap();
            (
                PlatformClient::new(&transport, None)
                    .unwrap()
                    .enroll(&token, &key)
                    .unwrap(),
                key,
            )
        }
    })
    .await;
    platform_store::agents::revoke(&world.db().await, enrolled.agent_id.as_str(), Utc::now())
        .await
        .unwrap();
    let error = blocking(move || {
        let identity =
            ClientIdentity::from_pem(&enrolled.certificate_chain_pem, key.expose_key_pem())
                .unwrap();
        PlatformClient::new(&transport, Some(&identity))
            .unwrap()
            .renew(&HostKey::generate().unwrap())
            .err()
    })
    .await;
    assert_eq!(error, Some(TransportError::IdentityRevoked));
    world.stop().await;
}
