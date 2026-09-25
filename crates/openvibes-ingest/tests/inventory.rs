//! `POST /v1/inventory` (protocol P8) through the agent's real client.

mod support;

use chrono::Duration;
use openvibes_core::{
    EnrollmentToken, Identifier, InstalledPackage, InventoryReport, OsRelease, PackageManager,
    SchemaVersion,
};
use openvibes_transport::{ClientIdentity, HostKey, PlatformClient, TransportError};
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

fn package(name: &str, version: &str) -> InstalledPackage {
    InstalledPackage {
        manager: PackageManager::Rpm,
        name: name.into(),
        version: version.into(),
        release: Some("1.fc44".into()),
        epoch: None,
        arch: Some("x86_64".into()),
        vendor: None,
    }
}

fn report(agent_id: &str, packages: Vec<InstalledPackage>) -> InventoryReport {
    InventoryReport {
        schema_version: SchemaVersion::V1,
        agent_id: Identifier::new(agent_id).unwrap(),
        os: OsRelease {
            id: Identifier::new("fedora").unwrap(),
            version_id: Identifier::new("44").unwrap(),
        },
        running_kernel: None,
        collected_at_unix_ms: 1_790_000_000_000,
        packages,
    }
}

async fn send(
    world: &World,
    chain: &[String],
    key: &str,
    report: InventoryReport,
) -> Result<(), TransportError> {
    let transport = world.transport();
    let (chain, key) = (chain.to_vec(), key.to_owned());
    blocking(move || {
        let identity = ClientIdentity::from_pem(&chain, &key).unwrap();
        PlatformClient::new(&transport, Some(&identity))
            .unwrap()
            .report_inventory(&report)
    })
    .await
}

async fn stored(world: &World, agent_id: &str) -> Vec<String> {
    world
        .db()
        .await
        .query(
            "SELECT p.name || '-' || p.version FROM host_packages h
             JOIN package_versions p ON p.id = h.package_version_id
             WHERE h.agent_id = $1 ORDER BY 1",
            &[&agent_id],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect()
}

#[tokio::test]
async fn an_inventory_report_is_stored_and_replaced() {
    let world = World::start().await;
    let (agent, chain, key) = enrolled(&world).await;
    send(
        &world,
        &chain,
        &key,
        report(
            &agent,
            vec![package("bash", "5.2.37"), package("openssl", "3.5.1")],
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        stored(&world, &agent).await,
        ["bash-5.2.37", "openssl-3.5.1"]
    );
    // The same report again is accepted and changes nothing.
    send(
        &world,
        &chain,
        &key,
        report(
            &agent,
            vec![package("openssl", "3.5.1"), package("bash", "5.2.37")],
        ),
    )
    .await
    .unwrap();
    send(
        &world,
        &chain,
        &key,
        report(&agent, vec![package("bash", "5.2.38")]),
    )
    .await
    .unwrap();
    assert_eq!(stored(&world, &agent).await, ["bash-5.2.38"]);
    let os: (String, String) = {
        let row = world
            .db()
            .await
            .query_one(
                "SELECT os_id, os_version FROM agents WHERE agent_id = $1",
                &[&agent],
            )
            .await
            .unwrap();
        (row.get(0), row.get(1))
    };
    assert_eq!(os, ("fedora".into(), "44".into()));
    world.stop().await;
}

#[tokio::test]
async fn a_reboot_alone_updates_the_running_kernel() {
    let world = World::start().await;
    let (agent, chain, key) = enrolled(&world).await;
    let kernel = |release: &str| {
        let mut report = report(&agent, vec![package("kernel-core", "6.17.7")]);
        report.running_kernel = Some(release.into());
        report
    };
    let running = || async {
        world
            .db()
            .await
            .query_one(
                "SELECT running_kernel FROM agents WHERE agent_id = $1",
                &[&agent],
            )
            .await
            .unwrap()
            .get::<_, Option<String>>(0)
    };
    send(&world, &chain, &key, kernel("6.17.4-1.fc44.x86_64"))
        .await
        .unwrap();
    assert_eq!(running().await.as_deref(), Some("6.17.4-1.fc44.x86_64"));
    // Same packages, new kernel: stored, not skipped as unchanged (P9).
    send(&world, &chain, &key, kernel("6.17.7-1.fc44.x86_64"))
        .await
        .unwrap();
    assert_eq!(running().await.as_deref(), Some("6.17.7-1.fc44.x86_64"));
    world.stop().await;
}

#[tokio::test]
async fn a_report_for_another_agent_is_refused() {
    let world = World::start().await;
    let (agent, chain, key) = enrolled(&world).await;
    let (other, _, _) = enrolled(&world).await;
    let result = send(
        &world,
        &chain,
        &key,
        report(&other, vec![package("bash", "5.2.37")]),
    )
    .await;
    assert!(result.is_err(), "400 for another agent's id");
    assert!(stored(&world, &agent).await.is_empty());
    assert!(stored(&world, &other).await.is_empty());
    world.stop().await;
}

#[tokio::test]
async fn an_unauthenticated_report_is_refused() {
    let world = World::start().await;
    let body = serde_json::to_vec(&report("agent.x", vec![])).unwrap();
    assert_eq!(
        world.raw("/v1/inventory", &body, None).await.map(|r| r.0),
        Some(401)
    );
    world.stop().await;
}

#[tokio::test]
async fn more_than_ten_thousand_packages_are_refused() {
    let world = World::start().await;
    let (agent, chain, key) = enrolled(&world).await;
    let packages: Vec<serde_json::Value> = (0..10_001)
        .map(|n| serde_json::json!({ "manager": "rpm", "name": format!("p{n}"), "version": "1" }))
        .collect();
    let body = serde_json::json!({
        "schema_version": 1, "agent_id": agent,
        "os": { "id": "fedora", "version_id": "44" },
        "collected_at_unix_ms": 1_790_000_000_000_i64, "packages": packages,
    });
    let bytes = serde_json::to_vec(&body).unwrap();
    assert!(
        bytes.len() < 1024 * 1024,
        "under the body limit: refused for the count"
    );
    let status = world
        .raw("/v1/inventory", &bytes, Some((&chain.concat(), &key)))
        .await
        .map(|r| r.0);
    assert_eq!(status, Some(400));
    assert!(stored(&world, &agent).await.is_empty());
    world.stop().await;
}
