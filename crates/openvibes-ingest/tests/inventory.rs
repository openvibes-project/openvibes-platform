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
        source: None,
        source_version: None,
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
async fn more_than_fifty_thousand_packages_are_refused() {
    let world = World::start().await;
    let (agent, chain, key) = enrolled(&world).await;
    let packages: Vec<serde_json::Value> = (0..50_001)
        .map(|n| serde_json::json!({ "manager": "rpm", "name": format!("p{n}"), "version": "1" }))
        .collect();
    let body = serde_json::json!({
        "schema_version": 1, "agent_id": agent,
        "os": { "id": "fedora", "version_id": "44" },
        "collected_at_unix_ms": 1_790_000_000_000_i64, "packages": packages,
    });
    let bytes = serde_json::to_vec(&body).unwrap();
    assert!(
        bytes.len() < 8 * 1024 * 1024,
        "under the inventory body limit: refused for the count"
    );
    let status = world
        .raw("/v1/inventory", &bytes, Some((&chain.concat(), &key)))
        .await
        .map(|r| r.0);
    assert_eq!(status, Some(400));
    assert!(stored(&world, &agent).await.is_empty());
    world.stop().await;
}

fn long_package(i: usize) -> InstalledPackage {
    InstalledPackage {
        manager: PackageManager::Rpm,
        name: format!("texlive-collection-package-{i:06}"),
        version: "20250308".into(),
        release: Some("91.fc44".into()),
        epoch: Some(12),
        arch: Some("noarch".into()),
        vendor: Some("Fedora Project".into()),
        source: Some("texlive".into()),
        source_version: None,
    }
}

// M1 limits review: an inventory may be up to 8 MiB and 50,000 packages,
// on /v1/inventory only.
#[tokio::test]
async fn inventories_over_one_mib_are_stored() {
    let world = World::start().await;
    let (agent, chain, key) = enrolled(&world).await;
    let packages: Vec<InstalledPackage> = (0..40_000).map(long_package).collect();
    let body = serde_json::to_vec(&report(&agent, packages.clone())).unwrap();
    assert!(body.len() > 2 * 1024 * 1024, "{} bytes", body.len());
    send(&world, &chain, &key, report(&agent, packages))
        .await
        .unwrap();
    let count: i64 = world
        .db()
        .await
        .query_one(
            "SELECT count(*) FROM host_packages WHERE agent_id = $1",
            &[&agent],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 40_000);
    world.stop().await;
}

#[tokio::test]
async fn only_inventories_may_exceed_one_mib() {
    let world = World::start().await;
    let (_agent, chain, key) = enrolled(&world).await;
    let client = Some((chain.join("").leak() as &str, key.leak() as &str));
    let findings = vec![b' '; 1024 * 1024 + 1];
    let (status, _) = world.raw("/v1/findings", &findings, client).await.unwrap();
    assert_eq!(status, 400, "findings keep the 1 MiB limit");
    // Refused on the declared length, before the body is read: the client
    // may see a 400 or the connection closing while it still writes.
    let inventory = vec![b' '; 8 * 1024 * 1024 + 1];
    let answer = world.raw("/v1/inventory", &inventory, client).await;
    assert!(
        matches!(answer, None | Some((400, _))),
        "inventories stop at 8 MiB: {answer:?}"
    );
    world.stop().await;
}

// At most max_inventory_in_flight inventories are handled at once; the next
// one gets 503 (TransportError::Unavailable) and the agent retries.
#[tokio::test]
async fn a_busy_inventory_endpoint_answers_503() {
    let world = World::start_with(|config| config.max_inventory_in_flight = 1).await;
    let (agent, chain, key) = enrolled(&world).await;
    // Hold the host's row lock, so the first report waits inside the
    // handler while holding the only slot.
    let mut locker = world.db().await;
    let lock = locker.transaction().await.unwrap();
    lock.execute(
        "SELECT 1 FROM agents WHERE agent_id = $1 FOR UPDATE",
        &[&agent],
    )
    .await
    .unwrap();
    let first = {
        let (world_transport, chain, key, agent) =
            (world.transport(), chain.clone(), key.clone(), agent.clone());
        tokio::task::spawn_blocking(move || {
            let identity = ClientIdentity::from_pem(&chain, &key).unwrap();
            PlatformClient::new(&world_transport, Some(&identity))
                .unwrap()
                .report_inventory(&report(&agent, vec![package("bash", "5.2.37")]))
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let second = send(
        &world,
        &chain,
        &key,
        report(&agent, vec![package("bash", "5.2.38")]),
    )
    .await;
    assert_eq!(second, Err(TransportError::Unavailable));
    lock.rollback().await.unwrap();
    assert_eq!(first.await.unwrap(), Ok(()));
    world.stop().await;
}

// The inventory slot is taken before the body is read (review): a request
// that finds every slot busy is answered 503 at once, without the server
// buffering up to 8 MiB for it, so memory stays bounded by the slots.
#[tokio::test]
async fn a_busy_inventory_endpoint_answers_before_reading_the_body() {
    let world = World::start_with(|config| config.max_inventory_in_flight = 1).await;
    let (agent, chain, key) = enrolled(&world).await;
    let mut locker = world.db().await;
    let lock = locker.transaction().await.unwrap();
    lock.execute(
        "SELECT 1 FROM agents WHERE agent_id = $1 FOR UPDATE",
        &[&agent],
    )
    .await
    .unwrap();
    let first = {
        let (transport, chain, key, agent) =
            (world.transport(), chain.clone(), key.clone(), agent.clone());
        tokio::task::spawn_blocking(move || {
            let identity = ClientIdentity::from_pem(&chain, &key).unwrap();
            PlatformClient::new(&transport, Some(&identity))
                .unwrap()
                .report_inventory(&report(&agent, vec![package("bash", "5.2.37")]))
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let chain_pem = chain.concat();
    let status = world
        .raw_partial(
            "/v1/inventory",
            8 * 1024 * 1024,
            &[b' '; 100],
            (&chain_pem, &key),
            std::time::Duration::from_secs(3),
        )
        .await;
    assert_eq!(status, Some(503), "answered before the 8 MiB body arrived");
    lock.rollback().await.unwrap();
    assert_eq!(first.await.unwrap(), Ok(()));
    world.stop().await;
}
