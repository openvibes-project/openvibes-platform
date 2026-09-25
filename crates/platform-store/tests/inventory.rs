//! Inventory storage (VM1), run as the least-privilege `openvibes_ingest`.

mod common;

use chrono::{Duration, Utc};
use common::TestDb;
use platform_store::{
    Client,
    ingest::{self, Enrolled, IssuedCert},
    inventory::{self, InventoryOutcome, PackageRow},
    tokens::{self, NewToken},
};
use tokio_postgres::error::SqlState;

async fn setup() -> (TestDb, Client, String) {
    let db = TestDb::create().await;
    let mut admin = db.pool.get().await.unwrap();
    platform_store::migrate(&mut admin).await.unwrap();
    let token = tokens::create(
        &admin,
        &NewToken {
            token_sha256: [9; 32],
            label: None,
            created_by: "test".into(),
            expires_at: Utc::now() + Duration::days(1),
            max_uses: 5,
        },
    )
    .await
    .unwrap();
    let mut client = db.pool.get().await.unwrap();
    client
        .batch_execute("SET ROLE openvibes_ingest")
        .await
        .unwrap();
    let now = Utc::now();
    let issued = move |_: &str| {
        Ok(IssuedCert {
            serial: [0x41; 16],
            spki_sha256: [7; 32],
            not_before: now,
            not_after: now + Duration::days(30),
            chain_pem: vec!["pem".into()],
        })
    };
    let Enrolled::New(identity) = ingest::enroll(&mut client, &token, [7; 32], now, issued)
        .await
        .unwrap()
    else {
        panic!("enrolled");
    };
    (db, client, identity.agent_id)
}

fn package(name: &str, version: &str, release: &str) -> PackageRow {
    PackageRow {
        manager: "rpm".into(),
        name: name.into(),
        epoch: 0,
        version: version.into(),
        release: release.into(),
        arch: "x86_64".into(),
    }
}

async fn stored(client: &Client, agent_id: &str) -> Vec<(String, String)> {
    client
        .query(
            "SELECT p.name, p.version FROM host_packages h JOIN package_versions p
             ON p.id = h.package_version_id WHERE h.agent_id = $1 ORDER BY 1, 2",
            &[&agent_id],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect()
}

#[tokio::test]
async fn an_inventory_replaces_the_previous_one() {
    let (db, mut client, agent) = setup().await;
    let first = [
        package("bash", "5.2.37", "1.fc44"),
        package("kernel-core", "6.17.4", "300.fc44"),
        package("kernel-core", "6.17.7", "300.fc44"),
    ];
    let outcome = inventory::replace(
        &mut client,
        &agent,
        "fedora",
        "44",
        &first,
        [1; 32],
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(outcome, InventoryOutcome::Stored);
    assert_eq!(
        stored(&client, &agent).await,
        [
            ("bash".into(), "5.2.37".into()),
            ("kernel-core".into(), "6.17.4".into()),
            ("kernel-core".into(), "6.17.7".into()),
        ],
        "several installed versions of one package (kernels) are all kept"
    );
    let second = [package("bash", "5.2.38", "1.fc44")];
    inventory::replace(
        &mut client,
        &agent,
        "fedora",
        "44",
        &second,
        [2; 32],
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(
        stored(&client, &agent).await,
        [("bash".into(), "5.2.38".into())]
    );
    let row = client
        .query_one(
            "SELECT os_id, os_version FROM agents WHERE agent_id = $1",
            &[&agent],
        )
        .await
        .unwrap();
    assert_eq!(
        (row.get::<_, String>(0), row.get::<_, String>(1)),
        ("fedora".into(), "44".into())
    );
    db.drop().await;
}

#[tokio::test]
async fn an_identical_inventory_is_not_stored_again() {
    let (db, mut client, agent) = setup().await;
    let packages = [package("bash", "5.2.37", "1.fc44")];
    inventory::replace(
        &mut client,
        &agent,
        "fedora",
        "44",
        &packages,
        [1; 32],
        Utc::now(),
    )
    .await
    .unwrap();
    let outcome = inventory::replace(
        &mut client,
        &agent,
        "fedora",
        "44",
        &packages,
        [1; 32],
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(outcome, InventoryOutcome::Unchanged);
    db.drop().await;
}

#[tokio::test]
async fn hosts_share_package_versions() {
    let (db, mut client, agent) = setup().await;
    let packages = [package("bash", "5.2.37", "1.fc44")];
    inventory::replace(
        &mut client,
        &agent,
        "fedora",
        "44",
        &packages,
        [1; 32],
        Utc::now(),
    )
    .await
    .unwrap();
    inventory::replace(
        &mut client,
        &agent,
        "fedora",
        "44",
        &packages,
        [3; 32],
        Utc::now(),
    )
    .await
    .unwrap();
    let distinct: i64 = client
        .query_one("SELECT count(*) FROM package_versions", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(distinct, 1);
    db.drop().await;
}

#[tokio::test]
async fn a_stored_inventory_notifies_the_vulnerability_service() {
    let (db, mut client, agent) = setup().await;
    let (listener, mut connection) = tokio_postgres::connect(&db.url(), tokio_postgres::NoTls)
        .await
        .unwrap();
    let (sender, mut received) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(message) = std::future::poll_fn(|cx| connection.poll_message(cx)).await {
            if let Ok(tokio_postgres::AsyncMessage::Notification(note)) = message {
                let _ = sender.send((note.channel().to_owned(), note.payload().to_owned()));
            }
        }
    });
    listener
        .batch_execute("LISTEN inventory_changed")
        .await
        .unwrap();
    let packages = [package("bash", "5.2.37", "1.fc44")];
    inventory::replace(
        &mut client,
        &agent,
        "fedora",
        "44",
        &packages,
        [1; 32],
        Utc::now(),
    )
    .await
    .unwrap();
    let note = tokio::time::timeout(std::time::Duration::from_secs(5), received.recv())
        .await
        .expect("a notification")
        .unwrap();
    assert_eq!(note, ("inventory_changed".to_owned(), agent.clone()));
    // Unchanged: no second notification.
    inventory::replace(
        &mut client,
        &agent,
        "fedora",
        "44",
        &packages,
        [1; 32],
        Utc::now(),
    )
    .await
    .unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(500), received.recv())
            .await
            .is_err()
    );
    drop(listener);
    db.drop().await;
}

#[tokio::test]
async fn the_ingest_role_cannot_touch_other_tables() {
    let (db, client, _) = setup().await;
    for denied in [
        "DELETE FROM package_versions",
        "UPDATE package_versions SET name = 'x'",
        "UPDATE host_packages SET package_version_id = 1",
    ] {
        let error = client.batch_execute(denied).await.expect_err(denied);
        assert_eq!(
            error.code(),
            Some(&SqlState::INSUFFICIENT_PRIVILEGE),
            "{denied}"
        );
    }
    db.drop().await;
}
