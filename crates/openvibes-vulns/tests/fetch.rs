//! Fetching a Fedora feed through a local mirror: metalink → repomd.xml →
//! updateinfo, verified by digest at each step.

mod common;

use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    routing::get,
};
use chrono::Utc;
use common::TestDb;
use openvibes_vulns::{
    feed::SourceId,
    fetch::{self, Checked, Fetcher},
    repodata::hex,
};
use platform_store::inventory::{self, PackageRow};
use sha2::{Digest, Sha256};

#[derive(Clone, Default)]
struct Mirror {
    files: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    downloads: Arc<AtomicUsize>,
}

async fn serve(
    State(mirror): State<Mirror>,
    Path(path): Path<String>,
) -> Result<Vec<u8>, StatusCode> {
    if path.ends_with("updateinfo.xml.zst") {
        mirror.downloads.fetch_add(1, Ordering::SeqCst);
    }
    mirror
        .files
        .lock()
        .unwrap()
        .get(&path)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)
}

async fn start() -> (Mirror, SocketAddr) {
    let mirror = Mirror::default();
    let app = Router::new()
        .route("/{*path}", get(serve))
        .with_state(mirror.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (mirror, addr)
}

fn sha(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// Publishes `updateinfo` on both mirrors, with a matching repomd.xml and
/// a metalink naming that repomd's digest. Returns the metalink template.
fn publish(mirror: &Mirror, addr: SocketAddr, updateinfo: &[u8], served: &[u8]) -> String {
    let href = format!("repodata/{}-updateinfo.xml.zst", sha(updateinfo));
    let repomd = format!(
        "<?xml version=\"1.0\"?><repomd xmlns=\"http://linux.duke.edu/metadata/repo\">\
         <data type=\"updateinfo\"><checksum type=\"sha256\">{}</checksum>\
         <location href=\"{href}\"/><size>{}</size></data></repomd>",
        sha(updateinfo),
        updateinfo.len()
    );
    let metalink = format!(
        "<?xml version=\"1.0\"?><metalink><files><file name=\"repomd.xml\"><verification>\
         <hash type=\"sha256\">{}</hash></verification><resources>\
         <url protocol=\"http\">http://{addr}/m1/repodata/repomd.xml</url>\
         <url protocol=\"http\">http://{addr}/m2/repodata/repomd.xml</url>\
         </resources></file></files></metalink>",
        sha(repomd.as_bytes())
    );
    let mut files = mirror.files.lock().unwrap();
    files.insert("metalink".into(), metalink.into_bytes());
    for m in ["m1", "m2"] {
        files.insert(
            format!("{m}/repodata/repomd.xml"),
            repomd.clone().into_bytes(),
        );
        files.insert(format!("{m}/{href}"), served.to_vec());
    }
    format!("http://{addr}/metalink?release={{release}}&arch={{arch}}")
}

fn feed() -> Vec<u8> {
    std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/updateinfo-f44.xml.zst"),
    )
    .unwrap()
}

async fn setup() -> (TestDb, platform_store::Client) {
    let db = TestDb::create().await;
    let mut admin = db.pool.get().await.unwrap();
    platform_store::migrate(&mut admin).await.unwrap();
    let agent = "agent.00000000-0000-4000-8000-0000000000f1";
    admin
        .execute(
            "INSERT INTO agents (agent_id, status, enrolled_at) VALUES ($1, 'active', now())",
            &[&agent],
        )
        .await
        .unwrap();
    let wordpress = PackageRow {
        manager: "rpm".into(),
        name: "wordpress".into(),
        epoch: 0,
        version: "6.9.6".into(),
        release: "1.fc44".into(),
        arch: "noarch".into(),
    };
    inventory::replace(
        &mut admin,
        agent,
        "fedora",
        "44",
        &[wordpress],
        [1; 32],
        Utc::now(),
    )
    .await
    .unwrap();
    let client = db.pool.get().await.unwrap();
    client
        .batch_execute("SET ROLE openvibes_vulns")
        .await
        .unwrap();
    (db, client)
}

fn source() -> SourceId {
    "fedora-44-x86_64".parse().unwrap()
}

#[tokio::test]
async fn a_feed_is_imported_once_then_found_unchanged() {
    let (db, mut client) = setup().await;
    let (mirror, addr) = start().await;
    let content = feed();
    let template = publish(&mirror, addr, &content, &content);
    let fetcher = Fetcher::new(&template, None, 64 << 20).unwrap();
    let first = fetch::check(&mut client, &fetcher, &source(), Utc::now())
        .await
        .unwrap();
    assert!(
        matches!(first, Checked::Imported(report) if report.advisories == 3 && report.open == 1)
    );
    let second = fetch::check(&mut client, &fetcher, &source(), Utc::now())
        .await
        .unwrap();
    assert_eq!(second, Checked::Unchanged);
    assert_eq!(
        mirror.downloads.load(Ordering::SeqCst),
        1,
        "unchanged: no second download"
    );
    db.drop().await;
}

#[tokio::test]
async fn a_mirror_with_a_wrong_index_is_skipped() {
    let (db, mut client) = setup().await;
    let (mirror, addr) = start().await;
    let content = feed();
    let template = publish(&mirror, addr, &content, &content);
    mirror
        .files
        .lock()
        .unwrap()
        .insert("m1/repodata/repomd.xml".into(), b"<repomd/>".to_vec());
    let fetcher = Fetcher::new(&template, None, 64 << 20).unwrap();
    let checked = fetch::check(&mut client, &fetcher, &source(), Utc::now())
        .await
        .unwrap();
    assert!(matches!(checked, Checked::Imported(_)));
    db.drop().await;
}

#[tokio::test]
async fn a_tampered_download_is_refused_and_existing_data_kept() {
    let (db, mut client) = setup().await;
    let (mirror, addr) = start().await;
    let content = feed();
    let template = publish(&mirror, addr, &content, &content);
    let fetcher = Fetcher::new(&template, None, 64 << 20).unwrap();
    fetch::check(&mut client, &fetcher, &source(), Utc::now())
        .await
        .unwrap();
    // A new version is announced, but every mirror serves altered bytes.
    let mut newer = content.clone();
    newer.extend_from_slice(b"\0");
    let mut tampered = newer.clone();
    tampered[10] ^= 0xff;
    publish(&mirror, addr, &newer, &tampered);
    let error = fetch::check(&mut client, &fetcher, &source(), Utc::now())
        .await
        .unwrap_err();
    assert!(error.contains("digest"), "{error}");
    let row = client
        .query_one(
            "SELECT last_error, advisories FROM feed_sources WHERE source = 'fedora-44-x86_64'",
            &[],
        )
        .await
        .unwrap();
    assert!(row.get::<_, Option<String>>(0).unwrap().contains("digest"));
    assert_eq!(row.get::<_, i32>(1), 3, "the previous advisories are kept");
    let open: i64 = client
        .query_one(
            "SELECT count(*) FROM vulnerabilities WHERE fixed_at IS NULL",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(open, 1);
    db.drop().await;
}

#[test]
fn the_mirror_list_must_use_https_except_on_loopback() {
    assert!(
        Fetcher::new(
            "http://mirrors.example.org/metalink?repo=f{release}",
            None,
            1
        )
        .is_err()
    );
    assert!(Fetcher::new("https://mirrors.fedoraproject.org/metalink?repo=updates-released-f{release}&arch={arch}", None, 1).is_ok());
    assert!(Fetcher::new("http://127.0.0.1:8080/metalink", None, 1).is_ok());
    assert!(Fetcher::new("http://[::1]:8080/metalink", None, 1).is_ok());
    assert!(
        Fetcher::new("http://[::ffff:8.8.8.8]/metalink", None, 1).is_err(),
        "only loopback may use plain HTTP"
    );
}

#[tokio::test]
async fn the_current_index_is_preferred_over_a_lagging_mirror() {
    let (db, mut client) = setup().await;
    let (mirror, addr) = start().await;
    let current = feed();
    let mut old = current.clone();
    old.extend_from_slice(b"\0old");
    // Publish the old version, keep its repomd, then publish the current one.
    publish(&mirror, addr, &old, &old);
    let old_repomd = mirror.files.lock().unwrap()["m1/repodata/repomd.xml"].clone();
    let template = publish(&mirror, addr, &current, &current);
    // Mirror 1 still serves the old index (an alternate in the metalink).
    let metalink = String::from_utf8(mirror.files.lock().unwrap()["metalink"].clone()).unwrap();
    let with_alternate = metalink.replace(
        "</verification>",
        &format!(
            "</verification><verification><hash type=\"sha256\">{}</hash></verification>",
            sha(&old_repomd)
        ),
    );
    {
        let mut files = mirror.files.lock().unwrap();
        files.insert("metalink".into(), with_alternate.into_bytes());
        files.insert("m1/repodata/repomd.xml".into(), old_repomd);
    }
    let fetcher = Fetcher::new(&template, None, 64 << 20).unwrap();
    fetch::check(&mut client, &fetcher, &source(), Utc::now())
        .await
        .unwrap();
    let stored: Vec<u8> = client
        .query_one("SELECT content_sha256 FROM feed_sources", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        hex(&stored),
        sha(&current),
        "mirror 2's current index, not mirror 1's older one"
    );
    db.drop().await;
}
