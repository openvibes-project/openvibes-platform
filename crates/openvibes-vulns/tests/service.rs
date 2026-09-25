//! The `openvibes-vulns` service: checks feeds at start, re-matches a host
//! when its inventory changes, and refuses unsafe configuration.

mod common;

use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    routing::get,
};
use chrono::Utc;
use common::TestDb;
use openvibes_vulns::{config::VulnsConfig, repodata::hex, service};
use platform_store::inventory::{self, PackageRow};
use sha2::{Digest, Sha256};

type Files = Arc<Mutex<HashMap<String, Vec<u8>>>>;

/// Serves the feed chain and a KEV file; returns the metalink template and
/// the KEV URL.
async fn mirror(content: Vec<u8>) -> (String, String) {
    let sha = |b: &[u8]| hex(&Sha256::digest(b));
    let files: Files = Arc::default();
    let app = Router::new()
        .route(
            "/{*path}",
            get(
                |State(files): State<Files>, Path(path): Path<String>| async move {
                    files
                        .lock()
                        .unwrap()
                        .get(&path)
                        .cloned()
                        .ok_or(StatusCode::NOT_FOUND)
                },
            ),
        )
        .with_state(files.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let href = format!("repodata/{}-updateinfo.xml.zst", sha(&content));
    let repomd = format!(
        "<repomd><data type=\"updateinfo\"><checksum type=\"sha256\">{}</checksum>\
         <location href=\"{href}\"/><size>{}</size></data></repomd>",
        sha(&content),
        content.len()
    );
    let metalink = format!(
        "<metalink><files><file name=\"repomd.xml\"><verification><hash type=\"sha256\">{}</hash>\
         </verification><resources><url protocol=\"http\">http://{addr}/m/repodata/repomd.xml</url>\
         </resources></file></files></metalink>",
        sha(repomd.as_bytes())
    );
    let mut map = files.lock().unwrap();
    map.insert("metalink".into(), metalink.into_bytes());
    map.insert("m/repodata/repomd.xml".into(), repomd.into_bytes());
    map.insert(format!("m/{href}"), content);
    let kev = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/kev.json");
    map.insert("kev.json".into(), std::fs::read(kev).unwrap());
    (
        format!("http://{addr}/metalink?release={{release}}&arch={{arch}}"),
        format!("http://{addr}/kev.json"),
    )
}

fn wordpress() -> PackageRow {
    PackageRow {
        manager: "rpm".into(),
        name: "wordpress".into(),
        epoch: 0,
        version: "6.9.6".into(),
        release: "1.fc44".into(),
        arch: "noarch".into(),
    }
}

async fn wait_for(db: &TestDb, sql: &str, want: i64) {
    let client = db.pool.get().await.unwrap();
    for _ in 0..100 {
        let n: i64 = client.query_one(sql, &[]).await.unwrap().get(0);
        if n == want {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for {sql} = {want}");
}

#[tokio::test]
async fn checks_feeds_at_start_and_rematches_changed_hosts() {
    let db = TestDb::create().await;
    let mut admin = db.pool.get().await.unwrap();
    platform_store::migrate(&mut admin).await.unwrap();
    let first = "agent.00000000-0000-4000-8000-0000000000c1";
    let second = "agent.00000000-0000-4000-8000-0000000000c2";
    for agent in [first, second] {
        admin
            .execute(
                "INSERT INTO agents (agent_id, status, enrolled_at) VALUES ($1, 'active', now())",
                &[&agent],
            )
            .await
            .unwrap();
    }
    // One Fedora 44 host exists before start, so release 44 is checked.
    inventory::replace(
        &mut admin,
        first,
        "fedora",
        "44",
        None,
        &[],
        [1; 32],
        Utc::now(),
    )
    .await
    .unwrap();
    let content = std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/updateinfo-f44.xml.zst"),
    )
    .unwrap();
    let (template, kev_url) = mirror(content).await;
    let health = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let health_addr = health.local_addr().unwrap();
    let config = VulnsConfig {
        database_url: db.url(),
        health_listen: health_addr,
        check_interval_minutes: 60,
        metalink_url: template,
        arch: "x86_64".into(),
        proxy_url: None,
        max_download_bytes: 64 << 20,
        kev_url,
        epss_url: String::new(),
    };
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(service::run(config, health, async {
        let _ = stopped.await;
    }));
    wait_for(
        &db,
        "SELECT coalesce(max(advisories), 0)::bigint FROM feed_sources WHERE source LIKE 'fedora-%'",
        3,
    )
    .await;
    // Enrichment is checked with the feeds; EPSS is turned off here.
    wait_for(
        &db,
        "SELECT count(*) FROM cve_enrichment WHERE kev_added IS NOT NULL",
        5,
    )
    .await;
    // A new inventory is matched at once, not at the next hourly check.
    inventory::replace(
        &mut admin,
        second,
        "fedora",
        "44",
        None,
        &[wordpress()],
        [2; 32],
        Utc::now(),
    )
    .await
    .unwrap();
    wait_for(
        &db,
        "SELECT count(*) FROM vulnerabilities WHERE agent_id = 'agent.00000000-0000-4000-8000-0000000000c2' AND fixed_at IS NULL",
        1,
    )
    .await;
    let ready = reqwest_like(health_addr, "/ready").await;
    assert_eq!(ready, 200);
    let _ = stop.send(());
    task.await.unwrap().unwrap();
    db.drop().await;
}

/// Minimal HTTP GET returning the status code.
async fn reqwest_like(addr: SocketAddr, path: &str) -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    tcp.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut response = String::new();
    tcp.read_to_string(&mut response).await.unwrap();
    response.split_whitespace().nth(1).unwrap().parse().unwrap()
}

#[test]
fn unsafe_or_out_of_range_configuration_is_refused() {
    let base = |extra: &str| format!("database_url = \"postgresql:///openvibes\"\n{extra}");
    let dir = std::env::temp_dir().join(format!("ov-vulns-config-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let load = |text: String| {
        let path = dir.join("vulns.toml");
        std::fs::write(&path, text).unwrap();
        openvibes_vulns::config::load_config(&path)
    };
    let config = load(base("")).unwrap();
    assert_eq!(config.check_interval_minutes, 60);
    assert_eq!(config.health_listen.to_string(), "127.0.0.1:18483");
    assert_eq!(config.kev_url, openvibes_vulns::fetch::KEV_URL);
    assert_eq!(config.epss_url, openvibes_vulns::fetch::EPSS_URL);
    assert!(
        load(base("kev_url = \"\"\nepss_url = \"\"\n")).is_ok(),
        "off"
    );
    for bad in [
        base("health_listen = \"0.0.0.0:18483\"\n"),
        base("check_interval_minutes = 14\n"),
        base("check_interval_minutes = 1441\n"),
        base("metalink_url = \"http://mirrors.example.org/metalink\"\n"),
        base("unknown = 1\n"),
        base("kev_url = \"http://www.cisa.gov/kev.json\"\n"),
        base("epss_url = \"ftp://example.org/epss.csv.gz\"\n"),
    ] {
        assert!(load(bad.clone()).is_err(), "{bad}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
