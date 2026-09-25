//! Fetching KEV and EPSS from a local server that honours `If-None-Match`.

mod common;

use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use axum::{
    Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::Utc;
use common::TestDb;
use openvibes_vulns::{
    enrich::Source,
    fetch::{self, Fetcher},
};

#[derive(Clone, Default)]
struct Server {
    /// Body and ETag served; no ETag when `None`.
    content: Arc<Mutex<(Vec<u8>, Option<String>)>>,
    downloads: Arc<AtomicUsize>,
}

async fn serve(State(server): State<Server>, request: HeaderMap) -> Response {
    let (body, etag) = server.content.lock().unwrap().clone();
    let sent = request
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok());
    if etag.is_some() && sent == etag.as_deref() {
        return StatusCode::NOT_MODIFIED.into_response();
    }
    server.downloads.fetch_add(1, Ordering::SeqCst);
    match etag {
        Some(tag) => ([(header::ETAG, tag)], body).into_response(),
        None => body.into_response(),
    }
}

async fn start() -> (Server, SocketAddr) {
    let server = Server::default();
    let app = Router::new()
        .route("/kev.json", get(serve))
        .with_state(server.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (server, addr)
}

fn kev(cve: &str) -> Vec<u8> {
    format!(r#"{{"vulnerabilities":[{{"cveID":"{cve}","dateAdded":"2026-09-01"}}]}}"#).into_bytes()
}

async fn setup() -> (TestDb, platform_store::Client, Fetcher) {
    let db = TestDb::create().await;
    platform_store::migrate(&mut db.pool.get().await.unwrap())
        .await
        .unwrap();
    let client = db.pool.get().await.unwrap();
    client
        .batch_execute("SET ROLE openvibes_vulns")
        .await
        .unwrap();
    let fetcher = Fetcher::new("http://127.0.0.1/metalink", None, 1 << 20).unwrap();
    (db, client, fetcher)
}

async fn kev_rows(client: &platform_store::Client) -> Vec<String> {
    client
        .query(
            "SELECT cve_id FROM cve_enrichment WHERE kev_added IS NOT NULL ORDER BY 1",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect()
}

#[tokio::test]
async fn an_unchanged_source_costs_one_not_modified() {
    let (db, mut client, fetcher) = setup().await;
    let (server, addr) = start().await;
    let url = format!("http://{addr}/kev.json");
    *server.content.lock().unwrap() = (kev("CVE-2026-1111"), Some("\"v1\"".into()));
    let first = fetch::check_enrichment(&mut client, &fetcher, Source::Kev, &url, Utc::now()).await;
    assert_eq!(first, Ok(Some(1)));
    let second =
        fetch::check_enrichment(&mut client, &fetcher, Source::Kev, &url, Utc::now()).await;
    assert_eq!(second, Ok(None), "304");
    assert_eq!(server.downloads.load(Ordering::SeqCst), 1);

    *server.content.lock().unwrap() = (kev("CVE-2026-2222"), Some("\"v2\"".into()));
    let third = fetch::check_enrichment(&mut client, &fetcher, Source::Kev, &url, Utc::now()).await;
    assert_eq!(third, Ok(Some(1)));
    assert_eq!(kev_rows(&client).await, ["CVE-2026-2222"]);
    db.drop().await;
}

#[tokio::test]
async fn an_identical_body_without_etag_is_not_imported_again() {
    let (db, mut client, fetcher) = setup().await;
    let (server, addr) = start().await;
    let url = format!("http://{addr}/kev.json");
    *server.content.lock().unwrap() = (kev("CVE-2026-1111"), None);
    let first = fetch::check_enrichment(&mut client, &fetcher, Source::Kev, &url, Utc::now()).await;
    assert_eq!(first, Ok(Some(1)));
    let second =
        fetch::check_enrichment(&mut client, &fetcher, Source::Kev, &url, Utc::now()).await;
    assert_eq!(second, Ok(None), "same digest");
    db.drop().await;
}

#[tokio::test]
async fn a_bad_download_is_recorded_and_keeps_the_previous_data() {
    let (db, mut client, fetcher) = setup().await;
    let (server, addr) = start().await;
    let url = format!("http://{addr}/kev.json");
    *server.content.lock().unwrap() = (kev("CVE-2026-1111"), Some("\"v1\"".into()));
    fetch::check_enrichment(&mut client, &fetcher, Source::Kev, &url, Utc::now())
        .await
        .unwrap();
    *server.content.lock().unwrap() = (b"<html>busy</html>".to_vec(), Some("\"v2\"".into()));
    let bad = fetch::check_enrichment(&mut client, &fetcher, Source::Kev, &url, Utc::now()).await;
    assert_eq!(bad, Err("not a readable kev feed".into()));
    assert_eq!(kev_rows(&client).await, ["CVE-2026-1111"]);
    let missing = fetch::check_enrichment(
        &mut client,
        &fetcher,
        Source::Kev,
        &format!("http://{addr}/gone"),
        Utc::now(),
    )
    .await;
    assert!(missing.is_err());
    let feed = platform_store::vulns::feeds(&client)
        .await
        .unwrap()
        .remove(0);
    assert!(feed.last_error.is_some());
    assert_eq!(feed.advisories, 1);
    db.drop().await;
}

#[test]
fn source_urls_must_use_https_except_on_loopback() {
    assert!(fetch::check_source_url("https://www.cisa.gov/kev.json").is_ok());
    assert!(fetch::check_source_url("http://127.0.0.1:8080/kev.json").is_ok());
    assert_eq!(
        fetch::check_source_url("http://www.cisa.gov/kev.json"),
        Err("enrichment source URLs must use https".into())
    );
}
