//! NVD sync (backfill by CVE, incremental by last-modified window, paging)
//! and EUVD paging, against a local server that answers like both APIs.

mod common;

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Json, Router,
    extract::{RawQuery, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::{DateTime, Utc};
use common::TestDb;
use openvibes_vulns::{
    fetch::Fetcher,
    sources::{self, NvdClient, NvdReport},
};
use platform_store::{Client, vulns};
use serde_json::{Value, json};

#[derive(Clone, Default)]
struct Api {
    /// NVD records by CVE id, answered to `cveId=`.
    known: Arc<Mutex<HashMap<String, Value>>>,
    /// NVD records answered to a last-modified window, one per page.
    changed: Arc<Mutex<Vec<Value>>>,
    /// Windows asked for, and API keys sent.
    windows: Arc<Mutex<Vec<(String, String)>>>,
    keys: Arc<Mutex<Vec<String>>>,
    /// Answer every NVD request with this status instead.
    fail: Arc<Mutex<Option<u16>>>,
    /// EUVD exploited items.
    euvd: Arc<Mutex<Vec<Value>>>,
}

/// `a=1&b=2` as a map (the test values need no percent-decoding).
fn params(raw: Option<String>) -> HashMap<String, String> {
    raw.unwrap_or_default()
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
}

fn record(id: &str, score: f64) -> Value {
    json!({"cve": {"id": id, "lastModified": "2026-09-24T10:00:00.000",
        "descriptions": [{"lang": "en", "value": format!("{id} description")}],
        "metrics": {"cvssMetricV31": [{"type": "Primary",
            "cvssData": {"baseScore": score, "vectorString": "CVSS:3.1/AV:N"}}]}}})
}

fn page(items: Vec<Value>, total: usize, start: usize) -> Json<Value> {
    Json(json!({"resultsPerPage": items.len(), "startIndex": start,
        "totalResults": total, "vulnerabilities": items}))
}

async fn nvd(State(api): State<Api>, headers: HeaderMap, RawQuery(raw): RawQuery) -> Response {
    let query = params(raw);
    if let Some(key) = headers.get("apiKey").and_then(|v| v.to_str().ok()) {
        api.keys.lock().unwrap().push(key.to_owned());
    }
    if let Some(status) = *api.fail.lock().unwrap() {
        return StatusCode::from_u16(status).unwrap().into_response();
    }
    if let Some(id) = query.get("cveId") {
        let found: Vec<Value> = api
            .known
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .into_iter()
            .collect();
        let total = found.len();
        return page(found, total, 0).into_response();
    }
    let window = (
        query.get("lastModStartDate").cloned().unwrap_or_default(),
        query.get("lastModEndDate").cloned().unwrap_or_default(),
    );
    let start: usize = query
        .get("startIndex")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if start == 0 {
        api.windows.lock().unwrap().push(window);
    }
    let changed = api.changed.lock().unwrap().clone();
    let items = changed.iter().skip(start).take(1).cloned().collect();
    page(items, changed.len(), start).into_response()
}

async fn euvd(State(api): State<Api>, RawQuery(raw): RawQuery) -> Json<Value> {
    let query = params(raw);
    assert_eq!(query.get("exploited").map(String::as_str), Some("true"));
    let size: usize = query["size"].parse().unwrap();
    let number: usize = query["page"].parse().unwrap();
    let all = api.euvd.lock().unwrap().clone();
    let items: Vec<Value> = all.iter().skip(number * size).take(size).cloned().collect();
    Json(json!({"items": items, "total": all.len()}))
}

async fn start() -> (Api, SocketAddr) {
    let api = Api::default();
    let app = Router::new()
        .route("/nvd", get(nvd))
        .route("/euvd", get(euvd))
        .with_state(api.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (api, addr)
}

async fn setup(cves: &[&str]) -> (TestDb, Client, Fetcher) {
    let db = TestDb::create().await;
    platform_store::migrate(&mut db.pool.get().await.unwrap())
        .await
        .unwrap();
    let mut client = db.pool.get().await.unwrap();
    client
        .batch_execute("SET ROLE openvibes_vulns")
        .await
        .unwrap();
    vulns::replace_advisories(
        &mut client,
        "fedora-44-x86_64",
        "fedora",
        "44",
        &[vulns::NewAdvisory {
            advisory_id: "FEDORA-2026-test".into(),
            severity: "important".into(),
            title: "test".into(),
            issued_at: None,
            updated_at: None,
            url: "https://bodhi.fedoraproject.org/updates/FEDORA-2026-test".into(),
            cves: cves.iter().map(|c| (*c).to_owned()).collect(),
            packages: vec![],
        }],
        Utc::now(),
    )
    .await
    .unwrap();
    let fetcher = Fetcher::new("http://127.0.0.1/metalink", None, 1 << 20).unwrap();
    (db, client, fetcher)
}

async fn score(client: &Client, cve: &str) -> Option<f32> {
    client
        .query_opt(
            "SELECT cvss_score FROM cve_enrichment WHERE cve_id = $1",
            &[&cve],
        )
        .await
        .unwrap()
        .and_then(|row| row.get(0))
}

fn at(text: &str) -> DateTime<Utc> {
    text.parse().unwrap()
}

#[tokio::test]
async fn backfill_then_incremental_windows_with_paging() {
    let (db, mut client, fetcher) =
        setup(&["CVE-2026-1111", "CVE-2026-2222", "CVE-2026-9999"]).await;
    let (api, addr) = start().await;
    api.known.lock().unwrap().extend([
        ("CVE-2026-1111".into(), record("CVE-2026-1111", 5.0)),
        ("CVE-2026-2222".into(), record("CVE-2026-2222", 7.5)),
    ]);
    let nvd = NvdClient::new(
        &fetcher,
        &format!("http://{addr}/nvd"),
        Some("secret-key".into()),
        Some(Duration::ZERO),
    )
    .unwrap();

    // First run: no sync point yet, so no window; every named CVE is asked.
    let first = sources::sync_nvd(&mut client, &nvd, at("2026-09-25T12:00:00Z"))
        .await
        .unwrap();
    assert_eq!(
        first,
        NvdReport {
            updated: 0,
            backfilled: 2,
            unknown: 1
        }
    );
    assert_eq!(score(&client, "CVE-2026-2222").await, Some(7.5));
    assert!(api.windows.lock().unwrap().is_empty());
    assert!(
        api.keys.lock().unwrap().iter().all(|k| k == "secret-key"),
        "the key goes in the apiKey header"
    );

    // Next run: one window since the last run, paged; only named CVEs kept.
    *api.changed.lock().unwrap() = vec![record("CVE-2026-1111", 9.8), record("CVE-2020-0001", 1.0)];
    let second = sources::sync_nvd(&mut client, &nvd, at("2026-09-25T13:00:00Z"))
        .await
        .unwrap();
    assert_eq!(second.updated, 1);
    assert_eq!(score(&client, "CVE-2026-1111").await, Some(9.8));
    assert_eq!(score(&client, "CVE-2020-0001").await, None);
    assert_eq!(
        *api.windows.lock().unwrap(),
        [(
            "2026-09-25T12:00:00.000Z".to_owned(),
            "2026-09-25T13:00:00.000Z".to_owned()
        )]
    );
    db.drop().await;
}

#[tokio::test]
async fn a_long_gap_is_split_into_windows_of_at_most_120_days() {
    let (db, mut client, fetcher) = setup(&["CVE-2026-1111"]).await;
    let (api, addr) = start().await;
    let nvd = NvdClient::new(
        &fetcher,
        &format!("http://{addr}/nvd"),
        None,
        Some(Duration::ZERO),
    )
    .unwrap();
    sources::sync_nvd(&mut client, &nvd, at("2026-01-01T00:00:00Z"))
        .await
        .unwrap();
    sources::sync_nvd(&mut client, &nvd, at("2026-07-20T00:00:00Z"))
        .await
        .unwrap();
    assert_eq!(
        *api.windows.lock().unwrap(),
        [
            (
                "2026-01-01T00:00:00.000Z".to_owned(),
                "2026-05-01T00:00:00.000Z".to_owned()
            ),
            (
                "2026-05-01T00:00:00.000Z".to_owned(),
                "2026-07-20T00:00:00.000Z".to_owned()
            ),
        ]
    );
    db.drop().await;
}

#[tokio::test]
async fn a_refused_request_stops_the_run_and_keeps_the_sync_point() {
    let (db, mut client, fetcher) = setup(&["CVE-2026-1111"]).await;
    let (api, addr) = start().await;
    let nvd = NvdClient::new(
        &fetcher,
        &format!("http://{addr}/nvd"),
        None,
        Some(Duration::ZERO),
    )
    .unwrap();
    sources::sync_nvd(&mut client, &nvd, at("2026-09-25T12:00:00Z"))
        .await
        .unwrap();
    *api.fail.lock().unwrap() = Some(429);
    let refused = sources::sync_nvd(&mut client, &nvd, at("2026-09-25T13:00:00Z")).await;
    assert!(refused.is_err());
    *api.fail.lock().unwrap() = None;
    api.windows.lock().unwrap().clear();
    sources::sync_nvd(&mut client, &nvd, at("2026-09-25T14:00:00Z"))
        .await
        .unwrap();
    assert_eq!(
        api.windows.lock().unwrap()[0].0,
        "2026-09-25T12:00:00.000Z",
        "the refused hour is asked again"
    );
    let feed = vulns::feeds(&client)
        .await
        .unwrap()
        .into_iter()
        .find(|f| f.source == "nvd")
        .unwrap();
    assert_eq!(feed.last_error, None, "cleared by the good run");
    db.drop().await;
}

#[tokio::test]
async fn euvd_is_read_page_by_page_and_unchanged_is_not_reimported() {
    let (db, mut client, fetcher) = setup(&[]).await;
    let (api, addr) = start().await;
    *api.euvd.lock().unwrap() = (1..=5)
        .map(|n| json!({"id": format!("EUVD-2026-{n}"), "aliases": format!("CVE-2026-100{n}\nGHSA-x")}))
        .collect();
    let url = format!("http://{addr}/euvd");
    let first = sources::check_euvd(&mut client, &fetcher, &url, 2, Utc::now()).await;
    assert_eq!(first, Ok(Some(5)));
    let second = sources::check_euvd(&mut client, &fetcher, &url, 2, Utc::now()).await;
    assert_eq!(second, Ok(None));
    let marked: i64 = client
        .query_one(
            "SELECT count(*) FROM cve_enrichment WHERE euvd_exploited",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(marked, 5);
    db.drop().await;
}

#[test]
fn the_api_key_file_must_be_private() {
    let dir = std::env::temp_dir().join(format!("ov-nvd-key-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("nvd.key");
    std::fs::write(&path, "abc-123\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            sources::read_api_key(&path),
            Err("nvd_api_key_file must not be readable by group or others".into())
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert_eq!(sources::read_api_key(&path), Ok("abc-123".into()));
    std::fs::write(&path, "abc 123\n").unwrap();
    assert!(sources::read_api_key(&path).is_err(), "not header-safe");
    let _ = std::fs::remove_dir_all(&dir);
}
