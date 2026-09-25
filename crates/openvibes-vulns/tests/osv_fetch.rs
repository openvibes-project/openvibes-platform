//! Keeping OSV current (OSV spec D4): a full `all.zip` import at first, then
//! only the records OSV's change list names, against a local server.

mod common;

use std::{
    io::Write,
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
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::Utc;
use common::TestDb;
use openvibes_vulns::{
    fetch::Fetcher,
    osv::Release,
    osv_fetch::{self, OsvSync, Synced},
};
use platform_store::{
    Client,
    inventory::{self, PackageRow},
};

const D12: &str = "agent.00000000-0000-4000-8000-0000000000d1";
const D13: &str = "agent.00000000-0000-4000-8000-0000000000d3";

#[derive(Clone, Default)]
struct Osv {
    /// Records by id, as `<id>.json` and inside `all.zip`.
    records: Arc<Mutex<Vec<(String, String)>>>,
    /// `modified_id.csv` lines, newest first.
    changes: Arc<Mutex<Vec<String>>>,
    zips: Arc<AtomicUsize>,
    singles: Arc<AtomicUsize>,
}

fn zip(records: &[(String, String)]) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (id, json) in records {
        zip.start_file(format!("{id}.json"), options).unwrap();
        zip.write_all(json.as_bytes()).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

async fn serve(State(osv): State<Osv>, Path(file): Path<String>, request: HeaderMap) -> Response {
    match file.as_str() {
        "all.zip" => {
            osv.zips.fetch_add(1, Ordering::SeqCst);
            zip(&osv.records.lock().unwrap()).into_response()
        }
        "modified_id.csv" => {
            let body = osv.changes.lock().unwrap().join("\n");
            let etag = format!("\"{}\"", body.len());
            let sent = request
                .get(header::IF_NONE_MATCH)
                .and_then(|v| v.to_str().ok());
            if sent == Some(etag.as_str()) {
                return StatusCode::NOT_MODIFIED.into_response();
            }
            ([(header::ETAG, etag)], body).into_response()
        }
        name => {
            osv.singles.fetch_add(1, Ordering::SeqCst);
            let id = name.trim_end_matches(".json");
            let records = osv.records.lock().unwrap();
            match records.iter().find(|(r, _)| r == id) {
                Some((_, json)) => json.clone().into_response(),
                None => StatusCode::NOT_FOUND.into_response(),
            }
        }
    }
}

async fn start() -> (Osv, SocketAddr) {
    let osv = Osv::default();
    let app = Router::new()
        .route("/Debian/{file}", get(serve))
        .with_state(osv.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (osv, addr)
}

fn fixture(name: &str) -> (String, String) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/osv")
        .join(format!("{name}.json"));
    (name.to_owned(), std::fs::read_to_string(path).unwrap())
}

fn openssl(id: &str, fixed: &str) -> (String, String) {
    (
        id.to_owned(),
        format!(
            r#"{{"id":"{id}","upstream":["{cve}"],"affected":[{{"package":{{"name":"openssl",
            "ecosystem":"Debian:12"}},"ranges":[{{"type":"ECOSYSTEM","events":[{{"introduced":"0"}},
            {{"fixed":"{fixed}"}}]}}],"ecosystem_specific":{{"urgency":"high"}}}}]}}"#,
            cve = id.trim_start_matches("DEBIAN-")
        ),
    )
}

async fn host(admin: &mut Client, agent: &str, version: &str, digest: u8) {
    admin
        .execute(
            "INSERT INTO agents (agent_id, status, enrolled_at) VALUES ($1, 'active', now())
             ON CONFLICT DO NOTHING",
            &[&agent],
        )
        .await
        .unwrap();
    let package = |name: &str, v: &str, r: &str, source: Option<&str>| PackageRow {
        manager: "dpkg".into(),
        name: name.into(),
        epoch: 0,
        version: v.into(),
        release: r.into(),
        arch: "amd64".into(),
        source: source.map(Into::into),
        source_version: None,
    };
    inventory::replace(
        admin,
        agent,
        "debian",
        version,
        None,
        &[
            package("libpam0g", "1.5.2", "6+deb12u1", Some("pam")),
            package("libssl3", "3.0.11", "1~deb12u2", Some("openssl")),
        ],
        [digest; 32],
        Utc::now(),
    )
    .await
    .unwrap();
}

async fn open(client: &Client) -> Vec<String> {
    client
        .query(
            "SELECT agent_id || ' ' || advisory_id FROM vulnerabilities WHERE fixed_at IS NULL ORDER BY 1",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect()
}

#[tokio::test]
async fn full_import_first_then_only_changed_records() {
    let db = TestDb::create().await;
    let mut admin = db.pool.get().await.unwrap();
    platform_store::migrate(&mut admin).await.unwrap();
    host(&mut admin, D12, "12", 1).await;
    let mut vulns = db.pool.get().await.unwrap();
    vulns
        .batch_execute("SET ROLE openvibes_vulns")
        .await
        .unwrap();
    let (osv, addr) = start().await;
    *osv.records.lock().unwrap() = vec![
        fixture("DEBIAN-CVE-2024-10041"),
        fixture("DEBIAN-CVE-2005-4808"),
        fixture("RLSA-2022_4582"),
    ];
    *osv.changes.lock().unwrap() = vec![
        "2026-09-20T10:00:00Z,DEBIAN-CVE-2024-10041".into(),
        "2026-09-19T10:00:00Z,DEBIAN-CVE-2005-4808".into(),
    ];
    let dir = std::env::temp_dir().join(format!("ov-osv-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let fetcher = Fetcher::new("http://127.0.0.1/metalink", None, 1 << 20).unwrap();
    let sync = OsvSync::new(&fetcher, &format!("http://{addr}"), &dir, 1 << 20, 3).unwrap();
    let debian12: Release = "debian-12".parse().unwrap();

    // First: the whole file.
    let first = osv_fetch::sync(
        &mut vulns,
        &sync,
        "Debian",
        std::slice::from_ref(&debian12),
        Utc::now(),
    )
    .await;
    assert!(matches!(first, Ok(Synced::Full { .. })), "{first:?}");
    assert_eq!(osv.zips.load(Ordering::SeqCst), 1);
    assert_eq!(
        open(&vulns).await,
        [format!("{D12} DEBIAN-CVE-2024-10041/debian-12")]
    );
    assert!(
        std::fs::read_dir(&dir).unwrap().next().is_none(),
        "download removed"
    );

    // Nothing changed: one 304.
    let same = osv_fetch::sync(
        &mut vulns,
        &sync,
        "Debian",
        std::slice::from_ref(&debian12),
        Utc::now(),
    )
    .await;
    assert_eq!(same, Ok(Synced::Unchanged));

    // Two changes, one of another kind: only the Debian record is fetched.
    osv.records
        .lock()
        .unwrap()
        .push(openssl("DEBIAN-CVE-2026-3333", "3.0.13-1~deb12u1"));
    osv.changes.lock().unwrap().splice(
        0..0,
        [
            "2026-09-25T10:00:00Z,DEBIAN-CVE-2026-3333".to_owned(),
            "2026-09-25T09:00:00Z,DSA-9999-1".to_owned(),
        ],
    );
    let changed = osv_fetch::sync(
        &mut vulns,
        &sync,
        "Debian",
        std::slice::from_ref(&debian12),
        Utc::now(),
    )
    .await;
    assert_eq!(
        changed,
        Ok(Synced::Changes {
            records: 1,
            open: 2
        })
    );
    assert_eq!(
        osv.singles.load(Ordering::SeqCst),
        1,
        "DSA notices are not fetched"
    );
    assert_eq!(osv.zips.load(Ordering::SeqCst), 1);
    assert!(
        open(&vulns)
            .await
            .contains(&format!("{D12} DEBIAN-CVE-2026-3333/debian-12"))
    );

    // More changes than the limit (3): the whole file again.
    osv.changes.lock().unwrap().splice(
        0..0,
        (0..4).map(|i| format!("2026-09-26T10:00:0{i}Z,DEBIAN-CVE-2026-400{i}")),
    );
    let many = osv_fetch::sync(
        &mut vulns,
        &sync,
        "Debian",
        std::slice::from_ref(&debian12),
        Utc::now(),
    )
    .await;
    assert!(matches!(many, Ok(Synced::Full { .. })), "{many:?}");
    assert_eq!(osv.zips.load(Ordering::SeqCst), 2);

    // A host on a release not imported yet: a full import covering both.
    host(&mut admin, D13, "13", 2).await;
    let releases: Vec<Release> = vec![debian12, "debian-13".parse().unwrap()];
    let new_release = osv_fetch::sync(&mut vulns, &sync, "Debian", &releases, Utc::now()).await;
    assert!(
        matches!(new_release, Ok(Synced::Full { .. })),
        "{new_release:?}"
    );
    assert_eq!(
        osv.zips.load(Ordering::SeqCst),
        3,
        "one download for both releases"
    );
    assert!(
        open(&vulns)
            .await
            .contains(&format!("{D13} DEBIAN-CVE-2024-10041/debian-13")),
        "pam is still unfixed in 13 at 1.5.2"
    );
    let _ = std::fs::remove_dir_all(&dir);
    db.drop().await;
}

#[tokio::test]
async fn releases_hosts_run_are_grouped_by_ecosystem() {
    let db = TestDb::create().await;
    let mut admin = db.pool.get().await.unwrap();
    platform_store::migrate(&mut admin).await.unwrap();
    host(&mut admin, D12, "12", 1).await;
    host(&mut admin, D13, "13", 2).await;
    let vulns = db.pool.get().await.unwrap();
    vulns
        .batch_execute("SET ROLE openvibes_vulns")
        .await
        .unwrap();
    let groups = osv_fetch::releases_by_ecosystem(&vulns).await.unwrap();
    let names: Vec<(&str, Vec<String>)> = groups
        .iter()
        .map(|(ecosystem, releases)| (*ecosystem, releases.iter().map(Release::name).collect()))
        .collect();
    assert_eq!(
        names,
        [(
            "Debian",
            vec!["debian-12".to_owned(), "debian-13".to_owned()]
        )]
    );
    db.drop().await;
}

#[test]
fn the_osv_url_must_use_https_except_on_loopback() {
    let fetcher = Fetcher::new("http://127.0.0.1/metalink", None, 1 << 20).unwrap();
    let dir = std::env::temp_dir();
    assert!(OsvSync::new(&fetcher, "http://osv.example.org", &dir, 1, 1).is_err());
    assert!(OsvSync::new(&fetcher, osv_fetch::OSV_URL, &dir, 1, 1).is_ok());
}
