//! A build against a local upstream: every file is fetched once, a second
//! build reuses what did not change (304s), a failing source keeps its
//! earlier copy, and the tree verifies as a platform would verify it and
//! packs into a bundle the platform's reader accepts.
// The test writes under the system temporary directory; it is not shipped code.
#![allow(clippy::disallowed_types)]

use std::{
    collections::HashMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use axum::{
    Router,
    extract::State,
    http::{HeaderMap, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::get,
};
use openvibes_feed::{build, config::Config, key, pack};
use openvibes_vulns::{
    bundle,
    feedfmt::{self, TrustedKey},
    repodata::hex,
};
use sha2::{Digest, Sha256};

#[derive(Clone, Default)]
struct Upstream {
    files: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    not_modified: Arc<AtomicUsize>,
    /// NVD API records, as `cves/2.0` gives them.
    nvd: Arc<Mutex<Vec<serde_json::Value>>>,
}

/// NVD's `cves/2.0`: the records last modified inside the window, two to a page.
async fn nvd(State(up): State<Upstream>, uri: Uri) -> Response {
    let query: HashMap<String, String> = uri
        .query()
        .unwrap_or("")
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
    let bound = |name: &str| query[name].trim_end_matches('Z').to_owned();
    let (from, to) = (bound("lastModStartDate"), bound("lastModEndDate"));
    let index: usize = query["startIndex"].parse().unwrap();
    let inside: Vec<serde_json::Value> = up
        .nvd
        .lock()
        .unwrap()
        .iter()
        .filter(|cve| {
            let at = cve["lastModified"].as_str().unwrap();
            from.as_str() <= at && at <= to.as_str()
        })
        .cloned()
        .collect();
    let page: Vec<serde_json::Value> = inside
        .iter()
        .skip(index)
        .take(2)
        .map(|cve| serde_json::json!({ "cve": cve }))
        .collect();
    let body = serde_json::json!({
        "totalResults": inside.len(), "startIndex": index,
        "resultsPerPage": page.len(), "vulnerabilities": page,
    });
    (
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

fn etag(bytes: &[u8]) -> String {
    format!("\"{}\"", &hex(&Sha256::digest(bytes))[..16])
}

async fn serve(State(up): State<Upstream>, uri: Uri, headers: HeaderMap) -> Response {
    let path = uri.path().trim_start_matches('/').to_owned();
    // EUVD pages: the fixture on page 0, nothing after.
    let key = if path == "euvd" && !uri.query().unwrap_or("").contains("page=0") {
        "euvd-empty".to_owned()
    } else {
        path
    };
    let Some(body) = up.files.lock().unwrap().get(&key).cloned() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let tag = etag(&body);
    if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        == Some(tag.as_str())
    {
        up.not_modified.fetch_add(1, Ordering::SeqCst);
        return StatusCode::NOT_MODIFIED.into_response();
    }
    ([(header::ETAG, tag)], body).into_response()
}

async fn start() -> (Upstream, SocketAddr) {
    let up = Upstream::default();
    let app = Router::new()
        .route("/nvd", get(nvd))
        .route("/{*path}", get(serve))
        .with_state(up.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (up, addr)
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../openvibes-vulns/tests/fixtures")
            .join(name),
    )
    .unwrap()
}

fn sha(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn publish(up: &Upstream, addr: SocketAddr) {
    let updateinfo = fixture("updateinfo-f44.xml.zst");
    let href = format!("repodata/{}-updateinfo.xml.zst", sha(&updateinfo));
    let repomd = format!(
        "<?xml version=\"1.0\"?><repomd xmlns=\"http://linux.duke.edu/metadata/repo\">\
         <data type=\"updateinfo\"><checksum type=\"sha256\">{}</checksum>\
         <location href=\"{href}\"/><size>{}</size></data></repomd>",
        sha(&updateinfo),
        updateinfo.len()
    );
    let metalink = format!(
        "<?xml version=\"1.0\"?><metalink><files><file name=\"repomd.xml\"><verification>\
         <hash type=\"sha256\">{}</hash></verification><resources>\
         <url protocol=\"http\">http://{addr}/m1/repodata/repomd.xml</url>\
         </resources></file></files></metalink>",
        sha(repomd.as_bytes())
    );
    let mut files = up.files.lock().unwrap();
    files.insert("metalink".into(), metalink.into_bytes());
    files.insert("m1/repodata/repomd.xml".into(), repomd.into_bytes());
    files.insert(format!("m1/{href}"), updateinfo);
    files.insert("kev".into(), fixture("kev.json"));
    files.insert("epss".into(), fixture("epss.csv.gz"));
    files.insert("euvd".into(), fixture("euvd.json"));
    files.insert("euvd-empty".into(), br#"{"items":[],"total":0}"#.to_vec());
    files.insert(
        "Debian/all.zip".into(),
        b"an osv zip, as far as the builder cares".to_vec(),
    );
}

fn config(addr: SocketAddr) -> Config {
    Config {
        fedora: vec!["fedora-44-x86_64".into()],
        osv_releases: vec!["debian-12".into(), "debian-13".into()],
        metalink_url: format!("http://{addr}/metalink?release={{release}}&arch={{arch}}"),
        osv_url: format!("http://{addr}"),
        kev_url: format!("http://{addr}/kev"),
        epss_url: format!("http://{addr}/epss"),
        euvd_url: format!("http://{addr}/euvd"),
        nvd_url: String::new(),
        ..Config::default()
    }
}

struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("ov-feed-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(config: &Config, key: &key::FeedKey, out: &Path, only: &[String]) -> build::Report {
    build::run(
        config,
        key,
        &build::Options {
            out,
            only,
            valid_days: 7,
        },
    )
    .unwrap()
}

fn verified(out: &Path, key: &key::FeedKey) -> feedfmt::Accepted {
    let bytes = std::fs::read(out.join("feed.json")).unwrap();
    feedfmt::verify(
        &bytes,
        &[TrustedKey {
            feed_id: key.feed_id.clone(),
            key_id: key.key_id.clone(),
            public_key: key.signing.verifying_key().to_bytes(),
        }],
        &[],
        chrono::Utc::now().timestamp(),
    )
    .unwrap()
}

#[test]
fn keys_are_private_and_never_overwritten() {
    let dir = Dir::new("keys");
    let path = dir.0.join("feed.key");
    let made = key::generate(&path, "site", "k1").unwrap();
    assert_eq!(made.fingerprint().split(' ').count(), 8);
    assert!(key::generate(&path, "site", "k2").is_err());
    assert!(key::generate(&dir.0.join("bad"), "no spaces", "k1").is_err());
    let loaded = key::load(&path).unwrap();
    assert_eq!(loaded.public(), made.public());
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(key::load(&path).unwrap_err().contains("chmod 600"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_build_verifies_reuses_unchanged_files_and_packs() {
    let (up, addr) = start().await;
    publish(&up, addr);
    let dir = Dir::new("build");
    let key = key::generate(&dir.0.join("k"), "site", "k1").unwrap();
    let (cfg, out) = (config(addr), dir.0.join("tree"));
    let (c, k, o) = (
        cfg.clone(),
        key::load(&dir.0.join("k")).unwrap(),
        out.clone(),
    );
    let first = tokio::task::spawn_blocking(move || run(&c, &k, &o, &[]))
        .await
        .unwrap();
    assert_eq!(first.failed, 0, "{:?}", first.lines);
    let accepted = verified(&out, &key);
    let kinds: Vec<_> = accepted
        .manifest
        .files
        .iter()
        .map(|f| (f.source.as_str(), f.kind.as_str()))
        .collect();
    assert_eq!(
        kinds,
        [
            ("debian", "osv"),
            ("epss", "epss"),
            ("euvd", "euvd"),
            ("fedora-44-x86_64", "repomd"),
            ("fedora-44-x86_64", "updateinfo"),
            ("kev", "kev"),
        ]
    );
    let osv = &accepted.manifest.files[0];
    assert_eq!(
        osv.releases.as_deref(),
        Some(&["debian-12".to_owned(), "debian-13".to_owned()][..])
    );
    for file in &accepted.manifest.files {
        let bytes = std::fs::read(out.join("blobs").join(&file.sha256)).unwrap();
        assert_eq!(
            (sha(&bytes), bytes.len() as u64),
            (file.sha256.clone(), file.size)
        );
    }
    // The EUVD file is one response holding the whole list.
    let euvd = accepted
        .manifest
        .files
        .iter()
        .find(|f| f.source == "euvd")
        .unwrap();
    let list: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("blobs").join(&euvd.sha256)).unwrap())
            .unwrap();
    assert!(list["items"].as_array().unwrap().len() > 1);

    // A second build changes nothing upstream: 304s and reused blobs.
    let before = up.not_modified.load(Ordering::SeqCst);
    let (c, k, o) = (
        cfg.clone(),
        key::load(&dir.0.join("k")).unwrap(),
        out.clone(),
    );
    let second = tokio::task::spawn_blocking(move || run(&c, &k, &o, &[]))
        .await
        .unwrap();
    assert!(second.sequence > first.sequence);
    assert!(
        second.lines.iter().all(|l| l.contains("unchanged")),
        "{:?}",
        second.lines
    );
    assert!(up.not_modified.load(Ordering::SeqCst) >= before + 3);
    assert_eq!(verified(&out, &key).manifest.sequence, second.sequence);

    // A source that fails keeps its earlier copy and says so.
    up.files.lock().unwrap().remove("kev");
    let (c, k, o) = (
        cfg.clone(),
        key::load(&dir.0.join("k")).unwrap(),
        out.clone(),
    );
    let third = tokio::task::spawn_blocking(move || run(&c, &k, &o, &[]))
        .await
        .unwrap();
    assert_eq!(third.failed, 1);
    assert!(
        third
            .lines
            .iter()
            .any(|l| l.contains("kev/kev kept from an earlier build")),
        "{:?}",
        third.lines
    );
    assert!(
        verified(&out, &key)
            .manifest
            .files
            .iter()
            .any(|f| f.source == "kev")
    );

    // When every source fails, nothing is signed: the old feed keeps ageing.
    let before = std::fs::read(out.join("feed.json")).unwrap();
    up.files.lock().unwrap().clear();
    let (c, k, o) = (
        cfg.clone(),
        key::load(&dir.0.join("k")).unwrap(),
        out.clone(),
    );
    let down = tokio::task::spawn_blocking(move || {
        build::run(
            &c,
            &k,
            &build::Options {
                out: &o,
                only: &[],
                valid_days: 7,
            },
        )
    })
    .await
    .unwrap();
    assert!(down.unwrap_err().contains("nothing published"));
    assert_eq!(std::fs::read(out.join("feed.json")).unwrap(), before);
    publish(&up, addr);
    up.files.lock().unwrap().remove("kev");

    // A subset build into its own tree carries only those sources.
    let small = dir.0.join("small");
    let (c, k, o) = (
        cfg.clone(),
        key::load(&dir.0.join("k")).unwrap(),
        small.clone(),
    );
    let only = vec!["fedora-44-x86_64".to_owned()];
    let subset = tokio::task::spawn_blocking(move || run(&c, &k, &o, &only))
        .await
        .unwrap();
    // A subset build into the existing tree leaves the other sources as they were.
    let (c, k, o) = (
        cfg.clone(),
        key::load(&dir.0.join("k")).unwrap(),
        out.clone(),
    );
    let only = vec!["epss".to_owned()];
    tokio::task::spawn_blocking(move || run(&c, &k, &o, &only))
        .await
        .unwrap();
    assert_eq!(verified(&out, &key).manifest.files.len(), 6);
    // Valid days outside 1 to 30 are refused.
    let bad = build::run(
        &cfg,
        &key,
        &build::Options {
            out: &out,
            only: &[],
            valid_days: 99,
        },
    );
    assert!(bad.is_err());
    // The sequence is at least the Unix time, so a second tree built later
    // with the same key still sorts after the first (builds are hours apart).
    assert!(subset.sequence >= first.sequence);
    assert_eq!(verified(&small, &key).manifest.files.len(), 2);

    // The tree packs into a tar the platform's reader unpacks and verifies.
    let tar = dir.0.join("feed.tar");
    assert_eq!(pack::bundle(&out, &tar).unwrap(), 6);
    assert!(pack::bundle(&out, &tar).is_err(), "never overwrites");
    let work = dir.0.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let trusted = TrustedKey {
        feed_id: key.feed_id.clone(),
        key_id: key.key_id.clone(),
        public_key: key.signing.verifying_key().to_bytes(),
    };
    let unpacked = bundle::unpack_tar(&tar, &work, |bytes| {
        let ok = feedfmt::verify(bytes, &[trusted], &[], chrono::Utc::now().timestamp())
            .map_err(|e| e.to_string())?;
        Ok(ok
            .manifest
            .files
            .iter()
            .map(|f| (f.sha256.clone(), f.size))
            .collect())
    })
    .unwrap();
    let accepted = verified(&out, &key);
    for file in &accepted.manifest.files {
        assert!(unpacked.blob(&file.sha256).is_some(), "{}", file.name);
    }
}

/// Only NVD, against the local API: no other source, no pause.
fn nvd_config(addr: SocketAddr) -> Config {
    Config {
        osv_url: String::new(),
        kev_url: String::new(),
        epss_url: String::new(),
        euvd_url: String::new(),
        nvd_url: format!("http://{addr}/nvd"),
        nvd_pause_ms: Some(0),
        ..Config::default()
    }
}

fn nvd_hashes(out: &Path, key: &key::FeedKey) -> Vec<(String, String)> {
    let mut files: Vec<(String, String)> = verified(out, key)
        .manifest
        .files
        .into_iter()
        .filter(|f| f.kind == feedfmt::Kind::Nvd)
        .map(|f| (f.name, f.sha256))
        .collect();
    files.sort();
    files
}

#[tokio::test(flavor = "multi_thread")]
async fn nvd_is_read_by_windows_and_only_changed_years_are_rewritten() {
    let (up, addr) = start().await;
    let page: serde_json::Value = serde_json::from_slice(&fixture("nvd-cpe.json")).unwrap();
    let cves: Vec<serde_json::Value> = page["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["cve"].clone())
        .collect();
    *up.nvd.lock().unwrap() = cves.clone();
    let dir = Dir::new("nvd");
    let key = key::generate(&dir.0.join("k"), "site", "k1").unwrap();
    let (cfg, out) = (nvd_config(addr), dir.0.join("tree"));

    // The first read covers every window, and every record is in a year file.
    let first = tokio::task::spawn_blocking({
        let (cfg, out, key) = (
            cfg.clone(),
            out.clone(),
            key::load(&dir.0.join("k")).unwrap(),
        );
        move || run(&cfg, &key, &out, &[])
    })
    .await
    .unwrap();
    assert_eq!(first.failed, 0, "{:?}", first.lines);
    let years = nvd_hashes(&out, &key);
    assert!(years.len() >= 2, "{years:?}");
    let read = |out: &Path| -> usize {
        verified(out, &key)
            .manifest
            .files
            .iter()
            .filter(|f| f.kind == feedfmt::Kind::Nvd)
            .map(|f| {
                let bytes = std::fs::read(out.join("blobs").join(&f.sha256)).unwrap();
                openvibes_vulns::enrich::parse_slim(&bytes, 1 << 30)
                    .unwrap()
                    .entries
                    .len()
            })
            .sum()
    };
    assert_eq!(read(&out), cves.len());

    // Nothing changed: the same files.
    let again = tokio::task::spawn_blocking({
        let (cfg, out, key) = (
            cfg.clone(),
            out.clone(),
            key::load(&dir.0.join("k")).unwrap(),
        );
        move || run(&cfg, &key, &out, &[])
    })
    .await
    .unwrap();
    assert_eq!(nvd_hashes(&out, &key), years);
    assert!(again.sequence > first.sequence);

    // One record changes: only its year is rewritten.
    let changed = cves[0]["id"].as_str().unwrap().to_owned();
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    {
        let mut all = up.nvd.lock().unwrap();
        let cve = all
            .iter_mut()
            .find(|c| c["id"] == changed.as_str())
            .unwrap();
        cve["lastModified"] = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.3f")
            .to_string()
            .into();
        cve["descriptions"] = serde_json::json!([{ "lang": "en", "value": "changed text" }]);
    }
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let third = tokio::task::spawn_blocking({
        let (cfg, out, key) = (
            cfg.clone(),
            out.clone(),
            key::load(&dir.0.join("k")).unwrap(),
        );
        move || run(&cfg, &key, &out, &[])
    })
    .await
    .unwrap();
    assert_eq!(third.failed, 0, "{:?}", third.lines);
    let now = nvd_hashes(&out, &key);
    let year = format!("nvd-{}.json.gz", &changed[4..8]);
    for ((name, before), (_, after)) in years.iter().zip(&now) {
        assert_eq!(*name == year, before != after, "{name}");
    }
    assert_eq!(read(&out), cves.len());

    // A year file gone from blobs/ is an error, not a year started over.
    let gone = nvd_hashes(&out, &key).remove(0).1;
    let kept = std::fs::read(out.join("blobs").join(&gone)).unwrap();
    std::fs::remove_file(out.join("blobs").join(&gone)).unwrap();
    {
        let mut all = up.nvd.lock().unwrap();
        for cve in all.iter_mut() {
            cve["lastModified"] = chrono::Utc::now()
                .format("%Y-%m-%dT%H:%M:%S%.3f")
                .to_string()
                .into();
        }
    }
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let broken = build::run(
        &cfg,
        &key,
        &build::Options {
            out: &out,
            only: &[],
            valid_days: 7,
        },
    )
    .unwrap_err();
    assert!(broken.contains("missing from blobs/"), "{broken}");
    std::fs::write(out.join("blobs").join(&gone), kept).unwrap();

    // NVD down and nothing else wanted: nothing is signed.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let before = std::fs::read(out.join("feed.json")).unwrap();
    let down = Config {
        nvd_url: "http://127.0.0.1:9/nvd".into(),
        ..cfg
    };
    let failed = build::run(
        &down,
        &key,
        &build::Options {
            out: &out,
            only: &[],
            valid_days: 7,
        },
    );
    assert!(failed.unwrap_err().contains("nothing published"));
    assert_eq!(std::fs::read(out.join("feed.json")).unwrap(), before);
}
