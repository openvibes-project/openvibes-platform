//! Reading a feed mirror over HTTP: the first key is pinned, only changed
//! files are downloaded, and a refused or unreachable mirror leaves the data
//! already applied alone. Runs as the `openvibes-vulns` role, so a missing
//! grant fails here and not on an installed system.

mod common;

use std::{
    collections::HashMap,
    io::{Read, Write},
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    routing::get,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use common::TestDb;
use ed25519_dalek::{Signer, SigningKey};
use openvibes_vulns::{
    feedfmt::{self, preimage},
    fetch::Fetcher,
    mirror::{self, Mirror, Synced},
};
use sha2::{Digest, Sha256};

#[derive(Clone, Default)]
struct Site {
    files: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    hits: Arc<Mutex<Vec<String>>>,
}

async fn serve(State(site): State<Site>, Path(path): Path<String>) -> Result<Vec<u8>, StatusCode> {
    site.hits.lock().unwrap().push(path.clone());
    site.files
        .lock()
        .unwrap()
        .get(&path)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)
}

async fn start() -> (Site, String) {
    let site = Site::default();
    let app = Router::new()
        .route("/{*path}", get(serve))
        .with_state(site.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (site, format!("http://{addr}"))
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name),
    )
    .unwrap()
}

/// The EPSS fixture with the first score changed, so its hash differs.
fn epss_changed() -> Vec<u8> {
    let mut text = String::new();
    flate2::read::GzDecoder::new(fixture("epss.csv.gz").as_slice())
        .read_to_string(&mut text)
        .unwrap();
    let text = text.replacen("0.03351", "0.04444", 1);
    let mut out = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    out.write_all(text.as_bytes()).unwrap();
    out.finish().unwrap()
}

struct Built<'a> {
    signer: &'a SigningKey,
    key_id: &'a str,
    sequence: u64,
    expires_in: i64,
    public_key: bool,
}

fn hex(bytes: &[u8]) -> String {
    feedfmt::hex(&Sha256::digest(bytes))
}

/// Publishes a feed with a KEV and an EPSS file on `site`.
fn publish(site: &Site, built: &Built<'_>, kev: &[u8], epss: &[u8], fetched_ago: i64) {
    publish_files(
        site,
        built,
        &[
            ("kev", "kev", "kev.json", kev),
            ("epss", "epss", "epss.csv.gz", epss),
        ],
        fetched_ago,
    );
}

/// Publishes a feed of `(source, kind, name, bytes)` files on `site`.
fn publish_files(
    site: &Site,
    built: &Built<'_>,
    list: &[(&str, &str, &str, &[u8])],
    fetched_ago: i64,
) {
    let now = Utc::now().timestamp();
    let entry = |(source, kind, name, bytes): &(&str, &str, &str, &[u8])| {
        format!(
            r#"{{"source":"{source}","kind":"{kind}","name":"{name}","sha256":"{}","size":{},"fetched_at":{},"upstream":"https://example.org/{name}"}}"#,
            hex(bytes),
            bytes.len(),
            now - fetched_ago
        )
    };
    let entries: Vec<String> = list.iter().map(entry).collect();
    let manifest = format!(
        r#"{{"sequence":{},"created_at":{},"expires_at":{},"files":[{}]}}"#,
        built.sequence,
        now - 30,
        now + built.expires_in,
        entries.join(",")
    );
    let signature = built
        .signer
        .sign(&preimage("site", built.key_id, &manifest))
        .to_bytes();
    let key = built.public_key.then(|| {
        format!(
            r#""public_key":"{}","#,
            URL_SAFE_NO_PAD.encode(built.signer.verifying_key().to_bytes())
        )
    });
    let envelope = format!(
        r#"{{"format":1,"feed_id":"site","key_id":"{}","signature":"{}",{}"manifest":{}}}"#,
        built.key_id,
        URL_SAFE_NO_PAD.encode(signature),
        key.unwrap_or_default(),
        serde_json::to_string(&manifest).unwrap()
    );
    let mut files = site.files.lock().unwrap();
    files.insert("feed.json".into(), envelope.into_bytes());
    for (_, _, _, bytes) in list {
        files.insert(format!("blobs/{}", hex(bytes)), bytes.to_vec());
    }
}

fn blob_hits(site: &Site) -> usize {
    site.hits
        .lock()
        .unwrap()
        .iter()
        .filter(|p| p.starts_with("blobs/"))
        .count()
}

struct Env {
    db: TestDb,
    client: platform_store::Client,
    mirror: Mirror,
    site: Site,
    work: PathBuf,
}

async fn setup() -> Env {
    let (site, base) = start().await;
    let db = TestDb::create().await;
    let mut admin = db.pool.get().await.unwrap();
    platform_store::migrate(&mut admin).await.unwrap();
    let client = db.pool.get().await.unwrap();
    client
        .batch_execute("SET ROLE \"openvibes-vulns\"")
        .await
        .unwrap();
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let work = std::env::temp_dir().join(format!(
        "ov-mirror-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let fetcher = Fetcher::new(&format!("{base}/m"), None, 64 << 20).unwrap();
    Env {
        db,
        client,
        mirror: Mirror::new(fetcher, &base, &work),
        site,
        work,
    }
}

impl Env {
    async fn sync(&mut self) -> Result<Synced, String> {
        mirror::sync(&mut self.client, &mut self.mirror, Utc::now()).await
    }

    async fn count(&self, sql: &str) -> i64 {
        let admin = self.db.pool.get().await.unwrap();
        admin.query_one(sql, &[]).await.unwrap().get(0)
    }

    async fn status_error(&self) -> Option<String> {
        let admin = self.db.pool.get().await.unwrap();
        admin
            .query_one(
                "SELECT last_error FROM feed_sources WHERE source = 'mirror'",
                &[],
            )
            .await
            .unwrap()
            .get(0)
    }

    async fn finish(self) {
        drop(self.client);
        self.db.drop().await;
        let _ = std::fs::remove_dir_all(&self.work);
    }
}

const KEVS: &str = "SELECT count(*) FROM cve_enrichment WHERE kev_added IS NOT NULL";

fn first() -> SigningKey {
    SigningKey::from_bytes(&[5; 32])
}

fn built(signer: &SigningKey, sequence: u64) -> Built<'_> {
    Built {
        signer,
        key_id: "k1",
        sequence,
        expires_in: 3600,
        public_key: true,
    }
}

#[tokio::test]
async fn the_first_feed_pins_its_key_and_applies() {
    let mut env = setup().await;
    let signer = first();
    publish(
        &env.site,
        &built(&signer, 1),
        &fixture("kev.json"),
        &fixture("epss.csv.gz"),
        120,
    );
    let synced = env.sync().await.unwrap();
    assert!(
        matches!(
            synced,
            Synced::Applied {
                sequence: 1,
                applied: 2,
                refused: 0
            }
        ),
        "{synced:?}"
    );
    assert_eq!(env.count(KEVS).await, 5);
    assert_eq!(
        env.count("SELECT count(*) FROM feed_trust_keys WHERE pinned")
            .await,
        1
    );
    assert_eq!(
        env.count("SELECT count(*) FROM audit_log WHERE action = 'feeds.mirror_pin'")
            .await,
        1
    );
    assert_eq!(
        env.count("SELECT count(*) FROM audit_log WHERE action = 'feeds.mirror_apply'")
            .await,
        1
    );
    assert_eq!(
        env.count("SELECT count(*) FROM feed_state WHERE origin = 'mirror'")
            .await,
        1
    );
    assert_eq!(env.status_error().await, None);
    env.finish().await;
}

#[tokio::test]
async fn the_same_feed_is_unchanged_and_a_new_one_downloads_only_what_changed() {
    let mut env = setup().await;
    let signer = first();
    let (kev, epss) = (fixture("kev.json"), fixture("epss.csv.gz"));
    publish(&env.site, &built(&signer, 1), &kev, &epss, 120);
    env.sync().await.unwrap();
    assert_eq!(blob_hits(&env.site), 2);
    // The same bytes again: nothing is fetched but feed.json.
    assert_eq!(env.sync().await.unwrap(), Synced::Unchanged);
    assert_eq!(blob_hits(&env.site), 2);
    // A new sequence where only EPSS changed.
    let changed = epss_changed();
    publish(&env.site, &built(&signer, 2), &kev, &changed, 60);
    let synced = env.sync().await.unwrap();
    assert!(
        matches!(
            synced,
            Synced::Applied {
                sequence: 2,
                applied: 1,
                refused: 0
            }
        ),
        "{synced:?}"
    );
    assert_eq!(
        blob_hits(&env.site),
        3,
        "only the changed file was downloaded"
    );
    assert_eq!(
        env.count("SELECT count(*) FROM audit_log WHERE action = 'feeds.mirror_apply'")
            .await,
        2
    );
    assert_eq!(
        env.count("SELECT count(*) FROM audit_log WHERE action = 'feeds.mirror_pin'")
            .await,
        1
    );
    env.finish().await;
}

#[tokio::test]
async fn a_different_key_is_refused_and_the_old_data_keeps_serving() {
    let mut env = setup().await;
    let signer = first();
    let (kev, epss) = (fixture("kev.json"), fixture("epss.csv.gz"));
    publish(&env.site, &built(&signer, 1), &kev, &epss, 120);
    env.sync().await.unwrap();
    // The same ids, another key.
    let other = SigningKey::from_bytes(&[6; 32]);
    publish(&env.site, &built(&other, 2), &kev, &epss_changed(), 60);
    let error = env.sync().await.unwrap_err();
    assert!(error.contains("another key"), "{error}");
    assert_eq!(env.status_error().await.as_deref(), Some(error.as_str()));
    assert_eq!(env.count(KEVS).await, 5);
    // A new key id from another key is not pinned over the first either.
    let mut next = built(&other, 3);
    next.key_id = "k2";
    publish(&env.site, &next, &kev, &epss_changed(), 60);
    assert!(env.sync().await.unwrap_err().contains("pinned"));
    assert_eq!(env.count("SELECT count(*) FROM feed_trust_keys").await, 1);
    assert_eq!(
        env.count("SELECT count(*) FROM audit_log WHERE action = 'feeds.mirror_refused'")
            .await,
        2
    );
    env.finish().await;
}

#[tokio::test]
async fn a_forged_feed_pins_nothing() {
    let mut env = setup().await;
    let signer = first();
    publish(
        &env.site,
        &built(&signer, 1),
        &fixture("kev.json"),
        &fixture("epss.csv.gz"),
        120,
    );
    // Tamper with the signed text after signing.
    let tampered = {
        let mut files = env.site.files.lock().unwrap();
        let text = String::from_utf8(files["feed.json"].clone()).unwrap();
        let text = text.replace("example.org", "example.com");
        files.insert("feed.json".into(), text.clone().into_bytes());
        text
    };
    assert!(tampered.contains("example.com"));
    let error = env.sync().await.unwrap_err();
    assert!(error.contains("bad_signature"), "{error}");
    assert_eq!(env.count("SELECT count(*) FROM feed_trust_keys").await, 0);
    assert_eq!(env.count(KEVS).await, 0);
    env.finish().await;
}

#[tokio::test]
async fn an_expired_feed_a_replay_and_a_wrong_file_change_nothing() {
    let mut env = setup().await;
    let signer = first();
    let (kev, epss) = (fixture("kev.json"), fixture("epss.csv.gz"));
    let mut late = built(&signer, 1);
    late.expires_in = -10;
    publish(&env.site, &late, &kev, &epss, 120);
    assert!(env.sync().await.unwrap_err().contains("expired"));
    assert_eq!(
        env.count("SELECT count(*) FROM feed_trust_keys").await,
        0,
        "an expired feed pins nothing"
    );

    publish(&env.site, &built(&signer, 5), &kev, &epss, 120);
    env.sync().await.unwrap();
    publish(&env.site, &built(&signer, 4), &kev, &epss_changed(), 60);
    assert!(env.sync().await.unwrap_err().contains("sequence_replay"));

    // A file whose bytes are not what the manifest says.
    let changed = epss_changed();
    publish(&env.site, &built(&signer, 6), &kev, &changed, 60);
    env.site
        .files
        .lock()
        .unwrap()
        .insert(format!("blobs/{}", hex(&changed)), b"not the file".to_vec());
    let error = env.sync().await.unwrap_err();
    assert!(error.contains("does not match"), "{error}");
    assert_eq!(env.count(KEVS).await, 5, "the old data keeps serving");
    assert!(
        std::fs::read_dir(&env.work).map_or(true, |mut d| d.next().is_none()),
        "the work folder is removed"
    );
    env.finish().await;
}

#[tokio::test]
async fn an_unreachable_mirror_is_a_status_error_only() {
    let mut env = setup().await;
    let signer = first();
    publish(
        &env.site,
        &built(&signer, 1),
        &fixture("kev.json"),
        &fixture("epss.csv.gz"),
        120,
    );
    env.sync().await.unwrap();
    let feed = env.site.files.lock().unwrap().remove("feed.json").unwrap();
    assert!(env.sync().await.is_err());
    assert!(env.status_error().await.is_some());
    assert_eq!(env.count(KEVS).await, 5);
    // Back again: the error clears.
    env.site
        .files
        .lock()
        .unwrap()
        .insert("feed.json".into(), feed);
    assert_eq!(env.sync().await.unwrap(), Synced::Unchanged);
    assert_eq!(env.status_error().await, None);
    env.finish().await;
}

#[tokio::test]
async fn a_feed_without_a_public_key_cannot_be_pinned() {
    let mut env = setup().await;
    let signer = first();
    let mut plain = built(&signer, 1);
    plain.public_key = false;
    publish(
        &env.site,
        &plain,
        &fixture("kev.json"),
        &fixture("epss.csv.gz"),
        120,
    );
    let error = env.sync().await.unwrap_err();
    assert!(error.contains("no public key"), "{error}");
    env.finish().await;
}

#[tokio::test]
async fn an_old_feed_served_again_is_an_error_once_it_has_expired() {
    let mut env = setup().await;
    let signer = first();
    let mut short = built(&signer, 1);
    short.expires_in = 3600;
    publish(
        &env.site,
        &short,
        &fixture("kev.json"),
        &fixture("epss.csv.gz"),
        120,
    );
    env.sync().await.unwrap();
    // The same bytes, an hour and a minute later.
    let later = Utc::now() + chrono::Duration::seconds(3660);
    let error = mirror::sync(&mut env.client, &mut env.mirror, later)
        .await
        .unwrap_err();
    assert!(error.contains("expired"), "{error}");
    assert_eq!(env.status_error().await.as_deref(), Some(error.as_str()));
    assert_eq!(env.count(KEVS).await, 5, "the old data keeps serving");
    env.finish().await;
}

#[tokio::test]
async fn a_failed_updateinfo_is_retried_with_its_repomd() {
    let mut env = setup().await;
    let signer = first();
    let updateinfo = fixture("updateinfo-f44.xml.zst");
    let repomd = format!(
        "<repomd><data type=\"updateinfo\"><checksum type=\"sha256\">{}</checksum>\
         <location href=\"repodata/{}-updateinfo.xml.zst\"/><size>{}</size></data></repomd>",
        hex(&updateinfo),
        hex(&updateinfo),
        updateinfo.len()
    )
    .into_bytes();
    let list: [(&str, &str, &str, &[u8]); 2] = [
        ("fedora-44-x86_64", "repomd", "repomd.xml", &repomd),
        (
            "fedora-44-x86_64",
            "updateinfo",
            "updateinfo.xml.zst",
            &updateinfo,
        ),
    ];
    publish_files(&env.site, &built(&signer, 1), &list, 120);
    // The updateinfo cannot be downloaded the first time.
    let name = format!("blobs/{}", hex(&updateinfo));
    let held = env.site.files.lock().unwrap().remove(&name).unwrap();
    assert!(env.sync().await.is_err());
    assert_eq!(
        env.count("SELECT count(*) FROM feed_applied_files WHERE kind = 'repomd'")
            .await,
        1,
        "the repomd.xml is applied on its own"
    );
    env.site.files.lock().unwrap().insert(name, held);
    env.sync().await.unwrap();
    assert_eq!(env.status_error().await, None);
    assert_eq!(
        env.count("SELECT count(*) FROM feed_applied_files WHERE kind = 'updateinfo'")
            .await,
        1
    );
    env.finish().await;
}

#[tokio::test]
async fn expiry_follows_the_feed_applied_last_not_an_older_key() {
    let mut env = setup().await;
    let (kev, epss) = (fixture("kev.json"), fixture("epss.csv.gz"));
    let first_key = first();
    let mut short = built(&first_key, 1);
    short.expires_in = 3600;
    publish(&env.site, &short, &kev, &epss, 120);
    env.sync().await.unwrap();
    // The administrator trusts a second key and the mirror switches to it.
    let second = SigningKey::from_bytes(&[8; 32]);
    let admin = env.db.pool.get().await.unwrap();
    admin
        .execute(
            "INSERT INTO feed_trust_keys (feed_id, key_id, public_key, added_at) \
             VALUES ('site', 'k2', $1, now())",
            &[&second.verifying_key().to_bytes().as_slice()],
        )
        .await
        .unwrap();
    let mut next = built(&second, 1);
    next.key_id = "k2";
    next.expires_in = 7 * 86_400;
    publish(&env.site, &next, &kev, &epss_changed(), 60);
    env.sync().await.unwrap();
    // After the first key's feed has expired, the current one is fresh.
    let later = Utc::now() + chrono::Duration::seconds(2 * 86_400);
    assert_eq!(
        mirror::sync(&mut env.client, &mut env.mirror, later).await,
        Ok(Synced::Unchanged)
    );
    assert_eq!(env.status_error().await, None);
    env.finish().await;
}
