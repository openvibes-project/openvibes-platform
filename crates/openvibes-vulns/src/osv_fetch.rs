//! Keeping OSV current (OSV spec D4). Per ecosystem (Debian, Ubuntu, Rocky
//! Linux, AlmaLinux): the first sync, a release not yet imported, or more
//! changes than `max_changes` download the ecosystem's `all.zip` once and
//! import every release hosts run from it; otherwise only the records
//! OSV's `modified_id.csv` lists since the last sync are fetched, one by
//! one (a 304 when nothing changed).

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use platform_store::{Client, StoreError, vulns};
use sha2::{Digest, Sha256};

use crate::{
    feed::{self, ImportReport},
    fetch::{self, Fetcher},
    matching,
    osv::{self, Release},
};

/// OSV.dev's bucket of per-ecosystem files.
pub const OSV_URL: &str = "https://osv-vulnerabilities.storage.googleapis.com";
/// Changes above which one download of the whole file is cheaper.
pub const MAX_CHANGES: usize = 5000;
/// Largest `modified_id.csv` or single record read.
const MAX_INDEX: u64 = 64 << 20;

/// Where and how OSV is fetched.
pub struct OsvSync {
    fetcher: Fetcher,
    base: String,
    dir: PathBuf,
    max_zip: u64,
    max_changes: usize,
}

/// What a sync did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Synced {
    /// Nothing changed since the last sync.
    Unchanged,
    /// The whole file was imported: advisories over all releases, and the
    /// vulnerabilities open on them afterwards.
    Full {
        /// Advisories stored.
        advisories: usize,
        /// Open vulnerabilities.
        open: usize,
    },
    /// Only changed records were fetched and imported.
    Changes {
        /// Records fetched.
        records: usize,
        /// Open vulnerabilities on the releases afterwards.
        open: usize,
    },
}

impl OsvSync {
    /// Syncs from `base` (HTTPS; plain HTTP only on loopback), downloading
    /// `all.zip` files of at most `max_zip` bytes into `dir`.
    pub fn new(
        fetcher: &Fetcher,
        base: &str,
        dir: &Path,
        max_zip: u64,
        max_changes: usize,
    ) -> Result<Self, String> {
        fetch::check_source_url(base)?;
        Ok(Self {
            fetcher: fetcher.clone(),
            base: base.trim_end_matches('/').to_owned(),
            dir: dir.to_owned(),
            max_zip,
            max_changes,
        })
    }

    fn url(&self, ecosystem: &str, file: &str) -> String {
        format!("{}/{}/{file}", self.base, ecosystem.replace(' ', "%20"))
    }
}

/// The source name holding an ecosystem's sync point, e.g. `osv-debian`.
fn state_name(ecosystem: &str) -> String {
    format!("osv-{}", ecosystem.to_ascii_lowercase().replace(' ', "-"))
}

/// The releases hosts run that OSV covers, grouped by ecosystem.
pub async fn releases_by_ecosystem(
    client: &Client,
) -> Result<Vec<(&'static str, Vec<Release>)>, StoreError> {
    let rows = client
        .query(
            "SELECT DISTINCT os_id, os_release FROM agents
             WHERE os_id IN ('rocky', 'almalinux', 'debian', 'ubuntu')
               AND os_release IS NOT NULL ORDER BY 1, 2",
            &[],
        )
        .await?;
    let mut groups: Vec<(&'static str, Vec<Release>)> = Vec::new();
    for row in rows {
        let name = format!("{}-{}", row.get::<_, String>(0), row.get::<_, String>(1));
        let Ok(release) = name.parse::<Release>() else {
            continue;
        };
        match groups.iter_mut().find(|(e, _)| *e == release.ecosystem()) {
            Some((_, releases)) => releases.push(release),
            None => groups.push((release.ecosystem(), vec![release])),
        }
    }
    Ok(groups)
}

/// `modified_id.csv` lines newer than `since`, newest first, as
/// (time, id); `None` once more than `limit` are newer.
fn changes_since(
    csv: &str,
    since: Option<DateTime<Utc>>,
    limit: usize,
) -> Option<(Vec<String>, Option<DateTime<Utc>>)> {
    let mut ids = Vec::new();
    let mut newest = None;
    for line in csv.lines() {
        let Some((time, id)) = line.split_once(',') else {
            continue;
        };
        let Ok(time) = DateTime::parse_from_rfc3339(time.trim()) else {
            continue;
        };
        let time = time.with_timezone(&Utc);
        newest = newest.max(Some(time));
        if since.is_some_and(|since| time <= since) {
            break;
        }
        ids.push(id.trim().to_owned());
        if ids.len() > limit {
            return None;
        }
    }
    Some((ids, newest))
}

/// Syncs one ecosystem for the releases hosts run on it. Failures are
/// recorded on the ecosystem's source (`osv-debian`) and leave the sync
/// point where it was, so the next run retries.
pub async fn sync(
    client: &mut Client,
    osv: &OsvSync,
    ecosystem: &str,
    releases: &[Release],
    now: DateTime<Utc>,
) -> Result<Synced, String> {
    let state = state_name(ecosystem);
    let result = run(client, osv, ecosystem, &state, releases, now).await;
    if let Err(error) = &result {
        let key = (state.as_str(), "osv", "", "");
        vulns::record_feed(client, key, Err(error), now)
            .await
            .map_err(|e| e.to_string())?;
    }
    result
}

async fn run(
    client: &mut Client,
    osv: &OsvSync,
    ecosystem: &str,
    state: &str,
    releases: &[Release],
    now: DateTime<Utc>,
) -> Result<Synced, String> {
    let store = |e: StoreError| e.to_string();
    let cursor = vulns::feed_cursor(client, state).await.map_err(store)?;
    let mut all_imported = true;
    for release in releases {
        all_imported &= vulns::feed_digest(client, &release.name())
            .await
            .map_err(store)?
            .is_some();
    }
    let etag = if cursor.is_some() && all_imported {
        vulns::feed_etag(client, state).await.map_err(store)?
    } else {
        None
    };
    let (network, url) = (osv.fetcher.clone(), osv.url(ecosystem, "modified_id.csv"));
    let index = tokio::task::spawn_blocking(move || network.get_if_changed(&url, etag.as_deref()))
        .await
        .map_err(|_| "download task failed".to_owned())??;
    let Some((csv, csv_etag)) = index else {
        vulns::touch_feed(client, state, now).await.map_err(store)?;
        return Ok(Synced::Unchanged);
    };
    if csv.len() as u64 > MAX_INDEX {
        return Err("modified_id.csv larger than the size cap".into());
    }
    let csv = String::from_utf8_lossy(&csv).into_owned();
    let changes = changes_since(&csv, cursor.filter(|_| all_imported), osv.max_changes);
    let (synced, newest) = match changes {
        Some((ids, newest)) if cursor.is_some() && all_imported => (
            changed_records(client, osv, ecosystem, releases, &ids, now).await?,
            newest,
        ),
        _ => {
            let newest = changes_since(&csv, None, usize::MAX).and_then(|(_, n)| n);
            (full(client, osv, ecosystem, releases, now).await?, newest)
        }
    };
    let digest: [u8; 32] = Sha256::digest(csv.as_bytes()).into();
    let key = (state, "osv", "", "");
    let count = i32::try_from(releases.len()).unwrap_or(i32::MAX);
    vulns::record_feed(client, key, Ok((digest, count)), now)
        .await
        .map_err(store)?;
    vulns::set_feed_etag(client, state, csv_etag.as_deref())
        .await
        .map_err(store)?;
    if let Some(newest) = newest {
        vulns::set_feed_cursor(client, state, newest)
            .await
            .map_err(store)?;
    }
    Ok(synced)
}

/// Downloads the ecosystem's `all.zip`, reads it once for every release,
/// and stores and matches each; the download is removed afterwards.
async fn full(
    client: &mut Client,
    osv: &OsvSync,
    ecosystem: &str,
    releases: &[Release],
    now: DateTime<Utc>,
) -> Result<Synced, String> {
    let path = osv.dir.join(format!("{}.zip", state_name(ecosystem)));
    let (network, url, target, limit) = (
        osv.fetcher.clone(),
        osv.url(ecosystem, "all.zip"),
        path.clone(),
        osv.max_zip,
    );
    let owned = releases.to_vec();
    let parsed = tokio::task::spawn_blocking(move || {
        let sha256 = network.download_to(&url, &target, limit)?;
        let file = std::fs::File::open(&target).map_err(|e| e.to_string())?;
        let found = osv::read_zip(std::io::BufReader::new(file), &owned, osv::MAX_OPEN_BYTES)
            .map_err(|_| "not a readable OSV all.zip".to_owned());
        found.map(|found| (sha256, found))
    })
    .await
    .map_err(|_| "download task failed".to_owned());
    let _ = std::fs::remove_file(&path);
    let (sha256, found) = parsed??;
    let (mut advisories, mut open) = (0, 0);
    for (release, found) in releases.iter().zip(found) {
        let name = release.name();
        let key = (name.as_str(), release.os_id, release.version.as_str(), "");
        let ImportReport {
            advisories: stored,
            open: opened,
        } = feed::store_and_match(client, key, &found.advisories, sha256, now)
            .await
            .map_err(|e| e.to_string())?;
        advisories += stored;
        open += opened;
    }
    Ok(Synced::Full { advisories, open })
}

/// Fetches the changed records of the kinds these releases use, stores
/// their advisories, and re-matches the releases they touch.
async fn changed_records(
    client: &mut Client,
    osv: &OsvSync,
    ecosystem: &str,
    releases: &[Release],
    ids: &[String],
    now: DateTime<Utc>,
) -> Result<Synced, String> {
    let store = |e: StoreError| e.to_string();
    let wanted: Vec<&String> = ids
        .iter()
        .filter(|id| releases.iter().any(|r| r.accepts(id)))
        .collect();
    let mut rows = vec![Vec::new(); releases.len()];
    for id in &wanted {
        let (network, url) = (
            osv.fetcher.clone(),
            osv.url(ecosystem, &format!("{id}.json")),
        );
        let body = tokio::task::spawn_blocking(move || network.get_with(&url, &[]))
            .await
            .map_err(|_| "download task failed".to_owned())??;
        // A record OSV cannot serve or parse is skipped, not fatal.
        let Ok(record) = osv::parse(&body) else {
            continue;
        };
        for (release, rows) in releases.iter().zip(rows.iter_mut()) {
            rows.extend(osv::advisory(&record, release));
        }
    }
    let mut open = 0;
    for (release, rows) in releases.iter().zip(rows) {
        let name = release.name();
        if !rows.is_empty() {
            vulns::replace_advisories(client, &name, release.os_id, &release.version, &rows, now)
                .await
                .map_err(store)?;
        }
        open += matching::match_release(client, release.os_id, &release.version, now)
            .await
            .map_err(store)?;
        vulns::touch_feed(client, &name, now).await.map_err(store)?;
    }
    Ok(Synced::Changes {
        records: wanted.len(),
        open,
    })
}
