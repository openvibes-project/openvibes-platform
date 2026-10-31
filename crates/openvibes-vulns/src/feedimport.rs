//! Applying a verified feed (openvibes-protocol `spec/feed-v1.md`, step 7):
//! each file is checked against its manifest entry, then read by the importer
//! its kind names, with that importer's own limits and validation. A file that
//! fails does not stop the others; the manifest itself is recorded first, and
//! an older one (or a different one with the same sequence) is refused before
//! any file is read. The blobs are the caller's private copies, never the
//! operator's own tree.

use std::{collections::HashMap, fs::File, io::Read, path::Path};

use chrono::{DateTime, TimeZone, Utc};
use platform_store::{
    Client, StoreError,
    feeds::{self, Accepted as AcceptedRow, AppliedFile},
};
use sha2::{Digest, Sha256};

use crate::{
    bundle::Unpacked,
    enrich, feed,
    feedfmt::{self, Accepted, FileEntry, Kind},
    osv, osv_fetch, repodata,
};

/// What happened to one file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// Imported; the text says how much.
    Applied(String),
    /// The same file was applied before, so nothing was read again.
    Unchanged,
    /// Not applied, and why.
    Refused(String),
    /// Left alone on purpose, and why.
    Skipped(String),
}

/// One file's line in the report.
#[derive(Clone, Debug)]
pub struct FileReport {
    /// The file's source.
    pub source: String,
    /// The file's kind.
    pub kind: Kind,
    /// The file's name.
    pub name: String,
    /// What happened.
    pub outcome: Outcome,
}

fn time(seconds: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(seconds, 0).single().unwrap_or_default()
}

/// Streams a file once for its length and hex SHA-256.
fn measure(path: &Path) -> std::io::Result<(u64, String)> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 16];
    let mut length = 0u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        length += read as u64;
    }
    Ok((length, feedfmt::hex(&hasher.finalize())))
}

fn read_all(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let mut data = Vec::new();
    File::open(path)
        .and_then(|file| file.take(limit + 1).read_to_end(&mut data))
        .map_err(|e| format!("cannot read the file: {e}"))?;
    if data.len() as u64 > limit {
        return Err("larger than its limit".into());
    }
    Ok(data)
}

fn ecosystem(source: &str) -> Option<&'static str> {
    match source {
        "debian" => Some("Debian"),
        "ubuntu" => Some("Ubuntu"),
        "rocky-linux" => Some("Rocky Linux"),
        "almalinux" => Some("AlmaLinux"),
        _ => None,
    }
}

/// Applies the files of an accepted feed. `only` limits it to these sources
/// (empty: all). `origin` is `mirror` or `bundle`.
///
/// # Errors
/// The database refused the record of the manifest itself; a file's own
/// failure is a [`Outcome::Refused`] in the report.
pub async fn apply(
    client: &mut Client,
    feed_files: &Unpacked,
    accepted: &Accepted,
    origin: &str,
    only: &[String],
    now: DateTime<Utc>,
) -> Result<Vec<FileReport>, String> {
    if let Some(unknown) = only
        .iter()
        .find(|name| !accepted.manifest.files.iter().any(|f| &f.source == *name))
    {
        return Err(format!("the feed has no source {unknown}"));
    }
    let recorded = feeds::record_accepted(
        client,
        &AcceptedRow {
            feed_id: &accepted.feed_id,
            key_id: &accepted.key_id,
            sequence: accepted.manifest.sequence,
            manifest_digest: accepted.digest,
            created_at: time(accepted.manifest.created_at),
            expires_at: time(accepted.manifest.expires_at),
            origin,
        },
        now,
    )
    .await
    .map_err(|e| e.to_string())?;
    if !recorded {
        return Err("a newer feed was accepted in the meantime; nothing was applied".into());
    }
    let known: HashMap<(String, String, String), AppliedFile> = feeds::applied_files(client)
        .await
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|file| {
            (
                (file.source.clone(), file.kind.clone(), file.name.clone()),
                file,
            )
        })
        .collect();
    // NVD last: it keeps only CVEs the advisories above name. Its files are
    // read again, even unchanged, when this run added advisories or a new
    // installed product needs its ranges (the API sync does the same by
    // reading further back).
    let mut ordered: Vec<&FileEntry> = accepted.manifest.files.iter().collect();
    ordered.sort_by_key(|entry| entry.kind == Kind::Nvd);
    let mut reread = if ordered.iter().any(|e| e.kind == Kind::Nvd) {
        crate::cpe::ensure_products(client, "fedora")
            .await
            .map_err(|e| e.to_string())?
    } else {
        false
    };
    let mut reports = Vec::new();
    for entry in ordered {
        let outcome = if !only.is_empty() && !only.contains(&entry.source) {
            Outcome::Skipped("not selected".into())
        } else {
            apply_file(client, feed_files, accepted, entry, &known, now, reread)
                .await
                .map_err(|e| e.to_string())?
        };
        if matches!(entry.kind, Kind::Updateinfo | Kind::Osv)
            && matches!(outcome, Outcome::Applied(_))
        {
            reread = true;
        }
        reports.push(FileReport {
            source: entry.source.clone(),
            kind: entry.kind,
            name: entry.name.clone(),
            outcome,
        });
    }
    // CPE findings follow the stored ranges and the Fedora advisories.
    if reports.iter().any(|r| {
        matches!(r.kind, Kind::Nvd | Kind::Updateinfo) && matches!(r.outcome, Outcome::Applied(_))
    }) {
        crate::cpe::refresh_all(client, now).await;
    }
    Ok(reports)
}

async fn apply_file(
    client: &mut Client,
    feed_files: &Unpacked,
    accepted: &Accepted,
    entry: &FileEntry,
    known: &HashMap<(String, String, String), AppliedFile>,
    now: DateTime<Utc>,
    reread: bool,
) -> Result<Outcome, StoreError> {
    let Some(path) = feed_files.blob(&entry.sha256) else {
        return Ok(Outcome::Refused("the blob is not in the feed".into()));
    };
    let previous = known.get(&(
        entry.source.clone(),
        entry.kind.as_str().to_owned(),
        entry.name.clone(),
    ));
    let (length, digest) = match measure(&path) {
        Ok(measured) => measured,
        Err(error) => return Ok(Outcome::Refused(format!("cannot read the blob: {error}"))),
    };
    if let Err(refusal) = feedfmt::check_file(
        entry,
        length,
        &digest,
        previous.map(|file| file.fetched_at.timestamp()),
        entry.kind.max_size(),
    ) {
        return Ok(Outcome::Refused(match refusal {
            feedfmt::FileRefusal::OlderThanApplied => "older than the file applied before".into(),
            other => format!("{} ", other.as_str()).trim().replace('_', " "),
        }));
    }
    if previous.is_some_and(|file| hex_of(&file.sha256) == entry.sha256)
        && !(reread && entry.kind == Kind::Nvd)
    {
        return Ok(Outcome::Unchanged);
    }
    let step = match entry.kind {
        Kind::Repomd => Ok(Step::Done("kept for the updateinfo check".into())),
        Kind::Updateinfo => updateinfo(client, feed_files, accepted, entry, &path, now).await,
        Kind::Osv => osv_file(client, entry, &path, now).await,
        Kind::Kev | Kind::Epss | Kind::Euvd => enrichment(client, entry, &path, now).await,
        Kind::Nvd => nvd_file(client, &path, now).await,
    };
    match step {
        Ok(Step::Done(detail)) => {
            let newest = feeds::record_file(
                client,
                &AppliedFile {
                    source: entry.source.clone(),
                    kind: entry.kind.as_str().to_owned(),
                    name: entry.name.clone(),
                    sha256: decode(&entry.sha256),
                    fetched_at: time(entry.fetched_at),
                },
                &accepted.feed_id,
                &accepted.key_id,
                accepted.manifest.sequence,
                now,
            )
            .await?;
            Ok(if newest {
                Outcome::Applied(detail)
            } else {
                Outcome::Refused("a newer file was applied in the meantime".into())
            })
        }
        Ok(Step::Skip(why)) => Ok(Outcome::Skipped(why)),
        Err(message) => Ok(Outcome::Refused(message)),
    }
}

/// How an importer left a file: read and to be recorded, or left alone.
enum Step {
    Done(String),
    Skip(String),
}

fn hex_of(bytes: &[u8; 32]) -> String {
    feedfmt::hex(bytes)
}

fn decode(hex: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(2 * i..2 * i + 2).unwrap_or("00"), 16).unwrap_or(0);
    }
    out
}

async fn updateinfo(
    client: &mut Client,
    feed_files: &Unpacked,
    accepted: &Accepted,
    entry: &FileEntry,
    path: &Path,
    now: DateTime<Utc>,
) -> Result<Step, String> {
    let source: feed::SourceId = entry.source.parse()?;
    // The repository index in the same feed must name this very file.
    let index = accepted
        .manifest
        .files
        .iter()
        .find(|f| f.kind == Kind::Repomd && f.source == entry.source)
        .ok_or("no repomd.xml for this source in the feed")?;
    let repomd = feed_files
        .blob(&index.sha256)
        .ok_or("the repomd.xml blob is not in the feed")
        .and_then(|p| read_all(&p, Kind::Repomd.max_size()).map_err(|_| "repomd.xml unreadable"))?;
    if feedfmt::hex(&Sha256::digest(&repomd)) != index.sha256 {
        return Err("repomd.xml does not match its manifest entry".into());
    }
    let location = repodata::updateinfo_location(&repomd)
        .map_err(|_| "repomd.xml does not name an updateinfo file".to_owned())?;
    if feedfmt::hex(&location.sha256) != entry.sha256 {
        return Err("updateinfo does not match repomd.xml".into());
    }
    let content = read_all(path, Kind::Updateinfo.max_size())?;
    let report = feed::import(client, &source, &content, now)
        .await
        .map_err(|e| e.to_string())?;
    Ok(Step::Done(format!(
        "{} advisories into {}; {} open",
        report.advisories,
        source.name(),
        report.open
    )))
}

async fn osv_file(
    client: &mut Client,
    entry: &FileEntry,
    path: &Path,
    now: DateTime<Utc>,
) -> Result<Step, String> {
    let ecosystem = ecosystem(&entry.source).ok_or("unknown ecosystem")?;
    let named: Vec<osv::Release> = entry
        .releases
        .iter()
        .flatten()
        .map(|name| name.parse::<osv::Release>())
        .collect::<Result<_, _>>()?;
    if named.iter().any(|release| release.ecosystem() != ecosystem) {
        return Err(format!("a release does not belong to {ecosystem}"));
    }
    // Only the releases hosts run are read, as the live sync does.
    let wanted: Vec<osv::Release> = osv_fetch::releases_by_ecosystem(client)
        .await
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|(name, _)| *name == ecosystem)
        .flat_map(|(_, releases)| releases)
        .filter(|release| named.contains(release))
        .collect();
    if wanted.is_empty() {
        return Ok(Step::Skip(
            "no host runs a release in this file; nothing read".into(),
        ));
    }
    let (target, releases) = (path.to_owned(), wanted.clone());
    let found = tokio::task::spawn_blocking(move || {
        let file = File::open(target).map_err(|e| e.to_string())?;
        osv::read_zip(
            std::io::BufReader::new(file),
            &releases,
            osv::MAX_OPEN_BYTES,
        )
        .map_err(|_| "not a readable OSV all.zip".to_owned())
    })
    .await
    .map_err(|_| "reading task failed".to_owned())??;
    let sha256: [u8; 32] = decode(&entry.sha256);
    let (mut advisories, mut open) = (0, 0);
    for (release, found) in wanted.iter().zip(found) {
        let name = release.name();
        let key = (name.as_str(), release.os_id, release.version.as_str(), "");
        let report = feed::store_and_match(client, key, &found.advisories, sha256, now)
            .await
            .map_err(|e| e.to_string())?;
        advisories += report.advisories;
        open += report.open;
    }
    Ok(Step::Done(format!(
        "{advisories} advisories into {} release(s); {open} open",
        wanted.len()
    )))
}

async fn enrichment(
    client: &mut Client,
    entry: &FileEntry,
    path: &Path,
    now: DateTime<Utc>,
) -> Result<Step, String> {
    let source = match entry.kind {
        Kind::Kev => enrich::Source::Kev,
        Kind::Epss => enrich::Source::Epss,
        _ => enrich::Source::Euvd,
    };
    let content = read_all(path, entry.kind.max_size())?;
    let count = enrich::import(client, source, &content, now)
        .await
        .map_err(|e| e.to_string())?;
    Ok(Step::Done(format!("{count} CVEs from {source}")))
}

async fn nvd_file(client: &mut Client, path: &Path, now: DateTime<Utc>) -> Result<Step, String> {
    let content = read_all(path, Kind::Nvd.max_size())?;
    let page = enrich::parse_slim(&content, enrich::SLIM_NVD_MAX_OPEN)
        .map_err(|_| "not a readable slim NVD file".to_owned())?;
    let store = |e: StoreError| e.to_string();
    // The enrichment of CVEs advisories name, and the ranges of products
    // installed packages could be: what the API sync keeps.
    let named = platform_store::enrichment::upsert_nvd(client, &page.entries, now)
        .await
        .map_err(store)?;
    let ids: Vec<String> = page.entries.iter().map(|e| e.cve_id.clone()).collect();
    let ranges = platform_store::cpe::replace_applicability(client, &ids, &page.applicability)
        .await
        .map_err(store)?;
    Ok(Step::Done(format!(
        "{} CVEs of {}: {named} named by advisories, {ranges} ranges kept",
        page.entries.len(),
        page.year
    )))
}
