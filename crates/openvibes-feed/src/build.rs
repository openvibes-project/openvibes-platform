//! Building a feed: fetch each wanted upstream (conditionally, with the same
//! fetcher, caps and proxy setting the platform's vulnerability service
//! uses), store the bytes as immutable blobs named by SHA-256, then sign and
//! write `feed.json` last, so a reader never sees a manifest whose blobs are
//! not there.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use ed25519_dalek::Signer;
use openvibes_vulns::{
    feed::SourceId,
    feedfmt::{self, Kind, TrustedKey},
    fetch::{self, Fetcher},
    osv::Release,
    repodata::hex,
    sources,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{config::Config, key::FeedKey, nvd};

/// One file the last build held: enough to reuse it without fetching.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct Held {
    pub(crate) name: String,
    pub(crate) sha256: String,
    pub(crate) size: u64,
    pub(crate) fetched_at: i64,
    pub(crate) upstream: String,
    #[serde(default)]
    pub(crate) etag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) releases: Option<Vec<String>>,
}

/// What `state.json` keeps between builds.
#[derive(Debug, Default, Deserialize, Serialize)]
struct State {
    sequence: u64,
    /// `source/kind` to the file last published for it.
    files: BTreeMap<String, Held>,
    /// Blobs of the manifest before the current one, kept for readers still
    /// fetching it.
    previous: Vec<String>,
}

#[derive(Serialize)]
struct OutFile<'a> {
    source: &'a str,
    kind: &'a str,
    name: &'a str,
    sha256: &'a str,
    size: u64,
    fetched_at: i64,
    upstream: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    releases: Option<&'a Vec<String>>,
}

#[derive(Serialize)]
struct OutManifest<'a> {
    sequence: u64,
    created_at: i64,
    expires_at: i64,
    files: Vec<OutFile<'a>>,
}

#[derive(Serialize)]
struct OutEnvelope<'a> {
    format: u32,
    feed_id: &'a str,
    key_id: &'a str,
    signature: String,
    manifest: &'a str,
}

/// What a build did.
#[derive(Debug)]
pub struct Report {
    /// One line per file.
    pub lines: Vec<String>,
    /// Sources that could not be fetched (a previous copy was kept if any).
    pub failed: usize,
    /// The published sequence.
    pub sequence: u64,
}

/// Where to build and what to include.
pub struct Options<'a> {
    /// The tree to write: `feed.json`, `blobs/`, `state.json`.
    pub out: &'a Path,
    /// Only these sources (empty: all configured).
    pub only: &'a [String],
    /// Days the feed stays valid.
    pub valid_days: u32,
}

pub(crate) fn blobs(out: &Path) -> PathBuf {
    out.join("blobs")
}

pub(crate) fn blob_exists(out: &Path, sha: &str) -> bool {
    fs::symlink_metadata(blobs(out).join(sha)).is_ok_and(|m| m.is_file())
}

fn temp_path(out: &Path, tag: &str) -> PathBuf {
    blobs(out).join(format!(".tmp-{}-{tag}", std::process::id()))
}

/// Writes `bytes` as the blob named by its hash; returns that hash.
pub(crate) fn store(out: &Path, bytes: &[u8]) -> Result<String, String> {
    let sha = hex(&Sha256::digest(bytes));
    if !blob_exists(out, &sha) {
        let tmp = temp_path(out, "bytes");
        fs::write(&tmp, bytes).map_err(|e| format!("cannot write a blob: {e}"))?;
        fs::rename(&tmp, blobs(out).join(&sha)).map_err(|e| format!("cannot write a blob: {e}"))?;
    }
    Ok(sha)
}

fn wants(only: &[String], source: &str) -> bool {
    only.is_empty() || only.iter().any(|s| s == source)
}

fn parse_hex(text: &str) -> Option<[u8; 32]> {
    (text.len() == 64).then_some(())?;
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

/// A small file fetched by URL with an ETag, stored whole.
fn small(
    fetcher: &Fetcher,
    out: &Path,
    url: &str,
    (kind, name): (Kind, &str),
    prev: Option<&Held>,
    now: i64,
) -> Result<Held, String> {
    let kept = prev.filter(|p| blob_exists(out, &p.sha256));
    let etag = kept.and_then(|p| p.etag.as_deref());
    match fetcher.get_if_changed(url, etag)? {
        None => {
            let kept = kept.ok_or("not modified, but no earlier copy")?;
            Ok(Held {
                fetched_at: now,
                ..kept.clone()
            })
        }
        Some((body, etag)) => finish(out, &body, kind, name, url, etag, now),
    }
}

fn finish(
    out: &Path,
    body: &[u8],
    kind: Kind,
    name: &str,
    url: &str,
    etag: Option<String>,
    now: i64,
) -> Result<Held, String> {
    let size = body.len() as u64;
    if size == 0 || size > kind.max_size() {
        return Err(format!(
            "{name} is {size} bytes, outside the format's limit"
        ));
    }
    Ok(Held {
        name: name.to_owned(),
        sha256: store(out, body)?,
        size,
        fetched_at: now,
        upstream: url.to_owned(),
        etag,
        releases: None,
    })
}

fn fedora(
    fetcher: &Fetcher,
    out: &Path,
    config: &Config,
    source: &str,
    prev: (Option<&Held>, Option<&Held>),
    now: i64,
) -> Result<(Held, Held), String> {
    let id: SourceId = source.parse()?;
    fn usable<'a>(out: &Path, held: Option<&'a Held>) -> Option<&'a Held> {
        held.filter(|h| blob_exists(out, &h.sha256))
    }
    let (repomd, info) = (usable(out, prev.0), usable(out, prev.1));
    let known = repomd.and(info).and_then(|h| parse_hex(&h.sha256));
    let upstream = config
        .metalink_url
        .replace("{release}", &id.os_version)
        .replace("{arch}", &id.arch);
    match fetcher.fedora_files(&id, known)? {
        None => {
            let (repomd, info) = (
                repomd.ok_or("unchanged without a copy")?,
                info.ok_or("unchanged without a copy")?,
            );
            Ok((
                Held {
                    fetched_at: now,
                    ..repomd.clone()
                },
                Held {
                    fetched_at: now,
                    ..info.clone()
                },
            ))
        }
        Some(files) => {
            let compression = files.name.rsplit_once('.').map_or("", |(_, ext)| ext);
            let name = match compression {
                "zst" | "gz" | "xz" | "bz2" => format!("updateinfo.xml.{compression}"),
                _ => "updateinfo.xml".to_owned(),
            };
            Ok((
                finish(
                    out,
                    &files.repomd,
                    Kind::Repomd,
                    "repomd.xml",
                    &upstream,
                    None,
                    now,
                )?,
                finish(
                    out,
                    &files.updateinfo,
                    Kind::Updateinfo,
                    &name,
                    &upstream,
                    None,
                    now,
                )?,
            ))
        }
    }
}

fn osv(
    fetcher: &Fetcher,
    out: &Path,
    config: &Config,
    (ecosystem, releases): (&str, &[String]),
    prev: Option<&Held>,
    now: i64,
) -> Result<Held, String> {
    let url = format!(
        "{}/{}/all.zip",
        config.osv_url.trim_end_matches('/'),
        ecosystem.replace(' ', "%20")
    );
    let kept = prev.filter(|p| blob_exists(out, &p.sha256));
    let tmp = temp_path(out, "osv");
    let limit = config.max_osv_bytes.min(Kind::Osv.max_size());
    let found =
        fetcher.download_if_changed(&url, &tmp, limit, kept.and_then(|p| p.etag.as_deref()));
    let result = match found {
        Err(error) => Err(error),
        Ok(None) => kept
            .map(|k| Held {
                fetched_at: now,
                releases: Some(releases.to_vec()),
                ..k.clone()
            })
            .ok_or_else(|| "not modified, but no earlier copy".to_owned()),
        Ok(Some((digest, etag))) => {
            let sha = hex(&digest);
            let size = fs::metadata(&tmp)
                .map_err(|e| format!("cannot read the download: {e}"))?
                .len();
            if size == 0 {
                Err("the download is empty".to_owned())
            } else {
                if blob_exists(out, &sha) {
                    let _ = fs::remove_file(&tmp);
                } else {
                    fs::rename(&tmp, blobs(out).join(&sha))
                        .map_err(|e| format!("cannot write a blob: {e}"))?;
                }
                Ok(Held {
                    name: "all.zip".into(),
                    sha256: sha,
                    size,
                    fetched_at: now,
                    upstream: url.clone(),
                    etag,
                    releases: Some(releases.to_vec()),
                })
            }
        }
    };
    let _ = fs::remove_file(&tmp);
    result
}

/// Builds and publishes one feed.
///
/// # Errors
/// Nothing could be fetched or reused, or the tree cannot be written. A
/// source that fails but has an earlier copy keeps that copy and counts in
/// [`Report::failed`].
pub fn run(config: &Config, key: &FeedKey, options: &Options<'_>) -> Result<Report, String> {
    let out = options.out;
    if !(1..=30).contains(&options.valid_days) {
        return Err("valid days is 1 to 30".into());
    }
    fs::create_dir_all(blobs(out)).map_err(|e| format!("cannot create {}: {e}", out.display()))?;
    let state: State = match fs::read_to_string(out.join("state.json")) {
        Ok(text) => serde_json::from_str(&text).map_err(|_| "state.json is damaged; remove it")?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
        Err(e) => return Err(format!("cannot read state.json: {e}")),
    };
    let now = Utc::now().timestamp();
    for url in [
        &config.kev_url,
        &config.epss_url,
        &config.euvd_url,
        &config.osv_url,
        &config.nvd_url,
    ] {
        if !url.is_empty() {
            fetch::check_source_url(url)?;
        }
    }
    let fetcher = Fetcher::new(
        &config.metalink_url,
        config.proxy_url.as_deref(),
        config.max_file_bytes,
    )?;

    let mut got = Collected {
        out: out.to_owned(),
        ..Collected::default()
    };
    let prev = |key: &str| state.files.get(key);

    if wants(options.only, "kev") && !config.kev_url.is_empty() {
        let result = small(
            &fetcher,
            out,
            &config.kev_url,
            (Kind::Kev, "known_exploited_vulnerabilities.json"),
            prev("kev/kev"),
            now,
        );
        got.one("kev", "kev/kev", result, prev("kev/kev"));
    }
    if wants(options.only, "epss") && !config.epss_url.is_empty() {
        let result = small(
            &fetcher,
            out,
            &config.epss_url,
            (Kind::Epss, "epss_scores-current.csv.gz"),
            prev("epss/epss"),
            now,
        );
        got.one("epss", "epss/epss", result, prev("epss/epss"));
    }
    if wants(options.only, "euvd") && !config.euvd_url.is_empty() {
        let result = sources::fetch_euvd_list(&fetcher, &config.euvd_url, 100).and_then(|body| {
            finish(
                out,
                &body,
                Kind::Euvd,
                "exploited.json",
                &config.euvd_url,
                None,
                now,
            )
        });
        got.one("euvd", "euvd/euvd", result, prev("euvd/euvd"));
    }
    for source in config.fedora.iter().filter(|s| wants(options.only, s)) {
        let (rk, uk) = (format!("{source}/repomd"), format!("{source}/updateinfo"));
        match fedora(&fetcher, out, config, source, (prev(&rk), prev(&uk)), now) {
            Ok((repomd, info)) => {
                got.one(source, &rk, Ok(repomd), prev(&rk));
                got.one(source, &uk, Ok(info), prev(&uk));
            }
            Err(error) => {
                got.one(source, &uk, Err(error), prev(&uk));
                got.keep(&rk, prev(&rk));
            }
        }
    }
    if wants(options.only, "nvd") && !config.nvd_url.is_empty() {
        let synced = nvd::sync(&fetcher, config, out, now)?;
        got.lines.push(synced.line);
        if let Some(error) = synced.error {
            got.failed += 1;
            got.lines.push(format!("nvd FAILED: {error}"));
        }
        if synced.fresh {
            got.fetched += 1;
        }
        // Files stand either way: what NVD held when the last pass finished.
        got.current.extend(synced.files);
    }
    let mut groups: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    for name in &config.osv_releases {
        let release: Release = name.parse()?;
        groups
            .entry(release.ecosystem())
            .or_default()
            .push(release.name());
    }
    for (ecosystem, mut releases) in groups {
        let source = ecosystem.to_ascii_lowercase().replace(' ', "-");
        if !wants(options.only, &source) || config.osv_url.is_empty() {
            continue;
        }
        releases.sort();
        releases.dedup();
        let key = format!("{source}/osv");
        let result = osv(
            &fetcher,
            out,
            config,
            (ecosystem, &releases),
            prev(&key),
            now,
        );
        got.one(&source, &key, result, prev(&key));
    }

    // Nothing fetched or confirmed unchanged in this run: signing earlier
    // copies with a new `created_at` would make an outage look fresh, so the
    // old feed is left to expire.
    if got.fetched == 0 {
        return Err(format!(
            "no source could be fetched; nothing published\n{}",
            got.lines.join("\n")
        ));
    }
    // Sources this run did not ask for stay as the last build had them.
    if !options.only.is_empty() {
        for (key, held) in &state.files {
            let source = key.rsplit_once('/').map_or("", |(s, _)| s);
            if !wants(options.only, source) && blob_exists(out, &held.sha256) {
                got.current
                    .entry(key.clone())
                    .or_insert_with(|| held.clone());
            }
        }
    }
    let created = now;
    let expires = now + i64::from(options.valid_days) * 86_400;
    let sequence = (state.sequence + 1).max(u64::try_from(now).unwrap_or(1));
    let files: Vec<OutFile<'_>> = got
        .current
        .iter()
        .filter_map(|(key, held)| {
            let (source, kind) = key.rsplit_once('/')?;
            // Several files of one kind (NVD years) carry `#<name>` after it.
            let kind = kind.split('#').next()?;
            Some(OutFile {
                source,
                kind,
                name: &held.name,
                sha256: &held.sha256,
                size: held.size,
                fetched_at: held.fetched_at,
                upstream: &held.upstream,
                releases: held.releases.as_ref(),
            })
        })
        .collect();
    let manifest = serde_json::to_string(&OutManifest {
        sequence,
        created_at: created,
        expires_at: expires,
        files,
    })
    .map_err(|_| "cannot write the manifest".to_owned())?;
    let signature = key
        .signing
        .sign(&feedfmt::preimage(&key.feed_id, &key.key_id, &manifest));
    let envelope = serde_json::to_vec(&OutEnvelope {
        format: 1,
        feed_id: &key.feed_id,
        key_id: &key.key_id,
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        manifest: &manifest,
    })
    .map_err(|_| "cannot write feed.json".to_owned())?;
    // What is published must pass the verifier a platform runs.
    feedfmt::verify(
        &envelope,
        &[TrustedKey {
            feed_id: key.feed_id.clone(),
            key_id: key.key_id.clone(),
            public_key: key.signing.verifying_key().to_bytes(),
        }],
        &[],
        now,
    )
    .map_err(|why| format!("the feed built does not verify ({why}); nothing published"))?;
    write_atomic(&out.join("feed.json"), &envelope)?;

    let published: BTreeSet<String> = got.current.values().map(|h| h.sha256.clone()).collect();
    let nvd_held = nvd::held_hashes(out);
    let keep: BTreeSet<&String> = published
        .iter()
        .chain(state.previous.iter())
        .chain(nvd_held.iter())
        .collect();
    prune(out, &keep);
    let state = State {
        sequence,
        files: got.current,
        previous: published.into_iter().collect(),
    };
    let text =
        serde_json::to_vec_pretty(&state).map_err(|_| "cannot write state.json".to_owned())?;
    write_atomic(&out.join("state.json"), &text)?;
    Ok(Report {
        lines: got.lines,
        failed: got.failed,
        sequence,
    })
}

/// Files gathered during a build, with the lines that describe them.
#[derive(Default)]
struct Collected {
    out: PathBuf,
    /// Files fetched, or confirmed unchanged, in this run.
    fetched: usize,
    current: BTreeMap<String, Held>,
    lines: Vec<String>,
    failed: usize,
}

impl Collected {
    /// Records a file, or why it could not be had and whether an earlier
    /// copy stands in for it.
    fn one(&mut self, tag: &str, key: &str, result: Result<Held, String>, earlier: Option<&Held>) {
        match result {
            Ok(held) => {
                let how = if earlier.is_some_and(|e| e.sha256 == held.sha256) {
                    "unchanged"
                } else {
                    "new"
                };
                self.lines.push(format!("{key} {how} {} bytes", held.size));
                self.fetched += 1;
                self.current.insert(key.to_owned(), held);
            }
            Err(error) => {
                self.failed += 1;
                self.lines.push(format!("{tag} FAILED: {error}"));
                self.keep(key, earlier);
            }
        }
    }

    fn keep(&mut self, key: &str, earlier: Option<&Held>) {
        if let Some(held) = earlier.filter(|h| blob_exists(&self.out, &h.sha256)) {
            self.lines.push(format!("{key} kept from an earlier build"));
            self.current.insert(key.to_owned(), held.clone());
        }
    }
}

pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    fs::rename(&tmp, path).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

/// Removes blobs no kept manifest names, and leftover temporary files.
fn prune(out: &Path, keep: &BTreeSet<&String>) {
    let Ok(entries) = fs::read_dir(blobs(out)) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !keep.contains(&name) {
            let _ = fs::remove_file(entry.path());
        }
    }
}
