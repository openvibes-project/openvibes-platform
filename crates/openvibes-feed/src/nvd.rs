//! NVD as slim year files: the builder reads NVD's API by last-modified
//! windows (as the platform's own sync does), keeps one gzip file per CVE
//! year (openvibes-protocol `spec/feed-v1.md`, "Slim NVD"), and rewrites only
//! the years whose records changed. Progress is saved after every window in
//! `nvd-state.json`, so a first build interrupted after twenty minutes
//! resumes where it stopped. NVD joins the feed only once a first pass has
//! reached the present, so a platform never reads half of NVD.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    path::Path,
    time::{Duration, Instant},
};

use chrono::{DateTime, Utc};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use openvibes_vulns::{
    enrich::{self, SlimFile, SlimRecord},
    feedfmt::Kind,
    fetch::Fetcher,
    sources,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    build::{Held, blob_exists, blobs, store, write_atomic},
    config::Config,
};

const FILE: &str = "nvd-state.json";

/// What `nvd-state.json` keeps between builds.
#[derive(Debug, Default, Deserialize, Serialize)]
struct State {
    /// Unix seconds up to which NVD has been read.
    cursor: Option<i64>,
    /// Whether a pass has reached the present once.
    complete: bool,
    /// Year to the file last written for it.
    years: BTreeMap<u32, Held>,
}

/// What a run of [`sync`] leaves for the manifest.
pub struct Synced {
    /// `nvd/nvd#<year>` to the year's file; empty until a first pass is complete.
    pub files: Vec<(String, Held)>,
    /// How it went, one line.
    pub line: String,
    /// NVD was read up to the present in this run.
    pub fresh: bool,
    /// The error that stopped this run, if any.
    pub error: Option<String>,
}

/// Blobs NVD's saved state needs, so a prune keeps them.
pub fn held_hashes(out: &Path) -> BTreeSet<String> {
    load(out)
        .map(|state| state.years.values().map(|h| h.sha256.clone()).collect())
        .unwrap_or_default()
}

fn load(out: &Path) -> Result<State, String> {
    match fs::read_to_string(out.join(FILE)) {
        Ok(text) => serde_json::from_str(&text)
            .map_err(|_| format!("{FILE} is damaged; remove it to read NVD again")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
        Err(e) => Err(format!("cannot read {FILE}: {e}")),
    }
}

fn save(out: &Path, state: &State) -> Result<(), String> {
    let text = serde_json::to_vec_pretty(state).map_err(|_| format!("cannot write {FILE}"))?;
    write_atomic(&out.join(FILE), &text)
}

struct Api<'a> {
    fetcher: &'a Fetcher,
    url: &'a str,
    key: Option<&'a str>,
    pause: Duration,
    last: Option<Instant>,
}

impl Api<'_> {
    /// One page of NVD's `cves/2.0`, `pause` after the previous request.
    fn page(&mut self, query: &str) -> Result<Value, String> {
        if let Some(at) = self.last {
            std::thread::sleep(self.pause.saturating_sub(at.elapsed()));
        }
        let headers: Vec<(&str, &str)> = self.key.iter().map(|k| ("apiKey", *k)).collect();
        let body = self
            .fetcher
            .get_with(&format!("{}?{query}", self.url), &headers);
        self.last = Some(Instant::now());
        serde_json::from_slice(&body?).map_err(|_| "not a readable NVD response".to_owned())
    }
}

fn read_year(out: &Path, held: &Held) -> Result<BTreeMap<String, SlimRecord>, String> {
    let bytes = fs::read(blobs(out).join(&held.sha256))
        .map_err(|e| format!("cannot read an earlier NVD file: {e}"))?;
    let mut json = Vec::new();
    GzDecoder::new(&bytes[..])
        .take(enrich::SLIM_NVD_MAX_OPEN)
        .read_to_end(&mut json)
        .map_err(|_| "an earlier NVD file is damaged".to_owned())?;
    let file: SlimFile =
        serde_json::from_slice(&json).map_err(|_| "an earlier NVD file is damaged".to_owned())?;
    Ok(file
        .records
        .into_iter()
        .map(|record| (record.id.clone(), record))
        .collect())
}

/// Merges what a window found into the years' files and saves them.
fn flush(
    out: &Path,
    state: &mut State,
    found: BTreeMap<u32, BTreeMap<String, SlimRecord>>,
    now: i64,
    upstream: &str,
) -> Result<(), String> {
    for (year, fresh) in found {
        let mut records = match state.years.get(&year) {
            Some(held) if blob_exists(out, &held.sha256) => read_year(out, held)?,
            // Starting the year over would publish it with only recent records.
            Some(_) => {
                return Err(format!(
                    "the file for {year} is missing from blobs/; remove {FILE} to read NVD again"
                ));
            }
            None => BTreeMap::new(),
        };
        records.extend(fresh);
        let json = serde_json::to_vec(&SlimFile {
            format: 1,
            year,
            records: records.into_values().collect(),
        })
        .map_err(|_| "cannot write an NVD file".to_owned())?;
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&json)
            .map_err(|_| "cannot write an NVD file".to_owned())?;
        let bytes = gz
            .finish()
            .map_err(|_| "cannot write an NVD file".to_owned())?;
        let size = bytes.len() as u64;
        if size > Kind::Nvd.max_size() {
            return Err(format!(
                "the NVD file for {year} is larger than the format allows"
            ));
        }
        // What is published must be what a platform accepts.
        enrich::parse_slim(&bytes, enrich::SLIM_NVD_MAX_OPEN).map_err(|_| {
            format!("the NVD file for {year} is not accepted by the platform's reader")
        })?;
        let sha256 = store(out, &bytes)?;
        if state.years.get(&year).is_some_and(|h| h.sha256 == sha256) {
            continue;
        }
        state.years.insert(
            year,
            Held {
                name: format!("nvd-{year}.json.gz"),
                sha256,
                size,
                fetched_at: now,
                upstream: upstream.to_owned(),
                etag: None,
                releases: None,
            },
        );
    }
    Ok(())
}

/// Reads NVD up to `now` and returns the year files.
///
/// # Errors
/// `nvd-state.json` is damaged or cannot be written. A failure reading NVD
/// is in [`Synced::error`] with the progress saved.
pub fn sync(fetcher: &Fetcher, config: &Config, out: &Path, now: i64) -> Result<Synced, String> {
    let mut state = load(out)?;
    let key = match &config.nvd_api_key_file {
        Some(path) => {
            let text = fs::read_to_string(path)
                .map_err(|e| format!("cannot read the NVD API key file {path}: {e}"))?;
            Some(text.trim().to_owned()).filter(|k| !k.is_empty())
        }
        None => None,
    };
    let default_pause = if key.is_some() {
        Duration::from_millis(600)
    } else {
        Duration::from_secs(6)
    };
    let pause = config
        .nvd_pause_ms
        .map_or(default_pause, Duration::from_millis);
    let mut api = Api {
        fetcher,
        url: &config.nvd_url,
        key: key.as_deref(),
        pause,
        last: None,
    };
    let end = DateTime::from_timestamp(now, 0).unwrap_or_default();
    let mut at = state
        .cursor
        .and_then(|c| DateTime::from_timestamp(c, 0))
        .unwrap_or_else(sources::applicability_start);
    let (mut windows, mut cves) = (0u32, 0u64);
    let result: Result<(), String> = (|| {
        while at < end {
            let to = (at + chrono::Duration::days(sources::MAX_WINDOW_DAYS)).min(end);
            let mut found: BTreeMap<u32, BTreeMap<String, SlimRecord>> = BTreeMap::new();
            let mut start = 0u64;
            loop {
                let page = api.page(&format!(
                    "lastModStartDate={}&lastModEndDate={}&resultsPerPage={}&startIndex={start}",
                    sources::nvd_time(at),
                    sources::nvd_time(to),
                    sources::PAGE
                ))?;
                let items = page["vulnerabilities"]
                    .as_array()
                    .ok_or("not a readable NVD response")?;
                for item in items {
                    if let Some(record) = enrich::slim_record(&item["cve"])
                        && let Ok(year) = record.id[4..8].parse::<u32>()
                    {
                        cves += 1;
                        found
                            .entry(year)
                            .or_default()
                            .insert(record.id.clone(), record);
                    }
                }
                start += items.len() as u64;
                let total = page["totalResults"].as_u64().unwrap_or(0);
                if items.is_empty() || start >= total {
                    break;
                }
            }
            flush(out, &mut state, found, now, &config.nvd_url)?;
            state.cursor = Some(to.timestamp());
            save(out, &state)?;
            windows += 1;
            at = to;
        }
        Ok(())
    })();
    let (fresh, error) = match result {
        Ok(()) => {
            state.complete = true;
            save(out, &state)?;
            (true, None)
        }
        Err(error) => (false, Some(error)),
    };
    let files: Vec<(String, Held)> = if state.complete {
        state
            .years
            .iter()
            .filter(|(_, held)| blob_exists(out, &held.sha256))
            .map(|(year, held)| (format!("nvd/nvd#{year}"), held.clone()))
            .collect()
    } else {
        Vec::new()
    };
    let line = if state.complete {
        format!(
            "nvd {} year files; read {windows} windows, {cves} CVEs this run",
            files.len()
        )
    } else {
        format!(
            "nvd not published yet: the first read reached {} ({windows} windows, {cves} CVEs this run)",
            state
                .cursor
                .and_then(|c| DateTime::<Utc>::from_timestamp(c, 0))
                .map_or_else(
                    || "nothing".to_owned(),
                    |t| t.format("%Y-%m-%d").to_string()
                )
        )
    };
    Ok(Synced {
        files,
        line,
        fresh,
        error,
    })
}
