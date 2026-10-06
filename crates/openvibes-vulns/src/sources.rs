//! Fetching NVD and EUVD (VM5). NVD is kept only for CVEs advisories name:
//! each run asks for what changed since the last one (windows of at most
//! 120 days, paged) and then, one by one, for named CVEs it has not seen,
//! paced to NVD's rate limit. EUVD's exploited list is read page by page.

use std::{path::Path, time::Duration};

use chrono::{DateTime, Utc};
use platform_store::{Client, cpe as cpe_store, enrichment, vulns};
use sha2::{Digest, Sha256};
use tokio::{sync::Mutex, time::Instant};

use crate::{
    enrich::{self, Euvd, NvdPage},
    fetch::{self, Fetcher},
};

/// NVD CVE API 2.0.
pub const NVD_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
/// ENISA EUVD search API.
pub const EUVD_URL: &str = "https://euvdservices.enisa.europa.eu/api/search";
/// NVD's longest last-modified window.
const MAX_WINDOW_DAYS: i64 = 120;
/// NVD's largest page.
const PAGE: u32 = 2000;
/// Named CVEs asked about one by one per run.
const BACKFILL_PER_RUN: i64 = 1000;
/// EUVD pages read at most (100 entries each).
const MAX_EUVD_PAGES: u64 = 1000;

/// A paced NVD client: one request at a time, `pause` apart.
pub struct NvdClient {
    fetcher: Fetcher,
    url: String,
    key: Option<String>,
    pause: Duration,
    last: Mutex<Option<Instant>>,
}

/// What an NVD run did.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NvdReport {
    /// Named CVEs updated from the last-modified windows.
    pub updated: u64,
    /// Named CVEs fetched for the first time.
    pub backfilled: u64,
    /// Named CVEs NVD did not know (asked again after 7 days).
    pub unknown: u64,
}

impl NvdClient {
    /// A client for `url` (HTTPS). Without `pause`, requests are 6 s apart,
    /// 0.6 s with an API key (NVD's published limits).
    pub fn new(
        fetcher: &Fetcher,
        url: &str,
        key: Option<String>,
        pause: Option<Duration>,
    ) -> Result<Self, String> {
        fetch::check_source_url(url)?;
        let pause = pause.unwrap_or(if key.is_some() {
            Duration::from_millis(600)
        } else {
            Duration::from_secs(6)
        });
        Ok(Self {
            fetcher: fetcher.clone(),
            url: url.to_owned(),
            key,
            pause,
            last: Mutex::new(None),
        })
    }

    async fn page(&self, query: String) -> Result<NvdPage, String> {
        let mut last = self.last.lock().await;
        if let Some(at) = *last {
            tokio::time::sleep_until(at + self.pause).await;
        }
        let (fetcher, url, key) = (
            self.fetcher.clone(),
            format!("{}?{query}", self.url),
            self.key.clone(),
        );
        let body = tokio::task::spawn_blocking(move || {
            let headers: Vec<(&str, &str)> = key.iter().map(|k| ("apiKey", k.as_str())).collect();
            fetcher.get_with(&url, &headers)
        })
        .await
        .map_err(|_| "download task failed".to_owned());
        *last = Some(Instant::now());
        enrich::parse_nvd(&body??).map_err(|_| "not a readable nvd response".to_owned())
    }
}

fn nvd_time(at: DateTime<Utc>) -> String {
    at.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

async fn run_nvd(
    client: &mut Client,
    nvd: &NvdClient,
    now: DateTime<Utc>,
) -> Result<NvdReport, String> {
    let store = |e: platform_store::StoreError| e.to_string();
    let mut report = NvdReport::default();
    match vulns::feed_cursor(client, "nvd").await.map_err(store)? {
        // First run: nothing to catch up on; the backfill covers it.
        None => vulns::set_feed_cursor(client, "nvd", now)
            .await
            .map_err(store)?,
        Some(mut from) => {
            while from < now {
                let to = (from + chrono::Duration::days(MAX_WINDOW_DAYS)).min(now);
                let mut start = 0;
                loop {
                    let page = nvd
                        .page(format!(
                            "lastModStartDate={}&lastModEndDate={}&resultsPerPage={PAGE}&startIndex={start}",
                            nvd_time(from),
                            nvd_time(to)
                        ))
                        .await?;
                    report.updated += enrichment::upsert_nvd(client, &page.entries, now)
                        .await
                        .map_err(store)?;
                    start += page.count;
                    if page.count == 0 || start >= page.total {
                        break;
                    }
                }
                // Each window is kept once done, so an error resumes here.
                vulns::set_feed_cursor(client, "nvd", to)
                    .await
                    .map_err(store)?;
                from = to;
            }
        }
    }
    let pending = enrichment::nvd_pending(client, now, BACKFILL_PER_RUN)
        .await
        .map_err(store)?;
    for cve in pending {
        let page = nvd.page(format!("cveId={cve}")).await?;
        if enrichment::upsert_nvd(client, &page.entries, now)
            .await
            .map_err(store)?
            > 0
        {
            report.backfilled += 1;
        } else {
            enrichment::mark_nvd_checked(client, &[cve], now)
                .await
                .map_err(store)?;
            report.unknown += 1;
        }
    }
    Ok(report)
}

/// One NVD run: catch up by last-modified windows since the last run, then
/// fetch named CVEs not yet seen. Any failure (including NVD refusing with
/// 403 or 429) stops the run, keeps what was done, is recorded on the
/// `nvd` source, and the next run resumes from the last finished window.
pub async fn sync_nvd(
    client: &mut Client,
    nvd: &NvdClient,
    now: DateTime<Utc>,
) -> Result<NvdReport, String> {
    let result = run_nvd(client, nvd, now).await;
    let key = ("nvd", "cve", "", "");
    let recorded = match &result {
        Ok(_) => {
            let known = enrichment::nvd_known(client)
                .await
                .map_err(|e| e.to_string())?;
            let digest: [u8; 32] = Sha256::digest(known.to_be_bytes()).into();
            let count = i32::try_from(known).unwrap_or(i32::MAX);
            vulns::record_feed(client, key, Ok((digest, count)), now).await
        }
        Err(error) => vulns::record_feed(client, key, Err(error), now).await,
    };
    recorded.map_err(|e| e.to_string())?;
    result
}

/// Where the first read of NVD for applicability ranges starts (NVD's
/// oldest records were modified well after this).
fn applicability_start() -> DateTime<Utc> {
    DateTime::from_timestamp(1_262_304_000, 0).unwrap_or_default() // 2010-01-01
}

/// What an applicability run did.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ApplicabilityReport {
    /// Whether NVD was read again from the start (a new product appeared).
    pub restarted: bool,
    /// CVE records read.
    pub cves: u64,
    /// Ranges kept.
    pub ranges: u64,
}

/// Keeps NVD's affected ranges (CPE applicability) for the products
/// installed packages could be (spec 2026-10-06-cpe-matching-design.md).
/// Reads NVD by last-modified windows from a sync point of its own (`nvd-cpe`),
/// each finished window saved, so an error resumes there; reads NVD from the
/// start when a product appears that was not kept before. Records read
/// also refresh the enrichment of CVEs advisories name.
pub async fn sync_applicability(
    client: &mut Client,
    nvd: &NvdClient,
    now: DateTime<Utc>,
) -> Result<ApplicabilityReport, String> {
    let store = |e: platform_store::StoreError| e.to_string();
    let mut report = ApplicabilityReport::default();
    let fresh = crate::cpe::ensure_products(client, "fedora")
        .await
        .map_err(store)?;
    let cursor = vulns::feed_cursor(client, "nvd-cpe").await.map_err(store)?;
    let mut from = match cursor {
        Some(cursor) if !fresh => cursor,
        _ => {
            report.restarted = cursor.is_some();
            applicability_start()
        }
    };
    let result = async {
        while from < now {
            let to = (from + chrono::Duration::days(MAX_WINDOW_DAYS)).min(now);
            let mut start = 0;
            loop {
                let page = nvd
                    .page(format!(
                        "lastModStartDate={}&lastModEndDate={}&resultsPerPage={PAGE}&startIndex={start}",
                        nvd_time(from),
                        nvd_time(to)
                    ))
                    .await?;
                let ids: Vec<String> = page.entries.iter().map(|e| e.cve_id.clone()).collect();
                report.cves += ids.len() as u64;
                report.ranges += cpe_store::replace_applicability(client, &ids, &page.applicability)
                    .await
                    .map_err(store)?;
                enrichment::upsert_nvd(client, &page.entries, now)
                    .await
                    .map_err(store)?;
                start += page.count;
                if page.count == 0 || start >= page.total {
                    break;
                }
            }
            vulns::set_feed_cursor(client, "nvd-cpe", to)
                .await
                .map_err(store)?;
            from = to;
        }
        Ok::<(), String>(())
    }
    .await;
    let key = ("nvd-cpe", "cve", "", "");
    match &result {
        Ok(()) => {
            let digest: [u8; 32] = Sha256::digest(report.ranges.to_be_bytes()).into();
            let count = i32::try_from(report.ranges).unwrap_or(i32::MAX);
            vulns::record_feed(client, key, Ok((digest, count)), now)
                .await
                .map_err(store)?;
        }
        Err(error) => {
            vulns::record_feed(client, key, Err(error), now)
                .await
                .map_err(store)?;
        }
    }
    result.map(|()| report)
}

/// Reads EUVD's exploited list page by page (`page_size` per page) and
/// imports it unless it equals the last import. Returns the CVEs stored, or
/// `None` when unchanged. A failure is recorded on `euvd`; data is kept.
pub async fn check_euvd(
    client: &mut Client,
    fetcher: &Fetcher,
    url: &str,
    page_size: u32,
    now: DateTime<Utc>,
) -> Result<Option<usize>, String> {
    let key = ("euvd", "cve", "", "");
    let (network, base) = (fetcher.clone(), url.to_owned());
    let pages = tokio::task::spawn_blocking(move || -> Result<Vec<Euvd>, String> {
        let (mut entries, mut seen) = (Vec::new(), 0);
        for number in 0..MAX_EUVD_PAGES {
            let body = network.get_with(
                &format!("{base}?exploited=true&size={page_size}&page={number}"),
                &[],
            )?;
            let page =
                enrich::parse_euvd(&body).map_err(|_| "not a readable euvd response".to_owned())?;
            seen += page.items;
            entries.extend(page.entries);
            if page.items == 0 || seen >= page.total {
                break;
            }
        }
        Ok(entries)
    })
    .await
    .map_err(|_| "download task failed".to_owned())?;
    let store = |e: platform_store::StoreError| e.to_string();
    let mut entries = match pages {
        Ok(entries) => entries,
        Err(error) => {
            vulns::record_feed(client, key, Err(&error), now)
                .await
                .map_err(store)?;
            return Err(error);
        }
    };
    entries.sort_by(|a, b| a.cve_id.cmp(&b.cve_id));
    entries.dedup_by(|a, b| a.cve_id == b.cve_id);
    let mut hasher = Sha256::new();
    for e in &entries {
        hasher.update(format!(
            "{} {} {:?}\n",
            e.cve_id, e.euvd_id, e.exploited_since
        ));
    }
    let digest: [u8; 32] = hasher.finalize().into();
    if vulns::feed_digest(client, "euvd").await.map_err(store)? == Some(digest) {
        vulns::touch_feed(client, "euvd", now)
            .await
            .map_err(store)?;
        return Ok(None);
    }
    enrichment::replace_euvd(client, &entries)
        .await
        .map_err(store)?;
    let count = i32::try_from(entries.len()).unwrap_or(i32::MAX);
    vulns::record_feed(client, key, Ok((digest, count)), now)
        .await
        .map_err(store)?;
    Ok(Some(entries.len()))
}

/// Reads an NVD API key from a file that group and others cannot read.
pub fn read_api_key(path: &Path) -> Result<String, String> {
    let metadata =
        std::fs::metadata(path).map_err(|_| "cannot read nvd_api_key_file".to_owned())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("nvd_api_key_file must not be readable by group or others".into());
        }
    }
    if metadata.len() > 1024 {
        return Err("nvd_api_key_file must hold one API key".into());
    }
    let text =
        std::fs::read_to_string(path).map_err(|_| "cannot read nvd_api_key_file".to_owned())?;
    let key = text.trim();
    if (1..=128).contains(&key.len()) && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        Ok(key.to_owned())
    } else {
        Err("nvd_api_key_file must hold one API key".into())
    }
}
