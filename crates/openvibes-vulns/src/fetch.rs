//! Fetching Fedora feeds: metalink (HTTPS) → `repomd.xml` (digest from the
//! metalink) → updateinfo (digest from `repomd.xml`) → import. Every step is
//! verified, so a mirror's own transport does not matter.

use std::time::Duration;

use chrono::{DateTime, Utc};
use platform_store::{Client, vulns};
use sha2::{Digest, Sha256};

use crate::{
    feed::{self, ImportReport, SourceId},
    repodata,
};

/// Default Fedora mirror list, per release and architecture.
pub const FEDORA_METALINK: &str =
    "https://mirrors.fedoraproject.org/metalink?repo=updates-released-f{release}&arch={arch}";
/// Largest metalink or `repomd.xml` read.
const MAX_INDEX: u64 = 1 << 20;
/// Mirrors tried per check.
const MIRRORS_TRIED: usize = 5;

/// Downloads feeds through one HTTP agent (proxy and timeouts applied).
#[derive(Clone)]
pub struct Fetcher {
    agent: ureq::Agent,
    template: String,
    max_bytes: u64,
}

/// What a check did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Checked {
    /// The feed had not changed; nothing was downloaded.
    Unchanged,
    /// New content was imported.
    Imported(ImportReport),
}

/// Whether a plain-HTTP URL names a loopback host exactly.
fn loopback(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = match authority.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => authority.split(':').next().unwrap_or(""),
    };
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

impl Fetcher {
    /// A fetcher for a metalink URL template (`{release}`, `{arch}`). The
    /// metalink must be HTTPS (plain HTTP only on loopback, for tests):
    /// it carries the digests everything else is checked against.
    pub fn new(template: &str, proxy: Option<&str>, max_bytes: u64) -> Result<Self, String> {
        if !template.starts_with("https://") && !loopback(template) {
            return Err("the mirror list URL must use https".into());
        }
        let proxy = proxy
            .map(ureq::Proxy::new)
            .transpose()
            .map_err(|_| "invalid proxy_url".to_owned())?;
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(120)))
            .max_redirects(5)
            .proxy(proxy)
            .build();
        Ok(Self {
            agent: config.into(),
            template: template.to_owned(),
            max_bytes,
        })
    }

    fn get(&self, url: &str, limit: u64) -> Result<Vec<u8>, String> {
        let mut response = self
            .agent
            .get(url)
            .call()
            .map_err(|error| format!("{}: {error}", host_of(url)))?;
        response
            .body_mut()
            .with_config()
            .limit(limit)
            .read_to_vec()
            .map_err(|error| format!("{}: {error}", host_of(url)))
    }
}

fn host_of(url: &str) -> &str {
    url.split("://")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .unwrap_or(url)
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// What the network side found: new content, or the digest it already has.
enum Found {
    Same,
    New(Vec<u8>),
}

/// The blocking network part: metalink → a mirror with a matching index →
/// the updateinfo file, unless its digest equals `known`.
fn download(
    fetcher: &Fetcher,
    source: &SourceId,
    known: Option<[u8; 32]>,
) -> Result<Found, String> {
    let url = fetcher
        .template
        .replace("{release}", &source.os_version)
        .replace("{arch}", &source.arch);
    let metalink = repodata::metalink(&fetcher.get(&url, MAX_INDEX)?)
        .map_err(|_| "unreadable mirror list".to_owned())?;
    let mut last = "no usable mirror".to_owned();
    // The current index first; an older one a lagging mirror still serves
    // (an alternate) only when no mirror has the current one, so checks do
    // not flip between versions.
    let passes = [&metalink.sha256[..1], &metalink.sha256[..]];
    for (accepted, repomd_url) in passes.iter().flat_map(|accepted| {
        metalink
            .urls
            .iter()
            .take(MIRRORS_TRIED)
            .map(move |url| (*accepted, url))
    }) {
        let repomd = match fetcher.get(repomd_url, MAX_INDEX) {
            Ok(bytes) => bytes,
            Err(error) => {
                last = error;
                continue;
            }
        };
        if !accepted.contains(&digest(&repomd)) {
            last = format!(
                "{}: repomd.xml digest does not match the mirror list",
                host_of(repomd_url)
            );
            continue;
        }
        let location = repodata::updateinfo_location(&repomd)
            .map_err(|_| "repomd.xml has no usable updateinfo".to_owned())?;
        if known == Some(location.sha256) {
            return Ok(Found::Same);
        }
        if location.size > fetcher.max_bytes {
            return Err(format!(
                "updateinfo is {} bytes, over the limit",
                location.size
            ));
        }
        let base = repomd_url.trim_end_matches("repodata/repomd.xml");
        let content = match fetcher.get(&format!("{base}{}", location.href), location.size + 1) {
            Ok(bytes) => bytes,
            Err(error) => {
                last = error;
                continue;
            }
        };
        if digest(&content) != location.sha256 {
            last = format!(
                "{}: updateinfo digest does not match repomd.xml",
                host_of(repomd_url)
            );
            continue;
        }
        return Ok(Found::New(content));
    }
    Err(last)
}

/// Checks one source: downloads and imports new content, or records an
/// unchanged check. A failure is recorded on the feed; stored advisories
/// and vulnerabilities are kept.
pub async fn check(
    client: &mut Client,
    fetcher: &Fetcher,
    source: &SourceId,
    now: DateTime<Utc>,
) -> Result<Checked, String> {
    let name = source.name();
    let known = vulns::feed_digest(client, &name)
        .await
        .map_err(|e| e.to_string())?;
    let (network, owned) = (fetcher.clone(), source.clone());
    let found = tokio::task::spawn_blocking(move || download(&network, &owned, known))
        .await
        .map_err(|_| "download task failed".to_owned())?;
    match found {
        Ok(Found::Same) => {
            vulns::touch_feed(client, &name, now)
                .await
                .map_err(|e| e.to_string())?;
            Ok(Checked::Unchanged)
        }
        Ok(Found::New(content)) => feed::import(client, source, &content, now)
            .await
            .map(Checked::Imported)
            .map_err(|e| e.to_string()),
        Err(error) => {
            let key = (
                name.as_str(),
                source.os_id.as_str(),
                source.os_version.as_str(),
                source.arch.as_str(),
            );
            vulns::record_feed(client, key, Err(&error), now)
                .await
                .map_err(|e| e.to_string())?;
            Err(error)
        }
    }
}
