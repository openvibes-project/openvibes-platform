//! NVD API 2.0 and EUVD search responses.

use chrono::NaiveDateTime;
pub use platform_store::{
    cpe::Applicability,
    enrichment::{Euvd, Nvd},
};
use serde::Deserialize;
use serde_json::Value;

use super::is_cve;
use crate::updateinfo::ParseError;

/// Longest description kept, in bytes.
const MAX_DESCRIPTION: usize = 4096;
/// Longest CVSS vector kept (4.0 vectors run to about 200).
const MAX_VECTOR: usize = 512;

/// One page of an NVD `cves/2.0` response.
#[derive(Clone, Debug, PartialEq)]
pub struct NvdPage {
    /// Matching CVEs in all pages.
    pub total: u64,
    /// Index of this page's first CVE.
    pub start: u64,
    /// Records on this page, including any skipped.
    pub count: u64,
    /// The CVEs on this page.
    pub entries: Vec<Nvd>,
    /// Affected application product ranges of every CVE on this page.
    pub applicability: Vec<Applicability>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdResponse {
    total_results: u64,
    start_index: u64,
    vulnerabilities: Vec<NvdItem>,
}

#[derive(Deserialize)]
struct NvdItem {
    cve: Value,
}

/// CVSS metric keys, newest version first.
const CVSS: [(&str, &str); 4] = [
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
];

fn truncate(text: &str, max: usize) -> String {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

/// The newest CVSS version scored; within it NVD's own (`Primary`) first.
fn cvss(metrics: &Value) -> Option<(f32, &'static str, String)> {
    CVSS.iter().find_map(|(key, version)| {
        let list = metrics.get(key)?.as_array()?;
        let metric = list
            .iter()
            .find(|m| m["type"] == "Primary")
            .or_else(|| list.first())?;
        let data = &metric["cvssData"];
        let score = data["baseScore"]
            .as_f64()
            .filter(|s| (0.0..=10.0).contains(s))?;
        let vector = truncate(data["vectorString"].as_str().unwrap_or(""), MAX_VECTOR);
        // A score is 0.0 to 10.0 with one decimal: exact in f32.
        #[allow(clippy::cast_possible_truncation)]
        Some((score as f32, *version, vector))
    })
}

fn record(cve: &Value) -> Option<Nvd> {
    let cve_id = cve["id"].as_str().filter(|id| is_cve(id))?.to_owned();
    let scored = cvss(&cve["metrics"]);
    let mut cwe: Vec<String> = cve["weaknesses"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|w| w["description"].as_array().into_iter().flatten())
        .filter_map(|d| d["value"].as_str())
        .filter(|v| {
            v.strip_prefix("CWE-").is_some_and(|n| {
                !n.is_empty() && n.len() <= 9 && n.bytes().all(|b| b.is_ascii_digit())
            })
        })
        .map(str::to_owned)
        .collect();
    cwe.sort_by_key(|c| c[4..].parse::<u32>().unwrap_or(u32::MAX));
    cwe.dedup();
    let description = cve["descriptions"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|d| d["lang"] == "en")
        .and_then(|d| d["value"].as_str())
        .map(|text| truncate(text, MAX_DESCRIPTION));
    let modified_at = cve["lastModified"]
        .as_str()
        .and_then(|t| NaiveDateTime::parse_from_str(t, "%Y-%m-%dT%H:%M:%S%.f").ok())
        .map(|t| t.and_utc());
    Some(Nvd {
        cve_id,
        cvss_score: scored.as_ref().map(|s| s.0),
        cvss_version: scored.as_ref().map(|s| s.1.to_owned()),
        cvss_vector: scored.map(|s| s.2),
        cwe,
        description,
        modified_at,
    })
}

/// Parses an NVD `cves/2.0` response page. Records without a valid CVE id
/// are skipped; anything but an NVD response is `Malformed`.
pub fn parse_nvd(content: &[u8]) -> Result<NvdPage, ParseError> {
    let response: NvdResponse =
        serde_json::from_slice(content).map_err(|_| ParseError::Malformed)?;
    Ok(NvdPage {
        total: response.total_results,
        start: response.start_index,
        count: response.vulnerabilities.len() as u64,
        entries: response
            .vulnerabilities
            .iter()
            .filter_map(|item| record(&item.cve))
            .collect(),
        applicability: response
            .vulnerabilities
            .iter()
            .flat_map(|item| applicability(&item.cve))
            .collect(),
    })
}

/// Version text of a `cpe:2.3:a:vendor:product:version:update:...` name:
/// `None` for "any" (`*`) and "not applicable" (`-`) versions; an update
/// such as `p1` joins the version (`8.5p1`).
fn cpe_version(version: &str, update: &str) -> Option<String> {
    if version == "*" || version == "-" || version.is_empty() {
        return None;
    }
    Some(match update {
        "*" | "-" | "" => version.to_owned(),
        update => format!("{version}{update}"),
    })
}

/// The affected application ranges of one NVD record: `vulnerable` matches
/// of single `OR` nodes (`AND` configurations pair a product with a platform
/// and are skipped), as ranges. A start that is exclusive is skipped (rare).
/// Rejected records give none. Fedora releases NVD lists as affected ride
/// along on every range of the CVE.
fn applicability(cve: &Value) -> Vec<Applicability> {
    let Some(cve_id) = cve["id"].as_str().filter(|id| is_cve(id)) else {
        return Vec::new();
    };
    if cve["vulnStatus"] == "Rejected" {
        return Vec::new();
    }
    let cvss = cvss(&cve["metrics"]).map(|s| s.0);
    let mut fedora = Vec::new();
    let mut rows = Vec::new();
    for config in cve["configurations"].as_array().into_iter().flatten() {
        let and = config["operator"] == "AND";
        for node in config["nodes"].as_array().into_iter().flatten() {
            for found in node["cpeMatch"].as_array().into_iter().flatten() {
                let Some(criteria) = found["criteria"].as_str() else {
                    continue;
                };
                let parts: Vec<&str> = criteria.split(':').collect();
                if parts.len() < 7 || found["vulnerable"] != true {
                    continue;
                }
                if parts[2] == "o" && parts[3] == "fedoraproject" && parts[4] == "fedora" {
                    fedora.extend(cpe_version(parts[5], parts[6]));
                    continue;
                }
                if parts[2] != "a" || and || node["operator"] != "OR" || node["negate"] == true {
                    continue;
                }
                if found["versionStartExcluding"].is_string() {
                    continue;
                }
                let text = |key: &str| found[key].as_str().map(|v| truncate(v, 64));
                let (mut introduced, fixed, mut last) = (
                    text("versionStartIncluding"),
                    text("versionEndExcluding"),
                    text("versionEndIncluding"),
                );
                if introduced.is_none() && fixed.is_none() && last.is_none() {
                    // An exact version.
                    let Some(version) = cpe_version(parts[5], parts[6]) else {
                        continue;
                    };
                    introduced = Some(version.clone());
                    last = Some(version);
                }
                rows.push(Applicability {
                    cve_id: cve_id.to_owned(),
                    vendor: truncate(&parts[3].to_ascii_lowercase(), 64),
                    product: truncate(&parts[4].to_ascii_lowercase(), 64),
                    introduced,
                    fixed,
                    last_affected: last,
                    cvss,
                    fedora: Vec::new(),
                });
            }
        }
    }
    fedora.sort();
    fedora.dedup();
    for row in &mut rows {
        row.fedora.clone_from(&fedora);
    }
    rows
}

/// One page of EUVD's exploited list.
#[derive(Clone, Debug, PartialEq)]
pub struct EuvdPage {
    /// Entries in all pages.
    pub total: u64,
    /// Entries on this page (before splitting into CVE aliases).
    pub items: u64,
    /// One per CVE alias of each entry on this page.
    pub entries: Vec<Euvd>,
}

#[derive(Deserialize)]
struct EuvdResponse {
    items: Vec<EuvdItem>,
    total: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EuvdItem {
    id: String,
    #[serde(default)]
    aliases: String,
    #[serde(default)]
    exploited_since: Option<String>,
}

fn is_euvd(id: &str) -> bool {
    let mut parts = id.split('-');
    matches!(
        (parts.next(), parts.next(), parts.next(), parts.next()),
        (Some("EUVD"), Some(year), Some(number), None)
            if year.len() == 4 && (1..=19).contains(&number.len())
                && year.bytes().chain(number.bytes()).all(|b| b.is_ascii_digit())
    )
}

/// Parses an EUVD search response (`items`, `total`): each entry with a
/// valid EUVD id gives one record per CVE among its aliases.
pub fn parse_euvd(content: &[u8]) -> Result<EuvdPage, ParseError> {
    let response: EuvdResponse =
        serde_json::from_slice(content).map_err(|_| ParseError::Malformed)?;
    let items = response.items.len() as u64;
    let entries = response
        .items
        .into_iter()
        .filter(|item| is_euvd(&item.id))
        .flat_map(|item| {
            let since = item.exploited_since.as_deref().and_then(|t| {
                NaiveDateTime::parse_from_str(t, "%b %e, %Y, %I:%M:%S %p")
                    .ok()
                    .map(|t| t.date())
            });
            item.aliases
                .split_whitespace()
                .filter(|alias| is_cve(alias))
                .map(|cve| Euvd {
                    cve_id: cve.to_owned(),
                    euvd_id: item.id.clone(),
                    exploited_since: since,
                })
                .collect::<Vec<_>>()
        })
        .collect();
    Ok(EuvdPage {
        total: response.total,
        items,
        entries,
    })
}
