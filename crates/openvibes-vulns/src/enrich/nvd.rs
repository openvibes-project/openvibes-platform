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

pub(super) fn truncate(text: &str, max: usize) -> String {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

/// The newest CVSS version scored; within it NVD's own (`Primary`) first.
pub(super) fn cvss(metrics: &Value) -> Option<(f32, &'static str, String)> {
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

pub(super) fn record(cve: &Value) -> Option<Nvd> {
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
pub(super) fn cpe_version(version: &str, update: &str) -> Option<String> {
    if version == "*" || version == "-" || version.is_empty() {
        return None;
    }
    Some(match update {
        "*" | "-" | "" => version.to_owned(),
        update => format!("{version}{update}"),
    })
}

/// One affected application range from a `cpe:2.3:a:` name and its version
/// bounds; `None` for another part, a malformed name, or "any version".
/// With no bounds, the name's own version is an exact one. Shared by the API
/// sync and the slim feed files, so both give the same rows.
pub(super) fn range_row(
    cve_id: &str,
    cvss: Option<f32>,
    criteria: &str,
    start_including: Option<&str>,
    end_excluding: Option<&str>,
    end_including: Option<&str>,
) -> Option<Applicability> {
    let parts: Vec<&str> = criteria.split(':').collect();
    if parts.len() < 7 || parts[2] != "a" {
        return None;
    }
    let text = |value: Option<&str>| value.map(|v| truncate(v, 64));
    let (mut introduced, fixed, mut last) = (
        text(start_including),
        text(end_excluding),
        text(end_including),
    );
    if introduced.is_none() && fixed.is_none() && last.is_none() {
        // An exact version.
        let version = cpe_version(parts[5], parts[6])?;
        introduced = Some(version.clone());
        last = Some(version);
    }
    Some(Applicability {
        cve_id: cve_id.to_owned(),
        vendor: truncate(&parts[3].to_ascii_lowercase(), 64),
        product: truncate(&parts[4].to_ascii_lowercase(), 64),
        introduced,
        fixed,
        last_affected: last,
        cvss,
        fedora: Vec::new(),
    })
}

/// One `cpeMatch` entry the platform keeps: an application name and its
/// version bounds as NVD gives them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawMatch {
    /// The `cpe:2.3:a:...` name.
    pub criteria: String,
    /// `versionStartIncluding`.
    pub start_including: Option<String>,
    /// `versionEndExcluding`.
    pub end_excluding: Option<String>,
    /// `versionEndIncluding`.
    pub end_including: Option<String>,
}

/// Most operating systems one record lists.
pub(super) const MAX_OS: usize = 256;

/// Whether `entry` is a well-formed operating-system name of a slim NVD
/// record: `vendor:product:version`, each part 1 to 64 characters from
/// `a-z 0-9 . _ ~ + -`.
pub(super) fn os_ok(entry: &str) -> bool {
    let parts: Vec<&str> = entry.split(':').collect();
    parts.len() == 3
        && parts.iter().all(|p| {
            (1..=64).contains(&p.len())
                && p.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._~+-".contains(&b))
        })
}

/// The Fedora releases among operating-system names: what the platform uses
/// of the list today.
pub(super) fn fedora_releases(os: &[String]) -> Vec<String> {
    os.iter()
        .filter_map(|o| o.strip_prefix("fedoraproject:fedora:"))
        .map(str::to_owned)
        .collect()
}

/// What the platform keeps of one NVD record's configurations: the
/// `vulnerable` application matches of single `OR` nodes (`AND`
/// configurations pair a product with a platform and are skipped, as are
/// negated nodes and exclusive starts, which are rare), and every operating
/// system NVD lists as affected, as sorted `vendor:product:version` names.
/// Rejected records give nothing.
pub(super) fn kept_matches(cve: &Value) -> (Vec<RawMatch>, Vec<String>) {
    let mut systems = Vec::new();
    let mut kept = Vec::new();
    if cve["vulnStatus"] == "Rejected" {
        return (kept, systems);
    }
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
                if parts[2] == "o" {
                    if let Some(version) = cpe_version(parts[5], parts[6]) {
                        let name =
                            format!("{}:{}:{version}", parts[3], parts[4]).to_ascii_lowercase();
                        if os_ok(&name) {
                            systems.push(name);
                        }
                    }
                    continue;
                }
                if parts[2] != "a" || and || node["operator"] != "OR" || node["negate"] == true {
                    continue;
                }
                if found["versionStartExcluding"].is_string() {
                    continue;
                }
                let text = |key: &str| found[key].as_str().map(str::to_owned);
                kept.push(RawMatch {
                    criteria: criteria.to_owned(),
                    start_including: text("versionStartIncluding"),
                    end_excluding: text("versionEndExcluding"),
                    end_including: text("versionEndIncluding"),
                });
            }
        }
    }
    systems.sort();
    systems.dedup();
    systems.truncate(MAX_OS);
    (kept, systems)
}

/// The affected application ranges of one NVD record, with the Fedora
/// releases NVD lists as affected on every range of the CVE.
fn applicability(cve: &Value) -> Vec<Applicability> {
    let Some(cve_id) = cve["id"].as_str().filter(|id| is_cve(id)) else {
        return Vec::new();
    };
    let cvss = cvss(&cve["metrics"]).map(|s| s.0);
    let (kept, systems) = kept_matches(cve);
    let fedora = fedora_releases(&systems);
    kept.iter()
        .filter_map(|m| {
            let mut row = range_row(
                cve_id,
                cvss,
                &m.criteria,
                m.start_including.as_deref(),
                m.end_excluding.as_deref(),
                m.end_including.as_deref(),
            )?;
            row.fedora.clone_from(&fedora);
            Some(row)
        })
        .collect()
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
