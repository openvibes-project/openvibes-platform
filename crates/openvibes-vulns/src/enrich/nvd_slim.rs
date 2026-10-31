//! The slim NVD form feeds carry (openvibes-protocol `spec/feed-v1.md`,
//! "Slim NVD"): one gzip JSON file per CVE year with just what the platform
//! keeps of NVD. The mirror's builder writes it from NVD API records
//! ([`slim_record`]); the platform reads it back into the rows the API sync
//! stores ([`parse_slim`]), so a feed gives the same data as the API.

use std::io::Read;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    is_cve,
    nvd::{
        Applicability, MAX_OS, Nvd, RawMatch, cvss, fedora_releases, kept_matches, os_ok,
        range_row, record, truncate,
    },
};
use crate::updateinfo::ParseError;

/// The only slim NVD format version.
pub const FORMAT: u32 = 1;
/// Most ranges one record may carry.
pub const MAX_RANGES: usize = 5000;
/// Largest a year file may be once decompressed.
pub const MAX_OPEN_BYTES: u64 = 256 << 20;
const MAX_DESCRIPTION: usize = 4096;
const MAX_VECTOR: usize = 512;
const MAX_BOUND: usize = 64;

/// A slim year file.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlimFile {
    /// Always 1.
    pub format: u32,
    /// The year in the CVE ids of every record.
    pub year: u32,
    /// The records, by id.
    pub records: Vec<SlimRecord>,
}

/// One CVE.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlimRecord {
    /// CVE id.
    pub id: String,
    /// NVD's `lastModified`, as it gives it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
    /// The newest CVSS version scored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvss: Option<SlimCvss>,
    /// CWE ids.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cwe: Vec<String>,
    /// English description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Affected application ranges.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ranges: Vec<SlimRange>,
    /// Every operating system NVD lists as affected, as sorted
    /// `vendor:product:version` names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub os: Vec<String>,
}

/// A CVSS score.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlimCvss {
    /// 4.0, 3.1, 3.0 or 2.0.
    pub version: String,
    /// Base score, 0.0 to 10.0.
    pub score: Tenths,
    /// NVD's severity word.
    pub severity: String,
    /// The vector string.
    pub vector: String,
}

/// A score, kept as the decimal text NVD gave so the file is byte-stable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tenths(pub u16);

impl Serialize for Tenths {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_f64(f64::from(self.0) / 10.0)
    }
}

impl<'de> Deserialize<'de> for Tenths {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let score = f64::deserialize(deserializer)?;
        if !(0.0..=10.0).contains(&score) {
            return Err(serde::de::Error::custom("score out of range"));
        }
        // A score has one decimal.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        Ok(Self((score * 10.0).round() as u16))
    }
}

/// One affected range.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlimRange {
    /// The `cpe:2.3:a:` name.
    pub cpe: String,
    /// `versionStartIncluding`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_including: Option<String>,
    /// `versionStartExcluding`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_excluding: Option<String>,
    /// `versionEndIncluding`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_including: Option<String>,
    /// `versionEndExcluding`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_excluding: Option<String>,
}

fn severity(cve: &Value, score: f32) -> String {
    let named = [
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ]
    .iter()
    .filter_map(|key| cve["metrics"].get(key)?.as_array()?.first())
    .find_map(|m| {
        m["cvssData"]["baseSeverity"]
            .as_str()
            .or_else(|| m["baseSeverity"].as_str())
    });
    named.map_or_else(
        || {
            match score {
                s if s < 0.1 => "NONE",
                s if s < 4.0 => "LOW",
                s if s < 7.0 => "MEDIUM",
                s if s < 9.0 => "HIGH",
                _ => "CRITICAL",
            }
            .to_owned()
        },
        |word| truncate(&word.to_ascii_uppercase(), 16),
    )
}

/// The slim record of one NVD API record: what [`super::parse_nvd`] keeps,
/// plus the ranges it reads. `None` for a record without a valid CVE id.
/// Rejected records keep their score and text but no ranges.
#[must_use]
pub fn slim_record(cve: &Value) -> Option<SlimRecord> {
    let kept: Nvd = record(cve)?;
    let scored = cvss(&cve["metrics"]);
    let (matches, os) = kept_matches(cve);
    // Bounds are cut to 64 bytes as the API sync cuts them, and a range the
    // reader would refuse is left out, so the file is never refused.
    let cut = |bound: Option<String>| bound.map(|b| truncate(&b, MAX_BOUND));
    let mut ranges: Vec<SlimRange> = matches
        .into_iter()
        .map(|m: RawMatch| SlimRange {
            cpe: m.criteria,
            start_including: cut(m.start_including),
            start_excluding: None,
            end_including: cut(m.end_including),
            end_excluding: cut(m.end_excluding),
        })
        .filter(range_ok)
        .collect();
    ranges.truncate(MAX_RANGES);
    Some(SlimRecord {
        id: kept.cve_id,
        modified: cve["lastModified"].as_str().map(str::to_owned),
        cvss: scored.map(|(score, version, vector)| SlimCvss {
            version: version.to_owned(),
            // One decimal: exact in tenths.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            score: Tenths((score * 10.0).round() as u16),
            severity: severity(cve, score),
            vector,
        }),
        cwe: kept.cwe,
        description: kept.description,
        ranges,
        os,
    })
}

/// What a slim year file holds, as the rows the API sync stores.
#[derive(Clone, Debug, PartialEq)]
pub struct SlimPage {
    /// The year.
    pub year: u32,
    /// Per-CVE enrichment, as [`super::parse_nvd`] gives it.
    pub entries: Vec<Nvd>,
    /// Affected ranges of every record.
    pub applicability: Vec<Applicability>,
}

fn valid_cwe(cwe: &str) -> bool {
    cwe.strip_prefix("CWE-")
        .is_some_and(|n| !n.is_empty() && n.len() <= 9 && n.bytes().all(|b| b.is_ascii_digit()))
}

fn valid_bound(bound: Option<&String>) -> bool {
    bound.is_none_or(|b| b.len() <= MAX_BOUND && !b.chars().any(char::is_control))
}

/// Whether a range is one the reader accepts: an application name of at most
/// 512 bytes and bounds of at most 64, none with control characters. The
/// builder writes only such ranges, so a file it makes is never refused.
fn range_ok(range: &SlimRange) -> bool {
    range.cpe.starts_with("cpe:2.3:a:")
        && range.cpe.len() <= 512
        && !range.cpe.chars().any(char::is_control)
        && valid_bound(range.start_including.as_ref())
        && valid_bound(range.end_including.as_ref())
        && valid_bound(range.end_excluding.as_ref())
        && valid_bound(range.start_excluding.as_ref())
}

/// Reads a slim NVD year file (gzip, at most `max_open` bytes once
/// decompressed). Any record that breaks the format refuses the file; what
/// is read is the same rows [`super::parse_nvd`] would give for the records.
///
/// # Errors
/// `Malformed` for anything that is not a well-formed slim file.
pub fn parse_slim(content: &[u8], max_open: u64) -> Result<SlimPage, ParseError> {
    let mut json = Vec::new();
    flate2::read::GzDecoder::new(content)
        .take(max_open + 1)
        .read_to_end(&mut json)
        .map_err(|_| ParseError::Malformed)?;
    if json.len() as u64 > max_open {
        return Err(ParseError::Malformed);
    }
    let file: SlimFile = serde_json::from_slice(&json).map_err(|_| ParseError::Malformed)?;
    if file.format != FORMAT {
        return Err(ParseError::Malformed);
    }
    let year = file.year.to_string();
    let (mut entries, mut applicability) = (Vec::new(), Vec::new());
    for record in file.records {
        let right_year = record
            .id
            .strip_prefix("CVE-")
            .and_then(|rest| rest.split('-').next())
            == Some(year.as_str());
        let bad = !is_cve(&record.id)
            || !right_year
            || record.cwe.iter().any(|c| !valid_cwe(c))
            || record
                .description
                .as_ref()
                .is_some_and(|d| d.len() > MAX_DESCRIPTION)
            || record.ranges.len() > MAX_RANGES
            || record.cvss.as_ref().is_some_and(|c| {
                c.vector.len() > MAX_VECTOR
                    || !["4.0", "3.1", "3.0", "2.0"].contains(&c.version.as_str())
            })
            || !record.ranges.iter().all(range_ok)
            || record.os.len() > MAX_OS
            || !record.os.iter().all(|o| os_ok(o));
        if bad {
            return Err(ParseError::Malformed);
        }
        let score = record.cvss.as_ref().map(|c| f32::from(c.score.0) / 10.0);
        let modified_at = record
            .modified
            .as_deref()
            .and_then(|t| chrono::NaiveDateTime::parse_from_str(t, "%Y-%m-%dT%H:%M:%S%.f").ok())
            .map(|t| t.and_utc());
        // The platform uses the Fedora releases among them, as the API sync does.
        let fedora = fedora_releases(&record.os);
        for range in &record.ranges {
            // An exclusive start is skipped, as the API sync does.
            if range.start_excluding.is_some() {
                continue;
            }
            applicability.extend(
                range_row(
                    &record.id,
                    score,
                    &range.cpe,
                    range.start_including.as_deref(),
                    range.end_excluding.as_deref(),
                    range.end_including.as_deref(),
                )
                .map(|mut row| {
                    row.fedora.clone_from(&fedora);
                    row
                }),
            );
        }
        entries.push(Nvd {
            cve_id: record.id,
            cvss_score: score,
            cvss_version: record.cvss.as_ref().map(|c| c.version.clone()),
            cvss_vector: record.cvss.map(|c| c.vector),
            cwe: record.cwe,
            description: record.description,
            modified_at,
        });
    }
    Ok(SlimPage {
        year: file.year,
        entries,
        applicability,
    })
}
