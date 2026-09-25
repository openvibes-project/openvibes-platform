//! CVE enrichment sources (VM spec §9): CISA KEV (exploited in the wild)
//! and FIRST EPSS (probability of exploitation in the next 30 days).

use std::{fmt, io::Read, str::FromStr};

use chrono::{DateTime, NaiveDate, Utc};
pub use platform_store::enrichment::{Epss, Kev};
use platform_store::{Client, StoreError, enrichment, vulns};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::updateinfo::ParseError;

/// Largest EPSS file read once decompressed (the full file is 11 MB).
pub const MAX_EPSS_OPEN: u64 = 128 << 20;

/// An enrichment source, stored in `feed_sources` under its name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Source {
    /// CISA Known Exploited Vulnerabilities.
    Kev,
    /// FIRST Exploit Prediction Scoring System.
    Epss,
}

impl Source {
    /// `kev` or `epss`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Kev => "kev",
            Self::Epss => "epss",
        }
    }
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Source {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, String> {
        match value {
            "kev" => Ok(Self::Kev),
            "epss" => Ok(Self::Epss),
            _ => Err("use kev or epss".into()),
        }
    }
}

/// Why an import failed; the previous enrichment is kept.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrichError {
    /// The content is not a readable file of that source.
    Parse(Source, ParseError),
    /// The database refused.
    Store(StoreError),
}

impl fmt::Display for EnrichError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(source, ParseError::TooLarge) => {
                write!(f, "{source} feed larger than the size cap")
            }
            Self::Parse(source, ParseError::Malformed) => write!(f, "not a readable {source} feed"),
            Self::Store(error) => write!(f, "{error}"),
        }
    }
}

impl From<StoreError> for EnrichError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

/// Imports a KEV or EPSS file and records the source's state. Returns the
/// number of CVEs it lists. A failure is recorded on the source and changes
/// nothing else.
pub async fn import(
    client: &mut Client,
    source: Source,
    content: &[u8],
    now: DateTime<Utc>,
) -> Result<usize, EnrichError> {
    // Enrichment sources are per CVE, not per release.
    let key = (source.name(), "cve", "", "");
    let stored = match source {
        Source::Kev => match parse_kev(content) {
            Ok(entries) => enrichment::replace_kev(client, &entries)
                .await
                .map(|()| Ok(entries.len())),
            Err(error) => Ok(Err(error)),
        },
        Source::Epss => match parse_epss(content, MAX_EPSS_OPEN) {
            Ok(file) => enrichment::replace_epss(client, file.date, &file.scores)
                .await
                .map(|()| Ok(file.scores.len())),
            Err(error) => Ok(Err(error)),
        },
    }?;
    match stored {
        Ok(count) => {
            let sha256: [u8; 32] = Sha256::digest(content).into();
            let records = i32::try_from(count).unwrap_or(i32::MAX);
            vulns::record_feed(client, key, Ok((sha256, records)), now).await?;
            Ok(count)
        }
        Err(error) => {
            let error = EnrichError::Parse(source, error);
            vulns::record_feed(client, key, Err(&error.to_string()), now).await?;
            Err(error)
        }
    }
}

/// One EPSS file: the day it scores and every CVE's score.
#[derive(Clone, Debug, PartialEq)]
pub struct EpssFile {
    /// From the header comment (`score_date:`), when present.
    pub date: Option<NaiveDate>,
    /// Scores in file order.
    pub scores: Vec<Epss>,
}

/// Whether `id` is a CVE id: `CVE-`, a four-digit year, 4 to 19 digits.
#[must_use]
pub fn is_cve(id: &str) -> bool {
    let digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    let mut parts = id.split('-');
    matches!(
        (parts.next(), parts.next(), parts.next(), parts.next()),
        (Some("CVE"), Some(year), Some(number), None)
            if year.len() == 4 && digits(year) && (4..=19).contains(&number.len()) && digits(number)
    )
}

#[derive(Deserialize)]
struct Catalog {
    vulnerabilities: Vec<CatalogEntry>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CatalogEntry {
    #[serde(rename = "cveID")]
    cve_id: String,
    date_added: String,
    #[serde(default)]
    due_date: Option<String>,
    #[serde(default)]
    known_ransomware_campaign_use: Option<String>,
}

/// Parses the KEV catalog JSON. Entries without a valid CVE id or added
/// date are skipped; anything but a catalog is `Malformed`.
pub fn parse_kev(content: &[u8]) -> Result<Vec<Kev>, ParseError> {
    let catalog: Catalog = serde_json::from_slice(content).map_err(|_| ParseError::Malformed)?;
    Ok(catalog
        .vulnerabilities
        .into_iter()
        .filter(|entry| is_cve(&entry.cve_id))
        .filter_map(|entry| {
            Some(Kev {
                added: entry.date_added.parse().ok()?,
                due: entry.due_date.and_then(|d| d.parse().ok()),
                ransomware: entry.known_ransomware_campaign_use.as_deref() == Some("Known"),
                cve_id: entry.cve_id,
            })
        })
        .collect())
}

/// Parses an EPSS CSV, gzip-compressed or plain (by its magic bytes), at
/// most `max_open` bytes once decompressed. Any bad row refuses the file.
pub fn parse_epss(content: &[u8], max_open: u64) -> Result<EpssFile, ParseError> {
    let reader: Box<dyn Read> = if content.starts_with(&[0x1f, 0x8b]) {
        Box::new(flate2::read::GzDecoder::new(content))
    } else {
        Box::new(content)
    };
    let mut text = String::new();
    reader
        .take(max_open + 1)
        .read_to_string(&mut text)
        .map_err(|_| ParseError::Malformed)?;
    if text.len() as u64 > max_open {
        return Err(ParseError::TooLarge);
    }
    let mut date = None;
    let mut lines = text.lines().filter(|line| !line.is_empty());
    let mut header = lines.next();
    if let Some(comment) = header.and_then(|line| line.strip_prefix('#')) {
        date = comment
            .split(',')
            .find_map(|field| field.strip_prefix("score_date:"))
            .and_then(|value| value.get(..10))
            .and_then(|day| day.parse().ok());
        header = lines.next();
    }
    if header != Some("cve,epss,percentile") {
        return Err(ParseError::Malformed);
    }
    let unit = |value: &str| {
        value
            .parse::<f32>()
            .ok()
            .filter(|v| (0.0..=1.0).contains(v))
    };
    let scores = lines
        .map(|line| {
            let mut fields = line.split(',');
            match (fields.next(), fields.next(), fields.next(), fields.next()) {
                (Some(cve), Some(score), Some(percentile), None) if is_cve(cve) => Some(Epss {
                    cve_id: cve.to_owned(),
                    score: unit(score)?,
                    percentile: unit(percentile)?,
                }),
                _ => None,
            }
        })
        .collect::<Option<Vec<_>>>()
        .ok_or(ParseError::Malformed)?;
    Ok(EpssFile { date, scores })
}

#[cfg(test)]
mod tests {
    use super::is_cve;

    #[test]
    fn cve_ids() {
        assert!(is_cve("CVE-2021-44228"));
        assert!(is_cve("CVE-1999-0001"));
        assert!(!is_cve("CVE-2021-123"));
        assert!(!is_cve("CVE-21-44228"));
        assert!(!is_cve("cve-2021-44228"));
        assert!(!is_cve("CVE-2021-44228-x"));
    }
}
