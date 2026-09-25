//! OSV.dev records for Rocky Linux, AlmaLinux, Debian and Ubuntu (spec
//! `2026-09-25-osv-distributions-design.md`): one record becomes one
//! advisory per release it affects.

use std::{fmt, str::FromStr};

use chrono::{DateTime, Utc};
use platform_store::vulns::{FixedRow, NewAdvisory};
use serde::Deserialize;
use serde_json::Value;

use crate::{enrich::is_cve, updateinfo::ParseError};

/// A distribution release OSV publishes for, e.g. `debian-12`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Release {
    /// os-release `ID`: `rocky`, `almalinux`, `debian`, or `ubuntu`.
    pub os_id: &'static str,
    /// The release as advisories name it: `9`, `12`, `24.04`.
    pub version: String,
}

impl Release {
    /// The source's name, e.g. `debian-12`.
    #[must_use]
    pub fn name(&self) -> String {
        format!("{}-{}", self.os_id, self.version)
    }

    /// The OSV directory to download: the whole ecosystem, filtered to
    /// this release on import. (OSV's per-release files, e.g. `Debian:12`,
    /// stopped updating in October 2024.)
    #[must_use]
    pub fn ecosystem(&self) -> &'static str {
        match self.os_id {
            "rocky" => "Rocky Linux",
            "almalinux" => "AlmaLinux",
            "debian" => "Debian",
            _ => "Ubuntu",
        }
    }

    /// The record kind each distribution publishes its vulnerabilities as;
    /// others (notices that repeat them, bug-fix advisories, legacy ids)
    /// are skipped so nothing is listed twice.
    pub(crate) fn accepts(&self, id: &str) -> bool {
        let prefix = match self.os_id {
            "rocky" => "RLSA-",
            "almalinux" => "ALSA-",
            "debian" => "DEBIAN-CVE-",
            _ => "UBUNTU-CVE-",
        };
        id.starts_with(prefix)
    }

    /// Whether an `affected[].package.ecosystem` is this release.
    fn is(&self, ecosystem: &str) -> bool {
        match self.os_id {
            "rocky" => ecosystem == format!("Rocky Linux:{}", self.version),
            "almalinux" => ecosystem == format!("AlmaLinux:{}", self.version),
            "debian" => ecosystem == format!("Debian:{}", self.version),
            _ => {
                ecosystem == format!("Ubuntu:{}", self.version)
                    || ecosystem == format!("Ubuntu:{}:LTS", self.version)
            }
        }
    }
}

impl fmt::Display for Release {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name())
    }
}

impl FromStr for Release {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, String> {
        let digits =
            |s: &str| !s.is_empty() && s.len() <= 4 && s.bytes().all(|b| b.is_ascii_digit());
        let parsed = match value.split_once('-') {
            Some(("rocky", v)) if digits(v) => Some(("rocky", v)),
            Some(("almalinux", v)) if digits(v) => Some(("almalinux", v)),
            Some(("debian", v)) if digits(v) => Some(("debian", v)),
            Some(("ubuntu", v))
                if v.split_once('.')
                    .is_some_and(|(y, m)| digits(y) && m.len() == 2 && digits(m)) =>
            {
                Some(("ubuntu", v))
            }
            _ => None,
        };
        parsed
            .map(|(os_id, version)| Self {
                os_id,
                version: version.to_owned(),
            })
            .ok_or_else(|| "use rocky-N, almalinux-N, debian-N, or ubuntu-YY.MM".to_owned())
    }
}

/// One OSV record, reduced to what matching needs.
#[derive(Clone, Debug, PartialEq)]
pub struct Record {
    /// e.g. `CVE-2024-1234`, `RLSA-2024:1234`, `UBUNTU-CVE-2024-1234`.
    pub id: String,
    /// Summary, or the details' first line, or the id.
    pub title: String,
    /// CVE ids from the id, `aliases`, `upstream` and `related`.
    pub cves: Vec<String>,
    /// Record-level severity (title prefix, Ubuntu priority).
    pub severity: Option<&'static str>,
    /// Published.
    pub published: Option<DateTime<Utc>>,
    /// Last modified.
    pub modified: Option<DateTime<Utc>>,
    affected: Vec<Affected>,
}

#[derive(Clone, Debug, PartialEq)]
struct Affected {
    ecosystem: String,
    name: String,
    /// Debian's per-release urgency.
    severity: Option<&'static str>,
    /// Marked `unimportant` (Debian) or `negligible` (Ubuntu): not a
    /// security problem in practice; skipped, as the distributions' own
    /// tools do.
    ignored: bool,
    ranges: Vec<(Option<String>, Option<String>, Option<String>)>,
}

#[derive(Deserialize)]
struct RawRecord {
    id: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    details: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    upstream: Vec<String>,
    #[serde(default)]
    related: Vec<String>,
    #[serde(default)]
    severity: Vec<Value>,
    #[serde(default)]
    published: Option<String>,
    #[serde(default)]
    modified: Option<String>,
    #[serde(default)]
    affected: Vec<Value>,
}

fn time(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

/// Maps a distribution's severity word onto the platform's scale.
fn severity(word: &str) -> Option<&'static str> {
    match word.trim().to_ascii_lowercase().as_str() {
        "critical" => Some("critical"),
        "high" | "important" => Some("important"),
        "medium" | "moderate" => Some("moderate"),
        "low" | "negligible" | "unimportant" => Some("low"),
        _ => None,
    }
}

/// `ECOSYSTEM` range events as (introduced, fixed, last_affected) ranges;
/// an introduced `0` means from the start.
fn ranges(ranges: &[Value]) -> Vec<(Option<String>, Option<String>, Option<String>)> {
    let mut out = Vec::new();
    for range in ranges.iter().filter(|r| r["type"] == "ECOSYSTEM") {
        let mut open: Option<Option<String>> = None;
        for event in range["events"].as_array().into_iter().flatten() {
            let text = |key: &str| event[key].as_str().map(str::to_owned);
            if let Some(introduced) = text("introduced") {
                if let Some(start) = open.take() {
                    out.push((start, None, None));
                }
                open = Some(Some(introduced).filter(|v| v != "0"));
            } else if let Some(fixed) = text("fixed") {
                out.push((open.take().flatten(), Some(fixed), None));
            } else if let Some(last) = text("last_affected") {
                out.push((open.take().flatten(), None, Some(last)));
            }
        }
        if let Some(start) = open {
            out.push((start, None, None));
        }
    }
    out
}

/// Parses one OSV JSON record.
pub fn parse(content: &[u8]) -> Result<Record, ParseError> {
    let raw: RawRecord = serde_json::from_slice(content).map_err(|_| ParseError::Malformed)?;
    if raw.id.is_empty() || raw.id.len() > 128 {
        return Err(ParseError::Malformed);
    }
    let mut cves: Vec<String> = std::iter::once(&raw.id)
        .chain(&raw.aliases)
        .chain(&raw.upstream)
        .chain(&raw.related)
        .filter(|id| is_cve(id))
        .cloned()
        .collect();
    cves.sort();
    cves.dedup();
    let title_severity = raw
        .summary
        .split_once(':')
        .and_then(|(word, _)| severity(word));
    let ubuntu_word = raw
        .severity
        .iter()
        .find(|s| s["type"] == "Ubuntu")
        .and_then(|s| s["score"].as_str());
    let ubuntu = ubuntu_word.and_then(severity);
    let negligible = |word: Option<&str>| {
        word.is_some_and(|w| {
            matches!(
                w.trim().to_ascii_lowercase().as_str(),
                "unimportant" | "negligible"
            )
        })
    };
    let record_ignored = negligible(ubuntu_word);
    let title = [
        raw.summary.as_str(),
        raw.details.lines().next().unwrap_or(""),
    ]
    .into_iter()
    .find(|t| !t.trim().is_empty())
    .map_or_else(|| raw.id.clone(), |t| t.trim().chars().take(200).collect());
    let affected = raw
        .affected
        .iter()
        .filter_map(|a| {
            Some(Affected {
                ecosystem: a["package"]["ecosystem"].as_str()?.to_owned(),
                name: a["package"]["name"]
                    .as_str()
                    .filter(|n| !n.is_empty())?
                    .to_owned(),
                severity: a["ecosystem_specific"]["urgency"]
                    .as_str()
                    .and_then(severity),
                ignored: record_ignored || negligible(a["ecosystem_specific"]["urgency"].as_str()),
                ranges: ranges(a["ranges"].as_array().map_or(&[][..], Vec::as_slice)),
            })
        })
        .collect();
    Ok(Record {
        id: raw.id,
        title,
        cves,
        severity: title_severity.or(ubuntu),
        published: raw.published.as_deref().and_then(time),
        modified: raw.modified.as_deref().and_then(time),
        affected,
    })
}

/// The advisory a record makes for one release (`ID/release`), or `None`
/// when it affects nothing there, is not the distribution's own record
/// kind, or is marked unimportant or negligible.
#[must_use]
pub fn advisory(record: &Record, release: &Release) -> Option<NewAdvisory> {
    if !release.accepts(&record.id) {
        return None;
    }
    let mine: Vec<&Affected> = record
        .affected
        .iter()
        .filter(|a| release.is(&a.ecosystem) && !a.ignored)
        .collect();
    // Debian, Ubuntu and Rocky name source packages; AlmaLinux binaries.
    let (scheme, match_on) = match release.os_id {
        "debian" | "ubuntu" => ("dpkg", "source"),
        "rocky" => ("rpm", "source"),
        _ => ("rpm", "binary"),
    };
    let packages: Vec<FixedRow> = mine
        .iter()
        .flat_map(|a| {
            a.ranges.iter().map(|(introduced, fixed, last)| FixedRow {
                name: a.name.clone(),
                // Any architecture: OSV names no architecture here.
                arch: String::new(),
                scheme: scheme.into(),
                match_on: match_on.into(),
                introduced: introduced.clone(),
                fixed: fixed.clone(),
                last_affected: last.clone(),
            })
        })
        .collect();
    if packages.is_empty() {
        return None;
    }
    let severity = mine
        .iter()
        .find_map(|a| a.severity)
        .or(record.severity)
        .unwrap_or("unrated");
    Some(NewAdvisory {
        advisory_id: format!("{}/{}", record.id, release.name()),
        severity: severity.into(),
        title: record.title.clone(),
        issued_at: record.published,
        updated_at: record.modified,
        url: format!("https://osv.dev/vulnerability/{}", record.id),
        cves: record.cves.clone(),
        packages,
    })
}

/// Largest single record read from a zip (Debian's largest are ~100 KB).
const MAX_RECORD: u64 = 4 << 20;
/// Largest total read from one zip (Ubuntu 24.04 opens to about 1.5 GB).
pub const MAX_OPEN_BYTES: u64 = 8 << 30;

/// What reading a zip found.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ZipAdvisories {
    /// Advisories for the release.
    pub advisories: Vec<NewAdvisory>,
    /// Records read.
    pub records: usize,
    /// Records skipped as unreadable or over the size cap.
    pub skipped: usize,
}

/// Reads an OSV `all.zip` record by record and keeps the advisories for
/// `release`. An unreadable record is skipped and counted; an unreadable
/// zip, or one opening past `max_open` bytes, is refused.
pub fn advisories_from_zip(
    content: &[u8],
    release: &Release,
    max_open: u64,
) -> Result<ZipAdvisories, ParseError> {
    read_zip(
        std::io::Cursor::new(content),
        std::slice::from_ref(release),
        max_open,
    )
    .map(|mut found| found.remove(0))
}

/// Reads an OSV `all.zip` once for several releases (one result each, in
/// order): a whole ecosystem's file is read once however many of its
/// releases hosts run.
pub fn read_zip<R: std::io::Read + std::io::Seek>(
    reader: R,
    releases: &[Release],
    max_open: u64,
) -> Result<Vec<ZipAdvisories>, ParseError> {
    use std::io::Read;
    let mut archive = zip::ZipArchive::new(reader).map_err(|_| ParseError::Malformed)?;
    let mut found = vec![ZipAdvisories::default(); releases.len()];
    let mut total = 0u64;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).map_err(|_| ParseError::Malformed)?;
        if !entry.name().ends_with(".json") {
            continue;
        }
        let mut bytes = Vec::new();
        let read = entry
            .by_ref()
            .take(MAX_RECORD + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ParseError::Malformed)?;
        total += read as u64;
        if total > max_open {
            return Err(ParseError::TooLarge);
        }
        let record = parse(&bytes).ok().filter(|_| read as u64 <= MAX_RECORD);
        for (release, found) in releases.iter().zip(found.iter_mut()) {
            found.records += 1;
            match &record {
                Some(record) => found.advisories.extend(advisory(record, release)),
                None => found.skipped += 1,
            }
        }
    }
    Ok(found)
}

/// Imports an OSV `all.zip` for one release: its advisories are stored,
/// the release is re-matched, and the source (`release.name()`) is
/// recorded; a failure is recorded on the source and changes nothing else.
/// Returns the import report and the number of records skipped.
pub async fn import(
    client: &mut platform_store::Client,
    release: &Release,
    content: Vec<u8>,
    now: DateTime<Utc>,
) -> Result<(crate::feed::ImportReport, usize), crate::feed::ImportError> {
    use sha2::{Digest, Sha256};
    let name = release.name();
    let key = (name.as_str(), release.os_id, release.version.as_str(), "");
    let sha256: [u8; 32] = Sha256::digest(&content).into();
    let owned = release.clone();
    let parsed =
        tokio::task::spawn_blocking(move || advisories_from_zip(&content, &owned, MAX_OPEN_BYTES))
            .await
            .unwrap_or(Err(ParseError::Malformed));
    let found = match parsed {
        Ok(found) => found,
        Err(error) => {
            let error = crate::feed::ImportError::Parse(error);
            platform_store::vulns::record_feed(client, key, Err(&error.to_string()), now).await?;
            return Err(error);
        }
    };
    let report = crate::feed::store_and_match(client, key, &found.advisories, sha256, now).await?;
    Ok((report, found.skipped))
}
