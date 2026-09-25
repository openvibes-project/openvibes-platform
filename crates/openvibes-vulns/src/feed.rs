//! Importing a feed's content: parse, store, record, re-match (VM spec §7).
//! Used by `openvibes-admin feeds import` and by the fetching service.

use std::{fmt, io::BufReader, str::FromStr};

use chrono::{DateTime, NaiveDateTime, Utc};
use platform_store::{
    Client, StoreError,
    vulns::{self, FixedRow, NewAdvisory},
};
use sha2::{Digest, Sha256};

use crate::{
    matching,
    updateinfo::{self, Advisory, ParseError, Severity},
};

/// Largest decompressed feed read (Fedora 44 is 45 MB).
pub const MAX_OPEN_BYTES: u64 = 512 << 20;

/// A feed source: `fedora-<release>-<arch>`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceId {
    /// e.g. `fedora`.
    pub os_id: String,
    /// e.g. `44`.
    pub os_version: String,
    /// e.g. `x86_64`.
    pub arch: String,
}

impl SourceId {
    /// The source's name, e.g. `fedora-44-x86_64`.
    #[must_use]
    pub fn name(&self) -> String {
        format!("{}-{}-{}", self.os_id, self.os_version, self.arch)
    }
}

impl FromStr for SourceId {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, String> {
        let mut parts = value.splitn(3, '-');
        match (parts.next(), parts.next(), parts.next()) {
            (Some("fedora"), Some(release), Some(arch))
                if !release.is_empty()
                    && release.bytes().all(|b| b.is_ascii_digit())
                    && !arch.is_empty()
                    && arch.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') =>
            {
                Ok(Self {
                    os_id: "fedora".into(),
                    os_version: release.into(),
                    arch: arch.into(),
                })
            }
            _ => Err("use fedora-<release>-<arch>, e.g. fedora-44-x86_64".into()),
        }
    }
}

/// Why an import failed; the previous advisories are kept.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImportError {
    /// The content is not readable updateinfo.
    Parse(ParseError),
    /// The database refused.
    Store(StoreError),
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(ParseError::TooLarge) => f.write_str("feed larger than the size cap"),
            Self::Parse(ParseError::Malformed) => f.write_str("not a readable feed file"),
            Self::Store(error) => write!(f, "{error}"),
        }
    }
}

impl From<StoreError> for ImportError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

/// What an import did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImportReport {
    /// Security advisories stored.
    pub advisories: usize,
    /// Open vulnerabilities on this release afterwards.
    pub open: usize,
}

fn severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::Important => "important",
        Severity::Moderate => "moderate",
        Severity::Low => "low",
        Severity::Unrated => "unrated",
    }
}

fn time(value: &str) -> Option<DateTime<Utc>> {
    NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S")
        .ok()
        .map(|t| t.and_utc())
}

/// The store's form of a parsed advisory.
#[must_use]
pub fn to_store(advisory: &Advisory) -> NewAdvisory {
    NewAdvisory {
        advisory_id: advisory.id.clone(),
        severity: severity(advisory.severity).into(),
        title: advisory.title.clone(),
        issued_at: time(&advisory.issued),
        updated_at: time(&advisory.updated),
        url: advisory.url(),
        cves: advisory.cves.clone(),
        packages: advisory
            .packages
            .iter()
            .map(|p| {
                FixedRow::rpm(
                    &p.name,
                    &p.arch,
                    &format!("{}:{}-{}", p.epoch, p.version, p.release),
                )
            })
            .collect(),
    }
}

/// Imports updateinfo content (plain or zstd, detected by its magic bytes)
/// for `source`, records the feed's state, and re-matches its release. A
/// failure is recorded on the feed and changes nothing else.
pub async fn import(
    client: &mut Client,
    source: &SourceId,
    content: &[u8],
    now: DateTime<Utc>,
) -> Result<ImportReport, ImportError> {
    let name = source.name();
    let key = (
        name.as_str(),
        source.os_id.as_str(),
        source.os_version.as_str(),
        source.arch.as_str(),
    );
    let parsed = if content.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
        updateinfo::read_zstd(BufReader::new(content), MAX_OPEN_BYTES)
    } else {
        updateinfo::read(BufReader::new(content), MAX_OPEN_BYTES)
    };
    let advisories = match parsed {
        Ok(advisories) => advisories,
        Err(error) => {
            let error = ImportError::Parse(error);
            vulns::record_feed(client, key, Err(&error.to_string()), now).await?;
            return Err(error);
        }
    };
    let rows: Vec<NewAdvisory> = advisories.iter().map(to_store).collect();
    store_and_match(client, key, &rows, Sha256::digest(content).into(), now).await
}

/// Stores a release's advisories, re-matches the release, and only then
/// records the feed as current (`key`: source, os id, release, arch), so a
/// failed match is retried by the next check, which sees the feed as
/// changed. Shared by the Fedora and OSV imports.
pub(crate) async fn store_and_match(
    client: &mut Client,
    key: (&str, &str, &str, &str),
    rows: &[NewAdvisory],
    sha256: [u8; 32],
    now: DateTime<Utc>,
) -> Result<ImportReport, ImportError> {
    let (name, os_id, os_version, _) = key;
    vulns::replace_advisories(client, name, os_id, os_version, rows, now).await?;
    let open = match matching::match_release(client, os_id, os_version, now).await {
        Ok(open) => open,
        Err(error) => {
            let message = format!("matching failed: {error}");
            vulns::record_feed(client, key, Err(&message), now).await?;
            return Err(ImportError::Store(error));
        }
    };
    let count = i32::try_from(rows.len()).unwrap_or(i32::MAX);
    vulns::record_feed(client, key, Ok((sha256, count)), now).await?;
    Ok(ImportReport {
        advisories: rows.len(),
        open,
    })
}
