//! Protocol documents to store rows, shared by online delivery (ingest) and
//! file import (admin), so both refuse and store exactly alike.

use std::collections::BTreeSet;

use chrono::{DateTime, NaiveDate, Utc};
use openvibes_core::{Finding, InstalledPackage, OsRelease, PackageManager, Severity};

use crate::{StoreError, ingest::StoredFinding, inventory::PackageRow};

/// Findings observed further ahead than this are refused
/// (`future_observation`); the protocol states the window.
pub const MAX_FUTURE_MINUTES: i64 = 60;

fn severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

/// The row to store for `finding`, or the reason it is refused for good:
/// observed after `latest` (`future_observation`), before `oldest`
/// (`retention_expired`), with a value the store cannot hold
/// (`out_of_range`), or on a day without a partition (`unstorable`).
pub fn finding(
    finding: &Finding,
    oldest: DateTime<Utc>,
    latest: DateTime<Utc>,
    partitions: &BTreeSet<NaiveDate>,
) -> Result<StoredFinding, &'static str> {
    let observed_at =
        DateTime::from_timestamp_millis(finding.observed_at_unix_ms).ok_or("out_of_range")?;
    let rule_version = i64::try_from(finding.rule_version).map_err(|_| "out_of_range")?;
    if observed_at > latest {
        return Err("future_observation");
    }
    if observed_at < oldest {
        return Err("retention_expired");
    }
    if !partitions.contains(&observed_at.date_naive()) {
        // No partition for a day inside retention: an operator must fix
        // maintenance; retrying cannot help this finding.
        return Err("unstorable");
    }
    Ok(StoredFinding {
        finding_id: finding.finding_id.as_str().to_owned(),
        scan_id: finding.scan_id.as_str().to_owned(),
        rule_set_id: finding
            .rule_set_id
            .as_ref()
            .map_or_else(String::new, |id| id.as_str().to_owned()),
        rule_id: finding.rule_id.as_str().to_owned(),
        rule_version,
        observed_at,
        severity: severity(finding.severity).to_owned(),
        confidence: i16::from(finding.confidence.value()),
        message: finding.message.clone(),
        evidence: finding
            .evidence
            .iter()
            .map(|key| key.as_str().to_owned())
            .collect(),
    })
}

/// Package rows for the store and the inventory digest. Sorts `packages`
/// into a canonical order first, so the digest ignores how the agent listed
/// them; the digest covers the OS and running kernel too.
pub fn inventory(
    os: &OsRelease,
    running_kernel: Option<&str>,
    packages: &mut [InstalledPackage],
) -> Result<(Vec<PackageRow>, [u8; 32]), StoreError> {
    use sha2::Digest;
    packages.sort_by_cached_key(|package| serde_json::to_string(package).unwrap_or_default());
    let bytes =
        serde_json::to_vec(&(os, running_kernel, &*packages)).map_err(|_| StoreError::Query)?;
    let digest: [u8; 32] = sha2::Sha256::digest(&bytes).into();
    let rows = packages
        .iter()
        .map(|package| PackageRow {
            manager: match package.manager {
                PackageManager::Rpm => "rpm",
                PackageManager::Dpkg => "dpkg",
            }
            .to_owned(),
            name: package.name.clone(),
            epoch: package
                .epoch
                .and_then(|e| i32::try_from(e).ok())
                .unwrap_or(0),
            version: package.version.clone(),
            release: package.release.clone().unwrap_or_default(),
            arch: package.arch.clone().unwrap_or_default(),
            source: package.source.clone(),
            source_version: package.source_version.clone(),
        })
        .collect();
    Ok((rows, digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, NaiveDate, Utc};
    use openvibes_core::{InstalledPackage, OsRelease};
    use std::collections::BTreeSet;

    fn sample(observed: DateTime<Utc>) -> openvibes_core::Finding {
        serde_json::from_value(serde_json::json!({
            "schema_version": 1, "finding_id": "finding.1", "scan_id": "scan.1",
            "rule_id": "process.ssh.running", "rule_version": 3,
            "observed_at_unix_ms": observed.timestamp_millis(),
            "severity": "medium", "confidence": 100,
            "message": "An SSH server process was observed", "evidence": ["process.names"]
        }))
        .unwrap()
    }

    #[test]
    fn finding_outside_retention_is_refused_and_inside_is_kept() {
        let now = Utc::now();
        let days: BTreeSet<NaiveDate> = [now.date_naive()].into();
        let (oldest, latest) = (
            now - chrono::Duration::days(1),
            now + chrono::Duration::hours(1),
        );
        let old = sample(now - chrono::Duration::days(2));
        assert_eq!(
            finding(&old, oldest, latest, &days),
            Err("retention_expired")
        );
        let kept = finding(&sample(now), oldest, latest, &days).unwrap();
        assert_eq!((kept.rule_version, kept.severity.as_str()), (3, "medium"));
    }

    // Two orders of the same packages give one digest and the same rows.
    #[test]
    fn inventory_digest_ignores_package_order() {
        let os: OsRelease = serde_json::from_str(r#"{"id":"fedora","version_id":"44"}"#).unwrap();
        let a: InstalledPackage =
            serde_json::from_str(r#"{"manager":"rpm","name":"a","version":"1"}"#).unwrap();
        let b: InstalledPackage =
            serde_json::from_str(r#"{"manager":"dpkg","name":"b","version":"2","epoch":1}"#)
                .unwrap();
        let (rows1, d1) = inventory(&os, None, &mut [a.clone(), b.clone()]).unwrap();
        let (rows2, d2) = inventory(&os, None, &mut [b, a]).unwrap();
        assert_eq!(d1, d2);
        assert_eq!(rows1, rows2);
        assert!(rows1.iter().any(|row| row.epoch == 1));
    }
}
