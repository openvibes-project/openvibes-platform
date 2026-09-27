//! Protocol documents to store rows, shared by online delivery (ingest) and
//! file import (admin), so both refuse and store exactly alike.

use std::collections::BTreeSet;

use chrono::{DateTime, NaiveDate, Utc};
use openvibes_core::{
    Finding, InstalledPackage, NormalizedPackage, OsRelease, Severity, inventory_fingerprint,
};

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

/// The distinct normalised records of `packages` (protocol P11), as stored.
#[must_use]
pub fn package_rows(packages: &[InstalledPackage]) -> Vec<PackageRow> {
    packages
        .iter()
        .map(NormalizedPackage::from)
        .collect::<BTreeSet<_>>()
        .iter()
        .map(PackageRow::from)
        .collect()
}

/// Package rows for the store and the inventory's fingerprint (the
/// protocol's, P11), which covers the OS and running kernel too and ignores
/// the order the agent listed the packages in.
pub fn inventory(
    os: &OsRelease,
    running_kernel: Option<&str>,
    packages: &[InstalledPackage],
) -> Result<(Vec<PackageRow>, [u8; 32]), StoreError> {
    let digest = inventory_fingerprint(
        os,
        running_kernel,
        packages.iter().map(NormalizedPackage::from),
    );
    Ok((package_rows(packages), digest))
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

    #[test]
    fn the_inventory_digest_is_the_contract_fingerprint() {
        let text = include_str!("../../../protocol/vectors/inventory-fingerprint.json");
        let vectors: Vec<serde_json::Value> = serde_json::from_str(text).unwrap();
        assert_eq!(vectors.len(), 3);
        for vector in vectors {
            let input = &vector["inventory"];
            let os: OsRelease = serde_json::from_value(input["os"].clone()).unwrap();
            let packages: Vec<InstalledPackage> =
                serde_json::from_value(input["packages"].clone()).unwrap();
            let kernel = input["running_kernel"].as_str();
            let (rows, digest) = inventory(&os, kernel, &packages).unwrap();
            assert_eq!(
                openvibes_core::hex(&digest),
                vector["sha256"].as_str().unwrap()
            );
            let again = openvibes_core::inventory_fingerprint(
                &os,
                kernel,
                rows.iter().map(PackageRow::normalized),
            );
            assert_eq!(again, digest, "the stored rows give the same fingerprint");
        }
    }
}
