//! CPE matching storage (spec `docs/specs/2026-10-06-cpe-matching-design.md`):
//! NVD applicability ranges for products installed packages could be, and
//! the lower-confidence findings built from them. The version tests
//! themselves live in `openvibes-vulns`; this module stores and queries,
//! within the `openvibes-vulns` role's grants.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};

use crate::{Client, StoreError};

/// One affected range of one upstream product, from NVD `cpeMatch`.
#[derive(Clone, Debug, PartialEq)]
pub struct Applicability {
    /// CVE id.
    pub cve_id: String,
    /// CPE vendor.
    pub vendor: String,
    /// CPE product, lower case.
    pub product: String,
    /// First affected version (`None`: from the start).
    pub introduced: Option<String>,
    /// First fixed version (`versionEndExcluding`).
    pub fixed: Option<String>,
    /// Last affected version (`versionEndIncluding`, or an exact version).
    pub last_affected: Option<String>,
    /// CVSS base score, for the finding's severity.
    pub cvss: Option<f32>,
    /// Fedora releases NVD itself lists as affected.
    pub fedora: Vec<String>,
}

/// An installed package name and, when reported, its source package.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct InstalledName {
    /// Binary package name.
    pub name: String,
    /// Source package name, when the host reported it.
    pub source: Option<String>,
}

/// One installed package version on hosts of a release.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseVersion {
    /// The package version's id.
    pub id: i64,
    /// Binary package name.
    pub name: String,
    /// Source package name, when reported.
    pub source: Option<String>,
    /// Upstream version (the RPM version, not the release).
    pub version: String,
    /// Full `E:V-R`, for display.
    pub installed: String,
}

/// A finding to store: an installed version in an affected range.
#[derive(Clone, Debug, PartialEq)]
pub struct NewFinding {
    /// The package version's id.
    pub package_version_id: i64,
    /// CVE id.
    pub cve_id: String,
    /// CPE product matched.
    pub product: String,
    /// Installed package name.
    pub package: String,
    /// Installed `E:V-R`.
    pub installed: String,
    /// The affected range, as text.
    pub range_text: String,
    /// Confidence, 0 to 100.
    pub confidence: i16,
    /// A sentence saying how it was matched.
    pub basis: String,
    /// CVSS base score.
    pub cvss: Option<f32>,
}

/// Distinct names of packages installed on hosts of `os_id`.
pub async fn installed_names(
    client: &Client,
    os_id: &str,
) -> Result<Vec<InstalledName>, StoreError> {
    let rows = client
        .query(
            "SELECT DISTINCT pv.name, pv.source
             FROM agents g JOIN host_packages h ON h.agent_id = g.agent_id
             JOIN package_versions pv ON pv.id = h.package_version_id
             WHERE g.os_id = $1 AND pv.manager = 'rpm'",
            &[&os_id],
        )
        .await?;
    let names: BTreeSet<InstalledName> = rows
        .iter()
        .map(|row| InstalledName {
            name: row.get(0),
            source: row.get(1),
        })
        .collect();
    Ok(names.into_iter().collect())
}

/// Adds products to keep; returns how many were new.
pub async fn add_products(client: &Client, products: &[String]) -> Result<u64, StoreError> {
    Ok(client
        .execute(
            "INSERT INTO cve_applicability_products (product)
             SELECT * FROM unnest($1::text[]) ON CONFLICT DO NOTHING",
            &[&products],
        )
        .await?)
}

/// Replaces the stored ranges of `cve_ids` with `rows`, keeping only rows
/// of products being kept. Returns the rows stored.
pub async fn replace_applicability(
    client: &mut Client,
    cve_ids: &[String],
    rows: &[Applicability],
) -> Result<u64, StoreError> {
    let transaction = client.transaction().await?;
    transaction
        .execute(
            "DELETE FROM cve_applicability WHERE cve_id = ANY($1)",
            &[&cve_ids],
        )
        .await?;
    let cves: Vec<&str> = rows.iter().map(|r| r.cve_id.as_str()).collect();
    let vendors: Vec<&str> = rows.iter().map(|r| r.vendor.as_str()).collect();
    let products: Vec<&str> = rows.iter().map(|r| r.product.as_str()).collect();
    let introduced: Vec<Option<&str>> = rows.iter().map(|r| r.introduced.as_deref()).collect();
    let fixed: Vec<Option<&str>> = rows.iter().map(|r| r.fixed.as_deref()).collect();
    let last: Vec<Option<&str>> = rows.iter().map(|r| r.last_affected.as_deref()).collect();
    let cvss: Vec<Option<f32>> = rows.iter().map(|r| r.cvss).collect();
    // text[][] cannot be ragged: release lists travel comma-joined.
    let fedora: Vec<String> = rows.iter().map(|r| r.fedora.join(",")).collect();
    let stored = transaction
        .execute(
            "INSERT INTO cve_applicability (cve_id, vendor, product, introduced, fixed,
                 last_affected, cvss, fedora)
             SELECT c, v, p, i, f, l, s, COALESCE(string_to_array(NULLIF(d, ''), ','), '{}')
             FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[],
                         $6::text[], $7::real[], $8::text[]) AS x(c, v, p, i, f, l, s, d)
             WHERE p IN (SELECT product FROM cve_applicability_products)",
            &[
                &cves,
                &vendors,
                &products,
                &introduced,
                &fixed,
                &last,
                &cvss,
                &fedora,
            ],
        )
        .await?;
    transaction.commit().await?;
    Ok(stored)
}

/// Stored ranges of these products.
pub async fn applicability_for(
    client: &Client,
    products: &[String],
) -> Result<Vec<Applicability>, StoreError> {
    Ok(client
        .query(
            "SELECT cve_id, vendor, product, introduced, fixed, last_affected, cvss, fedora
             FROM cve_applicability WHERE product = ANY($1)
             ORDER BY cve_id, product, introduced NULLS FIRST",
            &[&products],
        )
        .await?
        .iter()
        .map(|row| Applicability {
            cve_id: row.get(0),
            vendor: row.get(1),
            product: row.get(2),
            introduced: row.get(3),
            fixed: row.get(4),
            last_affected: row.get(5),
            cvss: row.get(6),
            fedora: row.get(7),
        })
        .collect())
}

/// CVEs some distribution advisory of the release already names; CPE
/// findings never repeat or contradict them.
pub async fn advised_cves(
    client: &Client,
    os_id: &str,
    os_version: &str,
) -> Result<BTreeSet<String>, StoreError> {
    Ok(client
        .query(
            "SELECT DISTINCT c.cve_id FROM advisory_cves c
             JOIN advisories a ON a.advisory_id = c.advisory_id
             WHERE a.os_id = $1 AND a.os_version = $2",
            &[&os_id, &os_version],
        )
        .await?
        .iter()
        .map(|row| row.get(0))
        .collect())
}

/// Distinct installed package versions on hosts of a release.
pub async fn release_versions(
    client: &Client,
    os_id: &str,
    os_version: &str,
) -> Result<Vec<ReleaseVersion>, StoreError> {
    Ok(client
        .query(
            "SELECT DISTINCT pv.id, pv.name, pv.source, pv.version,
                    pv.epoch || ':' || pv.version || '-' || pv.release
             FROM agents g JOIN host_packages h ON h.agent_id = g.agent_id
             JOIN package_versions pv ON pv.id = h.package_version_id
             WHERE g.os_id = $1 AND g.os_release = $2 AND pv.manager = 'rpm'",
            &[&os_id, &os_version],
        )
        .await?
        .iter()
        .map(|row| ReleaseVersion {
            id: row.get(0),
            name: row.get(1),
            source: row.get(2),
            version: row.get(3),
            installed: row.get(4),
        })
        .collect())
}

/// Makes the release's findings exactly `findings` (first-seen times of
/// ones that stay are kept). Returns the number stored.
pub async fn replace_findings(
    client: &mut Client,
    os_version: &str,
    findings: &[NewFinding],
    now: DateTime<Utc>,
) -> Result<usize, StoreError> {
    let transaction = client.transaction().await?;
    let versions: Vec<i64> = findings.iter().map(|f| f.package_version_id).collect();
    let cves: Vec<&str> = findings.iter().map(|f| f.cve_id.as_str()).collect();
    let products: Vec<&str> = findings.iter().map(|f| f.product.as_str()).collect();
    let packages: Vec<&str> = findings.iter().map(|f| f.package.as_str()).collect();
    let installed: Vec<&str> = findings.iter().map(|f| f.installed.as_str()).collect();
    let ranges: Vec<&str> = findings.iter().map(|f| f.range_text.as_str()).collect();
    let confidence: Vec<i16> = findings.iter().map(|f| f.confidence).collect();
    let basis: Vec<&str> = findings.iter().map(|f| f.basis.as_str()).collect();
    let cvss: Vec<Option<f32>> = findings.iter().map(|f| f.cvss).collect();
    transaction
        .execute(
            "DELETE FROM cpe_findings f WHERE f.os_version = $1 AND NOT EXISTS (
                 SELECT 1 FROM unnest($2::bigint[], $3::text[], $4::text[]) AS k(v, c, p)
                 WHERE k.v = f.package_version_id AND k.c = f.cve_id AND k.p = f.product)",
            &[&os_version, &versions, &cves, &products],
        )
        .await?;
    transaction
        .execute(
            "INSERT INTO cpe_findings (package_version_id, os_version, cve_id, product, package,
                 installed, range_text, confidence, basis, cvss, first_seen_at)
             SELECT v, $1, c, p, k, i, r, f, b, s, $11
             FROM unnest($2::bigint[], $3::text[], $4::text[], $5::text[], $6::text[],
                         $7::text[], $8::smallint[], $9::text[], $10::real[])
                  AS x(v, c, p, k, i, r, f, b, s)
             ON CONFLICT (package_version_id, os_version, cve_id, product) DO UPDATE SET
                 package = EXCLUDED.package, installed = EXCLUDED.installed,
                 range_text = EXCLUDED.range_text, confidence = EXCLUDED.confidence,
                 basis = EXCLUDED.basis, cvss = EXCLUDED.cvss",
            &[
                &os_version,
                &versions,
                &cves,
                &products,
                &packages,
                &installed,
                &ranges,
                &confidence,
                &basis,
                &cvss,
                &now,
            ],
        )
        .await?;
    transaction.commit().await?;
    Ok(findings.len())
}

/// One finding on one host, as operators see it.
#[derive(Clone, Debug, PartialEq)]
pub struct FindingRow {
    /// Host.
    pub agent_id: String,
    /// Host name, when reported.
    pub hostname: Option<String>,
    /// CVE id.
    pub cve_id: String,
    /// CPE product matched.
    pub product: String,
    /// Installed package name.
    pub package: String,
    /// Installed `E:V-R`.
    pub installed: String,
    /// The affected range, as text.
    pub range_text: String,
    /// Confidence, 0 to 100.
    pub confidence: i16,
    /// How it was matched.
    pub basis: String,
    /// When first seen.
    pub first_seen_at: DateTime<Utc>,
    /// CVSS from the CVE's applicability (NVD).
    pub cvss: Option<f32>,
    /// Exploited: on KEV or EUVD's list.
    pub exploited: bool,
    /// On CISA KEV.
    pub kev: bool,
    /// On EUVD's exploited list.
    pub euvd: bool,
    /// Earliest KEV due date.
    pub kev_due: Option<chrono::NaiveDate>,
    /// Used by ransomware.
    pub ransomware: bool,
    /// EPSS score.
    pub epss: Option<f32>,
    /// EPSS percentile.
    pub epss_percentile: Option<f32>,
    /// Title from NVD's description, when known.
    pub description: Option<String>,
}

/// Findings at or above `min_confidence` on hosts of `agents` (all hosts
/// when `None`), highest confidence and CVSS first, at most `limit`.
pub async fn list(
    client: &Client,
    min_confidence: i16,
    host: Option<&str>,
    cve: Option<&str>,
    agents: Option<&[String]>,
    limit: i64,
) -> Result<Vec<FindingRow>, StoreError> {
    Ok(client
        .query(
            "SELECT g.agent_id, g.hostname, f.cve_id, f.product, f.package, f.installed,
                    f.range_text, f.confidence, f.basis, f.first_seen_at, COALESCE(x.cvss_score, f.cvss),
                    COALESCE(x.kev_added IS NOT NULL, false), COALESCE(x.euvd_exploited, false),
                    x.kev_due, COALESCE(x.kev_ransomware, false), x.epss, x.epss_percentile,
                    x.description
             FROM cpe_findings f
             JOIN host_packages h ON h.package_version_id = f.package_version_id
             JOIN agents g ON g.agent_id = h.agent_id AND g.os_release = f.os_version
             LEFT JOIN cve_enrichment x ON x.cve_id = f.cve_id
             WHERE f.confidence >= $1
               AND ($2::text IS NULL OR g.agent_id = $2 OR g.hostname = $2)
               AND ($3::text IS NULL OR f.cve_id = $3)
               AND ($4::text[] IS NULL OR g.agent_id = ANY($4))
             ORDER BY (COALESCE(x.kev_added IS NOT NULL, false)
                       OR COALESCE(x.euvd_exploited, false)) DESC,
                      f.confidence DESC, COALESCE(x.cvss_score, f.cvss) DESC NULLS LAST,
                      f.cve_id, g.agent_id
             LIMIT $5",
            &[&min_confidence, &host, &cve, &agents, &limit],
        )
        .await?
        .iter()
        .map(|row| {
            let kev: bool = row.get(11);
            let euvd: bool = row.get(12);
            FindingRow {
                agent_id: row.get(0),
                hostname: row.get(1),
                cve_id: row.get(2),
                product: row.get(3),
                package: row.get(4),
                installed: row.get(5),
                range_text: row.get(6),
                confidence: row.get(7),
                basis: row.get(8),
                first_seen_at: row.get(9),
                cvss: row.get(10),
                exploited: kev || euvd,
                kev,
                euvd,
                kev_due: row.get(13),
                ransomware: row.get(14),
                epss: row.get(15),
                epss_percentile: row.get(16),
                description: row.get(17),
            }
        })
        .collect())
}
