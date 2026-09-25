//! NVD API 2.0 and EUVD responses, parsed from trimmed real responses
//! (2026-09-25).

use std::path::PathBuf;

use openvibes_vulns::{enrich, updateinfo::ParseError};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name),
    )
    .unwrap()
}

#[test]
fn nvd_keeps_the_newest_cvss_preferring_nvds_own() {
    let page = enrich::parse_nvd(&fixture("nvd.json")).unwrap();
    assert_eq!((page.total, page.start), (4, 0));
    let by_id = |id: &str| page.entries.iter().find(|e| e.cve_id == id).unwrap();

    let log4j = by_id("CVE-2021-44228");
    assert_eq!(log4j.cvss_score, Some(10.0));
    assert_eq!(log4j.cvss_version.as_deref(), Some("3.1"));
    assert_eq!(
        log4j.cvss_vector.as_deref(),
        Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
    );
    assert_eq!(log4j.cwe, ["CWE-20", "CWE-400", "CWE-502", "CWE-917"]);
    assert!(
        log4j
            .description
            .as_deref()
            .unwrap()
            .starts_with("Apache Log4j2 2.0-beta9"),
        "the English description"
    );
    assert_eq!(
        log4j.modified_at.unwrap().to_rfc3339(),
        "2026-08-11T19:33:44.513+00:00"
    );

    // CVSS 4.0 from the vendor beats NVD's own 3.1; CWE deduplicated.
    let v4 = by_id("CVE-2025-0108");
    assert_eq!(
        (v4.cvss_score, v4.cvss_version.as_deref()),
        (Some(8.8), Some("4.0"))
    );
    assert_eq!(v4.cwe, ["CWE-306"]);
    // 3.1 from a CNA beats NVD's own 2.0.
    let old = by_id("CVE-2008-4128");
    assert_eq!(
        (old.cvss_score, old.cvss_version.as_deref()),
        (Some(8.1), Some("3.1"))
    );
    // Not yet analysed: no score, no weakness, still a description.
    let fresh = by_id("CVE-2026-75432");
    assert_eq!(fresh.cvss_score, None);
    assert!(fresh.cwe.is_empty());
    assert!(fresh.description.is_some());
}

#[test]
fn nvd_refuses_other_json() {
    assert_eq!(enrich::parse_nvd(b"{}"), Err(ParseError::Malformed));
    assert_eq!(
        enrich::parse_nvd(b"<html>rate limited</html>"),
        Err(ParseError::Malformed)
    );
}

#[test]
fn euvd_maps_each_cve_alias_to_its_euvd_entry() {
    let page = enrich::parse_euvd(&fixture("euvd.json")).unwrap();
    assert_eq!(page.total, 1735);
    let pairs: Vec<(&str, &str)> = page
        .entries
        .iter()
        .map(|e| (e.cve_id.as_str(), e.euvd_id.as_str()))
        .collect();
    assert_eq!(
        pairs,
        [
            ("CVE-2026-5430", "EUVD-2026-53822"),
            ("CVE-2026-71362", "EUVD-2026-56844"),
            ("CVE-2026-81963", "EUVD-2026-73889"),
        ],
        "GHSA aliases skipped"
    );
    assert_eq!(page.entries[2].exploited_since, "2026-09-08".parse().ok());
    assert_eq!(enrich::parse_euvd(b"[]"), Err(ParseError::Malformed));
}
