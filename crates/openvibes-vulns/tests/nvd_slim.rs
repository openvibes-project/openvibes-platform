//! Slim NVD year files (feed format "Slim NVD"): written from NVD API
//! records and read back into the rows the API sync stores.

use std::io::Write;

use flate2::{Compression, write::GzEncoder};
use openvibes_vulns::enrich::{self, SLIM_NVD_MAX_OPEN, SlimFile, SlimRecord};
use serde_json::Value;

const NVD: &[u8] = include_bytes!("fixtures/nvd-cpe.json");

fn gz(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

fn file(year: u32, records: Vec<SlimRecord>) -> Vec<u8> {
    gz(&serde_json::to_vec(&SlimFile {
        format: 1,
        year,
        records,
    })
    .unwrap())
}

/// The fixture's records, slimmed and grouped by CVE year.
fn slimmed() -> Vec<(u32, Vec<SlimRecord>)> {
    let page: Value = serde_json::from_slice(NVD).unwrap();
    let mut years: Vec<(u32, Vec<SlimRecord>)> = Vec::new();
    for item in page["vulnerabilities"].as_array().unwrap() {
        let record = enrich::slim_record(&item["cve"]).unwrap();
        let year: u32 = record.id[4..8].parse().unwrap();
        match years.iter_mut().find(|(y, _)| *y == year) {
            Some((_, records)) => records.push(record),
            None => years.push((year, vec![record])),
        }
    }
    years
}

#[test]
fn a_slim_file_gives_the_rows_the_api_gives() {
    let api = enrich::parse_nvd(NVD).unwrap();
    let (mut entries, mut ranges) = (Vec::new(), Vec::new());
    for (year, records) in slimmed() {
        let page = enrich::parse_slim(&file(year, records), SLIM_NVD_MAX_OPEN).unwrap();
        assert_eq!(page.year, year);
        entries.extend(page.entries);
        ranges.extend(page.applicability);
    }
    let by_id = |a: &enrich::Nvd, b: &enrich::Nvd| a.cve_id.cmp(&b.cve_id);
    let mut want = api.entries.clone();
    want.sort_by(by_id);
    entries.sort_by(by_id);
    assert_eq!(entries, want);
    // The same ranges; the Fedora releases NVD lists are not in the slim form.
    let mut want = api.applicability.clone();
    for range in &mut want {
        range.fedora.clear();
    }
    let key = |r: &platform_store::cpe::Applicability| {
        (
            r.cve_id.clone(),
            r.product.clone(),
            r.introduced.clone(),
            r.fixed.clone(),
            r.last_affected.clone(),
        )
    };
    want.sort_by_key(key);
    ranges.sort_by_key(key);
    assert_eq!(ranges, want);
    assert!(!ranges.is_empty());
}

#[test]
fn a_record_that_breaks_the_format_refuses_the_file() {
    let (year, records) = slimmed().remove(0);
    let good = records[0].clone();
    let refused = |year: u32, record: SlimRecord| {
        enrich::parse_slim(&file(year, vec![record]), SLIM_NVD_MAX_OPEN).is_err()
    };
    // A record of another year, a bad id, a bad weakness id.
    assert!(refused(year + 1, good.clone()));
    let mut bad = good.clone();
    bad.id = "CVE-xx".into();
    assert!(refused(year, bad));
    let mut bad = good.clone();
    bad.cwe = vec!["CWE-x".into()];
    assert!(refused(year, bad));
    // Too long a description, too many ranges, a non-application name.
    let mut bad = good.clone();
    bad.description = Some("x".repeat(4097));
    assert!(refused(year, bad));
    let mut bad = good.clone();
    bad.ranges = vec![bad.ranges.first().cloned().unwrap(); 5001];
    assert!(refused(year, bad));
    let mut bad = good.clone();
    let mut range = good.ranges[0].clone();
    range.cpe = "cpe:2.3:o:vendor:product:1:*:*:*:*:*:*:*".into();
    bad.ranges = vec![range];
    assert!(refused(year, bad));
    // The good one passes; so do not-gzip, other formats and an unlimited bomb fail.
    assert!(!refused(year, good));
    assert!(enrich::parse_slim(b"not gzip", SLIM_NVD_MAX_OPEN).is_err());
    assert!(enrich::parse_slim(&gz(br#"{"format":2,"year":2024,"records":[]}"#), 1 << 20).is_err());
    assert!(enrich::parse_slim(&gz(&vec![b' '; 4096]), 1024).is_err());
}

#[test]
fn a_slimmed_record_keeps_only_what_the_platform_reads() {
    let all = slimmed();
    let records: Vec<&SlimRecord> = all.iter().flat_map(|(_, r)| r).collect();
    let curl = records.iter().find(|r| r.id == "CVE-2023-38545").unwrap();
    let cvss = curl.cvss.as_ref().unwrap();
    assert_eq!(cvss.version.len(), 3);
    assert!(!cvss.severity.is_empty());
    // OpenSSH's firmware-paired (`AND`) entries are left out.
    let ssh = records.iter().find(|r| r.id == "CVE-2024-6387").unwrap();
    assert!(
        ssh.ranges
            .iter()
            .all(|r| r.cpe.starts_with("cpe:2.3:a:openbsd:openssh"))
    );
}

#[test]
fn the_builder_writes_only_what_the_reader_accepts() {
    let cve = serde_json::json!({
        "id": "CVE-2024-0001", "lastModified": "2024-01-01T00:00:00.000",
        "descriptions": [{ "lang": "en", "value": "text" }],
        "configurations": [{ "nodes": [{ "operator": "OR", "cpeMatch": [
            { "vulnerable": true, "criteria": "cpe:2.3:a:v:long:*:*:*:*:*:*:*:*",
              "versionEndExcluding": "9".repeat(80) },
            { "vulnerable": true, "criteria": "cpe:2.3:a:v:odd:*:*:*:*:*:*:*:*",
              "versionEndExcluding": "1\u{7}" },
            { "vulnerable": true, "criteria": "cpe:2.3:a:v:fine:*:*:*:*:*:*:*:*",
              "versionEndExcluding": "2.0" },
        ] }] }],
    });
    let record = enrich::slim_record(&cve).unwrap();
    // The over-long bound is cut to 64 bytes, the one with a control
    // character is left out, and the file is accepted.
    assert_eq!(record.ranges.len(), 2);
    assert_eq!(record.ranges[0].end_excluding.as_deref().unwrap().len(), 64);
    let page = enrich::parse_slim(&file(2024, vec![record]), SLIM_NVD_MAX_OPEN).unwrap();
    // The same rows the API sync stores for the records it keeps.
    let api = enrich::parse_nvd(
        serde_json::json!({
            "totalResults": 1, "startIndex": 0,
            "vulnerabilities": [{ "cve": cve }],
        })
        .to_string()
        .as_bytes(),
    )
    .unwrap();
    let long = |rows: &[platform_store::cpe::Applicability]| {
        rows.iter()
            .find(|r| r.product == "long")
            .and_then(|r| r.fixed.clone())
    };
    assert_eq!(long(&page.applicability), long(&api.applicability));
    assert_eq!(page.applicability.len(), 2);
}
