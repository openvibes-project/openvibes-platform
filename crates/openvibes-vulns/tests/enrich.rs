//! CISA KEV and FIRST EPSS parsing against trimmed real files (2026-09-24).

use std::path::PathBuf;

use chrono::NaiveDate;
use openvibes_vulns::{
    enrich::{self, Epss, Kev},
    updateinfo::ParseError,
};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name),
    )
    .unwrap()
}

fn date(value: &str) -> NaiveDate {
    value.parse().unwrap()
}

#[test]
fn kev_entries_carry_dates_and_ransomware_use() {
    let kev = enrich::parse_kev(&fixture("kev.json")).unwrap();
    assert_eq!(kev.len(), 5);
    assert_eq!(
        kev[2],
        Kev {
            cve_id: "CVE-2026-59310".into(),
            added: date("2026-08-18"),
            due: Some(date("2026-08-21")),
            ransomware: true,
        }
    );
    assert!(!kev[0].ransomware, "Unknown is not known use");
}

#[test]
fn kev_skips_entries_without_a_cve_id_and_refuses_other_json() {
    let kev = enrich::parse_kev(
        br#"{"vulnerabilities":[
            {"cveID":"CVE-2026-1","dateAdded":"2026-09-01"},
            {"cveID":"not a cve","dateAdded":"2026-09-01"},
            {"cveID":"CVE-2026-12345","dateAdded":"2026-09-01","knownRansomwareCampaignUse":"Known"}
        ]}"#,
    )
    .unwrap();
    let ids: Vec<&str> = kev.iter().map(|k| k.cve_id.as_str()).collect();
    assert_eq!(ids, ["CVE-2026-12345"]);
    assert_eq!(kev[0].due, None);
    assert_eq!(
        enrich::parse_kev(br#"{"title":"x"}"#),
        Err(ParseError::Malformed)
    );
    assert_eq!(enrich::parse_kev(b"<html>"), Err(ParseError::Malformed));
}

#[test]
fn epss_reads_gzip_or_plain_with_its_score_date() {
    let file = enrich::parse_epss(&fixture("epss.csv.gz"), 1 << 20).unwrap();
    assert_eq!(file.date, Some(date("2026-09-24")));
    assert_eq!(file.scores.len(), 12);
    assert_eq!(
        file.scores[10],
        Epss {
            cve_id: "CVE-2021-44228".into(),
            score: 0.99999,
            percentile: 1.0,
        }
    );
    let plain = enrich::parse_epss(
        b"cve,epss,percentile\nCVE-2024-3094,0.85974,0.99724\n",
        1 << 20,
    )
    .unwrap();
    assert_eq!(plain.date, None);
    assert_eq!(plain.scores.len(), 1);
}

#[test]
fn epss_refuses_bad_rows_headers_and_oversized_content() {
    for bad in [
        &b"cve,epss,percentile\nCVE-2024-3094,1.5,0.9\n"[..],
        b"cve,epss,percentile\nCVE-2024-3094,0.5\n",
        b"cve,epss,percentile\nnope,0.5,0.5\n",
        b"id,score\nCVE-2024-3094,0.5\n",
        b"",
    ] {
        assert_eq!(
            enrich::parse_epss(bad, 1 << 20),
            Err(ParseError::Malformed),
            "{}",
            String::from_utf8_lossy(bad)
        );
    }
    assert_eq!(
        enrich::parse_epss(&fixture("epss.csv.gz"), 100),
        Err(ParseError::TooLarge)
    );
}
