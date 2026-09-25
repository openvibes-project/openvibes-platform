//! Importing KEV and EPSS into `cve_enrichment` as the least-privilege
//! `openvibes_vulns` role.

mod common;

use std::path::PathBuf;

use chrono::{NaiveDate, Utc};
use common::TestDb;
use openvibes_vulns::enrich::{self, Source};
use platform_store::Client;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name),
    )
    .unwrap()
}

async fn setup() -> (TestDb, Client) {
    let db = TestDb::create().await;
    platform_store::migrate(&mut db.pool.get().await.unwrap())
        .await
        .unwrap();
    let vulns = db.pool.get().await.unwrap();
    vulns
        .batch_execute("SET ROLE openvibes_vulns")
        .await
        .unwrap();
    (db, vulns)
}

type Row = (
    Option<NaiveDate>,
    Option<bool>,
    Option<f32>,
    Option<NaiveDate>,
);

async fn row(client: &Client, cve: &str) -> Option<Row> {
    client
        .query_opt(
            "SELECT kev_added, kev_ransomware, epss, epss_date FROM cve_enrichment WHERE cve_id = $1",
            &[&cve],
        )
        .await
        .unwrap()
        .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3)))
}

fn date(value: &str) -> Option<NaiveDate> {
    Some(value.parse().unwrap())
}

#[tokio::test]
async fn kev_and_epss_meet_in_one_row_per_cve() {
    let (db, mut vulns) = setup().await;
    let now = Utc::now();
    assert_eq!(
        enrich::import(&mut vulns, Source::Kev, &fixture("kev.json"), now)
            .await
            .unwrap(),
        5
    );
    assert_eq!(
        enrich::import(&mut vulns, Source::Epss, &fixture("epss.csv.gz"), now)
            .await
            .unwrap(),
        12
    );
    assert_eq!(
        row(&vulns, "CVE-2026-59310").await,
        Some((date("2026-08-18"), Some(true), None, None))
    );
    assert_eq!(
        row(&vulns, "CVE-2021-44228").await,
        Some((None, None, Some(0.99999), date("2026-09-24")))
    );
    let feeds = platform_store::vulns::feeds(&vulns).await.unwrap();
    let names: Vec<(&str, i32)> = feeds
        .iter()
        .map(|f| (f.source.as_str(), f.advisories))
        .collect();
    assert_eq!(names, [("epss", 12), ("kev", 5)]);
    db.drop().await;
}

#[tokio::test]
async fn a_cve_dropped_from_kev_loses_its_mark_but_keeps_its_epss() {
    let (db, mut vulns) = setup().await;
    let now = Utc::now();
    let kev = |cves: &[&str]| {
        let entries: Vec<String> = cves
            .iter()
            .map(|c| format!(r#"{{"cveID":"{c}","dateAdded":"2026-09-01"}}"#))
            .collect();
        format!(r#"{{"vulnerabilities":[{}]}}"#, entries.join(","))
    };
    enrich::import(
        &mut vulns,
        Source::Kev,
        kev(&["CVE-2024-3094", "CVE-2021-44228"]).as_bytes(),
        now,
    )
    .await
    .unwrap();
    enrich::import(&mut vulns, Source::Epss, &fixture("epss.csv.gz"), now)
        .await
        .unwrap();
    enrich::import(
        &mut vulns,
        Source::Kev,
        kev(&["CVE-2021-44228"]).as_bytes(),
        now,
    )
    .await
    .unwrap();
    let dropped = row(&vulns, "CVE-2024-3094").await.unwrap();
    assert_eq!((dropped.0, dropped.1), (None, None), "no longer on KEV");
    assert_eq!(dropped.2, Some(0.85974), "EPSS kept");
    assert_eq!(
        row(&vulns, "CVE-2021-44228").await.unwrap().0,
        date("2026-09-01")
    );
    db.drop().await;
}

#[tokio::test]
async fn bad_content_is_recorded_and_changes_nothing() {
    let (db, mut vulns) = setup().await;
    let now = Utc::now();
    enrich::import(&mut vulns, Source::Kev, &fixture("kev.json"), now)
        .await
        .unwrap();
    let error = enrich::import(&mut vulns, Source::Kev, b"<html>maintenance</html>", now)
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "not a readable kev feed");
    let feed = platform_store::vulns::feeds(&vulns)
        .await
        .unwrap()
        .remove(0);
    assert_eq!(feed.advisories, 5, "previous content counted");
    assert_eq!(feed.last_error.as_deref(), Some("not a readable kev feed"));
    assert!(row(&vulns, "CVE-2026-59310").await.unwrap().0.is_some());
    db.drop().await;
}
