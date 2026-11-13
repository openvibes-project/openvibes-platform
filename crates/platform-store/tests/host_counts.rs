//! A host's stored counts are what the Vulnerabilities list counts for that
//! host (#590): one per CVE, by the CVE's own severity (#622), fixable pairs
//! and pairs without a fix alike, reboot-pending ones included.
mod common;

use chrono::Utc;
use common::{
    hosts::id,
    vulns::{fixture, query, run},
};
use platform_store::{
    console_read::AgentScope,
    vuln_list::{Signal, VulnQuery, VulnSeverity},
    vulns,
};

fn n<K: PartialEq>(values: &[(K, i64)], key: K) -> i64 {
    values
        .iter()
        .find(|(k, _)| *k == key)
        .map_or(0, |(_, n)| *n)
}

#[tokio::test]
async fn each_hosts_counts_match_the_list_for_that_host() {
    let (db, c) = common::migrated().await;
    fixture(&c).await;
    // A .NET update rated "important" with three CVEs scored 9.8, 9.4 and
    // 9.1 on host 3: three Critical CVEs, not one important advisory.
    c.batch_execute(&format!(
        "INSERT INTO advisories (advisory_id, source, os_id, os_version, severity, title, url) VALUES
           ('FEDORA-DOTNET', 'fedora-44-x86_64', 'fedora', '44', 'important', 'dotnet', 'u');
         INSERT INTO advisory_cves VALUES ('FEDORA-DOTNET', 'CVE-D1'), ('FEDORA-DOTNET', 'CVE-D2'),
           ('FEDORA-DOTNET', 'CVE-D3');
         INSERT INTO cve_enrichment (cve_id, cvss_score) VALUES ('CVE-D1', 9.8), ('CVE-D2', 9.4), ('CVE-D3', 9.1);
         INSERT INTO vulnerabilities (agent_id, advisory_id, packages, first_seen_at, fixed_at, last_evaluated_at, reboot_needed)
           VALUES ('{h3}', 'FEDORA-DOTNET', '[{{\"name\":\"dotnet\",\"installed\":\"1\",\"fixed\":\"2\"}}]', now(), NULL, now(), false);",
        h3 = id(3)
    ))
    .await
    .unwrap();
    let now = Utc::now();
    for host in [id(1), id(2), id(3)] {
        vulns::refresh_counts(&c, &[host.to_owned()], now)
            .await
            .unwrap();
        let page = run(
            &c,
            &VulnQuery {
                host: Some(host),
                ..query()
            },
            &AgentScope::Global,
        )
        .await;
        let list = &page.counts;
        let stored = c
            .query_one(
                "SELECT critical, important, moderate, low, unrated, exploited
                 FROM host_vulnerability_counts WHERE agent_id = $1",
                &[&host],
            )
            .await
            .unwrap();
        let got: Vec<i64> = (0..6).map(|i| i64::from(stored.get::<_, i32>(i))).collect();
        let want = vec![
            n(&list.severity, VulnSeverity::Critical),
            n(&list.severity, VulnSeverity::Important),
            n(&list.severity, VulnSeverity::Moderate),
            n(&list.severity, VulnSeverity::Low),
            n(&list.severity, VulnSeverity::Unrated),
            n(&list.signal, Signal::Exploited),
        ];
        assert_eq!(got, want, "{host}: stored counts against the list");
        // The Hosts list's critical column is the same count.
        let listed: i32 = c
            .query_one(
                "SELECT critical FROM host_listed_critical WHERE agent_id = $1",
                &[&host],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(i64::from(listed), want[0], "{host}: Hosts list critical");
    }
    // Host 3: the three .NET CVEs are Critical.
    let critical: i32 = c
        .query_one(
            "SELECT critical FROM host_vulnerability_counts WHERE agent_id = $1",
            &[&id(3)],
        )
        .await
        .unwrap()
        .get(0);
    assert!(critical >= 3, "host 3 has the three .NET CVEs: {critical}");
    db.drop().await;
}
