//! A CVE's severity comes from its own CVSS score (#622); a distribution's
//! rating applies only without one, and to an advisory that names no CVE.

mod common;

use common::TestDb;

#[tokio::test]
async fn a_cves_own_cvss_score_beats_its_advisorys_rating() {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    let one = |sql: &'static str| {
        let client = &client;
        async move {
            client
                .query_one(sql, &[])
                .await
                .unwrap()
                .get::<_, String>(0)
        }
    };
    // The bands, and the rating only without a score.
    for (sql, want) in [
        ("SELECT openvibes_severity(9.2, 'important')", "critical"),
        ("SELECT openvibes_severity(9.0, 'low')", "critical"),
        ("SELECT openvibes_severity(8.9, 'critical')", "important"),
        ("SELECT openvibes_severity(4.0, 'critical')", "moderate"),
        ("SELECT openvibes_severity(3.3, 'important')", "low"),
        ("SELECT openvibes_severity(NULL, 'important')", "important"),
        ("SELECT openvibes_severity(0, 'critical')", "critical"),
        ("SELECT openvibes_severity(NULL, NULL)", "unrated"),
    ] {
        assert_eq!(one(sql).await, want, "{sql}");
    }

    // Fedora rated a pcre2 update "important" for all its CVEs, 8.2 down to
    // 3.3: the advisory is as bad as its worst CVE, each CVE by its own score.
    client
        .batch_execute(
            "INSERT INTO advisories (advisory_id, source, os_id, os_version, severity, title, url) VALUES
               ('FEDORA-PCRE', 'fedora-44-x86_64', 'fedora', '44', 'important', 'pcre2', ''),
               ('FEDORA-CRIT', 'fedora-44-x86_64', 'fedora', '44', 'important', 'brotli', ''),
               ('FEDORA-CA', 'fedora-44-x86_64', 'fedora', '44', 'critical', 'ca-certificates', ''),
               ('FEDORA-NOSCORE', 'fedora-44-x86_64', 'fedora', '44', 'moderate', 'x', '');
             INSERT INTO advisory_cves (advisory_id, cve_id) VALUES
               ('FEDORA-PCRE', 'CVE-82'), ('FEDORA-PCRE', 'CVE-33'),
               ('FEDORA-CRIT', 'CVE-92'), ('FEDORA-NOSCORE', 'CVE-NONE');
             INSERT INTO cve_enrichment (cve_id, cvss_score) VALUES
               ('CVE-82', 8.2), ('CVE-33', 3.3), ('CVE-92', 9.2), ('CVE-NONE', NULL);",
        )
        .await
        .unwrap();
    for (id, want) in [
        ("FEDORA-PCRE", "important"),
        ("FEDORA-CRIT", "critical"),
        ("FEDORA-CA", "critical"),
        ("FEDORA-NOSCORE", "moderate"),
    ] {
        let got: String = client
            .query_one(
                "SELECT openvibes_advisory_severity(advisory_id, severity) FROM advisories WHERE advisory_id = $1",
                &[&id],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(got, want, "{id}");
    }
    drop(client);
    db.drop().await;
}
