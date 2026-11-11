//! Advisories a distribution left unrated get a level from CVSS (#579).

mod common;

use common::TestDb;

#[tokio::test]
async fn unrated_advisories_take_their_level_from_cvss_and_rated_ones_keep_theirs() {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    client
        .batch_execute(
            "INSERT INTO advisories (advisory_id, source, os_id, os_version, severity, title, url) VALUES
               ('A-SCORED', 'osv', 'debian', '13', 'unrated', 'a', ''),
               ('A-MEDIUM', 'osv', 'debian', '13', 'unrated', 'b', ''),
               ('A-NOSCORE', 'osv', 'debian', '13', 'unrated', 'c', ''),
               ('A-RATED', 'fedora', 'fedora', '44', 'low', 'd', '');
             INSERT INTO advisory_cves (advisory_id, cve_id) VALUES
               ('A-SCORED', 'CVE-1'), ('A-SCORED', 'CVE-2'), ('A-MEDIUM', 'CVE-3'),
               ('A-NOSCORE', 'CVE-4'), ('A-RATED', 'CVE-1');
             INSERT INTO cve_enrichment (cve_id, cvss_score) VALUES
               ('CVE-1', 9.8), ('CVE-2', 5.0), ('CVE-3', 4.0), ('CVE-4', NULL);",
        )
        .await
        .unwrap();

    // No host has a match, so there is nothing to recount.
    assert!(
        platform_store::vulns::rate_unrated(&client)
            .await
            .unwrap()
            .is_empty()
    );
    let level = |rows: &[tokio_postgres::Row], id: &str| -> String {
        rows.iter()
            .find(|r| r.get::<_, &str>(0) == id)
            .unwrap()
            .get(1)
    };
    let rows = client
        .query("SELECT advisory_id, severity FROM advisories", &[])
        .await
        .unwrap();
    assert_eq!(
        level(&rows, "A-SCORED"),
        "critical",
        "the highest of its CVEs"
    );
    assert_eq!(level(&rows, "A-MEDIUM"), "moderate");
    assert_eq!(level(&rows, "A-NOSCORE"), "unrated");
    assert_eq!(
        level(&rows, "A-RATED"),
        "low",
        "a distribution's own level stays"
    );
    drop(client);
    db.drop().await;
}
