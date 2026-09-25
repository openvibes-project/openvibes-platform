//! CVE enrichment (VM spec §6, §9): KEV and EPSS per CVE, within the
//! `openvibes_vulns` role's grants. Parsing lives in `openvibes-vulns`.

use chrono::NaiveDate;

use crate::{Client, StoreError};

/// A CVE on CISA's Known Exploited Vulnerabilities catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Kev {
    /// `CVE-YYYY-N…`.
    pub cve_id: String,
    /// Added to the catalog.
    pub added: NaiveDate,
    /// Remediation due date for US federal agencies.
    pub due: Option<NaiveDate>,
    /// Known use in ransomware campaigns.
    pub ransomware: bool,
}

/// A CVE's EPSS score.
#[derive(Clone, Debug, PartialEq)]
pub struct Epss {
    /// `CVE-YYYY-N…`.
    pub cve_id: String,
    /// Probability of exploitation in the next 30 days, 0 to 1.
    pub score: f32,
    /// Share of all scored CVEs at or below this score, 0 to 1.
    pub percentile: f32,
}

/// Replaces the KEV marks in one transaction: listed CVEs are marked (or
/// updated), CVEs no longer listed lose their mark. Other columns stay.
pub async fn replace_kev(client: &mut Client, entries: &[Kev]) -> Result<(), StoreError> {
    let mut entries: Vec<&Kev> = entries.iter().collect();
    entries.sort_by(|a, b| a.cve_id.cmp(&b.cve_id));
    entries.dedup_by(|a, b| a.cve_id == b.cve_id);
    let ids: Vec<&str> = entries.iter().map(|e| e.cve_id.as_str()).collect();
    let added: Vec<NaiveDate> = entries.iter().map(|e| e.added).collect();
    let due: Vec<Option<NaiveDate>> = entries.iter().map(|e| e.due).collect();
    let ransomware: Vec<bool> = entries.iter().map(|e| e.ransomware).collect();
    let transaction = client.transaction().await?;
    transaction
        .execute(
            "INSERT INTO cve_enrichment (cve_id, kev_added, kev_due, kev_ransomware)
             SELECT * FROM unnest($1::text[], $2::date[], $3::date[], $4::bool[])
             ON CONFLICT (cve_id) DO UPDATE SET kev_added = EXCLUDED.kev_added,
                 kev_due = EXCLUDED.kev_due, kev_ransomware = EXCLUDED.kev_ransomware",
            &[&ids, &added, &due, &ransomware],
        )
        .await?;
    transaction
        .execute(
            "UPDATE cve_enrichment SET kev_added = NULL, kev_due = NULL, kev_ransomware = NULL
             WHERE kev_added IS NOT NULL AND cve_id <> ALL($1)",
            &[&ids],
        )
        .await?;
    transaction.commit().await?;
    Ok(())
}

/// Upserts EPSS scores for `date` in one statement.
// ponytail: CVEs EPSS stops scoring keep their last score; EPSS only adds.
pub async fn replace_epss(
    client: &mut Client,
    date: Option<NaiveDate>,
    scores: &[Epss],
) -> Result<(), StoreError> {
    let mut scores: Vec<&Epss> = scores.iter().collect();
    scores.sort_by(|a, b| a.cve_id.cmp(&b.cve_id));
    scores.dedup_by(|a, b| a.cve_id == b.cve_id);
    let ids: Vec<&str> = scores.iter().map(|e| e.cve_id.as_str()).collect();
    let score: Vec<f32> = scores.iter().map(|e| e.score).collect();
    let percentile: Vec<f32> = scores.iter().map(|e| e.percentile).collect();
    client
        .execute(
            "INSERT INTO cve_enrichment (cve_id, epss, epss_percentile, epss_date)
             SELECT c, s, p, $4 FROM unnest($1::text[], $2::real[], $3::real[]) AS x(c, s, p)
             ON CONFLICT (cve_id) DO UPDATE SET epss = EXCLUDED.epss,
                 epss_percentile = EXCLUDED.epss_percentile, epss_date = EXCLUDED.epss_date",
            &[&ids, &score, &percentile, &date],
        )
        .await?;
    Ok(())
}
