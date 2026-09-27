//! CVE enrichment (VM spec §6, §9): KEV and EPSS per CVE, within the
//! `openvibes_vulns` role's grants. Parsing lives in `openvibes-vulns`.

use chrono::{DateTime, NaiveDate, Utc};

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

/// A CVE's NVD record, as kept.
#[derive(Clone, Debug, PartialEq)]
pub struct Nvd {
    /// `CVE-YYYY-N…`.
    pub cve_id: String,
    /// CVSS base score of the newest version scored.
    pub cvss_score: Option<f32>,
    /// That CVSS version, e.g. `3.1`.
    pub cvss_version: Option<String>,
    /// That CVSS vector.
    pub cvss_vector: Option<String>,
    /// Weakness types, e.g. `CWE-79`.
    pub cwe: Vec<String>,
    /// English description.
    pub description: Option<String>,
    /// NVD's last modification.
    pub modified_at: Option<DateTime<Utc>>,
}

/// A CVE on the EU vulnerability database's exploited list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Euvd {
    /// `CVE-YYYY-N…`.
    pub cve_id: String,
    /// `EUVD-YYYY-N…`.
    pub euvd_id: String,
    /// Exploited since, when given.
    pub exploited_since: Option<NaiveDate>,
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

/// One CVE of an advisory with what is known about it.
#[derive(Clone, Debug, PartialEq)]
pub struct CveDetail {
    /// `CVE-YYYY-N…`.
    pub cve_id: String,
    /// CVSS base score (NVD).
    pub cvss_score: Option<f32>,
    /// That CVSS version.
    pub cvss_version: Option<String>,
    /// Weakness types.
    pub cwe: Vec<String>,
    /// English description (NVD).
    pub description: Option<String>,
    /// On CISA KEV.
    pub kev: bool,
    /// EUVD id, when on EUVD's exploited list.
    pub euvd_exploited: Option<String>,
    /// EPSS score.
    pub epss: Option<f32>,
}

/// An advisory's CVEs with their enrichment, by CVE id.
pub async fn cve_details(client: &Client, advisory_id: &str) -> Result<Vec<CveDetail>, StoreError> {
    Ok(client
        .query(
            "SELECT c.cve_id, e.cvss_score, e.cvss_version, COALESCE(e.cwe, '{}'), e.description,
                    COALESCE(e.kev_added IS NOT NULL, false),
                    CASE WHEN e.euvd_exploited THEN e.euvd_id END, e.epss
             FROM advisory_cves c LEFT JOIN cve_enrichment e ON e.cve_id = c.cve_id
             WHERE c.advisory_id = $1 ORDER BY 1",
            &[&advisory_id],
        )
        .await?
        .iter()
        .map(|row| CveDetail {
            cve_id: row.get(0),
            cvss_score: row.get(1),
            cvss_version: row.get(2),
            cwe: row.get(3),
            description: row.get(4),
            kev: row.get(5),
            euvd_exploited: row.get(6),
            epss: row.get(7),
        })
        .collect())
}

/// Upserts NVD records for CVEs advisories name (others are dropped),
/// marking them checked at `now`. Returns the number stored.
pub async fn upsert_nvd(
    client: &Client,
    records: &[Nvd],
    now: DateTime<Utc>,
) -> Result<u64, StoreError> {
    let mut records: Vec<&Nvd> = records.iter().collect();
    records.sort_by(|a, b| a.cve_id.cmp(&b.cve_id));
    records.dedup_by(|a, b| a.cve_id == b.cve_id);
    let ids: Vec<&str> = records.iter().map(|r| r.cve_id.as_str()).collect();
    let scores: Vec<Option<f32>> = records.iter().map(|r| r.cvss_score).collect();
    let versions: Vec<Option<&str>> = records.iter().map(|r| r.cvss_version.as_deref()).collect();
    let vectors: Vec<Option<&str>> = records.iter().map(|r| r.cvss_vector.as_deref()).collect();
    // text[][] cannot be ragged: CWE lists travel as comma-joined text.
    let cwes: Vec<String> = records.iter().map(|r| r.cwe.join(",")).collect();
    let descriptions: Vec<Option<&str>> =
        records.iter().map(|r| r.description.as_deref()).collect();
    let modified: Vec<Option<DateTime<Utc>>> = records.iter().map(|r| r.modified_at).collect();
    Ok(client
        .execute(
            "INSERT INTO cve_enrichment (cve_id, cvss_score, cvss_version, cvss_vector, cwe,
                 description, nvd_modified_at, nvd_checked_at)
             SELECT c, s, v, vec, string_to_array(NULLIF(w, ''), ','), d, m, $8
             FROM unnest($1::text[], $2::real[], $3::text[], $4::text[], $5::text[],
                         $6::text[], $7::timestamptz[]) AS x(c, s, v, vec, w, d, m)
             WHERE c IN (SELECT cve_id FROM advisory_cves)
             ON CONFLICT (cve_id) DO UPDATE SET cvss_score = EXCLUDED.cvss_score,
                 cvss_version = EXCLUDED.cvss_version, cvss_vector = EXCLUDED.cvss_vector,
                 cwe = EXCLUDED.cwe, description = EXCLUDED.description,
                 nvd_modified_at = EXCLUDED.nvd_modified_at,
                 nvd_checked_at = EXCLUDED.nvd_checked_at",
            &[
                &ids,
                &scores,
                &versions,
                &vectors,
                &cwes,
                &descriptions,
                &modified,
                &now,
            ],
        )
        .await?)
}

/// Records that NVD was asked about `cves` at `now` (and did not know them).
pub async fn mark_nvd_checked(
    client: &Client,
    cves: &[String],
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    client
        .execute(
            "INSERT INTO cve_enrichment (cve_id, nvd_checked_at)
             SELECT c, $2 FROM unnest($1::text[]) AS c
             ON CONFLICT (cve_id) DO UPDATE SET nvd_checked_at = EXCLUDED.nvd_checked_at",
            &[&cves, &now],
        )
        .await?;
    Ok(())
}

/// CVEs of open vulnerabilities that NVD has not been asked about, or did
/// not know 7 days or more ago; newest ids first. (Debian's advisories
/// alone name tens of thousands of CVEs; only those hosts have matter.)
pub async fn nvd_pending(
    client: &Client,
    now: DateTime<Utc>,
    limit: i64,
) -> Result<Vec<String>, StoreError> {
    Ok(client
        .query(
            "SELECT DISTINCT c.cve_id FROM advisory_cves c
             JOIN vulnerabilities v ON v.advisory_id = c.advisory_id AND v.fixed_at IS NULL
             LEFT JOIN cve_enrichment e ON e.cve_id = c.cve_id
             WHERE (e.nvd_checked_at IS NULL
                OR (e.nvd_modified_at IS NULL
                    AND e.nvd_checked_at < $1::timestamptz - interval '7 days'))
             ORDER BY 1 DESC LIMIT $2",
            &[&now, &limit],
        )
        .await?
        .iter()
        .map(|row| row.get(0))
        .collect())
}

/// Replaces the EUVD exploited marks in one transaction, like [`replace_kev`].
pub async fn replace_euvd(client: &mut Client, entries: &[Euvd]) -> Result<(), StoreError> {
    let mut entries: Vec<&Euvd> = entries.iter().collect();
    entries.sort_by(|a, b| a.cve_id.cmp(&b.cve_id));
    entries.dedup_by(|a, b| a.cve_id == b.cve_id);
    let ids: Vec<&str> = entries.iter().map(|e| e.cve_id.as_str()).collect();
    let euvd: Vec<&str> = entries.iter().map(|e| e.euvd_id.as_str()).collect();
    let since: Vec<Option<NaiveDate>> = entries.iter().map(|e| e.exploited_since).collect();
    let transaction = client.transaction().await?;
    transaction
        .execute(
            "INSERT INTO cve_enrichment (cve_id, euvd_id, euvd_exploited, euvd_exploited_since)
             SELECT c, e, true, s FROM unnest($1::text[], $2::text[], $3::date[]) AS x(c, e, s)
             ON CONFLICT (cve_id) DO UPDATE SET euvd_id = EXCLUDED.euvd_id,
                 euvd_exploited = true, euvd_exploited_since = EXCLUDED.euvd_exploited_since",
            &[&ids, &euvd, &since],
        )
        .await?;
    transaction
        .execute(
            "UPDATE cve_enrichment SET euvd_exploited = NULL, euvd_exploited_since = NULL
             WHERE euvd_exploited AND cve_id <> ALL($1)",
            &[&ids],
        )
        .await?;
    transaction.commit().await?;
    Ok(())
}

/// Named CVEs with NVD data.
pub async fn nvd_known(client: &Client) -> Result<i64, StoreError> {
    Ok(client
        .query_one(
            "SELECT count(*) FROM cve_enrichment WHERE nvd_modified_at IS NOT NULL",
            &[],
        )
        .await?
        .get(0))
}
