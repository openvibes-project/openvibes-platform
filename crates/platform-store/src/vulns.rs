//! Advisories, vulnerabilities, and feed state (VM spec §6–§7), within the
//! `openvibes_vulns` role's grants. Matching itself (RPM version order)
//! lives in `openvibes-vulns`; this module stores and queries.

use chrono::{DateTime, NaiveDate, Utc};
use serde_json::Value;

use crate::{Client, StoreError};

mod feeds;
mod summary;
pub use feeds::*;
pub use summary::{Summary, summary};

/// A package an advisory affects, and the version range affected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixedRow {
    /// Package name: a binary package, or a Debian source package.
    pub name: String,
    /// Architecture (`noarch` fixes every architecture; empty for source).
    pub arch: String,
    /// `rpm` (`[E:]V-R`) or `dpkg` (`[E:]upstream[-revision]`).
    pub scheme: String,
    /// `binary`, or `source` (matched against dpkg source packages).
    pub match_on: String,
    /// First affected version; `None` for every version before the fix.
    pub introduced: Option<String>,
    /// First fixed version; `None` when no fix is known.
    pub fixed: Option<String>,
    /// Last affected version, when no fix is named.
    pub last_affected: Option<String>,
}

impl FixedRow {
    /// A binary RPM fixed in `fixed` (`E:V-R`), affected before it.
    #[must_use]
    pub fn rpm(name: &str, arch: &str, fixed: &str) -> Self {
        Self {
            name: name.to_owned(),
            arch: arch.to_owned(),
            scheme: "rpm".to_owned(),
            match_on: "binary".to_owned(),
            introduced: None,
            fixed: Some(fixed.to_owned()),
            last_affected: None,
        }
    }
}

/// An advisory to store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewAdvisory {
    /// `FEDORA-YYYY-…`.
    pub advisory_id: String,
    /// `critical`, `important`, `moderate`, `low`, or `unrated`.
    pub severity: String,
    /// Title.
    pub title: String,
    /// Issued.
    pub issued_at: Option<DateTime<Utc>>,
    /// Last updated.
    pub updated_at: Option<DateTime<Utc>>,
    /// Link to the advisory.
    pub url: String,
    /// CVE ids.
    pub cves: Vec<String>,
    /// Fixed packages.
    pub packages: Vec<FixedRow>,
}

/// Upserts a feed's advisories with their CVEs and fixed packages in one
/// transaction. Advisories missing from the feed are kept (their
/// vulnerability history stays). Returns the number stored.
pub async fn replace_advisories(
    client: &mut Client,
    source: &str,
    os_id: &str,
    os_version: &str,
    advisories: &[NewAdvisory],
    _now: DateTime<Utc>,
) -> Result<usize, StoreError> {
    let transaction = client.transaction().await?;
    let ids: Vec<&str> = advisories.iter().map(|a| a.advisory_id.as_str()).collect();
    let severities: Vec<&str> = advisories.iter().map(|a| a.severity.as_str()).collect();
    let titles: Vec<&str> = advisories.iter().map(|a| a.title.as_str()).collect();
    let issued: Vec<Option<DateTime<Utc>>> = advisories.iter().map(|a| a.issued_at).collect();
    let updated: Vec<Option<DateTime<Utc>>> = advisories.iter().map(|a| a.updated_at).collect();
    let urls: Vec<&str> = advisories.iter().map(|a| a.url.as_str()).collect();
    transaction
        .execute(
            "INSERT INTO advisories (advisory_id, source, os_id, os_version, severity, title,
                 issued_at, updated_at, url)
             SELECT i, $1, $2, $3, s, t, iss, upd, u
             FROM unnest($4::text[], $5::text[], $6::text[], $7::timestamptz[],
                         $8::timestamptz[], $9::text[]) AS x(i, s, t, iss, upd, u)
             ON CONFLICT (advisory_id) DO UPDATE SET source = EXCLUDED.source,
                 os_id = EXCLUDED.os_id, os_version = EXCLUDED.os_version,
                 severity = EXCLUDED.severity, title = EXCLUDED.title,
                 issued_at = EXCLUDED.issued_at, updated_at = EXCLUDED.updated_at,
                 url = EXCLUDED.url",
            &[
                &source,
                &os_id,
                &os_version,
                &ids,
                &severities,
                &titles,
                &issued,
                &updated,
                &urls,
            ],
        )
        .await?;
    transaction
        .execute(
            "DELETE FROM advisory_cves WHERE advisory_id = ANY($1)",
            &[&ids],
        )
        .await?;
    transaction
        .execute(
            "DELETE FROM advisory_packages WHERE advisory_id = ANY($1)",
            &[&ids],
        )
        .await?;
    let (mut cve_ids, mut cves) = (Vec::new(), Vec::new());
    let mut pkg_ids = Vec::new();
    let (mut names, mut arches, mut schemes, mut matches) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let (mut introduced, mut fixed, mut last) = (Vec::new(), Vec::new(), Vec::new());
    for advisory in advisories {
        for cve in &advisory.cves {
            cve_ids.push(advisory.advisory_id.as_str());
            cves.push(cve.as_str());
        }
        for package in &advisory.packages {
            pkg_ids.push(advisory.advisory_id.as_str());
            names.push(package.name.as_str());
            arches.push(package.arch.as_str());
            schemes.push(package.scheme.as_str());
            matches.push(package.match_on.as_str());
            introduced.push(package.introduced.as_deref());
            fixed.push(package.fixed.as_deref());
            last.push(package.last_affected.as_deref());
        }
    }
    transaction
        .execute(
            "INSERT INTO advisory_cves (advisory_id, cve_id)
             SELECT * FROM unnest($1::text[], $2::text[]) ON CONFLICT DO NOTHING",
            &[&cve_ids, &cves],
        )
        .await?;
    transaction
        .execute(
            "INSERT INTO advisory_packages (advisory_id, name, arch, scheme, match_on,
                 introduced, fixed, last_affected)
             SELECT * FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[],
                                  $6::text[], $7::text[], $8::text[])
             ON CONFLICT DO NOTHING",
            &[
                &pkg_ids,
                &names,
                &arches,
                &schemes,
                &matches,
                &introduced,
                &fixed,
                &last,
            ],
        )
        .await?;
    transaction.commit().await?;
    // Fresh statistics for the matching that follows an import.
    client
        .batch_execute("ANALYZE advisories, advisory_cves, advisory_packages")
        .await?;
    Ok(advisories.len())
}

/// One installed package version that an advisory's fixed package could
/// apply to (same name, compatible architecture).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Candidate {
    /// Host.
    pub agent_id: String,
    /// Advisory.
    pub advisory_id: String,
    /// Package name.
    pub name: String,
    /// Fixed package's architecture.
    pub fixed_arch: String,
    /// `rpm` or `dpkg`: how the versions compare.
    pub scheme: String,
    /// First affected version, when the range starts later.
    pub introduced: Option<String>,
    /// First fixed version; `None` when no fix is known.
    pub fixed: Option<String>,
    /// Last affected version, when no fix is named.
    pub last_affected: Option<String>,
    /// Installed full version (`E:V-R` for rpm).
    pub installed: String,
    /// The host's running kernel (`uname -r`), when reported.
    pub running_kernel: Option<String>,
}

/// The hosts on a release, by agent id.
pub async fn release_hosts(
    client: &Client,
    os_id: &str,
    os_version: &str,
) -> Result<Vec<String>, StoreError> {
    Ok(client
        .query(
            "SELECT agent_id FROM agents WHERE os_id = $1 AND os_release = $2 ORDER BY 1",
            &[&os_id, &os_version],
        )
        .await?
        .iter()
        .map(|row| row.get(0))
        .collect())
}

/// Candidates on one release for these hosts.
pub async fn candidates(
    client: &Client,
    os_id: &str,
    os_version: &str,
    agents: &[String],
) -> Result<Vec<Candidate>, StoreError> {
    let rows = client
        .query(
            "SELECT h.agent_id, ap.advisory_id, ap.name, ap.arch, ap.scheme, ap.introduced,
                    ap.fixed, ap.last_affected,
                    pv.epoch || ':' || pv.version || '-' || pv.release, g.running_kernel
             FROM advisories a
             JOIN advisory_packages ap ON ap.advisory_id = a.advisory_id
             JOIN package_versions pv ON pv.name = ap.name
                 AND (pv.arch = ap.arch OR ap.arch = 'noarch' OR pv.arch = 'noarch')
             JOIN host_packages h ON h.package_version_id = pv.id
             JOIN agents g ON g.agent_id = h.agent_id
             WHERE a.os_id = $1 AND a.os_version = $2
               AND g.os_id = $1 AND g.os_release = $2
               AND ap.match_on = 'binary' AND ap.scheme = 'rpm'
               AND h.agent_id = ANY($3)",
            &[&os_id, &os_version, &agents],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|row| Candidate {
            agent_id: row.get(0),
            advisory_id: row.get(1),
            name: row.get(2),
            fixed_arch: row.get(3),
            scheme: row.get(4),
            introduced: row.get(5),
            fixed: row.get(6),
            last_affected: row.get(7),
            installed: row.get(8),
            running_kernel: row.get(9),
        })
        .collect())
}

/// A host's operating system as its last inventory reported it.
pub async fn host_release(
    client: &Client,
    agent_id: &str,
) -> Result<Option<(String, String)>, StoreError> {
    let row = client
        .query_opt(
            "SELECT os_id, os_release FROM agents WHERE agent_id = $1
               AND os_id IS NOT NULL AND os_release IS NOT NULL",
            &[&agent_id],
        )
        .await?;
    Ok(row.map(|row| (row.get(0), row.get(1))))
}

/// A vulnerability found by matching: the affected packages as JSON
/// (`[{name, installed, fixed, running?}]`).
#[derive(Clone, Debug, PartialEq)]
pub struct Found {
    /// Host.
    pub agent_id: String,
    /// Advisory.
    pub advisory_id: String,
    /// Affected packages.
    pub packages: Value,
    /// Every affected package is a kernel whose fix is installed but not
    /// running: a reboot, not an update, closes it.
    pub reboot_needed: bool,
}

/// Which hosts a matching run covered.
#[derive(Clone, Copy, Debug)]
pub enum Scope<'a> {
    /// These hosts of a release (one batch), against its advisories.
    Release {
        /// e.g. `fedora`.
        os_id: &'a str,
        /// e.g. `44`.
        os_version: &'a str,
        /// The batch's hosts.
        agents: &'a [String],
    },
    /// One host, against everything.
    Host(&'a str),
}

/// Records a matching run: found vulnerabilities are opened (or reopened,
/// keeping their first-seen time) and updated; open ones in scope that were
/// not found are fixed at `now`. Returns the number open in scope.
pub async fn apply(
    client: &mut Client,
    scope: Scope<'_>,
    found: &[Found],
    now: DateTime<Utc>,
) -> Result<usize, StoreError> {
    let transaction = client.transaction().await?;
    let agents: Vec<&str> = found.iter().map(|f| f.agent_id.as_str()).collect();
    let advisories: Vec<&str> = found.iter().map(|f| f.advisory_id.as_str()).collect();
    let packages: Vec<&Value> = found.iter().map(|f| &f.packages).collect();
    let reboots: Vec<bool> = found.iter().map(|f| f.reboot_needed).collect();
    transaction
        .execute(
            "INSERT INTO vulnerabilities (agent_id, advisory_id, packages, reboot_needed,
                 first_seen_at, last_evaluated_at)
             SELECT a, v, p, r, $4, $4
             FROM unnest($1::text[], $2::text[], $3::jsonb[], $5::bool[]) AS x(a, v, p, r)
             ON CONFLICT (agent_id, advisory_id) DO UPDATE SET packages = EXCLUDED.packages,
                 reboot_needed = EXCLUDED.reboot_needed,
                 last_evaluated_at = EXCLUDED.last_evaluated_at, fixed_at = NULL",
            &[&agents, &advisories, &packages, &now, &reboots],
        )
        .await?;
    let fixed = "UPDATE vulnerabilities SET fixed_at = $3, last_evaluated_at = $3
         WHERE fixed_at IS NULL
           AND (agent_id, advisory_id) NOT IN (SELECT * FROM unnest($1::text[], $2::text[]))";
    match scope {
        Scope::Release {
            os_id,
            os_version,
            agents: batch,
        } => {
            transaction
                .execute(
                    &format!(
                        "{fixed} AND agent_id = ANY($6)
                         AND advisory_id IN (SELECT advisory_id FROM advisories
                             WHERE os_id = $4 AND os_version = $5)"
                    ),
                    &[&agents, &advisories, &now, &os_id, &os_version, &batch],
                )
                .await?;
        }
        Scope::Host(agent_id) => {
            transaction
                .execute(
                    &format!("{fixed} AND agent_id = $4"),
                    &[&agents, &advisories, &now, &agent_id],
                )
                .await?;
        }
    }
    transaction.commit().await?;
    Ok(found.len())
}

/// One vulnerability as operators see it.
#[derive(Clone, Debug, PartialEq)]
pub struct VulnRow {
    /// Host.
    pub agent_id: String,
    /// Host name, when reported.
    pub hostname: Option<String>,
    /// Advisory.
    pub advisory_id: String,
    /// Severity.
    pub severity: String,
    /// Advisory title.
    pub title: String,
    /// CVE ids.
    pub cves: Vec<String>,
    /// Affected packages (`[{name, installed, fixed}]`).
    pub packages: Value,
    /// First seen.
    pub first_seen_at: DateTime<Utc>,
    /// Fixed, or `None` while open.
    pub fixed_at: Option<DateTime<Utc>>,
    /// Fix installed, reboot needed.
    pub reboot_needed: bool,
    /// Exploited in the wild: one of its CVEs is on KEV or EUVD's list.
    pub exploited: bool,
    /// One of its CVEs is on CISA KEV.
    pub kev: bool,
    /// One of its CVEs is on EUVD's exploited list.
    pub euvd: bool,
    /// Earliest KEV due date among its CVEs.
    pub kev_due: Option<NaiveDate>,
    /// One of its CVEs is known to be used by ransomware.
    pub ransomware: bool,
    /// Highest EPSS score among its CVEs.
    pub epss: Option<f32>,
    /// Highest EPSS percentile among its CVEs.
    pub epss_percentile: Option<f32>,
    /// Highest CVSS base score among its CVEs (NVD).
    pub cvss: Option<f32>,
}

/// Filters for [`list`].
#[derive(Clone, Debug, Default)]
pub struct ListFilter<'a> {
    /// One host (agent id or hostname).
    pub host: Option<&'a str>,
    /// One advisory.
    pub advisory: Option<&'a str>,
    /// One severity.
    pub severity: Option<&'a str>,
    /// One CVE.
    pub cve: Option<&'a str>,
    /// Fixed ones instead of open ones.
    pub fixed: bool,
}

/// Vulnerabilities by priority (VM spec §9): exploited (KEV or EUVD) first,
/// then the highest EPSS percentile among the advisory's CVEs, then
/// severity, then the highest CVSS, then oldest first.
pub async fn list(client: &Client, filter: &ListFilter<'_>) -> Result<Vec<VulnRow>, StoreError> {
    let rows = client
        .query(
            // Each advisory's CVEs and enrichment are combined once (a few
            // hundred advisories), not once per vulnerability: at 244,000
            // open rows the per-row form exceeded the statement timeout.
            "WITH adv AS (
                 SELECT a.advisory_id, a.severity, a.title,
                        COALESCE(array_agg(DISTINCT c.cve_id)
                            FILTER (WHERE c.cve_id IS NOT NULL), '{}') AS cves,
                        COALESCE(bool_or(x.kev_added IS NOT NULL), false) AS kev,
                        min(x.kev_due) AS due,
                        COALESCE(bool_or(x.kev_ransomware), false) AS ransomware,
                        max(x.epss) AS epss, max(x.epss_percentile) AS pct,
                        COALESCE(bool_or(x.euvd_exploited), false) AS euvd,
                        max(x.cvss_score) AS cvss
                 FROM advisories a
                 LEFT JOIN advisory_cves c ON c.advisory_id = a.advisory_id
                 LEFT JOIN cve_enrichment x ON x.cve_id = c.cve_id
                 WHERE ($3::text IS NULL OR a.advisory_id = $3)
                   AND ($4::text IS NULL OR a.severity = $4)
                 GROUP BY a.advisory_id, a.severity, a.title)
             SELECT v.agent_id, g.hostname, v.advisory_id, e.severity, e.title, e.cves,
                    v.packages, v.first_seen_at, v.fixed_at, v.reboot_needed,
                    e.kev, e.due, e.ransomware, e.epss, e.pct, e.euvd, e.cvss
             FROM vulnerabilities v
             JOIN adv e ON e.advisory_id = v.advisory_id
             JOIN agents g ON g.agent_id = v.agent_id
             WHERE (v.fixed_at IS NOT NULL) = $1
               AND ($2::text IS NULL OR v.agent_id = $2 OR g.hostname = $2)
               AND ($5::text IS NULL OR $5 = ANY(e.cves))
             ORDER BY (e.kev OR e.euvd) DESC, e.pct DESC NULLS LAST,
                      array_position(ARRAY['critical','important','moderate','low','unrated'],
                          e.severity), e.cvss DESC NULLS LAST, v.first_seen_at, v.agent_id
             LIMIT 10000",
            &[
                &filter.fixed,
                &filter.host,
                &filter.advisory,
                &filter.severity,
                &filter.cve,
            ],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|row| VulnRow {
            agent_id: row.get(0),
            hostname: row.get(1),
            advisory_id: row.get(2),
            severity: row.get(3),
            title: row.get(4),
            cves: row.get(5),
            packages: row.get(6),
            first_seen_at: row.get(7),
            fixed_at: row.get(8),
            reboot_needed: row.get(9),
            exploited: row.get::<_, bool>(10) || row.get::<_, bool>(15),
            kev: row.get(10),
            euvd: row.get(15),
            cvss: row.get(16),
            kev_due: row.get(11),
            ransomware: row.get(12),
            epss: row.get(13),
            epss_percentile: row.get(14),
        })
        .collect())
}
