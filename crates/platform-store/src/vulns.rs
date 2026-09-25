//! Advisories, vulnerabilities, and feed state (VM spec §6–§7), within the
//! `openvibes_vulns` role's grants. Matching itself (RPM version order)
//! lives in `openvibes-vulns`; this module stores and queries.

use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::{Client, StoreError};

/// A package version that fixes an advisory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixedRow {
    /// Package name.
    pub name: String,
    /// Architecture (`noarch` fixes every architecture).
    pub arch: String,
    /// Epoch.
    pub epoch: i32,
    /// Version.
    pub version: String,
    /// Release.
    pub release: String,
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
    let (mut pkg_ids, mut names, mut arches, mut epochs, mut versions, mut releases) = (
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    for advisory in advisories {
        for cve in &advisory.cves {
            cve_ids.push(advisory.advisory_id.as_str());
            cves.push(cve.as_str());
        }
        for package in &advisory.packages {
            pkg_ids.push(advisory.advisory_id.as_str());
            names.push(package.name.as_str());
            arches.push(package.arch.as_str());
            epochs.push(package.epoch);
            versions.push(package.version.as_str());
            releases.push(package.release.as_str());
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
            "INSERT INTO advisory_packages (advisory_id, name, arch, epoch, version, release)
             SELECT * FROM unnest($1::text[], $2::text[], $3::text[], $4::int[], $5::text[], $6::text[])
             ON CONFLICT DO NOTHING",
            &[&pkg_ids, &names, &arches, &epochs, &versions, &releases],
        )
        .await?;
    transaction.commit().await?;
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
    /// Fixed epoch, version, release.
    pub fixed: (i32, String, String),
    /// Installed epoch, version, release.
    pub installed: (i32, String, String),
}

/// Candidates on one release, optionally for one host only.
pub async fn candidates(
    client: &Client,
    os_id: &str,
    os_version: &str,
    agent_id: Option<&str>,
) -> Result<Vec<Candidate>, StoreError> {
    let rows = client
        .query(
            "SELECT h.agent_id, ap.advisory_id, ap.name, ap.arch, ap.epoch, ap.version,
                    ap.release, pv.epoch, pv.version, pv.release
             FROM advisories a
             JOIN advisory_packages ap ON ap.advisory_id = a.advisory_id
             JOIN package_versions pv ON pv.name = ap.name
                 AND (pv.arch = ap.arch OR ap.arch = 'noarch' OR pv.arch = 'noarch')
             JOIN host_packages h ON h.package_version_id = pv.id
             JOIN agents g ON g.agent_id = h.agent_id
             WHERE a.os_id = $1 AND a.os_version = $2
               AND g.os_id = $1 AND g.os_version = $2
               AND ($3::text IS NULL OR h.agent_id = $3)",
            &[&os_id, &os_version, &agent_id],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|row| Candidate {
            agent_id: row.get(0),
            advisory_id: row.get(1),
            name: row.get(2),
            fixed_arch: row.get(3),
            fixed: (row.get(4), row.get(5), row.get(6)),
            installed: (row.get(7), row.get(8), row.get(9)),
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
            "SELECT os_id, os_version FROM agents WHERE agent_id = $1
               AND os_id IS NOT NULL AND os_version IS NOT NULL",
            &[&agent_id],
        )
        .await?;
    Ok(row.map(|row| (row.get(0), row.get(1))))
}

/// A vulnerability found by matching: the affected packages as JSON
/// (`[{name, installed, fixed}]`).
#[derive(Clone, Debug, PartialEq)]
pub struct Found {
    /// Host.
    pub agent_id: String,
    /// Advisory.
    pub advisory_id: String,
    /// Affected packages.
    pub packages: Value,
}

/// Which hosts a matching run covered.
#[derive(Clone, Copy, Debug)]
pub enum Scope<'a> {
    /// Every host on this release, against this release's advisories.
    Release {
        /// e.g. `fedora`.
        os_id: &'a str,
        /// e.g. `44`.
        os_version: &'a str,
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
    transaction
        .execute(
            "INSERT INTO vulnerabilities (agent_id, advisory_id, packages, first_seen_at,
                 last_evaluated_at)
             SELECT a, v, p, $4, $4 FROM unnest($1::text[], $2::text[], $3::jsonb[]) AS x(a, v, p)
             ON CONFLICT (agent_id, advisory_id) DO UPDATE SET packages = EXCLUDED.packages,
                 last_evaluated_at = EXCLUDED.last_evaluated_at, fixed_at = NULL",
            &[&agents, &advisories, &packages, &now],
        )
        .await?;
    let fixed = "UPDATE vulnerabilities SET fixed_at = $3, last_evaluated_at = $3
         WHERE fixed_at IS NULL
           AND (agent_id, advisory_id) NOT IN (SELECT * FROM unnest($1::text[], $2::text[]))";
    match scope {
        Scope::Release { os_id, os_version } => {
            transaction
                .execute(
                    &format!(
                        "{fixed} AND agent_id IN (SELECT agent_id FROM agents
                             WHERE os_id = $4 AND os_version = $5)
                         AND advisory_id IN (SELECT advisory_id FROM advisories
                             WHERE os_id = $4 AND os_version = $5)"
                    ),
                    &[&agents, &advisories, &now, &os_id, &os_version],
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
