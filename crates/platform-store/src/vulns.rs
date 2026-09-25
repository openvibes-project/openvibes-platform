//! Advisories, vulnerabilities, and feed state (VM spec §6–§7), within the
//! `openvibes_vulns` role's grants. Matching itself (RPM version order)
//! lives in `openvibes-vulns`; this module stores and queries.

use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::{Client, StoreError};

mod feeds;
pub use feeds::*;

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
    /// The host's running kernel (`uname -r`), when reported.
    pub running_kernel: Option<String>,
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
                    ap.release, pv.epoch, pv.version, pv.release, g.running_kernel
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
            running_kernel: row.get(10),
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

/// Vulnerabilities, most severe first, then oldest first.
pub async fn list(client: &Client, filter: &ListFilter<'_>) -> Result<Vec<VulnRow>, StoreError> {
    let rows = client
        .query(
            "SELECT v.agent_id, g.hostname, v.advisory_id, a.severity, a.title,
                    COALESCE(array_agg(c.cve_id ORDER BY c.cve_id)
                        FILTER (WHERE c.cve_id IS NOT NULL), '{}'),
                    v.packages, v.first_seen_at, v.fixed_at, v.reboot_needed
             FROM vulnerabilities v
             JOIN advisories a ON a.advisory_id = v.advisory_id
             JOIN agents g ON g.agent_id = v.agent_id
             LEFT JOIN advisory_cves c ON c.advisory_id = v.advisory_id
             WHERE (v.fixed_at IS NOT NULL) = $1
               AND ($2::text IS NULL OR v.agent_id = $2 OR g.hostname = $2)
               AND ($3::text IS NULL OR v.advisory_id = $3)
               AND ($4::text IS NULL OR a.severity = $4)
               AND ($5::text IS NULL OR EXISTS (SELECT 1 FROM advisory_cves x
                    WHERE x.advisory_id = v.advisory_id AND x.cve_id = $5))
             GROUP BY v.agent_id, g.hostname, v.advisory_id, a.severity, a.title,
                      v.packages, v.first_seen_at, v.fixed_at, v.reboot_needed
             ORDER BY array_position(ARRAY['critical','important','moderate','low','unrated'],
                          a.severity), v.first_seen_at, v.agent_id
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
        })
        .collect())
}

/// Open vulnerabilities across the fleet.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Summary {
    /// Open count per severity, most severe first.
    pub by_severity: Vec<(String, i64)>,
    /// Hosts with at least one open.
    pub hosts: i64,
    /// Hosts with the most open: (agent id, hostname, open, critical+important).
    pub top_hosts: Vec<(String, Option<String>, i64, i64)>,
    /// Hosts whose only missing step is a reboot into an installed kernel
    /// fix; those are a state of their own, not counted as open.
    pub reboot_hosts: i64,
}

/// Counts open vulnerabilities (aggregated in SQL, so any fleet size).
pub async fn summary(client: &Client) -> Result<Summary, StoreError> {
    let by_severity = client
        .query(
            "SELECT a.severity, count(*) FROM vulnerabilities v
             JOIN advisories a ON a.advisory_id = v.advisory_id
             WHERE v.fixed_at IS NULL AND NOT v.reboot_needed GROUP BY a.severity
             ORDER BY array_position(ARRAY['critical','important','moderate','low','unrated'],
                          a.severity)",
            &[],
        )
        .await?
        .iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect();
    let hosts = client
        .query_one(
            "SELECT count(DISTINCT agent_id) FILTER (WHERE NOT reboot_needed),
                    count(DISTINCT agent_id) FILTER (WHERE reboot_needed)
             FROM vulnerabilities WHERE fixed_at IS NULL",
            &[],
        )
        .await?;
    let top_hosts = client
        .query(
            "SELECT v.agent_id, g.hostname, count(*),
                    count(*) FILTER (WHERE a.severity IN ('critical', 'important'))
             FROM vulnerabilities v
             JOIN advisories a ON a.advisory_id = v.advisory_id
             JOIN agents g ON g.agent_id = v.agent_id
             WHERE v.fixed_at IS NULL AND NOT v.reboot_needed
             GROUP BY v.agent_id, g.hostname ORDER BY 4 DESC, 3 DESC, 1 LIMIT 10",
            &[],
        )
        .await?
        .iter()
        .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3)))
        .collect();
    Ok(Summary {
        by_severity,
        hosts: hosts.get(0),
        top_hosts,
        reboot_hosts: hosts.get(1),
    })
}
