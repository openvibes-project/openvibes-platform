//! What matching reads: each host's installed versions next to the
//! advisory packages that could apply to them.

use crate::{Client, StoreError};

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
            // A binary entry matches that binary (compatible arch); a source
            // entry matches every binary built from it (protocol P10). The
            // installed version is the binary's, or for dpkg the source's
            // own when a binNMU recorded it.
            "SELECT h.agent_id, ap.advisory_id, ap.name, ap.arch, ap.scheme, ap.introduced,
                    ap.fixed, ap.last_affected,
                    CASE WHEN ap.scheme = 'dpkg' THEN COALESCE(pv.source_version,
                             pv.epoch || ':' || pv.version
                             || CASE WHEN pv.release <> '' THEN '-' || pv.release ELSE '' END)
                         ELSE pv.epoch || ':' || pv.version || '-' || pv.release END,
                    g.running_kernel
             FROM advisories a
             JOIN advisory_packages ap ON ap.advisory_id = a.advisory_id
             JOIN package_versions pv ON pv.manager = ap.scheme AND (
                 (ap.match_on = 'binary' AND pv.name = ap.name
                     AND (ap.arch IN ('', 'noarch') OR pv.arch = ap.arch OR pv.arch = 'noarch'))
                 OR (ap.match_on = 'source'
                     AND (pv.source = ap.name OR (pv.source IS NULL AND pv.name = ap.name))))
             JOIN host_packages h ON h.package_version_id = pv.id
             JOIN agents g ON g.agent_id = h.agent_id
             WHERE a.os_id = $1 AND a.os_version = $2
               AND g.os_id = $1 AND g.os_release = $2
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
