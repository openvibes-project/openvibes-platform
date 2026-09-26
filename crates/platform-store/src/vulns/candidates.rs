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
    /// The installed package version's id.
    pub version_id: i64,
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

/// The installed version as matching compares it: for dpkg the source's
/// own version when a binNMU recorded it, else `[E:]V[-R]`; for rpm `E:V-R`.
pub(crate) const INSTALLED: &str = "CASE WHEN pv.manager = 'dpkg' THEN COALESCE(pv.source_version,
         pv.epoch || ':' || pv.version
         || CASE WHEN pv.release <> '' THEN '-' || pv.release ELSE '' END)
     ELSE pv.epoch || ':' || pv.version || '-' || pv.release END";

/// Advisory packages joined to the package versions they could apply to:
/// a binary entry matches that binary (compatible arch); a source entry
/// every binary built from it (protocol P10).
const MATCH: &str = "FROM advisories a
     JOIN advisory_packages ap ON ap.advisory_id = a.advisory_id
     JOIN package_versions pv ON pv.manager = ap.scheme AND (
         (ap.match_on = 'binary' AND pv.name = ap.name
             AND (ap.arch IN ('', 'noarch') OR pv.arch = ap.arch OR pv.arch = 'noarch'))
         OR (ap.match_on = 'source'
             AND (pv.source = ap.name OR (pv.source IS NULL AND pv.name = ap.name))))";

fn candidate(row: &tokio_postgres::Row) -> Candidate {
    Candidate {
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
        version_id: row.get(10),
    }
}

/// Candidates on one release for these hosts, only for the (advisory,
/// package) pairs given (those that affect some version: see
/// [`version_candidates`]).
pub async fn candidates(
    client: &Client,
    os_id: &str,
    os_version: &str,
    agents: &[String],
    pairs: &[(String, String)],
) -> Result<Vec<Candidate>, StoreError> {
    let (advisories, names): (Vec<&str>, Vec<&str>) =
        pairs.iter().map(|(a, n)| (a.as_str(), n.as_str())).unzip();
    let rows = client
        .query(
            &format!(
                "SELECT h.agent_id, ap.advisory_id, ap.name, ap.arch, ap.scheme, ap.introduced,
                        ap.fixed, ap.last_affected, {INSTALLED}, g.running_kernel, pv.id
                 {MATCH}
                 JOIN host_packages h ON h.package_version_id = pv.id
                 JOIN agents g ON g.agent_id = h.agent_id
                 WHERE a.os_id = $1 AND a.os_version = $2
                   AND g.os_id = $1 AND g.os_release = $2
                   AND h.agent_id = ANY($3)
                   AND (ap.advisory_id, ap.name) IN
                       (SELECT * FROM unnest($4::text[], $5::text[]))"
            ),
            &[&os_id, &os_version, &agents, &advisories, &names],
        )
        .await?;
    Ok(rows.iter().map(candidate).collect())
}

/// Candidates per distinct package version (no host): the versions hosts
/// on the release have, or only `agent`'s. Evaluated once per version,
/// however many hosts share it.
pub async fn version_candidates(
    client: &Client,
    os_id: &str,
    os_version: &str,
    agent: Option<&str>,
) -> Result<Vec<Candidate>, StoreError> {
    let rows = client
        .query(
            &format!(
                "SELECT '', ap.advisory_id, ap.name, ap.arch, ap.scheme, ap.introduced,
                        ap.fixed, ap.last_affected, {INSTALLED}, NULL::text, pv.id
                 {MATCH}
                 WHERE a.os_id = $1 AND a.os_version = $2
                   AND pv.id IN (SELECT h.package_version_id FROM host_packages h
                                 JOIN agents g ON g.agent_id = h.agent_id
                                 WHERE g.os_id = $1 AND g.os_release = $2
                                   AND ($3::text IS NULL OR h.agent_id = $3))"
            ),
            &[&os_id, &os_version, &agent],
        )
        .await?;
    Ok(rows.iter().map(candidate).collect())
}

/// A vulnerability without a fix on one package version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionFound {
    /// Package version.
    pub version_id: i64,
    /// Advisory.
    pub advisory_id: String,
    /// The advisory's package name (binary or source).
    pub package: String,
}

/// Records the no-fix vulnerabilities of the evaluated versions: found
/// ones are kept (first seen unchanged) or added; others of those versions
/// are removed. Returns the number found.
pub async fn apply_versions(
    client: &mut Client,
    evaluated: &[i64],
    found: &[VersionFound],
    now: chrono::DateTime<chrono::Utc>,
) -> Result<usize, StoreError> {
    let ids: Vec<i64> = found.iter().map(|f| f.version_id).collect();
    let advisories: Vec<&str> = found.iter().map(|f| f.advisory_id.as_str()).collect();
    let packages: Vec<&str> = found.iter().map(|f| f.package.as_str()).collect();
    let transaction = client.transaction().await?;
    transaction
        .execute(
            "DELETE FROM version_vulnerabilities vv WHERE vv.package_version_id = ANY($1)
               AND NOT EXISTS (SELECT 1 FROM unnest($2::bigint[], $3::text[], $4::text[])
                                   AS f(v, a, p)
                               WHERE f.v = vv.package_version_id AND f.a = vv.advisory_id
                                 AND f.p = vv.package)",
            &[&evaluated, &ids, &advisories, &packages],
        )
        .await?;
    transaction
        .execute(
            "INSERT INTO version_vulnerabilities (package_version_id, advisory_id, package,
                 first_seen_at)
             SELECT v, a, p, $4 FROM unnest($1::bigint[], $2::text[], $3::text[]) AS x(v, a, p)
             ON CONFLICT DO NOTHING",
            &[&ids, &advisories, &packages, &now],
        )
        .await?;
    transaction.commit().await?;
    Ok(found.len())
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
