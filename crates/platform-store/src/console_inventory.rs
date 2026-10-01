//! Console reads of installed software (assets v1): one host's packages,
//! the fleet's software, and one package's versions and hosts. Scoped to
//! the caller's agents: a scoped caller's counts include only hosts in the
//! scope, and a host outside it reads as absent.
//!
//! "Vulnerable" for a host's package: the host has an open vulnerability
//! with a fix naming the package (the matcher always uses the host's
//! newest version of that name). Vulnerabilities without a fix are left
//! out: a Debian host has thousands, so they would flag most packages; the
//! Vulnerabilities view reports them. A vulnerability names its package
//! by name only (its JSON has no manager); agents report one OS package
//! manager per host (rpm or dpkg), so the name is unambiguous there.
//!
//! Revoked agents are not hosts any more: they are left out of every read
//! (imported hosts stay).

use chrono::{DateTime, Utc};

use crate::{
    Client, StoreError,
    console_read::{AgentScope, agent_visibility},
};

/// One installed package version on a host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostPackage {
    /// Package manager (`rpm`, `dpkg`).
    pub manager: String,
    /// Package name.
    pub name: String,
    /// Epoch (0 when none).
    pub epoch: i32,
    /// Version.
    pub version: String,
    /// Release ("" for dpkg).
    pub release: String,
    /// Architecture.
    pub arch: String,
    /// The host has an open vulnerability with a fix on it.
    pub fixable_vulnerable: bool,
}

/// One package across the visible hosts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Software {
    /// Package manager.
    pub manager: String,
    /// Package name.
    pub name: String,
    /// Visible hosts with any version of it.
    pub hosts: i64,
    /// Distinct versions in use (epoch, version, release).
    pub versions: i64,
    /// Visible hosts where it has an open vulnerability with a fix.
    pub fixable_vulnerable_hosts: i64,
}

/// One version of a package in use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SoftwareVersion {
    /// Epoch.
    pub epoch: i32,
    /// Version.
    pub version: String,
    /// Release.
    pub release: String,
    /// Architecture.
    pub arch: String,
    /// Visible hosts with it.
    pub hosts: i64,
    /// Of those, hosts where it has an open vulnerability with a fix.
    pub fixable_vulnerable_hosts: i64,
}

/// One host that has a package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SoftwareHost {
    /// Agent id.
    pub agent_id: String,
    /// Hostname, when known.
    pub hostname: Option<String>,
    /// The version it has (`epoch:version-release`, epoch and release only
    /// when present).
    pub version: String,
    /// Architecture.
    pub arch: String,
    /// The host's last contact.
    pub last_seen_at: Option<DateTime<Utc>>,
    /// It has an open vulnerability with a fix there.
    pub fixable_vulnerable: bool,
}

/// List filters for the fleet's software.
#[derive(Clone, Debug, Default)]
pub struct SoftwareFilters {
    /// Case-insensitive substring of the name.
    pub q: Option<String>,
    /// Only packages with an open vulnerability with a fix on at least
    /// one visible host.
    pub fixable: bool,
}

fn scope_params(scope: &AgentScope) -> (bool, Vec<String>) {
    match scope {
        AgentScope::Global => (true, Vec::new()),
        AgentScope::AssetGroups(groups) => (false, groups.clone()),
    }
}

/// SQL for "this host's (`hp.agent_id`) package `pv` is vulnerable".
const VULNERABLE: &str = "EXISTS (SELECT 1 FROM vulnerabilities v
        WHERE v.agent_id = hp.agent_id AND v.fixed_at IS NULL
          AND v.packages @> jsonb_build_array(jsonb_build_object('name', pv.name)))";

/// Whether the caller may see `agent_id`.
async fn visible(client: &Client, scope: &AgentScope, agent_id: &str) -> Result<bool, StoreError> {
    let (global, groups) = scope_params(scope);
    let visible = agent_visibility("a.agent_id", "$1", "$2");
    let query = format!(
        "SELECT 1 FROM agents a WHERE a.agent_id = $3 AND a.status <> 'revoked' AND {visible}"
    );
    Ok(client
        .query_opt(&query, &[&global, &groups, &agent_id])
        .await?
        .is_some())
}

/// A host's packages by name (then id), after `(name, id)`; `None` when the
/// host is outside the scope or unknown.
pub async fn host_packages(
    client: &Client,
    scope: &AgentScope,
    agent_id: &str,
    q: Option<&str>,
    after: Option<(&str, i64)>,
    limit: i64,
) -> Result<Option<Vec<(i64, HostPackage)>>, StoreError> {
    if !visible(client, scope, agent_id).await? {
        return Ok(None);
    }
    let (after_name, after_id) = after.map_or((None, 0), |(name, id)| (Some(name), id));
    let query = format!(
        "SELECT pv.id, pv.manager, pv.name, pv.epoch, pv.version, pv.release, pv.arch, {VULNERABLE}
         FROM host_packages hp JOIN package_versions pv ON pv.id = hp.package_version_id
         WHERE hp.agent_id = $1
           AND ($2::text IS NULL OR strpos(lower(pv.name), lower($2)) > 0)
           AND ($3::text IS NULL OR (pv.name, pv.id) > ($3, $4))
         ORDER BY pv.name, pv.id LIMIT $5"
    );
    let rows = client
        .query(&query, &[&agent_id, &q, &after_name, &after_id, &limit])
        .await?;
    Ok(Some(
        rows.iter()
            .map(|row| {
                (
                    row.get(0),
                    HostPackage {
                        manager: row.get(1),
                        name: row.get(2),
                        epoch: row.get(3),
                        version: row.get(4),
                        release: row.get(5),
                        arch: row.get(6),
                        fixable_vulnerable: row.get(7),
                    },
                )
            })
            .collect(),
    ))
}

/// Packages across the visible hosts, by name then manager, after
/// `(name, manager)`.
pub async fn software(
    client: &Client,
    scope: &AgentScope,
    filters: &SoftwareFilters,
    after: Option<(&str, &str)>,
    limit: i64,
) -> Result<Vec<Software>, StoreError> {
    let (global, groups) = scope_params(scope);
    // A global caller sees every host: no per-row visibility join (it
    // sorts every host-package row; most callers are global).
    // A scoped caller's hosts are worked out once (visible_agents).
    let visible = |agent: &str| {
        if global {
            // $1 and $2 are named so their types are known; revoked hosts
            // are few, so this stays a cheap anti-join.
            format!(
                "($1::boolean OR $2::text[] IS NULL)
                 AND NOT EXISTS (SELECT 1 FROM revoked_agents r WHERE r.agent_id = {agent})"
            )
        } else {
            format!("{agent} IN (SELECT agent_id FROM visible_agents)")
        }
    };
    let (visible_host, visible_vulnerability) = (visible("hp.agent_id"), visible("v.agent_id"));
    let visibility = agent_visibility("a.agent_id", "$1", "$2");
    let (after_name, after_manager) =
        after.map_or((None, ""), |(name, manager)| (Some(name), manager));
    // The page's names first (in name order, so the scan can stop after
    // `limit`), then the counts for those names only.
    let query = format!(
        "WITH visible_agents AS MATERIALIZED (
            SELECT a.agent_id FROM agents a
            WHERE NOT $1 AND a.status <> 'revoked' AND {visibility}
         ),
         revoked_agents AS MATERIALIZED (
            SELECT agent_id FROM agents WHERE status = 'revoked'
         ),
         vulnerable_names AS (
            -- Only for \"vulnerable only\": names with an open fixable
            -- vulnerability on a visible host (the matcher only reports
            -- installed packages).
            SELECT DISTINCT p->>'name' AS name
            FROM vulnerabilities v CROSS JOIN jsonb_array_elements(v.packages) p
            WHERE $6 AND v.fixed_at IS NULL
              AND {visible_vulnerability}
         ),
         page AS (
            SELECT pv.name, pv.manager FROM package_versions pv
            WHERE ($3::text IS NULL OR strpos(lower(pv.name), lower($3)) > 0)
              AND ($4::text IS NULL OR (pv.name, pv.manager) > ($4, $5))
              AND (NOT $6 OR pv.name IN (SELECT name FROM vulnerable_names))
              AND EXISTS (SELECT 1 FROM host_packages hp
                          WHERE hp.package_version_id = pv.id AND {visible_host})
            GROUP BY pv.name, pv.manager
            ORDER BY pv.name, pv.manager LIMIT $7
         ),
         pairs AS (
            SELECT DISTINCT v.agent_id COLLATE \"C\" AS agent_id, p->>'name' AS name
            FROM vulnerabilities v CROSS JOIN jsonb_array_elements(v.packages) p
            WHERE v.fixed_at IS NULL AND p->>'name' IN (SELECT name FROM page)
         ),
         -- Visible hosts × versions of the page's names, then hosts and
         -- versions each counted by grouping (hash), not count(DISTINCT):
         -- a DISTINCT count sorts every row under the text collation.
         per_version AS (
            SELECT pv.name, pv.manager, hp.agent_id COLLATE \"C\" AS agent_id, pv.epoch, pv.version, pv.release,
                bool_or(pr.agent_id IS NOT NULL) AS vulnerable
            FROM page
            JOIN package_versions pv ON pv.name = page.name AND pv.manager = page.manager
            JOIN host_packages hp ON hp.package_version_id = pv.id
            LEFT JOIN pairs pr ON pr.agent_id = hp.agent_id COLLATE \"C\" AND pr.name = pv.name
            WHERE {visible_host}
            GROUP BY pv.name, pv.manager, hp.agent_id COLLATE \"C\", pv.epoch, pv.version, pv.release
         ),
         hosts AS (
            SELECT name, manager, count(*) AS hosts, count(*) FILTER (WHERE vulnerable) AS vulnerable
            FROM (SELECT name, manager, agent_id, bool_or(vulnerable) AS vulnerable
                  FROM per_version GROUP BY name, manager, agent_id) h
            GROUP BY name, manager
         ),
         versions AS (
            SELECT name, manager, count(*) AS versions
            FROM (SELECT name, manager FROM per_version
                  GROUP BY name, manager, epoch, version, release) v
            GROUP BY name, manager
         )
         SELECT h.manager, h.name, h.hosts, v.versions, h.vulnerable
         FROM hosts h JOIN versions v ON v.name = h.name AND v.manager = h.manager
         ORDER BY h.name, h.manager"
    );
    let rows = client
        .query(
            &query,
            &[
                &global,
                &groups,
                &filters.q,
                &after_name,
                &after_manager,
                &filters.fixable,
                &limit,
            ],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|row| Software {
            manager: row.get(0),
            name: row.get(1),
            hosts: row.get(2),
            versions: row.get(3),
            fixable_vulnerable_hosts: row.get(4),
        })
        .collect())
}

/// The versions of `manager`/`name` in use on visible hosts, newest
/// first by text (callers show them; ordering is not a version compare).
/// Empty when no visible host has it.
pub async fn software_versions(
    client: &Client,
    scope: &AgentScope,
    manager: &str,
    name: &str,
) -> Result<Vec<SoftwareVersion>, StoreError> {
    let (global, groups) = scope_params(scope);
    let visible = agent_visibility("a.agent_id", "$1", "$2");
    let query = format!(
        "SELECT pv.epoch, pv.version, pv.release, pv.arch, count(DISTINCT hp.agent_id),
            count(DISTINCT hp.agent_id) FILTER (WHERE {VULNERABLE})
         FROM package_versions pv
         JOIN host_packages hp ON hp.package_version_id = pv.id
         JOIN agents a ON a.agent_id = hp.agent_id
         WHERE pv.manager = $3 AND pv.name = $4 AND a.status <> 'revoked' AND {visible}
         GROUP BY pv.id
         ORDER BY count(DISTINCT hp.agent_id) DESC, pv.version, pv.release, pv.arch, pv.id"
    );
    let rows = client
        .query(&query, &[&global, &groups, &manager, &name])
        .await?;
    Ok(rows
        .iter()
        .map(|row| SoftwareVersion {
            epoch: row.get(0),
            version: row.get(1),
            release: row.get(2),
            arch: row.get(3),
            hosts: row.get(4),
            fixable_vulnerable_hosts: row.get(5),
        })
        .collect())
}

/// Visible hosts that have `manager`/`name`, by hostname, agent id and
/// version row, after `(hostname, agent_id, version row)` (hostless agents
/// sort as ""; a multilib host has one row per architecture). Returns
/// each host with its version row id, for the cursor.
pub async fn software_hosts(
    client: &Client,
    scope: &AgentScope,
    manager: &str,
    name: &str,
    after: Option<(&str, &str, i64)>,
    limit: i64,
) -> Result<Vec<(i64, SoftwareHost)>, StoreError> {
    let (global, groups) = scope_params(scope);
    let visible = agent_visibility("a.agent_id", "$1", "$2");
    let (after_host, after_agent, after_id) =
        after.map_or((None, "", 0), |(host, agent, id)| (Some(host), agent, id));
    let query = format!(
        "SELECT a.agent_id, a.hostname,
            CASE WHEN pv.epoch <> 0 THEN pv.epoch || ':' ELSE '' END || pv.version
                || CASE WHEN pv.release <> '' THEN '-' || pv.release ELSE '' END,
            pv.arch, a.last_seen_at, {VULNERABLE}, pv.id
         FROM package_versions pv
         JOIN host_packages hp ON hp.package_version_id = pv.id
         JOIN agents a ON a.agent_id = hp.agent_id
         WHERE pv.manager = $3 AND pv.name = $4 AND a.status <> 'revoked' AND {visible}
           AND ($5::text IS NULL OR (coalesce(a.hostname, ''), a.agent_id, pv.id) > ($5, $6, $7))
         ORDER BY coalesce(a.hostname, ''), a.agent_id, pv.id LIMIT $8"
    );
    let rows = client
        .query(
            &query,
            &[
                &global,
                &groups,
                &manager,
                &name,
                &after_host,
                &after_agent,
                &after_id,
                &limit,
            ],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|row| {
            (
                row.get(6),
                SoftwareHost {
                    agent_id: row.get(0),
                    hostname: row.get(1),
                    version: row.get(2),
                    arch: row.get(3),
                    last_seen_at: row.get(4),
                    fixable_vulnerable: row.get(5),
                },
            )
        })
        .collect())
}
