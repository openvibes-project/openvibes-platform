//! Console reads of installed software (assets v1): one host's packages,
//! the fleet's software, and one package's versions and hosts. Scoped to
//! the caller's agents: a scoped caller's counts include only hosts in the
//! scope, and a host outside it reads as absent.
//!
//! "Vulnerable" for a host's package: the host has an open vulnerability
//! with a fix naming the package (the matcher always uses the host's
//! newest version of that name), and the fix is not already installed
//! with only a reboot missing (`reboot_needed`: updating would not help).
//! This relies on `vulnerabilities` holding only matches that have a fix;
//! those without one live in `version_vulnerabilities`. If the matcher
//! ever stores no-fix matches there, these reads must filter on the
//! package's `fixed` field. Vulnerabilities without a fix are left
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
    /// Distinct open advisories on it, with or without a fix, on visible
    /// hosts.
    pub advisories: i64,
    /// Open advisories with no fix yet (a subset of `advisories`).
    pub no_fix_advisories: i64,
    /// Worst severity among those advisories.
    pub worst_severity: Option<String>,
    /// One of those advisories is on an exploited list (KEV or EUVD).
    pub exploited: bool,
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
    /// Distinct open advisories that apply to this version (with or
    /// without a fix).
    pub advisories: i64,
}

/// An advisory open on a package, with the visible hosts it affects.
#[derive(Clone, Debug, PartialEq)]
pub struct SoftwareAdvisory {
    /// Advisory id.
    pub advisory_id: String,
    /// Severity.
    pub severity: String,
    /// Advisory title.
    pub title: String,
    /// Link to the advisory.
    pub url: String,
    /// CVE ids.
    pub cves: Vec<String>,
    /// Visible hosts it is open on.
    pub hosts: i64,
    /// The version that fixes the package, `None` while there is no fix.
    pub fixed_in: Option<String>,
    /// On CISA KEV or EUVD's exploited list.
    pub exploited: bool,
    /// Highest EPSS score among its CVEs.
    pub epss: Option<f32>,
    /// Highest CVSS base score among its CVEs.
    pub cvss: Option<f32>,
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
    /// Only packages in use in more than one version on visible hosts.
    pub multiple_versions: bool,
}

fn scope_params(scope: &AgentScope) -> (bool, Vec<String>) {
    match scope {
        AgentScope::Global => (true, Vec::new()),
        AgentScope::AssetGroups(groups) => (false, groups.clone()),
    }
}

/// SQL for "this host's (`hp.agent_id`) package `pv` is vulnerable".
const VULNERABLE: &str = "EXISTS (SELECT 1 FROM vulnerabilities v
        WHERE v.agent_id = hp.agent_id AND v.fixed_at IS NULL AND NOT v.reboot_needed
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

/// The distinct package names of one host, sorted; `None` when the host is
/// outside the scope or unknown. A rule test builds `package.names` from it.
pub async fn host_package_names(
    client: &Client,
    scope: &AgentScope,
    agent_id: &str,
) -> Result<Option<Vec<String>>, StoreError> {
    if !visible(client, scope, agent_id).await? {
        return Ok(None);
    }
    let rows = client
        .query(
            "SELECT DISTINCT pv.name
             FROM host_packages hp JOIN package_versions pv ON pv.id = hp.package_version_id
             WHERE hp.agent_id = $1 ORDER BY pv.name",
            &[&agent_id],
        )
        .await?;
    Ok(Some(rows.iter().map(|row| row.get(0)).collect()))
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
            WHERE $6 AND v.fixed_at IS NULL AND NOT v.reboot_needed
              AND {visible_vulnerability}
         ),
         page AS (
            SELECT pv.name, pv.manager FROM package_versions pv
            WHERE ($3::text IS NULL OR strpos(lower(pv.name), lower($3)) > 0)
              AND ($4::text IS NULL OR (pv.name, pv.manager) > ($4, $5))
              AND (NOT $6 OR pv.name IN (SELECT name FROM vulnerable_names))
              AND (NOT $8 OR (SELECT count(DISTINCT (p2.epoch, p2.version, p2.release))
                              FROM package_versions p2
                              WHERE p2.name = pv.name AND p2.manager = pv.manager
                                AND EXISTS (SELECT 1 FROM host_packages hp
                                            WHERE hp.package_version_id = p2.id
                                              AND {visible_host})) > 1)
              AND EXISTS (SELECT 1 FROM host_packages hp
                          WHERE hp.package_version_id = pv.id AND {visible_host})
            GROUP BY pv.name, pv.manager
            ORDER BY pv.name, pv.manager LIMIT $7
         ),
         pairs AS (
            SELECT DISTINCT v.agent_id COLLATE \"C\" AS agent_id, p->>'name' AS name
            FROM vulnerabilities v CROSS JOIN jsonb_array_elements(v.packages) p
            WHERE v.fixed_at IS NULL AND NOT v.reboot_needed AND p->>'name' IN (SELECT name FROM page)
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
                &filters.multiple_versions,
            ],
        )
        .await?;
    let mut software: Vec<Software> = rows
        .iter()
        .map(|row| Software {
            manager: row.get(0),
            name: row.get(1),
            hosts: row.get(2),
            versions: row.get(3),
            fixable_vulnerable_hosts: row.get(4),
            advisories: 0,
            no_fix_advisories: 0,
            worst_severity: None,
            exploited: false,
        })
        .collect();
    fill_risk(client, scope, &mut software).await?;
    Ok(software)
}

/// SQL: the advisories in `ids` (an expression yielding `text[]`) with
/// their CVEs and each one's exploited flag, EPSS and CVSS over its CVEs.
fn advisory_enrichment(ids: &str) -> String {
    format!(
        "SELECT a.advisory_id, a.severity, a.title, a.url,
            COALESCE(array_agg(DISTINCT c.cve_id) FILTER (WHERE c.cve_id IS NOT NULL), '{{}}') AS cves,
            COALESCE(bool_or(x.kev_added IS NOT NULL OR COALESCE(x.euvd_exploited, false)), false) AS exploited,
            max(x.epss) AS epss, max(x.cvss_score) AS cvss
         FROM advisories a
         LEFT JOIN advisory_cves c ON c.advisory_id = a.advisory_id
         LEFT JOIN cve_enrichment x ON x.cve_id = c.cve_id
         WHERE a.advisory_id = ANY({ids})
         GROUP BY a.advisory_id, a.severity, a.title, a.url"
    )
}

/// Severity names, worst first.
const SEVERITIES: &str = "ARRAY['critical','important','moderate','low','unrated']";

/// Fills the advisory counts of a page of packages: the open advisories
/// on visible hosts (fixable per host, from `vulnerabilities`; without a
/// fix, from the versions the hosts have), the worst severity, and
/// whether one is exploited. One query for the whole page.
async fn fill_risk(
    client: &Client,
    scope: &AgentScope,
    page: &mut [Software],
) -> Result<(), StoreError> {
    if page.is_empty() {
        return Ok(());
    }
    let (global, groups) = scope_params(scope);
    let names: Vec<&str> = page.iter().map(|s| s.name.as_str()).collect();
    // As in `software`: a global caller needs no per-row visibility join,
    // a scoped caller's hosts are worked out once.
    let visible = |agent: &str| {
        if global {
            format!(
                "($1::boolean OR $2::text[] IS NULL)
                 AND NOT EXISTS (SELECT 1 FROM revoked_agents r WHERE r.agent_id = {agent})"
            )
        } else {
            format!("{agent} IN (SELECT agent_id FROM visible_agents)")
        }
    };
    let (visible_vulnerability, visible_host) = (visible("v.agent_id"), visible("hp.agent_id"));
    let visibility = agent_visibility("a.agent_id", "$1", "$2");
    let query = format!(
        "WITH visible_agents AS MATERIALIZED (
            SELECT a.agent_id FROM agents a
            WHERE NOT $1 AND a.status <> 'revoked' AND {visibility}
         ),
         revoked_agents AS MATERIALIZED (
            SELECT agent_id FROM agents WHERE status = 'revoked'
         ),
         pairs AS (
            SELECT DISTINCT p->>'name' AS name, v.advisory_id, true AS fixable
            FROM vulnerabilities v CROSS JOIN jsonb_array_elements(v.packages) p
            WHERE v.fixed_at IS NULL AND NOT v.reboot_needed AND p->>'name' = ANY($3::text[])
              AND {visible_vulnerability}
            UNION
            SELECT pv.name, vv.advisory_id, false
            FROM package_versions pv
            JOIN version_vulnerabilities vv ON vv.package_version_id = pv.id
            WHERE pv.name = ANY($3::text[])
              AND EXISTS (SELECT 1 FROM host_packages hp
                          WHERE hp.package_version_id = pv.id AND {visible_host})
         ),
         enriched AS ({enrichment_sql})
         SELECT p.name,
                count(DISTINCT p.advisory_id),
                count(DISTINCT p.advisory_id) FILTER (WHERE NOT p.fixable
                    AND NOT EXISTS (SELECT 1 FROM pairs f
                                    WHERE f.fixable AND f.name = p.name AND f.advisory_id = p.advisory_id)),
                min(array_position({SEVERITIES}, e.severity)),
                COALESCE(bool_or(e.exploited), false)
         FROM pairs p JOIN enriched e ON e.advisory_id = p.advisory_id
         GROUP BY p.name",
        enrichment_sql = advisory_enrichment("ARRAY(SELECT advisory_id FROM pairs)")
    );
    let rows = client.query(&query, &[&global, &groups, &names]).await?;
    for row in rows {
        let name: String = row.get(0);
        let severity: Option<i32> = row.get(3);
        for software in page.iter_mut().filter(|s| s.name == name) {
            software.advisories = row.get(1);
            software.no_fix_advisories = row.get(2);
            software.worst_severity = severity.and_then(|rank| {
                ["critical", "important", "moderate", "low", "unrated"]
                    .get(usize::try_from(rank).ok()?.checked_sub(1)?)
                    .map(|s| (*s).to_string())
            });
            software.exploited = row.get(4);
        }
    }
    Ok(())
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
    let visible_h2 = agent_visibility("a2.agent_id", "$1", "$2").replace("a.status", "a2.status");
    let query = format!(
        "SELECT pv.epoch, pv.version, pv.release, pv.arch, count(DISTINCT hp.agent_id),
            count(DISTINCT hp.agent_id) FILTER (WHERE {VULNERABLE}),
            (SELECT count(*) FROM (
                SELECT vv.advisory_id FROM version_vulnerabilities vv
                WHERE vv.package_version_id = pv.id
                UNION
                SELECT v.advisory_id FROM vulnerabilities v
                JOIN host_packages h2 ON h2.agent_id = v.agent_id AND h2.package_version_id = pv.id
                JOIN agents a2 ON a2.agent_id = h2.agent_id AND a2.status <> 'revoked'
                WHERE v.fixed_at IS NULL AND NOT v.reboot_needed
                  AND v.packages @> jsonb_build_array(jsonb_build_object('name', pv.name))
                  AND {visible_h2}) x)
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
            advisories: row.get(6),
        })
        .collect())
}

/// The open advisories on `manager`/`name` across visible hosts, most
/// urgent first: exploited, then EPSS, severity, CVSS and host count.
/// Fixable ones come from the hosts' matches, those without a fix from the
/// versions the visible hosts have. At most `limit` are returned.
pub async fn software_advisories(
    client: &Client,
    scope: &AgentScope,
    manager: &str,
    name: &str,
    limit: i64,
) -> Result<Vec<SoftwareAdvisory>, StoreError> {
    let (global, groups) = scope_params(scope);
    let visible = agent_visibility("a.agent_id", "$1", "$2");
    let query = format!(
        "WITH hits AS (
            SELECT v.advisory_id, v.agent_id, p->>'fixed' AS fixed
            FROM vulnerabilities v CROSS JOIN jsonb_array_elements(v.packages) p
            JOIN agents a ON a.agent_id = v.agent_id
            WHERE v.fixed_at IS NULL AND NOT v.reboot_needed AND p->>'name' = $4
              AND a.status <> 'revoked' AND {visible}
              AND EXISTS (SELECT 1 FROM host_packages hp
                          JOIN package_versions pv ON pv.id = hp.package_version_id
                          WHERE hp.agent_id = v.agent_id AND pv.manager = $3 AND pv.name = $4)
            UNION ALL
            SELECT vv.advisory_id, hp.agent_id, NULL
            FROM package_versions pv
            JOIN version_vulnerabilities vv ON vv.package_version_id = pv.id
            JOIN host_packages hp ON hp.package_version_id = pv.id
            JOIN agents a ON a.agent_id = hp.agent_id
            WHERE pv.manager = $3 AND pv.name = $4 AND a.status <> 'revoked' AND {visible}
         ),
         grouped AS (
            SELECT advisory_id, count(DISTINCT agent_id) AS hosts, max(fixed) AS fixed
            FROM hits GROUP BY advisory_id
         ),
         enriched AS ({enrichment})
         SELECT e.advisory_id, e.severity, e.title, e.url, e.cves, g.hosts, g.fixed,
                e.exploited, e.epss, e.cvss
         FROM grouped g JOIN enriched e ON e.advisory_id = g.advisory_id
         ORDER BY e.exploited DESC, e.epss DESC NULLS LAST,
                  array_position({SEVERITIES}, e.severity), e.cvss DESC NULLS LAST,
                  g.hosts DESC, e.advisory_id
         LIMIT $5",
        enrichment = advisory_enrichment("ARRAY(SELECT advisory_id FROM grouped)")
    );
    let rows = client
        .query(&query, &[&global, &groups, &manager, &name, &limit])
        .await?;
    Ok(rows
        .iter()
        .map(|row| SoftwareAdvisory {
            advisory_id: row.get(0),
            severity: row.get(1),
            title: row.get(2),
            url: row.get(3),
            cves: row.get(4),
            hosts: row.get(5),
            fixed_in: row.get(6),
            exploited: row.get(7),
            epss: row.get(8),
            cvss: row.get(9),
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
            pv.arch, agent_seen_at(a.agent_id, a.last_seen_at), {VULNERABLE}, pv.id
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
