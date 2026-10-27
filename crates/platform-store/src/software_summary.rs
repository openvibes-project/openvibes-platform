//! A package's page (roles spec §10.3; step 5g rulings 2, 9–13): the summary
//! above the Hosts table and the Hosts table, over the hosts in the viewer's
//! scope, for one package name under every manager. Counts never include a
//! host the viewer cannot see; revoked hosts are left out. Advisories are
//! counted as the Software list counts them (see `software_list_sql`).

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};

use crate::{
    Client, StoreError,
    console_read::{AgentScope, MAX_PAGE_SIZE, agent_visibility},
    host_list::values,
    port_related::scope_params,
    port_summary::{FirstSeen, GroupShare},
    service_names,
    software_list::UsedBy,
    software_version::{full_version, natural},
    summary_parts::{KEPT, first_seen, group_shares},
    vuln_list_sql::{LOW_CONFIDENCE, SEVERITIES},
};

/// SQL: the open fixable pairs of the package `$1` on the hosts `$2` (the
/// Vulnerabilities list's defaults: triage open or an accepted risk that has
/// expired by `$3`, not a lower-confidence match), as `fx (advisory_id,
/// agent_id, reboot_needed, fixed)`.
const FIXABLE: &str = "fx AS MATERIALIZED (
  SELECT v.advisory_id, v.agent_id, v.reboot_needed, e ->> 'fixed' AS fixed
  FROM vulnerabilities v JOIN advisories a ON a.advisory_id = v.advisory_id
  LEFT JOIN vulnerability_triage t ON t.agent_id = v.agent_id AND t.advisory_id = v.advisory_id
  CROSS JOIN LATERAL jsonb_array_elements(v.packages) e
  WHERE v.fixed_at IS NULL AND v.agent_id = ANY($2::text[]) AND e ->> 'name' = $1::text
    AND NOT LOW_CONFIDENCE
    AND (t.state IS NULL OR t.state = 'open'
         OR (t.state = 'accepted_risk' AND t.accepted_until <= $3::timestamptz)))";

fn fixable() -> String {
    FIXABLE.replace("LOW_CONFIDENCE", LOW_CONFIDENCE)
}

/// One version in use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionInUse {
    /// Epoch (0 when none).
    pub epoch: i64,
    /// Upstream version.
    pub version: String,
    /// Release, empty when none.
    pub release: String,
    /// Architecture.
    pub arch: String,
    /// `rpm` or `dpkg`.
    pub manager: String,
    /// Hosts in reach that have it.
    pub hosts: i64,
    /// Open advisories that affect it.
    pub advisories: i64,
    /// Some of their CVE ids, at most four.
    pub cves: Vec<String>,
}

impl VersionInUse {
    /// `epoch:version-release`.
    #[must_use]
    pub fn full(&self) -> String {
        full_version(self.epoch, &self.version, &self.release)
    }
}

/// One open advisory on the package.
#[derive(Clone, Debug)]
pub struct PackageAdvisory {
    /// The advisory id.
    pub advisory_id: String,
    /// Severity.
    pub severity: String,
    /// Title.
    pub title: String,
    /// Its CVE ids.
    pub cves: Vec<String>,
    /// On the CISA KEV or EUVD exploited list.
    pub exploited: bool,
    /// EPSS probability.
    pub epss: Option<f32>,
    /// CVSS base score.
    pub cvss: Option<f32>,
    /// The version that fixes it, when there is one.
    pub fixed_in: Option<String>,
    /// Hosts in reach it is open on.
    pub hosts: i64,
}

/// One entry of Recent changes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageEvent {
    /// When.
    pub at: DateTime<Utc>,
    /// The host.
    pub agent_id: String,
    /// Its hostname.
    pub hostname: Option<String>,
    /// `appeared` or `went_away`.
    pub change: String,
    /// The version, `epoch:version-release`, as the log tells it.
    pub version: Option<String>,
}

/// A package's page above the Hosts table.
#[derive(Clone, Debug)]
pub struct SoftwareSummary {
    /// The package name.
    pub name: String,
    /// The package databases it is reported from, sorted.
    pub managers: Vec<String>,
    /// Hosts in reach that have it.
    pub hosts: i64,
    /// Active hosts in reach that have sent a package report.
    pub of: i64,
    /// The versions in use, most hosts first.
    pub versions: Vec<VersionInUse>,
    /// Open advisories, most urgent first, at most 50.
    pub advisories: Vec<PackageAdvisory>,
    /// All open advisories.
    pub advisory_total: i64,
    /// Of those, advisories no update fixes.
    pub no_fix: i64,
    /// Hosts where an update fixes an open advisory.
    pub update_hosts: i64,
    /// Services using it (matched by name), most hosts first.
    pub used_by: Vec<UsedBy>,
    /// First seen, when the log or an enrolment tells.
    pub first_seen: Option<FirstSeen>,
    /// Hosts that installed it in the last 7 days.
    pub week_added: i64,
    /// Hosts that changed its version in the last 7 days.
    pub week_updated: i64,
    /// Hosts that removed it in the last 7 days.
    pub week_removed: i64,
    /// Groups with a member that has it, most first.
    pub by_group: Vec<GroupShare>,
    /// The 20 newest changes in reach.
    pub changes: Vec<PackageEvent>,
    /// The hosts in reach that have it, for the actions' reach checks.
    pub host_ids: Vec<String>,
}

/// Units running on `hosts` that this package is matched to by name, most
/// hosts first (the twin of the list's `ubn`).
async fn used_by(client: &Client, hosts: &[String], name: &str) -> Result<Vec<UsedBy>, StoreError> {
    let lower = name.to_lowercase();
    let mut out: Vec<UsedBy> = client
        .query(
            "SELECT unit, count(DISTINCT agent_id) FROM host_services
             WHERE agent_id = ANY($1::text[]) GROUP BY unit",
            &[&hosts],
        )
        .await?
        .iter()
        .map(|row| UsedBy {
            unit: row.get(0),
            hosts: row.get(1),
        })
        .filter(|u| service_names::candidates(&u.unit).contains(&lower))
        .collect();
    out.sort_by(|a, b| b.hosts.cmp(&a.hosts).then_with(|| a.unit.cmp(&b.unit)));
    Ok(out)
}

/// The page above the Hosts table; `None` (404) when no host in reach has
/// the package and the log has nothing for it in reach in 90 days.
pub async fn software_summary(
    client: &Client,
    scope: &AgentScope,
    name: &str,
    now: DateTime<Utc>,
) -> Result<Option<SoftwareSummary>, StoreError> {
    let (global, groups) = scope_params(scope);
    let visible = agent_visibility("a.agent_id", "$1", "$2");
    let me = client
        .query_one(
            &format!(
                "WITH h AS (
                   SELECT hp.agent_id, a.enrolled_at, pv.id AS pvid, pv.manager
                   FROM package_versions pv JOIN host_packages hp ON hp.package_version_id = pv.id
                   JOIN agents a ON a.agent_id = hp.agent_id
                   WHERE pv.name = $3::text AND a.status <> 'revoked' AND {visible}),
                 floor AS (SELECT greatest(s.at, $4::timestamptz - interval '{KEPT} days') AS at
                           FROM change_log_start s)
                 SELECT COALESCE((SELECT array_agg(DISTINCT agent_id ORDER BY agent_id) FROM h), '{{}}'),
                        COALESCE((SELECT array_agg(DISTINCT manager ORDER BY manager) FROM h), '{{}}'),
                        (SELECT min(greatest(h.enrolled_at, floor.at)) FROM h, floor
                         WHERE NOT EXISTS (SELECT 1 FROM change_log c
                                           WHERE c.kind = 'package' AND c.key = $3::text
                                             AND c.agent_id = h.agent_id AND c.change = 'appeared')),
                        (SELECT floor.at FROM floor),
                        (SELECT count(*) FROM agents a
                         WHERE a.status = 'active' AND a.inventory_at IS NOT NULL AND {visible})"
            ),
            &[&global, &groups, &name, &now],
        )
        .await?;
    let host_ids: Vec<String> = me.get(0);
    let managers: Vec<String> = me.get(1);
    let enrolled_first: Option<DateTime<Utc>> = me.get(2);
    let floor: DateTime<Utc> = me.get(3);
    let of: i64 = me.get(4);

    let scope_pair = (&global, &groups);
    // The week, per host: installed, changed version (went away and appeared)
    // or removed (ruling 8).
    let week = client
        .query_one(
            &format!(
                "WITH d AS (
                   SELECT c.agent_id, bool_or(c.change = 'appeared') AS app,
                          bool_or(c.change = 'went_away') AS gone,
                          min(c.at) FILTER (WHERE c.change = 'appeared') AS first_at
                   FROM change_log c JOIN agents a ON a.agent_id = c.agent_id
                   WHERE c.kind = 'package' AND c.key = $3::text AND a.status <> 'revoked' AND {visible}
                     AND c.change IN ('appeared', 'went_away')
                     AND c.at > $4::timestamptz - interval '{KEPT} days'
                   GROUP BY c.agent_id),
                 w AS (
                   SELECT c.agent_id, bool_or(c.change = 'appeared') AS app, bool_or(c.change = 'went_away') AS gone
                   FROM change_log c JOIN agents a ON a.agent_id = c.agent_id
                   WHERE c.kind = 'package' AND c.key = $3::text AND a.status <> 'revoked' AND {visible}
                     AND c.change IN ('appeared', 'went_away') AND c.at > $5::timestamptz
                   GROUP BY c.agent_id)
                 SELECT (SELECT count(*) FROM w WHERE app AND NOT gone),
                        (SELECT count(*) FROM w WHERE app AND gone),
                        (SELECT count(*) FROM w WHERE gone AND NOT app),
                        (SELECT count(*) FROM d),
                        (SELECT min(first_at) FROM d)"
            ),
            &[&global, &groups, &name, &now, &(now - Duration::days(7))],
        )
        .await?;
    let (week_added, week_updated, week_removed): (i64, i64, i64) =
        (week.get(0), week.get(1), week.get(2));
    let logged: i64 = week.get(3);
    let first_logged: Option<DateTime<Utc>> = week.get(4);
    if host_ids.is_empty() && logged == 0 {
        return Ok(None);
    }
    let changes: Vec<PackageEvent> = client
        .query(
            &format!(
                "SELECT c.at, c.agent_id, a.hostname, c.change, c.detail ->> 'version'
                 FROM change_log c JOIN agents a ON a.agent_id = c.agent_id
                 WHERE c.kind = 'package' AND c.key = $3::text AND a.status <> 'revoked' AND {visible}
                   AND c.at > $4::timestamptz - interval '{KEPT} days'
                 ORDER BY c.at DESC, c.agent_id, c.change, c.detail ->> 'version'
                 LIMIT 20"
            ),
            &[scope_pair.0, scope_pair.1, &name, &now],
        )
        .await?
        .iter()
        .map(|row| PackageEvent {
            at: row.get(0),
            agent_id: row.get(1),
            hostname: row.get(2),
            change: row.get(3),
            version: row.get::<_, Option<String>>(4).map(|v| log_version(&v)),
        })
        .collect();

    let versions = versions_in_use(client, name, &host_ids, now).await?;

    let advisories = advisories(client, name, &host_ids, now).await?;
    let counts = client
        .query_one(
            &format!(
                "WITH {fx},
                 hv AS (SELECT DISTINCT hp.package_version_id AS pvid, hp.agent_id
                        FROM package_versions pv JOIN host_packages hp ON hp.package_version_id = pv.id
                        WHERE pv.name = $1::text AND hp.agent_id = ANY($2::text[])),
                 nf AS (SELECT DISTINCT vv.advisory_id FROM hv JOIN version_vulnerabilities vv ON vv.package_version_id = hv.pvid),
                 allv AS (SELECT advisory_id FROM fx UNION SELECT advisory_id FROM nf)
                 SELECT (SELECT count(*) FROM allv),
                        (SELECT count(*) FROM nf WHERE advisory_id NOT IN (SELECT advisory_id FROM fx)),
                        (SELECT count(DISTINCT agent_id) FROM fx WHERE NOT reboot_needed)",
                fx = fixable()
            ),
            &[&name, &host_ids, &now],
        )
        .await?;
    let first_seen = first_seen(first_logged, enrolled_first, floor);
    let by_group = group_shares(client, &visible, scope_pair, &host_ids).await?;
    let used_by = used_by(client, &host_ids, name).await?;
    Ok(Some(SoftwareSummary {
        name: name.to_owned(),
        managers,
        hosts: i64::try_from(host_ids.len()).unwrap_or(i64::MAX),
        of,
        versions,
        advisories,
        advisory_total: counts.get(0),
        no_fix: counts.get(1),
        update_hosts: counts.get(2),
        used_by,
        first_seen,
        week_added,
        week_updated,
        week_removed,
        by_group,
        changes,
        host_ids,
    }))
}

/// The log's `0:3.0.9-1` as the page writes a version: the epoch only when
/// it is not 0.
fn log_version(logged: &str) -> String {
    logged.strip_prefix("0:").unwrap_or(logged).to_owned()
}

/// The versions of `name` on `hosts`, most hosts first, each with the open
/// advisories that affect it.
async fn versions_in_use(
    client: &Client,
    name: &str,
    hosts: &[String],
    now: DateTime<Utc>,
) -> Result<Vec<VersionInUse>, StoreError> {
    let rows = client
        .query(
            &format!(
                "WITH {fx},
                 hv AS (SELECT hp.agent_id, pv.id AS pvid, pv.manager, pv.epoch::bigint AS epoch, pv.version,
                               pv.release, pv.arch
                        FROM package_versions pv JOIN host_packages hp ON hp.package_version_id = pv.id
                        WHERE pv.name = $1::text AND hp.agent_id = ANY($2::text[])),
                 va AS (
                   SELECT hv.pvid, vv.advisory_id FROM (SELECT DISTINCT pvid FROM hv) hv
                   JOIN version_vulnerabilities vv ON vv.package_version_id = hv.pvid
                   UNION
                   SELECT hv.pvid, fx.advisory_id FROM hv JOIN fx ON fx.agent_id = hv.agent_id),
                 vc AS (SELECT va.pvid, count(DISTINCT va.advisory_id) AS advisories,
                               array_agg(DISTINCT c.cve_id) FILTER (WHERE c.cve_id IS NOT NULL) AS cves
                        FROM va LEFT JOIN advisory_cves c ON c.advisory_id = va.advisory_id GROUP BY va.pvid),
                 hs AS (SELECT hv.pvid, hv.manager, hv.epoch, hv.version, hv.release, hv.arch,
                               count(DISTINCT hv.agent_id) AS hosts
                        FROM hv GROUP BY hv.pvid, hv.manager, hv.epoch, hv.version, hv.release, hv.arch)
                 SELECT hs.manager, hs.epoch, hs.version, hs.release, hs.arch, hs.hosts,
                        COALESCE(vc.advisories, 0), COALESCE(vc.cves, '{{}}')
                 FROM hs LEFT JOIN vc ON vc.pvid = hs.pvid
                 ORDER BY hs.hosts DESC, hs.version, hs.release, hs.arch, hs.manager",
                fx = fixable()
            ),
            &[&name, &hosts, &now],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|row| {
            let mut cves: Vec<String> = row.get(7);
            cves.sort();
            cves.truncate(4);
            VersionInUse {
                manager: row.get(0),
                epoch: row.get(1),
                version: row.get(2),
                release: row.get(3),
                arch: row.get(4),
                hosts: row.get(5),
                advisories: row.get(6),
                cves,
            }
        })
        .collect())
}

/// The open advisories on `name` across `hosts`, most urgent first: exploited,
/// then EPSS, severity, CVSS and host count (at most 50).
async fn advisories(
    client: &Client,
    name: &str,
    hosts: &[String],
    now: DateTime<Utc>,
) -> Result<Vec<PackageAdvisory>, StoreError> {
    let rows = client
        .query(
            &format!(
                "WITH {fx},
                 hv AS (SELECT DISTINCT hp.agent_id, hp.package_version_id AS pvid
                        FROM package_versions pv JOIN host_packages hp ON hp.package_version_id = pv.id
                        WHERE pv.name = $1::text AND hp.agent_id = ANY($2::text[])),
                 hits AS (
                   SELECT fx.advisory_id, fx.agent_id, fx.fixed FROM fx
                   UNION ALL
                   SELECT vv.advisory_id, hv.agent_id, NULL FROM hv
                   JOIN version_vulnerabilities vv ON vv.package_version_id = hv.pvid),
                 grouped AS (SELECT advisory_id, count(DISTINCT agent_id) AS hosts, max(fixed) AS fixed
                             FROM hits GROUP BY advisory_id),
                 enriched AS (
                   SELECT a.advisory_id, a.severity, a.title,
                          COALESCE(array_agg(DISTINCT c.cve_id) FILTER (WHERE c.cve_id IS NOT NULL), '{{}}') AS cves,
                          COALESCE(bool_or(x.kev_added IS NOT NULL OR COALESCE(x.euvd_exploited, false)), false) AS exploited,
                          max(x.epss) AS epss, max(x.cvss_score) AS cvss
                   FROM advisories a
                   LEFT JOIN advisory_cves c ON c.advisory_id = a.advisory_id
                   LEFT JOIN cve_enrichment x ON x.cve_id = c.cve_id
                   WHERE a.advisory_id IN (SELECT advisory_id FROM grouped)
                   GROUP BY a.advisory_id, a.severity, a.title)
                 SELECT e.advisory_id, e.severity, e.title, e.cves, e.exploited, e.epss, e.cvss, g.fixed, g.hosts
                 FROM grouped g JOIN enriched e ON e.advisory_id = g.advisory_id
                 ORDER BY e.exploited DESC, e.epss DESC NULLS LAST,
                          array_position({severities}, e.severity), e.cvss DESC NULLS LAST,
                          g.hosts DESC, e.advisory_id
                 LIMIT 50",
                fx = fixable(),
                severities = SEVERITIES
            ),
            &[&name, &hosts, &now],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|row| PackageAdvisory {
            advisory_id: row.get(0),
            severity: row.get(1),
            title: row.get(2),
            cves: row.get(3),
            exploited: row.get(4),
            epss: row.get(5),
            cvss: row.get(6),
            fixed_in: row.get(7),
            hosts: row.get(8),
        })
        .collect())
}

values!(
    /// The Hosts table's segments.
    SoftwareSegment {
        /// Every host that has the package.
        All = "all",
        /// An update fixes an open advisory there.
        Update = "update",
        /// No update is waiting.
        Current = "current",
    }
);

/// One version of the package on a host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostVersion {
    /// `rpm` or `dpkg`.
    pub manager: String,
    /// `epoch:version-release`.
    pub version: String,
    /// Architecture.
    pub arch: String,
}

/// One host that has the package.
#[derive(Clone, Debug)]
pub struct SoftwareHostRow {
    /// The host.
    pub agent_id: String,
    /// Its hostname.
    pub hostname: Option<String>,
    /// Its operating system, as the Hosts list names it.
    pub os: Option<String>,
    /// Its last address.
    pub ip: Option<String>,
    /// The versions it has, newest first.
    pub versions: Vec<HostVersion>,
    /// The version that fixes its open advisories (the newest of them), when
    /// an update is waiting.
    pub update_to: Option<String>,
    /// Services running there that use the package.
    pub used_by: Vec<String>,
    /// When it last sent a package report.
    pub reported_at: Option<DateTime<Utc>>,
}

/// How many hosts each segment holds.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SoftwareSegments {
    /// All.
    pub all: i64,
    /// Need an update.
    pub update: i64,
    /// Up to date.
    pub current: i64,
}

/// One page of the Hosts table.
#[derive(Clone, Debug)]
pub struct SoftwareHostsPage {
    /// The page, by hostname then agent id.
    pub rows: Vec<SoftwareHostRow>,
    /// Hosts in the chosen segment.
    pub total: i64,
    /// Every segment's size.
    pub segments: SoftwareSegments,
}

/// The Hosts table: one row per host in reach that has the package (ruling 12).
pub async fn software_hosts_page(
    client: &Client,
    scope: &AgentScope,
    name: &str,
    segment: SoftwareSegment,
    offset: i64,
    limit: i64,
    now: DateTime<Utc>,
) -> Result<SoftwareHostsPage, StoreError> {
    let (global, groups) = scope_params(scope);
    let visible = agent_visibility("a.agent_id", "$1", "$2");
    let ids: Vec<String> = client
        .query(
            &format!(
                "SELECT DISTINCT hp.agent_id
                 FROM package_versions pv JOIN host_packages hp ON hp.package_version_id = pv.id
                 JOIN agents a ON a.agent_id = hp.agent_id
                 WHERE pv.name = $3::text AND a.status <> 'revoked' AND {visible}"
            ),
            &[&global, &groups, &name],
        )
        .await?
        .iter()
        .map(|row| row.get(0))
        .collect();
    let rows = client
        .query(
            &format!(
                "WITH {fx},
                 upd AS (SELECT agent_id FROM fx WHERE NOT reboot_needed GROUP BY agent_id),
                 h AS (
                   SELECT a.agent_id, a.hostname, console_distribution_name(a.distribution) AS os,
                          host(a.last_address) AS ip, a.inventory_at,
                          u.agent_id IS NOT NULL AS needs
                   FROM agents a LEFT JOIN upd u ON u.agent_id = a.agent_id
                   WHERE a.agent_id = ANY($2::text[])),
                 counts AS (SELECT count(*) AS n_all, count(*) FILTER (WHERE needs) AS n_update,
                                   count(*) FILTER (WHERE NOT needs) AS n_current FROM h),
                 page AS (
                   SELECT h.*, row_number() OVER (ORDER BY h.hostname NULLS LAST, h.agent_id) AS ord
                   FROM h WHERE $4::text = 'all' OR ($4::text = 'update' AND h.needs)
                                OR ($4::text = 'current' AND NOT h.needs)
                   ORDER BY ord LIMIT $5 OFFSET $6)
                 SELECT c.n_all, c.n_update, c.n_current, p.agent_id, p.hostname, p.os, p.ip, p.inventory_at
                 FROM counts c LEFT JOIN page p ON true ORDER BY p.ord",
                fx = fixable()
            ),
            &[
                &name,
                &ids,
                &now,
                &segment.as_str(),
                &limit.clamp(1, i64::from(MAX_PAGE_SIZE)),
                &offset.clamp(0, 100_000),
            ],
        )
        .await?;
    let Some(first) = rows.first() else {
        return Ok(SoftwareHostsPage {
            rows: Vec::new(),
            total: 0,
            segments: SoftwareSegments::default(),
        });
    };
    let segments = SoftwareSegments {
        all: first.get(0),
        update: first.get(1),
        current: first.get(2),
    };
    let mut page: Vec<SoftwareHostRow> = rows
        .iter()
        .filter_map(|row| {
            Some(SoftwareHostRow {
                agent_id: row.get::<_, Option<String>>(3)?,
                hostname: row.get(4),
                os: row.get(5),
                ip: row.get(6),
                versions: Vec::new(),
                update_to: None,
                used_by: Vec::new(),
                reported_at: row.get(7),
            })
        })
        .collect();
    let on_page: Vec<String> = page.iter().map(|r| r.agent_id.clone()).collect();
    let installed = client
        .query(
            "SELECT hp.agent_id, pv.manager, pv.epoch::bigint, pv.version, pv.release, pv.arch
             FROM host_packages hp JOIN package_versions pv ON pv.id = hp.package_version_id
             WHERE pv.name = $1::text AND hp.agent_id = ANY($2::text[])",
            &[&name, &on_page],
        )
        .await?;
    let mut by_host: BTreeMap<String, Vec<(i64, String, String, HostVersion)>> = BTreeMap::new();
    for row in &installed {
        let (epoch, version, release): (i64, String, String) = (row.get(2), row.get(3), row.get(4));
        by_host.entry(row.get(0)).or_default().push((
            epoch,
            version.clone(),
            release.clone(),
            HostVersion {
                manager: row.get(1),
                version: full_version(epoch, &version, &release),
                arch: row.get(5),
            },
        ));
    }
    let fixes = client
        .query(
            &format!(
                "WITH {fx}
                 SELECT agent_id, fixed FROM fx WHERE NOT reboot_needed AND fixed IS NOT NULL",
                fx = fixable()
            ),
            &[&name, &on_page, &now],
        )
        .await?;
    let mut newest_fix: BTreeMap<String, String> = BTreeMap::new();
    for row in &fixes {
        let (agent, fixed): (String, String) = (row.get(0), row.get(1));
        match newest_fix.get(&agent) {
            Some(have) if natural(have) >= natural(&fixed) => {}
            _ => {
                newest_fix.insert(agent, fixed);
            }
        }
    }
    let units = client
        .query(
            "SELECT agent_id, unit FROM host_services WHERE agent_id = ANY($1::text[]) ORDER BY unit",
            &[&on_page],
        )
        .await?;
    let lower = name.to_lowercase();
    for r in &mut page {
        let mut versions = by_host.remove(&r.agent_id).unwrap_or_default();
        versions.sort_by(|a, b| {
            (b.0, natural(&b.1), natural(&b.2)).cmp(&(a.0, natural(&a.1), natural(&a.2)))
        });
        r.versions = versions.into_iter().map(|v| v.3).collect();
        r.update_to = newest_fix.remove(&r.agent_id);
        r.used_by = units
            .iter()
            .filter(|u| u.get::<_, String>(0) == r.agent_id)
            .map(|u| u.get::<_, String>(1))
            .filter(|unit| service_names::candidates(unit).contains(&lower))
            .collect();
    }
    Ok(SoftwareHostsPage {
        total: match segment {
            SoftwareSegment::All => segments.all,
            SoftwareSegment::Update => segments.update,
            SoftwareSegment::Current => segments.current,
        },
        segments,
        rows: page,
    })
}
