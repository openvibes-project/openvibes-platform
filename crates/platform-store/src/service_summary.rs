//! A service's page (roles spec §10.3; step 5f rulings 2, 11–13): the
//! summary above the Hosts table and the Hosts table, over the hosts in the
//! viewer's scope. Counts never include a host the viewer cannot see;
//! revoked hosts are left out.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};

use crate::{
    Client, StoreError,
    console_read::{AgentScope, MAX_PAGE_SIZE, agent_visibility},
    host_list::values,
    port_related::{RelatedReach, scope_params},
    port_summary::{FirstSeen, GroupShare},
    service_list::OwnedPort,
    service_names::{self, ServiceInfo},
    service_related::{ServiceRelated, related},
    summary_parts::{KEPT, change_counts, first_seen, group_shares, recent_changes},
};

/// SQL: does the `run_as` column `col` name root or SYSTEM? The twin of the
/// list's test (ruling 5).
fn privileged(col: &str) -> String {
    format!(
        "lower(coalesce({col}, '')) IN ('root', '0', 'system', 'localsystem', 'nt authority\\system')"
    )
}

/// One entry of Recent changes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceEvent {
    /// When.
    pub at: DateTime<Utc>,
    /// The host.
    pub agent_id: String,
    /// Its hostname.
    pub hostname: Option<String>,
    /// `appeared` or `went_away`.
    pub change: String,
}

/// A package matched to the unit by name, on how many of its hosts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MatchedPackage {
    /// The installed package's name.
    pub name: String,
    /// Hosts running the unit that have it.
    pub hosts: i64,
}

/// A service's page above the Hosts table.
#[derive(Clone, Debug)]
pub struct ServiceSummary {
    /// The unit as reported.
    pub unit: String,
    /// The map's name.
    pub name: Option<&'static str>,
    /// The map's usual use.
    pub usual_use: Option<&'static str>,
    /// Hosts in reach running it.
    pub running: i64,
    /// Active hosts in reach that have sent a services report.
    pub of: i64,
    /// Of the running hosts, those where it runs as root or SYSTEM.
    pub root: i64,
    /// Of the running hosts, those where it owns an exposed port.
    pub exposed: i64,
    /// Processes it runs across those hosts.
    pub processes: i64,
    /// The users it runs as with their host counts, most hosts first.
    pub run_as: Vec<(String, i64)>,
    /// Distinct programs, sorted.
    pub programs: Vec<String>,
    /// Packages matched to it by name, by name.
    pub packages: Vec<MatchedPackage>,
    /// Hosts running it that have any matched package.
    pub package_hosts: i64,
    /// Distinct versions of the first matched package among those hosts.
    pub versions: Option<i64>,
    /// Ports it owns, exposed first, at most 50.
    pub ports: Vec<OwnedPort>,
    /// First seen, when the log or an enrolment tells.
    pub first_seen: Option<FirstSeen>,
    /// Hosts that started running it in the last 7 days.
    pub week_added: i64,
    /// Hosts that stopped running it in the last 7 days.
    pub week_removed: i64,
    /// Groups with a member running it, most running first.
    pub by_group: Vec<GroupShare>,
    /// The 20 newest changes in reach.
    pub changes: Vec<ServiceEvent>,
    /// The Related card.
    pub related: ServiceRelated,
    /// The hosts in reach running it, for the actions' reach checks.
    pub hosts: Vec<String>,
}

/// The page above the Hosts table; `None` (404) when no host in reach runs
/// the unit and the log has nothing for it in reach in 90 days.
pub async fn service_summary(
    client: &Client,
    scope: &AgentScope,
    reach: &RelatedReach,
    unit: &str,
    now: DateTime<Utc>,
) -> Result<Option<ServiceSummary>, StoreError> {
    let (global, groups) = scope_params(scope);
    let visible = agent_visibility("a.agent_id", "$1", "$2");
    let root = privileged("s.run_as");
    let me = client
        .query_one(
            &format!(
                "WITH h AS (
                   SELECT s.agent_id, a.enrolled_at, s.processes, s.programs, s.run_as,
                          {root} AS root,
                          EXISTS (SELECT 1 FROM host_listeners l
                                  WHERE l.agent_id = s.agent_id AND l.service = s.unit AND l.exposed) AS exposed
                   FROM host_services s JOIN agents a ON a.agent_id = s.agent_id
                   WHERE s.unit = $3::text AND a.status <> 'revoked' AND {visible}),
                 floor AS (SELECT greatest(s.at, $4::timestamptz - interval '{KEPT} days') AS at
                           FROM change_log_start s)
                 SELECT (SELECT count(*) FROM h),
                        (SELECT count(*) FROM h WHERE root),
                        (SELECT count(*) FROM h WHERE exposed),
                        (SELECT COALESCE(sum(processes), 0)::bigint FROM h),
                        COALESCE((SELECT array_agg(agent_id ORDER BY agent_id) FROM h), '{{}}'),
                        COALESCE((SELECT array_agg(DISTINCT p ORDER BY p) FROM h, unnest(h.programs) p), '{{}}'),
                        COALESCE((SELECT jsonb_agg(jsonb_build_array(r.run_as, r.n) ORDER BY r.n DESC, r.run_as)
                                  FROM (SELECT run_as, count(*) AS n FROM h
                                        WHERE run_as IS NOT NULL GROUP BY run_as) r), '[]'),
                        (SELECT min(greatest(h.enrolled_at, floor.at)) FROM h, floor
                         WHERE NOT EXISTS (SELECT 1 FROM change_log c
                                           WHERE c.kind = 'service' AND c.key = $3::text
                                             AND c.agent_id = h.agent_id AND c.change = 'appeared')),
                        (SELECT floor.at FROM floor),
                        (SELECT count(*) FROM agents a
                         WHERE a.status = 'active' AND a.services_at IS NOT NULL AND {visible})"
            ),
            &[&global, &groups, &unit, &now],
        )
        .await?;
    let running: i64 = me.get(0);
    let root_hosts: i64 = me.get(1);
    let exposed: i64 = me.get(2);
    let processes: i64 = me.get(3);
    let hosts: Vec<String> = me.get(4);
    let programs: Vec<String> = me.get(5);
    let run_as: Vec<(String, i64)> =
        serde_json::from_value(me.get::<_, serde_json::Value>(6)).unwrap_or_default();
    let enrolled_first: Option<DateTime<Utc>> = me.get(7);
    let floor: DateTime<Utc> = me.get(8);
    let of: i64 = me.get(9);

    let scope = (&global, &groups);
    let counts = change_counts(client, "service", &visible, scope, unit, now).await?;
    let (week_added, week_removed, first_logged, logged) = (
        counts.week_added,
        counts.week_removed,
        counts.first_logged,
        counts.logged,
    );
    if running == 0 && logged == 0 {
        return Ok(None);
    }
    let changes: Vec<ServiceEvent> = recent_changes(
        client,
        "service",
        &visible,
        scope,
        unit,
        now,
        |at, agent_id, hostname, change| ServiceEvent {
            at,
            agent_id,
            hostname,
            change,
        },
    )
    .await?;
    let first_seen = first_seen(first_logged, enrolled_first, floor);

    let ports = client
        .query(
            "SELECT l.protocol, l.port, bool_or(l.exposed), count(DISTINCT l.agent_id)
             FROM host_listeners l
             WHERE l.service = $1::text AND l.agent_id = ANY($2::text[])
             GROUP BY l.protocol, l.port
             ORDER BY 3 DESC, l.port, l.protocol LIMIT 50",
            &[&unit, &hosts],
        )
        .await?
        .iter()
        .map(|row| OwnedPort {
            protocol: row.get(0),
            port: row.get(1),
            exposed: row.get(2),
            hosts: row.get(3),
        })
        .collect();

    let candidates = service_names::candidates(unit);
    let matched = client
        .query(
            "SELECT pv.name, count(DISTINCT hp.agent_id),
                    count(DISTINCT (pv.epoch, pv.version, pv.release))
             FROM host_packages hp JOIN package_versions pv ON pv.id = hp.package_version_id
             WHERE hp.agent_id = ANY($1::text[]) AND lower(pv.name) = ANY($2::text[])
             GROUP BY pv.name ORDER BY pv.name",
            &[&hosts, &candidates],
        )
        .await?;
    let versions = matched.first().map(|row| row.get::<_, i64>(2));
    let packages: Vec<MatchedPackage> = matched
        .iter()
        .map(|row| MatchedPackage {
            name: row.get(0),
            hosts: row.get(1),
        })
        .collect();
    let package_hosts: i64 = client
        .query_one(
            "SELECT count(DISTINCT hp.agent_id)
             FROM host_packages hp JOIN package_versions pv ON pv.id = hp.package_version_id
             WHERE hp.agent_id = ANY($1::text[]) AND lower(pv.name) = ANY($2::text[])",
            &[&hosts, &candidates],
        )
        .await?
        .get(0);

    let by_group = group_shares(client, &visible, scope, &hosts).await?;

    let info: Option<ServiceInfo> = service_names::service_info(unit);
    let matched_names: Vec<String> = packages.iter().map(|p| p.name.clone()).collect();
    Ok(Some(ServiceSummary {
        unit: unit.to_owned(),
        name: info.map(|i| i.name),
        usual_use: info.map(|i| i.usual_use),
        running,
        of,
        root: root_hosts,
        exposed,
        processes,
        run_as,
        programs,
        package_hosts,
        versions,
        packages,
        ports,
        first_seen,
        week_added,
        week_removed,
        by_group,
        changes,
        related: related(client, reach, unit, info, &hosts, &matched_names, now).await?,
        hosts,
    }))
}

values!(
    /// The Hosts table's segments.
    ServiceSegment {
        /// Every host running it.
        All = "all",
        /// It owns an exposed port there.
        Exposed = "exposed",
        /// It runs as root or SYSTEM there.
        Root = "root",
    }
);

/// Open problems on a host, each only with its read permission.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HostProblems {
    /// Open alarms from the unit's programs (`alarms.read`).
    pub alarms: Option<i64>,
    /// Open advisories of the matched packages (`vulnerabilities.read`).
    pub vulnerabilities: Option<i64>,
}

/// One host running the unit.
#[derive(Clone, Debug)]
pub struct ServiceHostRow {
    /// The host.
    pub agent_id: String,
    /// Its hostname.
    pub hostname: Option<String>,
    /// Its operating system, as the Hosts list names it.
    pub os: Option<String>,
    /// Its last address.
    pub ip: Option<String>,
    /// The matched package there and its version (`epoch:version-release`,
    /// epoch and release only when present).
    pub package: Option<(String, String)>,
    /// Processes it runs there.
    pub processes: i32,
    /// Its programs there, sorted.
    pub programs: Vec<String>,
    /// The user it runs as there.
    pub run_as: Option<String>,
    /// Ports it owns there: (protocol, port, exposed).
    pub ports: Vec<(String, i32, bool)>,
    /// Open problems.
    pub problems: HostProblems,
    /// The host's report leaves some owners out (`services_owners` partial).
    pub owners_partial: bool,
    /// When it last sent a services report.
    pub reported_at: Option<DateTime<Utc>>,
}

/// How many hosts each segment holds.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ServiceSegments {
    /// All.
    pub all: i64,
    /// Exposed.
    pub exposed: i64,
    /// Runs as root.
    pub root: i64,
}

/// One page of the Hosts table.
#[derive(Clone, Debug)]
pub struct ServiceHostsPage {
    /// The page, by hostname then agent id.
    pub rows: Vec<ServiceHostRow>,
    /// Hosts in the chosen segment.
    pub total: i64,
    /// Every segment's size.
    pub segments: ServiceSegments,
}

/// The Hosts table: one row per host in reach running the unit (ruling 12).
/// `problems` scopes read each problem count; `None` leaves it out.
pub async fn service_hosts_page(
    client: &Client,
    scope: &AgentScope,
    reach: &RelatedReach,
    unit: &str,
    segment: ServiceSegment,
    offset: i64,
    limit: i64,
) -> Result<ServiceHostsPage, StoreError> {
    let (global, groups) = scope_params(scope);
    let visible = agent_visibility("a.agent_id", "$1", "$2");
    let root = privileged("s.run_as");
    let rows = client
        .query(
            &format!(
                "WITH h AS (
                   SELECT s.agent_id, a.hostname, console_distribution_name(a.distribution) AS os,
                          host(a.last_address) AS ip, s.programs, s.processes, s.run_as,
                          {root} AS root,
                          COALESCE((SELECT bool_or(l.exposed) FROM host_listeners l
                                    WHERE l.agent_id = s.agent_id AND l.service = s.unit), false) AS exposed,
                          COALESCE((SELECT jsonb_agg(jsonb_build_array(o.protocol, o.port, o.exposed) ORDER BY o.port, o.protocol)
                                    FROM (SELECT l.protocol, l.port, bool_or(l.exposed) AS exposed
                                          FROM host_listeners l
                                          WHERE l.agent_id = s.agent_id AND l.service = s.unit
                                          GROUP BY l.protocol, l.port) o), '[]') AS ports,
                          a.services_owners = 'partial' AS partial, a.services_at
                   FROM host_services s JOIN agents a ON a.agent_id = s.agent_id
                   WHERE s.unit = $3::text AND a.status <> 'revoked' AND {visible}),
                 counts AS (SELECT count(*) AS n_all, count(*) FILTER (WHERE exposed) AS n_exposed,
                                   count(*) FILTER (WHERE root) AS n_root FROM h),
                 page AS (
                   SELECT h.*, row_number() OVER (ORDER BY h.hostname NULLS LAST, h.agent_id) AS ord
                   FROM h WHERE $4::text = 'all' OR ($4::text = 'exposed' AND h.exposed)
                                OR ($4::text = 'root' AND h.root)
                   ORDER BY ord LIMIT $5 OFFSET $6)
                 SELECT c.n_all, c.n_exposed, c.n_root, p.agent_id, p.hostname, p.os, p.ip, p.programs,
                        p.processes, p.run_as, p.ports, p.partial, p.services_at
                 FROM counts c LEFT JOIN page p ON true ORDER BY p.ord"
            ),
            &[
                &global,
                &groups,
                &unit,
                &segment.as_str(),
                &limit.clamp(1, i64::from(MAX_PAGE_SIZE)),
                &offset.clamp(0, 100_000),
            ],
        )
        .await?;
    let Some(first) = rows.first() else {
        return Ok(ServiceHostsPage {
            rows: Vec::new(),
            total: 0,
            segments: ServiceSegments::default(),
        });
    };
    let segments = ServiceSegments {
        all: first.get(0),
        exposed: first.get(1),
        root: first.get(2),
    };
    let mut page: Vec<ServiceHostRow> = rows
        .iter()
        .filter_map(|row| {
            let ports: Vec<(String, i32, bool)> =
                serde_json::from_value(row.get::<_, Option<serde_json::Value>>(10)?)
                    .unwrap_or_default();
            Some(ServiceHostRow {
                agent_id: row.get::<_, Option<String>>(3)?,
                hostname: row.get(4),
                os: row.get(5),
                ip: row.get(6),
                package: None,
                programs: row.get(7),
                processes: row.get(8),
                run_as: row.get(9),
                ports,
                problems: HostProblems::default(),
                owners_partial: row.get::<_, Option<bool>>(11).unwrap_or(false),
                reported_at: row.get(12),
            })
        })
        .collect();
    let ids: Vec<String> = page.iter().map(|r| r.agent_id.clone()).collect();
    let candidates = service_names::candidates(unit);
    // The newest installed version of each host's first matched package.
    // Versions compare by their digit runs, so 10.x is newer than 9.x.
    let installed = client
        .query(
            "SELECT hp.agent_id, pv.name, pv.epoch::bigint, pv.version, pv.release
             FROM host_packages hp JOIN package_versions pv ON pv.id = hp.package_version_id
             WHERE hp.agent_id = ANY($1::text[]) AND lower(pv.name) = ANY($2::text[])
             ORDER BY hp.agent_id, pv.name",
            &[&ids, &candidates],
        )
        .await?;
    let mut newest: BTreeMap<String, (String, i64, String, String)> = BTreeMap::new();
    for row in &installed {
        let (agent, name): (String, String) = (row.get(0), row.get(1));
        let (epoch, version, release): (i64, String, String) = (row.get(2), row.get(3), row.get(4));
        match newest.get(&agent) {
            Some((first, e, v, r))
                if *first != name
                    || (*e, natural(v), natural(r))
                        >= (epoch, natural(&version), natural(&release)) => {}
            _ => {
                newest.insert(agent, (name, epoch, version, release));
            }
        }
    }
    let chosen: Vec<String> = newest.values().map(|v| v.0.clone()).collect();
    for (agent, (name, epoch, version, release)) in newest {
        if let Some(r) = page.iter_mut().find(|r| r.agent_id == agent) {
            let epoch = if epoch > 0 {
                format!("{epoch}:")
            } else {
                String::new()
            };
            let release = if release.is_empty() {
                String::new()
            } else {
                format!("-{release}")
            };
            r.package = Some((name, format!("{epoch}{version}{release}")));
        }
    }
    if let Some(alarms) = &reach.alarms {
        let (g, gr) = scope_params(alarms);
        let visible = agent_visibility("a.agent_id", "$1", "$2");
        let counts = client
            .query(
                &format!(
                    "SELECT al.agent_id, count(*)
                     FROM alarms al JOIN agents a ON a.agent_id = al.agent_id
                     WHERE al.state = 'open' AND al.source = 'agent' AND al.agent_id = ANY($3::text[])
                       AND {visible}
                       AND EXISTS (SELECT 1 FROM host_services s
                                   WHERE s.agent_id = al.agent_id AND s.unit = $4
                                     AND left(regexp_replace(al.process ->> 'exe', '^.*/', ''), 15) = ANY(s.programs))
                     GROUP BY al.agent_id"
                ),
                &[&g, &gr, &ids, &unit],
            )
            .await?;
        for r in &mut page {
            r.problems.alarms = Some(
                counts
                    .iter()
                    .find(|c| c.get::<_, String>(0) == r.agent_id)
                    .map_or(0, |c| c.get(1)),
            );
        }
    }
    if let Some(vulns) = &reach.vulnerabilities {
        let (g, gr) = scope_params(vulns);
        let visible = agent_visibility("a.agent_id", "$1", "$2");
        let names = chosen;
        let counts = client
            .query(
                &format!(
                    "SELECT v.agent_id, count(DISTINCT v.advisory_id)
                     FROM vulnerabilities v JOIN agents a ON a.agent_id = v.agent_id
                     JOIN advisories adv ON adv.advisory_id = v.advisory_id
                     LEFT JOIN vulnerability_triage t ON t.agent_id = v.agent_id AND t.advisory_id = v.advisory_id
                     WHERE v.fixed_at IS NULL AND v.agent_id = ANY($3::text[]) AND {visible}
                       AND (t.state IS NULL OR t.state = 'open'
                            OR (t.state = 'accepted_risk' AND t.accepted_until <= now()))
                       AND split_part(adv.source, '-', 1) IN ('fedora', 'debian', 'ubuntu', 'rocky', 'almalinux')
                       AND EXISTS (SELECT 1 FROM jsonb_array_elements(v.packages) p
                                   WHERE p ->> 'name' = ANY($4::text[]))
                     GROUP BY v.agent_id"
                ),
                &[&g, &gr, &ids, &names],
            )
            .await?;
        for r in &mut page {
            r.problems.vulnerabilities = Some(
                counts
                    .iter()
                    .find(|c| c.get::<_, String>(0) == r.agent_id)
                    .map_or(0, |c| c.get(1)),
            );
        }
    }
    Ok(ServiceHostsPage {
        total: match segment {
            ServiceSegment::All => segments.all,
            ServiceSegment::Exposed => segments.exposed,
            ServiceSegment::Root => segments.root,
        },
        segments,
        rows: page,
    })
}

/// A version split into runs of digits (compared as numbers) and other text,
/// so that `10.1` sorts after `9.9`.
fn natural(version: &str) -> Vec<(u64, String)> {
    let mut out = Vec::new();
    let mut rest = version;
    while !rest.is_empty() {
        let digits = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        let (number, tail) = rest.split_at(digits);
        let text = tail
            .find(|c: char| c.is_ascii_digit())
            .unwrap_or(tail.len());
        out.push((number.parse().unwrap_or(0), tail[..text].to_owned()));
        rest = &tail[text..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_compare_by_their_numbers() {
        assert!(natural("10.1") > natural("9.9"));
        assert!(natural("9.2p1") < natural("9.10p1"));
        assert_eq!(natural("1.0"), natural("1.0"));
    }
}
