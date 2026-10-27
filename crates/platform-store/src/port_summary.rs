//! A port's page (roles spec §10.3; step 5e rulings 7, 8, 18, 20–22): the
//! summary above the Hosts table and the Hosts table, over the hosts in the
//! viewer's scope. Counts never include a host the viewer cannot see;
//! revoked hosts are left out.

use chrono::{DateTime, Duration, Utc};

use crate::{
    Client, StoreError,
    console_read::{AgentScope, MAX_PAGE_SIZE, agent_visibility},
    host_groups::GroupKind,
    host_list::values,
    port_names::{self, PortInfo},
    port_related::{PortRelated, RelatedReach, related},
};

/// How long the change log keeps a port viewable after its last host.
const KEPT: i64 = 90;

/// When the port was first seen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirstSeen {
    /// The time; with `before`, the earliest the log can tell.
    pub at: DateTime<Utc>,
    /// The port was already there when the log began or before its
    /// 90 days: shown as "Before {date}".
    pub before: bool,
}

/// One bar of "By group".
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupShare {
    /// Group id.
    pub id: String,
    /// Name.
    pub name: String,
    /// How it gets its hosts.
    pub kind: GroupKind,
    /// Members in reach listening on the port.
    pub listening: i64,
    /// Members in reach.
    pub of: i64,
}

/// One entry of Recent changes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortEvent {
    /// When.
    pub at: DateTime<Utc>,
    /// The host.
    pub agent_id: String,
    /// Its hostname.
    pub hostname: Option<String>,
    /// `appeared`, `went_away`, `exposed` or `local`.
    pub change: String,
}

/// A port's page above the Hosts table.
#[derive(Clone, Debug)]
pub struct PortSummary {
    /// `tcp` or `udp`.
    pub protocol: String,
    /// The port.
    pub port: u16,
    /// The map's name.
    pub name: Option<&'static str>,
    /// The map's usual use.
    pub usual_use: Option<&'static str>,
    /// Hosts in reach listening on it.
    pub listening: i64,
    /// Active hosts in reach that have sent a services report.
    pub of: i64,
    /// Of the listening hosts, exposed ones.
    pub exposed: i64,
    /// Of the listening hosts, loopback-only ones.
    pub local: i64,
    /// Distinct owner units seen on it.
    pub services: i64,
    /// First seen, when the log or an enrolment tells.
    pub first_seen: Option<FirstSeen>,
    /// Hosts that started listening in the last 7 days.
    pub week_added: i64,
    /// Hosts that stopped listening in the last 7 days.
    pub week_removed: i64,
    /// Distinct programs, sorted.
    pub programs: Vec<String>,
    /// Listening hosts whose owner was collected.
    pub owners_collected: i64,
    /// Groups with a listening member, most listening first.
    pub by_group: Vec<GroupShare>,
    /// The 20 newest changes in reach.
    pub changes: Vec<PortEvent>,
    /// The Related card.
    pub related: PortRelated,
}

fn scope_params(scope: &AgentScope) -> (bool, Vec<String>) {
    (scope.is_global(), scope.group_ids())
}

/// The page above the Hosts table; `None` (404) when no host in reach
/// listens on the port and the log has nothing for it in reach in 90 days.
pub async fn port_summary(
    client: &Client,
    scope: &AgentScope,
    reach: &RelatedReach,
    protocol: &str,
    port: u16,
    now: DateTime<Utc>,
) -> Result<Option<PortSummary>, StoreError> {
    let (global, groups) = scope_params(scope);
    let visible = agent_visibility("a.agent_id", "$1", "$2");
    let key = format!("{protocol}/{port}");
    let number = i32::from(port);
    let me = client
        .query_one(
            &format!(
                "WITH l AS (
                   SELECT l.agent_id, bool_or(l.exposed) AS exposed, bool_or(l.service IS NOT NULL) AS owned,
                          a.enrolled_at,
                          array_agg(DISTINCT l.service) FILTER (WHERE l.service IS NOT NULL) AS units,
                          array_agg(DISTINCT l.program) FILTER (WHERE l.program IS NOT NULL) AS programs
                   FROM host_listeners l JOIN agents a ON a.agent_id = l.agent_id
                   WHERE l.protocol = $3::text AND l.port = $4::int AND a.status <> 'revoked' AND {visible}
                   GROUP BY l.agent_id, a.enrolled_at),
                 floor AS (SELECT greatest(s.at, $5::timestamptz - interval '{KEPT} days') AS at
                           FROM change_log_start s)
                 SELECT (SELECT count(*) FROM l),
                        (SELECT count(*) FROM l WHERE exposed),
                        (SELECT count(*) FROM l WHERE owned),
                        COALESCE((SELECT array_agg(agent_id ORDER BY agent_id) FROM l), '{{}}'),
                        COALESCE((SELECT array_agg(DISTINCT u ORDER BY u) FROM l, unnest(l.units) u), '{{}}'),
                        COALESCE((SELECT array_agg(DISTINCT p ORDER BY p) FROM l, unnest(l.programs) p), '{{}}'),
                        (SELECT min(greatest(l.enrolled_at, floor.at)) FROM l, floor),
                        (SELECT floor.at FROM floor),
                        (SELECT count(*) FROM agents a
                         WHERE a.status = 'active' AND a.services_at IS NOT NULL AND {visible})"
            ),
            &[&global, &groups, &protocol, &number, &now],
        )
        .await?;
    let listening: i64 = me.get(0);
    let exposed: i64 = me.get(1);
    let owners_collected: i64 = me.get(2);
    let hosts: Vec<String> = me.get(3);
    let units: Vec<String> = me.get(4);
    let programs: Vec<String> = me.get(5);
    let enrolled_first: Option<DateTime<Utc>> = me.get(6);
    let floor: DateTime<Utc> = me.get(7);
    let of: i64 = me.get(8);

    let log = client
        .query(
            &format!(
                "SELECT c.at, c.agent_id, a.hostname, c.change
                 FROM change_log c JOIN agents a ON a.agent_id = c.agent_id
                 WHERE c.kind = 'listener' AND c.key = $3::text AND a.status <> 'revoked' AND {visible}
                   AND c.at > $4::timestamptz - interval '{KEPT} days'
                 ORDER BY c.at DESC, c.agent_id, c.change"
            ),
            &[&global, &groups, &key, &now],
        )
        .await?;
    let events: Vec<PortEvent> = log
        .iter()
        .map(|row| PortEvent {
            at: row.get(0),
            agent_id: row.get(1),
            hostname: row.get(2),
            change: row.get(3),
        })
        .collect();
    if listening == 0 && events.is_empty() {
        return Ok(None);
    }
    let week = now - Duration::days(7);
    let distinct = |change: &str| {
        let mut hosts: Vec<&str> = events
            .iter()
            .filter(|e| e.at > week && e.change == change)
            .map(|e| e.agent_id.as_str())
            .collect();
        hosts.sort_unstable();
        hosts.dedup();
        i64::try_from(hosts.len()).unwrap_or(i64::MAX)
    };
    let (week_added, week_removed) = (distinct("appeared"), distinct("went_away"));
    let first_logged = events
        .iter()
        .filter(|e| e.change == "appeared")
        .map(|e| e.at)
        .min();
    let first_seen = [first_logged, enrolled_first]
        .into_iter()
        .flatten()
        .min()
        .map(|at| FirstSeen {
            at,
            before: at <= floor,
        });

    let by_group = client
        .query(
            &format!(
                "SELECT g.asset_group_id::text, g.name, g.kind,
                        count(*) FILTER (WHERE m.agent_id = ANY($3::text[])), count(*)
                 FROM console_host_group_membership m
                 JOIN agents a ON a.agent_id = m.agent_id
                 JOIN console_asset_groups g ON g.asset_group_id = m.asset_group_id
                 WHERE a.status <> 'revoked' AND {visible}
                   AND m.asset_group_id IN (SELECT asset_group_id FROM console_host_group_membership
                                            WHERE agent_id = ANY($3::text[]))
                 GROUP BY g.asset_group_id, g.name, g.kind
                 ORDER BY 4 DESC, lower(g.name), g.asset_group_id"
            ),
            &[&global, &groups, &hosts],
        )
        .await?
        .iter()
        .map(|row| GroupShare {
            id: row.get(0),
            name: row.get(1),
            kind: GroupKind::parse(&row.get::<_, String>(2)),
            listening: row.get(3),
            of: row.get(4),
        })
        .collect();

    let info: Option<PortInfo> = port_names::port_info(protocol, port);
    Ok(Some(PortSummary {
        protocol: protocol.to_owned(),
        port,
        name: info.map(|i| i.name),
        usual_use: info.map(|i| i.usual_use),
        listening,
        of,
        exposed,
        local: listening - exposed,
        services: i64::try_from(units.len()).unwrap_or(i64::MAX),
        first_seen,
        week_added,
        week_removed,
        programs,
        owners_collected,
        by_group,
        changes: events.into_iter().take(20).collect(),
        related: related(client, reach, protocol, port, info, &hosts, now).await?,
    }))
}

values!(
    /// The Hosts table's segments.
    PortSegment {
        /// Every listening host.
        All = "all",
        /// Exposed on some address.
        Exposed = "exposed",
        /// Bound only to loopback.
        Local = "local",
    }
);

/// One host listening on the port.
#[derive(Clone, Debug)]
pub struct PortHostRow {
    /// The host.
    pub agent_id: String,
    /// Its hostname.
    pub hostname: Option<String>,
    /// Its operating system, as the Hosts list names it.
    pub os: Option<String>,
    /// Its last address.
    pub ip: Option<String>,
    /// Every address it binds, sorted.
    pub bound: Vec<String>,
    /// Exposed on any of them.
    pub exposed: bool,
    /// The owning unit, when collected.
    pub service: Option<String>,
    /// The owning program, when collected.
    pub program: Option<String>,
    /// The host's report leaves some owners out (`services_owners` partial).
    pub owners_partial: bool,
    /// When it last sent a services report.
    pub reported_at: Option<DateTime<Utc>>,
}

/// How many hosts each segment holds.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PortSegments {
    /// All.
    pub all: i64,
    /// Exposed.
    pub exposed: i64,
    /// Local only.
    pub local: i64,
}

/// One page of the Hosts table.
#[derive(Clone, Debug)]
pub struct PortHostsPage {
    /// The page, by hostname then agent id.
    pub rows: Vec<PortHostRow>,
    /// Hosts in the chosen segment.
    pub total: i64,
    /// Every segment's size.
    pub segments: PortSegments,
}

/// The Hosts table: one row per listening host in reach, whatever its
/// addresses (ruling 21).
pub async fn port_hosts_page(
    client: &Client,
    scope: &AgentScope,
    protocol: &str,
    port: u16,
    segment: PortSegment,
    offset: i64,
    limit: i64,
) -> Result<PortHostsPage, StoreError> {
    let (global, groups) = scope_params(scope);
    let visible = agent_visibility("a.agent_id", "$1", "$2");
    let number = i32::from(port);
    let rows = client
        .query(
            &format!(
                "WITH h AS (
                   SELECT l.agent_id, a.hostname, console_distribution_name(a.distribution) AS os,
                          host(a.last_address) AS ip,
                          array_agg(DISTINCT host(l.address) ORDER BY host(l.address)) AS bound,
                          bool_or(l.exposed) AS exposed,
                          (array_agg(l.service ORDER BY l.service) FILTER (WHERE l.service IS NOT NULL))[1] AS service,
                          (array_agg(l.program ORDER BY l.program) FILTER (WHERE l.program IS NOT NULL))[1] AS program,
                          a.services_owners = 'partial' AS partial, a.services_at
                   FROM host_listeners l JOIN agents a ON a.agent_id = l.agent_id
                   WHERE l.protocol = $3::text AND l.port = $4::int AND a.status <> 'revoked' AND {visible}
                   GROUP BY l.agent_id, a.hostname, a.distribution, a.last_address, a.services_owners, a.services_at),
                 counts AS (SELECT count(*) AS n_all, count(*) FILTER (WHERE exposed) AS n_exposed,
                                   count(*) FILTER (WHERE NOT exposed) AS n_local FROM h),
                 page AS (
                   SELECT h.*, row_number() OVER (ORDER BY h.hostname NULLS LAST, h.agent_id) AS ord
                   FROM h WHERE $5::text = 'all' OR ($5::text = 'exposed') = h.exposed
                   ORDER BY ord LIMIT $6 OFFSET $7)
                 SELECT c.n_all, c.n_exposed, c.n_local, p.agent_id, p.hostname, p.os, p.ip, p.bound,
                        p.exposed, p.service, p.program, p.partial, p.services_at
                 FROM counts c LEFT JOIN page p ON true ORDER BY p.ord"
            ),
            &[
                &global,
                &groups,
                &protocol,
                &number,
                &segment.as_str(),
                &limit.clamp(1, i64::from(MAX_PAGE_SIZE)),
                &offset.clamp(0, 100_000),
            ],
        )
        .await?;
    let Some(first) = rows.first() else {
        return Ok(PortHostsPage {
            rows: Vec::new(),
            total: 0,
            segments: PortSegments::default(),
        });
    };
    let segments = PortSegments {
        all: first.get(0),
        exposed: first.get(1),
        local: first.get(2),
    };
    Ok(PortHostsPage {
        total: match segment {
            PortSegment::All => segments.all,
            PortSegment::Exposed => segments.exposed,
            PortSegment::Local => segments.local,
        },
        segments,
        rows: rows
            .iter()
            .filter_map(|row| {
                Some(PortHostRow {
                    agent_id: row.get::<_, Option<String>>(3)?,
                    hostname: row.get(4),
                    os: row.get(5),
                    ip: row.get(6),
                    bound: row.get(7),
                    exposed: row.get(8),
                    service: row.get(9),
                    program: row.get(10),
                    owners_partial: row.get::<_, Option<bool>>(11).unwrap_or(false),
                    reported_at: row.get(12),
                })
            })
            .collect(),
    })
}
