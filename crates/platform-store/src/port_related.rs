//! A port's Related card (step 5e ruling 22): failing checks, open
//! vulnerabilities of the usual server's packages, and open alarms, each
//! counted on the hosts listening on the port and only with its own read
//! permission (its scope; the hosts are already in the viewer's reach).

use crate::{
    Client, StoreError,
    check_area::check_area,
    check_list_sql::{SEVERITIES, open_failing},
    check_related::rule_port,
    console_read::{AgentScope, agent_visibility},
    port_names::PortInfo,
};
use chrono::{DateTime, Utc};

/// Most checks the card names; the rest are a count.
const CHECKS: usize = 5;

/// A failing check concerning the port.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelatedCheck {
    /// Rule set.
    pub rule_set_id: String,
    /// Rule.
    pub rule_id: String,
    /// The rule's title, else its id.
    pub title: String,
    /// The worst open failing finding's severity.
    pub severity: String,
    /// Listening hosts failing it.
    pub hosts: i64,
}

/// Failing checks: the worst few, and how many there are.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RelatedChecks {
    /// Worst first, at most five.
    pub items: Vec<RelatedCheck>,
    /// All failing checks concerning the port.
    pub total: i64,
    /// The compliance area the card links to, when the map has one.
    pub area: Option<&'static str>,
}

/// Open advisories of one package of the port's usual server.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelatedPackage {
    /// The package name.
    pub package: String,
    /// Open advisories on the listening hosts, as the Vulnerabilities list's
    /// defaults count them: triage open, and not a lower-confidence match.
    pub advisories: i64,
    /// Listening hosts with one.
    pub hosts: i64,
}

/// Open alarms from the port's program.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelatedAlarms {
    /// No listening host names its program.
    pub program_not_collected: bool,
    /// Open alarms whose process is the listener's program.
    pub open: i64,
    /// Hosts with one.
    pub hosts: i64,
}

/// The Related card; a section is `None` without its permission.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PortRelated {
    /// Failing checks.
    pub compliance: Option<RelatedChecks>,
    /// Open advisories; empty for a port with no package in the map.
    pub vulnerabilities: Option<Vec<RelatedPackage>>,
    /// Open alarms.
    pub alarms: Option<RelatedAlarms>,
}

/// The scope each section is read in; `None` leaves the section out.
#[derive(Clone, Debug, Default)]
pub struct RelatedReach {
    /// `compliance.read`.
    pub compliance: Option<AgentScope>,
    /// `vulnerabilities.read`.
    pub vulnerabilities: Option<AgentScope>,
    /// `alarms.read`.
    pub alarms: Option<AgentScope>,
}

fn scope_params(scope: &AgentScope) -> (bool, Vec<String>) {
    (scope.is_global(), scope.group_ids())
}

/// Builds the card for the port on `hosts`, the listening agents in reach.
pub(crate) async fn related(
    client: &Client,
    reach: &RelatedReach,
    protocol: &str,
    port: u16,
    info: Option<PortInfo>,
    hosts: &[String],
    now: DateTime<Utc>,
) -> Result<PortRelated, StoreError> {
    let mut card = PortRelated::default();
    if let Some(scope) = &reach.compliance {
        card.compliance = Some(checks(client, scope, protocol, port, info, hosts, now).await?);
    }
    if let Some(scope) = &reach.vulnerabilities {
        card.vulnerabilities = Some(packages(client, scope, info, hosts).await?);
    }
    if let Some(scope) = &reach.alarms {
        card.alarms = Some(alarms(client, scope, protocol, port, hosts).await?);
    }
    Ok(card)
}

async fn checks(
    client: &Client,
    scope: &AgentScope,
    protocol: &str,
    port: u16,
    info: Option<PortInfo>,
    hosts: &[String],
    now: DateTime<Utc>,
) -> Result<RelatedChecks, StoreError> {
    let area = info.and_then(|i| i.area);
    let (global, groups) = scope_params(scope);
    let visible = agent_visibility("a.agent_id", "$1", "$2");
    let open = open_failing("$4");
    let rows = client
        .query(
            &format!(
                "SELECT f.rule_set_id, f.rule_id,
                        (array_agg(f.severity ORDER BY array_position({SEVERITIES}, f.severity)))[1],
                        count(DISTINCT f.agent_id),
                        (SELECT m.title FROM console_rule_meta m
                         WHERE m.rule_set_id = f.rule_set_id AND m.rule_id = f.rule_id
                         ORDER BY m.rule_set_version DESC LIMIT 1),
                        (SELECT m.expression FROM console_rule_meta m
                         WHERE m.rule_set_id = f.rule_set_id AND m.rule_id = f.rule_id
                         ORDER BY m.rule_set_version DESC LIMIT 1)
                 FROM current_findings f JOIN agents a ON a.agent_id = f.agent_id
                 LEFT JOIN console_finding_triage t
                   ON t.agent_id = f.agent_id AND t.rule_set_id = f.rule_set_id AND t.rule_id = f.rule_id
                 WHERE f.agent_id = ANY($3::text[]) AND {visible} AND {open}
                 GROUP BY f.rule_set_id, f.rule_id"
            ),
            &[&global, &groups, &hosts, &now],
        )
        .await?;
    let mut found: Vec<RelatedCheck> = rows
        .iter()
        .filter_map(|row| {
            let rule_id: String = row.get(1);
            let expression: Option<String> = row.get(5);
            let names_port = expression
                .as_deref()
                .and_then(|e| rule_port(&rule_id, e))
                .is_some_and(|(p, n)| p == protocol && n == port);
            (names_port || area.is_some_and(|a| check_area(&rule_id) == a)).then(|| RelatedCheck {
                rule_set_id: row.get(0),
                title: row
                    .get::<_, Option<String>>(4)
                    .unwrap_or_else(|| rule_id.clone()),
                rule_id,
                severity: row.get(2),
                hosts: row.get(3),
            })
        })
        .collect();
    let rank = |s: &str| {
        ["critical", "high", "medium", "low", "info"]
            .iter()
            .position(|x| *x == s)
    };
    found.sort_by(|a, b| {
        (rank(&a.severity), -a.hosts, &a.rule_set_id, &a.rule_id).cmp(&(
            rank(&b.severity),
            -b.hosts,
            &b.rule_set_id,
            &b.rule_id,
        ))
    });
    let total = i64::try_from(found.len()).unwrap_or(i64::MAX);
    found.truncate(CHECKS);
    Ok(RelatedChecks {
        items: found,
        total,
        area,
    })
}

async fn packages(
    client: &Client,
    scope: &AgentScope,
    info: Option<PortInfo>,
    hosts: &[String],
) -> Result<Vec<RelatedPackage>, StoreError> {
    let (global, groups) = scope_params(scope);
    let visible = agent_visibility("a.agent_id", "$1", "$2");
    let mut out = Vec::new();
    for package in info.map_or(&[][..], |i| i.packages) {
        let row = client
            .query_one(
                &format!(
                    "SELECT count(DISTINCT v.advisory_id), count(DISTINCT v.agent_id)
                     FROM vulnerabilities v JOIN agents a ON a.agent_id = v.agent_id
                     JOIN advisories adv ON adv.advisory_id = v.advisory_id
                     LEFT JOIN vulnerability_triage t ON t.agent_id = v.agent_id AND t.advisory_id = v.advisory_id
                     WHERE v.fixed_at IS NULL AND v.agent_id = ANY($3::text[]) AND {visible}
                       AND (t.state IS NULL OR t.state = 'open'
                            OR (t.state = 'accepted_risk' AND t.accepted_until <= now()))
                       AND split_part(adv.source, '-', 1) IN ('fedora', 'debian', 'ubuntu', 'rocky', 'almalinux')
                       AND EXISTS (SELECT 1 FROM jsonb_array_elements(v.packages) p
                                   WHERE p ->> 'name' = $4::text)"
                ),
                &[&global, &groups, &hosts, package],
            )
            .await?;
        out.push(RelatedPackage {
            package: (*package).to_owned(),
            advisories: row.get(0),
            hosts: row.get(1),
        });
    }
    Ok(out)
}

async fn alarms(
    client: &Client,
    scope: &AgentScope,
    protocol: &str,
    port: u16,
    hosts: &[String],
) -> Result<RelatedAlarms, StoreError> {
    let (global, groups) = scope_params(scope);
    let visible = agent_visibility("a.agent_id", "$1", "$2");
    let port = i32::from(port);
    let named: i64 = client
        .query_one(
            "SELECT count(*) FROM host_listeners
             WHERE agent_id = ANY($1::text[]) AND protocol = $2::text AND port = $3::int
               AND program IS NOT NULL",
            &[&hosts, &protocol, &port],
        )
        .await?
        .get(0);
    let row = client
        .query_one(
            &format!(
                "SELECT count(*), count(DISTINCT al.agent_id)
                 FROM alarms al JOIN agents a ON a.agent_id = al.agent_id
                 WHERE al.state = 'open' AND al.source = 'agent' AND al.agent_id = ANY($3::text[])
                   AND {visible}
                   AND EXISTS (SELECT 1 FROM host_listeners l
                               WHERE l.agent_id = al.agent_id AND l.protocol = $4::text AND l.port = $5::int
                                 AND l.program IS NOT NULL
                                 AND l.program = regexp_replace(al.process ->> 'exe', '^.*/', ''))"
            ),
            &[&global, &groups, &hosts, &protocol, &port],
        )
        .await?;
    Ok(RelatedAlarms {
        program_not_collected: named == 0,
        open: row.get(0),
        hosts: row.get(1),
    })
}
