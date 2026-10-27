//! A service's Related card (step 5f ruling 13): failing checks that name
//! the unit, open vulnerabilities of its packages, and open alarms from its
//! programs, each counted on the hosts running the unit and only with its
//! own read permission (its scope; the hosts are already in the viewer's
//! reach).

use chrono::{DateTime, Utc};

use crate::{
    Client, StoreError,
    check_related::rule_unit,
    console_read::{AgentScope, agent_visibility},
    port_related::{
        RelatedChecks, RelatedPackage, RelatedReach, advisory_counts, failing_checks,
        package_advisories, scope_params,
    },
    service_names::{self, ServiceInfo},
};

/// Open alarms from the unit's programs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceAlarms {
    /// No host running the unit names a program.
    pub programs_not_collected: bool,
    /// Open alarms whose process is one of the unit's programs on that host.
    pub open: i64,
    /// Hosts with one.
    pub hosts: i64,
}

/// Open advisories of the unit's packages.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ServiceVulnerabilities {
    /// One entry per package matched to the unit on those hosts.
    pub packages: Vec<RelatedPackage>,
    /// Distinct open advisories across them.
    pub advisories: i64,
    /// Hosts with at least one.
    pub hosts: i64,
}

/// The Related card; a section is `None` without its permission.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ServiceRelated {
    /// Failing checks.
    pub compliance: Option<RelatedChecks>,
    /// Open advisories of the matched packages.
    pub vulnerabilities: Option<ServiceVulnerabilities>,
    /// Open alarms.
    pub alarms: Option<ServiceAlarms>,
}

/// Builds the card for `unit` on `hosts`, the agents in reach running it;
/// `packages` are the installed names matched to it.
pub(crate) async fn related(
    client: &Client,
    reach: &RelatedReach,
    unit: &str,
    info: Option<ServiceInfo>,
    hosts: &[String],
    packages: &[String],
    now: DateTime<Utc>,
) -> Result<ServiceRelated, StoreError> {
    let mut card = ServiceRelated::default();
    if let Some(scope) = &reach.compliance {
        let base = service_names::base(unit);
        let names_unit = |rule_id: &str, expression: Option<&str>| {
            expression
                .and_then(|e| rule_unit(rule_id, e))
                .is_some_and(|u| service_names::base(&u) == base)
        };
        card.compliance = Some(
            failing_checks(
                client,
                scope,
                hosts,
                now,
                info.and_then(|i| i.area),
                &names_unit,
            )
            .await?,
        );
    }
    if let Some(scope) = &reach.vulnerabilities {
        card.vulnerabilities = Some(vulnerabilities(client, scope, hosts, packages).await?);
    }
    if let Some(scope) = &reach.alarms {
        card.alarms = Some(alarms(client, scope, unit, hosts).await?);
    }
    Ok(card)
}

async fn vulnerabilities(
    client: &Client,
    scope: &AgentScope,
    hosts: &[String],
    packages: &[String],
) -> Result<ServiceVulnerabilities, StoreError> {
    let mut out = ServiceVulnerabilities::default();
    for package in packages {
        out.packages
            .push(package_advisories(client, scope, hosts, package).await?);
    }
    if packages.is_empty() {
        return Ok(out);
    }
    (out.advisories, out.hosts) = advisory_counts(client, scope, hosts, packages).await?;
    Ok(out)
}

async fn alarms(
    client: &Client,
    scope: &AgentScope,
    unit: &str,
    hosts: &[String],
) -> Result<ServiceAlarms, StoreError> {
    let (global, groups) = scope_params(scope);
    let visible = agent_visibility("a.agent_id", "$1", "$2");
    let named: bool = client
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM host_services
                            WHERE agent_id = ANY($1::text[]) AND unit = $2 AND cardinality(programs) > 0)",
            &[&hosts, &unit],
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
                   AND EXISTS (SELECT 1 FROM host_services s
                               WHERE s.agent_id = al.agent_id AND s.unit = $4
                                 AND regexp_replace(al.process ->> 'exe', '^.*/', '') = ANY(s.programs))"
            ),
            &[&global, &groups, &hosts, &unit],
        )
        .await?;
    Ok(ServiceAlarms {
        programs_not_collected: !named,
        open: row.get(0),
        hosts: row.get(1),
    })
}
