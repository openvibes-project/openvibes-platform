//! A check's Related card (step 5c ruling 15): the port a `port.*` rule
//! names and the unit a `harden.services.*` rule names, read from the
//! rule's indexed expression, with the hosts in reach that have them.

use crate::{Client, StoreError, check_summary_sql as sql, console_read::AgentScope};

/// The exposed port a `port.*` check is about, and the hosts in reach
/// listening on it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelatedPort {
    /// `tcp` or `udp`.
    pub protocol: String,
    /// The port.
    pub port: u16,
    /// Hosts in reach where it is exposed.
    pub hosts: i64,
}

/// The unit a `harden.services.*` check is about, and the hosts in reach
/// running it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelatedService {
    /// The systemd unit.
    pub unit: String,
    /// Hosts in reach running it.
    pub hosts: i64,
}

/// Other failing checks in reach in the same area.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Deserialize)]
pub struct SameArea {
    /// How many.
    pub checks: i64,
    /// Their worst finding severity.
    pub worst: Option<String>,
}

/// The Related card.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CheckRelated {
    /// For `port.*` checks.
    pub port: Option<RelatedPort>,
    /// For `harden.services.*` checks.
    pub service: Option<RelatedService>,
    /// Same area.
    pub same_area: SameArea,
}

/// The first literal `expression` tests for membership in `fact`, as in
/// `'22' in facts['port.tcp.exposed']`. A rule naming several (rsh's
/// 512–514) gives its first.
#[must_use]
pub fn member_of(expression: &str, fact: &str) -> Option<String> {
    let needle = format!("' in facts['{fact}']");
    let end = expression.find(&needle)?;
    let start = expression[..end].rfind('\'')? + 1;
    let literal = &expression[start..end];
    (!literal.is_empty()).then(|| literal.to_owned())
}

/// The port of a `port.*` rule's expression: `(protocol, port)`.
#[must_use]
pub fn rule_port(rule_id: &str, expression: &str) -> Option<(&'static str, u16)> {
    if !rule_id.starts_with("port.") {
        return None;
    }
    ["tcp", "udp"].into_iter().find_map(|protocol| {
        let port = member_of(expression, &format!("port.{protocol}.exposed"))?;
        Some((protocol, port.parse().ok().filter(|p| *p > 0)?))
    })
}

/// The unit of a `harden.services.*` rule's expression.
#[must_use]
pub fn rule_unit(rule_id: &str, expression: &str) -> Option<String> {
    rule_id
        .starts_with("harden.services.")
        .then(|| member_of(expression, "service.enabled"))?
}

/// Port and service for `rule_id` with `expression`, counted in `scope`.
pub(crate) async fn port_and_service(
    client: &Client,
    scope: &AgentScope,
    rule_id: &str,
    expression: Option<&str>,
) -> Result<(Option<RelatedPort>, Option<RelatedService>), StoreError> {
    let Some(expression) = expression else {
        return Ok((None, None));
    };
    let port = match rule_port(rule_id, expression) {
        Some((protocol, port)) => {
            let hosts: i64 = client
                .query_one(
                    &sql::port_hosts(),
                    &[
                        &scope.is_global(),
                        &scope.group_ids(),
                        &protocol,
                        &i32::from(port),
                    ],
                )
                .await?
                .get(0);
            Some(RelatedPort {
                protocol: protocol.into(),
                port,
                hosts,
            })
        }
        None => None,
    };
    let service = match rule_unit(rule_id, expression) {
        Some(unit) => {
            let hosts: i64 = client
                .query_one(
                    &sql::unit_hosts(),
                    &[&scope.is_global(), &scope.group_ids(), &unit],
                )
                .await?
                .get(0);
            Some(RelatedService { unit, hosts })
        }
        None => None,
    };
    Ok((port, service))
}

#[cfg(test)]
mod tests {
    use super::{rule_port, rule_unit};

    #[test]
    fn ports_and_units_come_from_the_expression() {
        let ssh = "'22' in facts['port.tcp.exposed']";
        assert_eq!(rule_port("port.ssh.exposed", ssh), Some(("tcp", 22)));
        assert_eq!(
            rule_port("port.tftp.exposed", "'69' in facts['port.udp.exposed']"),
            Some(("udp", 69))
        );
        let rsh = "'512' in facts['port.tcp.exposed'] || '513' in facts['port.tcp.exposed']";
        assert_eq!(rule_port("port.rsh.exposed", rsh), Some(("tcp", 512)));
        assert_eq!(rule_port("harden.x", ssh), None, "only port.* checks");
        assert_eq!(
            rule_port("port.x", "'x' in facts['port.tcp.exposed']"),
            None
        );
        let avahi = "'avahi-daemon.service' in facts['service.enabled'] || 'avahi-daemon.socket' in facts['service.enabled']";
        assert_eq!(
            rule_unit("harden.services.avahi", avahi).as_deref(),
            Some("avahi-daemon.service")
        );
        assert_eq!(rule_unit("port.ssh.exposed", avahi), None);
        assert_eq!(rule_unit("harden.services.x", "facts['x'] == 1"), None);
    }
}
