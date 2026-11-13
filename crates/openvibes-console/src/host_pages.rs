//! What the port and service pages' routes share: the Related card's reach,
//! the actions' reach checks and the Hosts route's query.

use platform_store::{
    Client, StoreError,
    host_sort::{HostOrder, HostSort},
    port_related::RelatedReach,
    vuln_summary::reaches_any,
};

use crate::{
    EffectiveCapability, Permission,
    access::guard::scope_of,
    alarms::list::{number, pick},
};

/// The scopes in which the caller reads compliance, vulnerabilities and alarms.
pub(crate) fn related_reach(capabilities: &[EffectiveCapability]) -> RelatedReach {
    let scope = |p| scope_of(capabilities, p);
    RelatedReach {
        compliance: scope(Permission::ComplianceRead),
        vulnerabilities: scope(Permission::VulnerabilitiesRead),
        alarms: scope(Permission::AlarmsRead),
    }
}

/// Does the caller hold `permission` over any of `hosts`?
pub(crate) async fn holds(
    client: &Client,
    capabilities: &[EffectiveCapability],
    hosts: &[String],
    permission: Permission,
) -> Result<bool, StoreError> {
    match scope_of(capabilities, permission) {
        Some(scope) => reaches_any(client, hosts, &scope).await,
        None => Ok(false),
    }
}

/// The Hosts route's `segment`, `offset` and `limit` (empty values count as
/// absent); the name of the parameter that is invalid otherwise.
pub(crate) fn hosts_query<S>(
    (segment, offset, limit): (&Option<String>, &Option<String>, &Option<String>),
    parse: impl Fn(&str) -> Option<S>,
    default: S,
) -> Result<(S, i64, i64), &'static str> {
    let present = |v: &Option<String>| v.clone().filter(|v| !v.is_empty());
    Ok((
        pick(present(segment).as_deref(), "segment", parse)?.unwrap_or(default),
        number(present(offset).as_deref(), 0, 100_000, "offset")?,
        number(present(limit).as_deref(), 50, 100, "limit")?,
    ))
}

/// A Hosts table's `sort` (host, the default; state, where the table has a
/// `state`; or date) and `dir` (asc, the default, or desc); the name of the
/// parameter that is invalid otherwise.
pub(crate) fn host_order(
    sort: &Option<String>,
    dir: &Option<String>,
    state: bool,
) -> Result<HostOrder, &'static str> {
    let present = |v: &Option<String>| v.clone().filter(|v| !v.is_empty());
    let sort = pick(present(sort).as_deref(), "sort", HostSort::parse)?.unwrap_or(HostSort::Host);
    if sort == HostSort::State && !state {
        return Err("sort");
    }
    let descending = match present(dir).as_deref() {
        None | Some("asc") => false,
        Some("desc") => true,
        Some(_) => return Err("dir"),
    };
    Ok(HostOrder { sort, descending })
}
