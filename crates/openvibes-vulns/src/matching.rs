//! Matching stored inventories against advisories (VM spec §7).
//!
//! A host is affected by an advisory when, for one of its fixed packages,
//! the host's **newest** installed version of that name with a compatible
//! architecture (same, or either side `noarch`) is lower in RPM order. So an
//! old kernel kept beside a fixed one does not count, as `dnf` decides.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use platform_store::{
    Client, StoreError,
    vulns::{self, Candidate, Found, Scope},
};
use serde_json::json;

use crate::rpmver::compare_evr;

/// Re-evaluates every host on one release. Returns the number open.
pub async fn match_release(
    client: &mut Client,
    os_id: &str,
    os_version: &str,
    now: DateTime<Utc>,
) -> Result<usize, StoreError> {
    let candidates = vulns::candidates(client, os_id, os_version, None).await?;
    let found = evaluate(&candidates);
    vulns::apply(client, Scope::Release { os_id, os_version }, &found, now).await
}

/// Re-evaluates one host, after its inventory changed. A host without a
/// reported release is left as it is.
pub async fn match_host(
    client: &mut Client,
    agent_id: &str,
    now: DateTime<Utc>,
) -> Result<usize, StoreError> {
    let Some((os_id, os_version)) = vulns::host_release(client, agent_id).await? else {
        return Ok(0);
    };
    let candidates = vulns::candidates(client, &os_id, &os_version, Some(agent_id)).await?;
    let found = evaluate(&candidates);
    vulns::apply(client, Scope::Host(agent_id), &found, now).await
}

fn evr(evr: &(i32, String, String)) -> String {
    format!("{}:{}-{}", evr.0, evr.1, evr.2)
}

fn key(evr: &(i32, String, String)) -> (u32, &str, &str) {
    (
        u32::try_from(evr.0).unwrap_or(0),
        evr.1.as_str(),
        evr.2.as_str(),
    )
}

/// Decides which candidates are vulnerable; pure, so it is unit tested.
#[must_use]
pub fn evaluate(candidates: &[Candidate]) -> Vec<Found> {
    // Newest installed version per (host, advisory, package, fixed arch).
    let mut newest: BTreeMap<(&str, &str, &str, &str), &Candidate> = BTreeMap::new();
    for candidate in candidates {
        let slot = newest
            .entry((
                candidate.agent_id.as_str(),
                candidate.advisory_id.as_str(),
                candidate.name.as_str(),
                candidate.fixed_arch.as_str(),
            ))
            .or_insert(candidate);
        if compare_evr(key(&candidate.installed), key(&slot.installed)).is_gt() {
            *slot = candidate;
        }
    }
    // Affected packages per (host, advisory), one entry per package name.
    let mut affected: BTreeMap<(&str, &str), BTreeMap<&str, serde_json::Value>> = BTreeMap::new();
    for ((agent, advisory, name, _), candidate) in newest {
        if compare_evr(key(&candidate.installed), key(&candidate.fixed)).is_lt() {
            affected
                .entry((agent, advisory))
                .or_default()
                .entry(name)
                .or_insert_with(|| {
                    json!({
                        "name": name,
                        "installed": evr(&candidate.installed),
                        "fixed": evr(&candidate.fixed),
                    })
                });
        }
    }
    affected
        .into_iter()
        .map(|((agent, advisory), packages)| Found {
            agent_id: agent.to_owned(),
            advisory_id: advisory.to_owned(),
            packages: serde_json::Value::Array(packages.into_values().collect()),
        })
        .collect()
}
