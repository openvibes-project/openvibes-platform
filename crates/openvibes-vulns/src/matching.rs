//! Matching stored inventories against advisories (VM spec §7).
//!
//! A host is affected by an advisory when, for one of its fixed packages,
//! the host's **newest** installed version of that name with a compatible
//! architecture (same, or either side `noarch`) is lower in RPM order. So an
//! old kernel kept beside a fixed one does not count, as `dnf` decides.
//! A kernel whose fix is installed still counts while the host runs an
//! older one (protocol P9): open, flagged "fix installed, reboot needed".

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use platform_store::{
    Client, StoreError,
    vulns::{self, Candidate, Found, Scope},
};
use serde_json::json;

use crate::rpmver::compare_evr;

/// Hosts matched per query: one query over every host of a large fleet
/// exceeded the 10 s statement timeout at 10,000 hosts (`docs/sizing.md`).
pub const MATCH_BATCH: usize = 500;

/// Re-evaluates every host on one release, [`MATCH_BATCH`] hosts at a
/// time. Returns the number open.
pub async fn match_release(
    client: &mut Client,
    os_id: &str,
    os_version: &str,
    now: DateTime<Utc>,
) -> Result<usize, StoreError> {
    match_release_in_batches(client, os_id, os_version, MATCH_BATCH, now).await
}

/// [`match_release`] with a chosen batch size (each batch is one query and
/// one transaction; a failure keeps the batches already applied).
pub async fn match_release_in_batches(
    client: &mut Client,
    os_id: &str,
    os_version: &str,
    batch: usize,
    now: DateTime<Utc>,
) -> Result<usize, StoreError> {
    let hosts = vulns::release_hosts(client, os_id, os_version).await?;
    let mut open = 0;
    for agents in hosts.chunks(batch.max(1)) {
        let candidates = vulns::candidates(client, os_id, os_version, agents).await?;
        let found = evaluate(&candidates);
        let scope = Scope::Release {
            os_id,
            os_version,
            agents,
        };
        open += vulns::apply(client, scope, &found, now).await?;
    }
    Ok(open)
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
    let candidates = vulns::candidates(client, &os_id, &os_version, &[agent_id.to_owned()]).await?;
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

/// Packages that are the running kernel: their fix counts once booted.
fn is_kernel(name: &str) -> bool {
    matches!(name, "kernel" | "kernel-core") || name.starts_with("kernel-modules")
}

/// A `uname -r` release (`6.17.4-300.fc44.x86_64`, optionally `+debug`) as
/// epoch, version, release. Fedora kernels have epoch 0.
fn running_evr(uname: &str) -> Option<(i32, String, String)> {
    const ARCHES: [&str; 7] = [
        "x86_64", "aarch64", "ppc64le", "s390x", "i686", "armv7hl", "riscv64",
    ];
    let uname = uname.split('+').next()?;
    let uname = match uname.rsplit_once('.') {
        Some((rest, arch)) if ARCHES.contains(&arch) => rest,
        _ => uname,
    };
    let (version, release) = uname.split_once('-')?;
    Some((0, version.to_owned(), release.to_owned()))
}

/// An affected package's JSON entry, and whether only a reboot is missing.
type Entry = (serde_json::Value, bool);

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
    // Affected packages per (host, advisory), one entry per package name,
    // each with whether only a reboot is missing.
    let mut affected: BTreeMap<(&str, &str), BTreeMap<&str, Entry>> = BTreeMap::new();
    for ((agent, advisory, name, _), candidate) in newest {
        let fixed = key(&candidate.fixed);
        let update = compare_evr(key(&candidate.installed), fixed).is_lt();
        let running = candidate
            .running_kernel
            .as_deref()
            .filter(|_| is_kernel(name))
            .and_then(running_evr)
            .filter(|running| compare_evr(key(running), fixed).is_lt());
        if !update && running.is_none() {
            continue;
        }
        let mut entry = json!({
            "name": name,
            "installed": evr(&candidate.installed),
            "fixed": evr(&candidate.fixed),
        });
        if let Some(running) = &running {
            entry["running"] = evr(running).into();
        }
        affected
            .entry((agent, advisory))
            .or_default()
            .entry(name)
            .or_insert((entry, !update));
    }
    affected
        .into_iter()
        .map(|((agent, advisory), packages)| Found {
            agent_id: agent.to_owned(),
            advisory_id: advisory.to_owned(),
            reboot_needed: packages.values().all(|(_, reboot)| *reboot),
            packages: serde_json::Value::Array(
                packages.into_values().map(|(entry, _)| entry).collect(),
            ),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::running_evr;

    #[test]
    fn reads_uname_releases() {
        let evr = |v: &str, r: &str| Some((0, v.to_owned(), r.to_owned()));
        assert_eq!(
            running_evr("6.17.4-300.fc44.x86_64"),
            evr("6.17.4", "300.fc44")
        );
        assert_eq!(
            running_evr("6.17.4-300.fc44.x86_64+debug"),
            evr("6.17.4", "300.fc44")
        );
        assert_eq!(running_evr("6.17.4-300.fc44"), evr("6.17.4", "300.fc44"));
        assert_eq!(running_evr("6.17.4"), None);
    }
}
