//! Matching stored inventories against advisories (VM spec §7).
//!
//! A host is affected by an advisory when, for one of its fixed packages,
//! the host's **newest** installed version of that name with a compatible
//! architecture (same, or either side `noarch`) is lower in RPM order. So an
//! old kernel kept beside a fixed one does not count, as `dnf` decides.
//! A kernel whose fix is installed still counts while the host runs an
//! older one (protocol P9): open, flagged "fix installed, reboot needed".

use std::{cmp::Ordering, collections::BTreeMap};

use chrono::{DateTime, Utc};
use platform_store::{
    Client, StoreError,
    vulns::{self, Candidate, Found, Scope, VersionFound},
};
use serde_json::json;

use crate::{dpkgver, rpmver::compare_evr};

/// Hosts matched per query: one query over every host of a large fleet
/// exceeded the 10 s statement timeout at 10,000 hosts (`docs/sizing.md`).
pub const MATCH_BATCH: usize = 500;

/// What evaluating each distinct package version once finds: the fixable
/// (advisory, package) pairs worth matching per host, and the no-fix hits,
/// kept per version (the user, 2026-09-26).
#[derive(Debug, Default)]
struct PerVersion {
    pairs: Vec<(String, String)>,
    no_fix: Vec<VersionFound>,
    evaluated: Vec<i64>,
}

/// Evaluates advisories against each distinct installed version once.
fn per_version(candidates: &[Candidate]) -> PerVersion {
    let mut pairs = std::collections::BTreeSet::new();
    let mut no_fix = std::collections::BTreeSet::new();
    let mut evaluated = std::collections::BTreeSet::new();
    for candidate in candidates {
        evaluated.insert(candidate.version_id);
        // Kernels stay candidates even when fixed: the fix may not run yet.
        let kernel = candidate.scheme == "rpm" && is_kernel(&candidate.name);
        if candidate.fixed.is_some() {
            if kernel || in_range(candidate, &candidate.installed) {
                pairs.insert((candidate.advisory_id.clone(), candidate.name.clone()));
            }
        } else if in_range(candidate, &candidate.installed) {
            no_fix.insert((
                candidate.version_id,
                candidate.advisory_id.clone(),
                candidate.name.clone(),
            ));
        }
    }
    PerVersion {
        pairs: pairs.into_iter().collect(),
        no_fix: no_fix
            .into_iter()
            .map(|(version_id, advisory_id, package)| VersionFound {
                version_id,
                advisory_id,
                package,
            })
            .collect(),
        evaluated: evaluated.into_iter().collect(),
    }
}

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
    let versions = per_version(&vulns::version_candidates(client, os_id, os_version, None).await?);
    vulns::apply_versions(client, &versions.evaluated, &versions.no_fix, now).await?;
    let hosts = vulns::release_hosts(client, os_id, os_version).await?;
    let mut open = 0;
    for agents in hosts.chunks(batch.max(1)) {
        let candidates =
            vulns::candidates(client, os_id, os_version, agents, &versions.pairs).await?;
        let found = evaluate(&candidates);
        let scope = Scope::Release {
            os_id,
            os_version,
            agents,
        };
        open += vulns::apply(client, scope, &found, now).await?;
        vulns::refresh_counts(client, agents, now).await?;
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
    let versions =
        per_version(&vulns::version_candidates(client, &os_id, &os_version, Some(agent_id)).await?);
    vulns::apply_versions(client, &versions.evaluated, &versions.no_fix, now).await?;
    let candidates = vulns::candidates(
        client,
        &os_id,
        &os_version,
        &[agent_id.to_owned()],
        &versions.pairs,
    )
    .await?;
    let found = evaluate(&candidates);
    let open = vulns::apply(client, Scope::Host(agent_id), &found, now).await?;
    vulns::refresh_counts(client, &[agent_id.to_owned()], now).await?;
    Ok(open)
}

/// `[E:]V-R` split as RPM compares it; a missing epoch is 0.
fn rpm_parts(full: &str) -> (u32, &str, &str) {
    let (epoch, rest) = match full.split_once(':') {
        Some((epoch, rest)) if !epoch.is_empty() && epoch.bytes().all(|b| b.is_ascii_digit()) => {
            (epoch.parse().unwrap_or(u32::MAX), rest)
        }
        _ => (0, full),
    };
    match rest.rsplit_once('-') {
        Some((version, release)) => (epoch, version, release),
        None => (epoch, rest, ""),
    }
}

/// Version order of the package's scheme (`rpm` or `dpkg`).
fn compare(scheme: &str, a: &str, b: &str) -> Ordering {
    if scheme == "dpkg" {
        dpkgver::compare(a, b)
    } else {
        compare_evr(rpm_parts(a), rpm_parts(b))
    }
}

/// Whether `installed` falls in the candidate's affected range: from
/// `introduced` (or the start) up to `fixed`, or through `last_affected`,
/// or with neither, every later version (no fix known).
fn in_range(candidate: &Candidate, installed: &str) -> bool {
    let order = |a: &str, b: &str| compare(&candidate.scheme, a, b);
    let started = candidate
        .introduced
        .as_deref()
        .is_none_or(|from| from == "0" || order(installed, from).is_ge());
    started
        && match (&candidate.fixed, &candidate.last_affected) {
            (Some(fixed), _) => order(installed, fixed).is_lt(),
            (None, Some(last)) => order(installed, last).is_le(),
            (None, None) => true,
        }
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
    let mut newest: BTreeMap<(&str, &str, &str, &str, &str), &Candidate> = BTreeMap::new();
    // Without a fix, a vulnerability is kept per version, not per host.
    for candidate in candidates.iter().filter(|c| c.fixed.is_some()) {
        let slot = newest
            .entry((
                candidate.agent_id.as_str(),
                candidate.advisory_id.as_str(),
                candidate.name.as_str(),
                candidate.fixed_arch.as_str(),
                candidate.introduced.as_deref().unwrap_or(""),
            ))
            .or_insert(candidate);
        if compare(&candidate.scheme, &candidate.installed, &slot.installed).is_gt() {
            *slot = candidate;
        }
    }
    // Affected packages per (host, advisory), one entry per package name,
    // each with whether only a reboot is missing.
    let mut affected: BTreeMap<(&str, &str), BTreeMap<&str, Entry>> = BTreeMap::new();
    for ((agent, advisory, name, _, _), candidate) in newest {
        let update = in_range(candidate, &candidate.installed);
        // A kernel fix counts once it runs (protocol P9).
        let running = candidate
            .fixed
            .as_deref()
            .filter(|_| is_kernel(name) && candidate.scheme == "rpm")
            .and_then(|fixed| {
                let running = running_evr(candidate.running_kernel.as_deref()?)?;
                let running = format!("{}:{}-{}", running.0, running.1, running.2);
                compare("rpm", &running, fixed).is_lt().then_some(running)
            });
        if !update && running.is_none() {
            continue;
        }
        let mut entry = json!({
            "name": name,
            "installed": candidate.installed,
            "fixed": candidate.fixed,
        });
        if let Some(running) = &running {
            entry["running"] = running.clone().into();
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
