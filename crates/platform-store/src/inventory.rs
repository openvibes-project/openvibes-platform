//! Host package inventories (protocol P8, VM spec §6), stored as distinct
//! package versions shared by the fleet plus one link per host and version.
//! Runs within the `openvibes-ingest` role's grants.

use chrono::{DateTime, Utc};

use openvibes_core::NormalizedPackage;

use crate::{Client, StoreError};

/// One installed package, as matching needs it: the normalised record of
/// the P11 fingerprint (one row per distinct record).
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PackageRow {
    /// Package database (`rpm`, `dpkg`).
    pub manager: String,
    /// Package name.
    pub name: String,
    /// Epoch; 0 when the package sets none.
    pub epoch: i32,
    /// Upstream version.
    pub version: String,
    /// Distribution release; empty when absent.
    pub release: String,
    /// Architecture; empty when absent.
    pub arch: String,
    /// Source package when it differs from the binary's name (protocol P10).
    pub source: Option<String>,
    /// dpkg: the source's full version when it differs (a binNMU).
    pub source_version: Option<String>,
}

impl PackageRow {
    /// The record the P11 fingerprint is computed over.
    #[must_use]
    pub fn normalized(&self) -> NormalizedPackage {
        NormalizedPackage {
            manager: self.manager.clone(),
            name: self.name.clone(),
            epoch: u32::try_from(self.epoch).unwrap_or(0),
            version: self.version.clone(),
            release: self.release.clone(),
            arch: self.arch.clone(),
            source: self.source.clone(),
            source_version: self.source_version.clone(),
        }
    }
}

impl From<&NormalizedPackage> for PackageRow {
    fn from(package: &NormalizedPackage) -> Self {
        Self {
            manager: package.manager.clone(),
            name: package.name.clone(),
            // ponytail: epochs above 2^31 - 1 do not exist in practice; such a
            // host's fingerprint never matches, so it always gets full reports.
            epoch: i32::try_from(package.epoch).unwrap_or(0),
            version: package.version.clone(),
            release: package.release.clone(),
            arch: package.arch.clone(),
            source: package.source.clone(),
            source_version: package.source_version.clone(),
        }
    }
}

/// Outcome of [`replace`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InventoryOutcome {
    /// The host's inventory was replaced and the vulnerability service
    /// notified.
    Stored,
    /// The host already had exactly this inventory; nothing was written.
    Unchanged,
}

/// Replaces a host's inventory in one transaction, unless its digest equals
/// the stored one, and notifies `inventory_changed` with the agent id.
/// `running_kernel` is the `uname -r` release (protocol P9), when reported.
#[allow(clippy::too_many_arguments)]
pub async fn replace(
    client: &mut Client,
    agent_id: &str,
    os_id: &str,
    os_version: &str,
    running_kernel: Option<&str>,
    packages: &[PackageRow],
    sha256: [u8; 32],
    now: DateTime<Utc>,
) -> Result<InventoryOutcome, StoreError> {
    let transaction = client.transaction().await?;
    let stored: Option<Vec<u8>> = transaction
        .query_one(
            "SELECT inventory_sha256 FROM agents WHERE agent_id = $1 FOR UPDATE",
            &[&agent_id],
        )
        .await?
        .get(0);
    if stored.as_deref() == Some(sha256.as_slice()) {
        return Ok(InventoryOutcome::Unchanged);
    }
    let column = |f: fn(&PackageRow) -> &str| packages.iter().map(f).collect::<Vec<_>>();
    let managers = column(|p| &p.manager);
    let names = column(|p| &p.name);
    let versions = column(|p| &p.version);
    let releases = column(|p| &p.release);
    let arches = column(|p| &p.arch);
    let epochs: Vec<i32> = packages.iter().map(|p| p.epoch).collect();
    let sources: Vec<Option<&str>> = packages.iter().map(|p| p.source.as_deref()).collect();
    let source_versions: Vec<Option<&str>> = packages
        .iter()
        .map(|p| p.source_version.as_deref())
        .collect();
    // Insert unknown versions, then link the host to every listed version.
    transaction
        .execute(
            "INSERT INTO package_versions (manager, name, epoch, version, release, arch,
                 source, source_version)
             SELECT * FROM unnest($1::text[], $2::text[], $3::int[], $4::text[], $5::text[],
                                  $6::text[], $7::text[], $8::text[])
             ON CONFLICT DO NOTHING",
            &[
                &managers,
                &names,
                &epochs,
                &versions,
                &releases,
                &arches,
                &sources,
                &source_versions,
            ],
        )
        .await?;
    transaction
        .execute(
            "DELETE FROM host_packages WHERE agent_id = $1",
            &[&agent_id],
        )
        .await?;
    transaction
        .execute(
            "INSERT INTO host_packages (agent_id, package_version_id)
             SELECT DISTINCT $1::text, v.id
             FROM unnest($2::text[], $3::text[], $4::int[], $5::text[], $6::text[], $7::text[],
                         $8::text[], $9::text[])
                 AS i(manager, name, epoch, version, release, arch, source, source_version)
             JOIN package_versions v USING (manager, name, epoch, version, release, arch)
             WHERE v.source IS NOT DISTINCT FROM i.source
               AND v.source_version IS NOT DISTINCT FROM i.source_version",
            &[
                &agent_id,
                &managers,
                &names,
                &epochs,
                &versions,
                &releases,
                &arches,
                &sources,
                &source_versions,
            ],
        )
        .await?;
    transaction
        .execute(
            "UPDATE agents SET os_id = $2, os_version = $3, inventory_sha256 = $4,
                 inventory_at = $5, running_kernel = $6 WHERE agent_id = $1",
            &[
                &agent_id,
                &os_id,
                &os_version,
                &sha256.as_slice(),
                &now,
                &running_kernel,
            ],
        )
        .await?;
    transaction
        .execute("SELECT pg_notify('inventory_changed', $1)", &[&agent_id])
        .await?;
    transaction.commit().await?;
    Ok(InventoryOutcome::Stored)
}
