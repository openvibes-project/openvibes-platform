//! Host package inventories (protocol P8, VM spec §6), stored as distinct
//! package versions shared by the fleet plus one link per host and version.
//! Runs within the `openvibes-ingest` role's grants.

use chrono::{DateTime, Utc};

use std::collections::BTreeSet;

use deadpool_postgres::Transaction;
use openvibes_core::{NormalizedPackage, OsRelease, inventory_fingerprint};

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

/// Outcome of [`apply_changes`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChangesOutcome {
    /// The change set was applied and the vulnerability service notified.
    Stored,
    /// The change set does not fit the stored inventory; nothing was
    /// written and the agent must send the full inventory.
    Resync,
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
    if locked_digest(&transaction, agent_id).await?.as_deref() == Some(sha256.as_slice()) {
        return Ok(InventoryOutcome::Unchanged);
    }
    insert_versions(&transaction, packages).await?;
    transaction
        .execute(
            "DELETE FROM host_packages WHERE agent_id = $1",
            &[&agent_id],
        )
        .await?;
    link(&transaction, agent_id, packages).await?;
    finish(
        transaction,
        agent_id,
        os_id,
        os_version,
        running_kernel,
        sha256,
        now,
    )
    .await?;
    Ok(InventoryOutcome::Stored)
}

/// Applies a change set (protocol P11) under the host's row lock: only if
/// the stored fingerprint is `base`, every removed row is present, every
/// added row absent, and the result's fingerprint is `expected`. Anything
/// else is `Resync` and nothing is written (the transaction rolls back).
#[allow(clippy::too_many_arguments)]
pub async fn apply_changes(
    client: &mut Client,
    agent_id: &str,
    os: &OsRelease,
    running_kernel: Option<&str>,
    added: &[PackageRow],
    removed: &[PackageRow],
    base: [u8; 32],
    expected: [u8; 32],
    now: DateTime<Utc>,
) -> Result<ChangesOutcome, StoreError> {
    let transaction = client.transaction().await?;
    if locked_digest(&transaction, agent_id).await?.as_deref() != Some(base.as_slice()) {
        return Ok(ChangesOutcome::Resync);
    }
    let rows = transaction
        .query(
            "SELECT v.manager, v.name, v.epoch, v.version, v.release, v.arch, v.source,
                    v.source_version
             FROM host_packages h JOIN package_versions v ON v.id = h.package_version_id
             WHERE h.agent_id = $1",
            &[&agent_id],
        )
        .await?;
    let mut set: BTreeSet<PackageRow> = rows
        .iter()
        .map(|row| PackageRow {
            manager: row.get(0),
            name: row.get(1),
            epoch: row.get(2),
            version: row.get(3),
            release: row.get(4),
            arch: row.get(5),
            source: row.get(6),
            source_version: row.get(7),
        })
        .collect();
    if !removed.iter().all(|row| set.remove(row))
        || !added.iter().all(|row| set.insert(row.clone()))
    {
        return Ok(ChangesOutcome::Resync);
    }
    let result = inventory_fingerprint(os, running_kernel, set.iter().map(PackageRow::normalized));
    if result != expected {
        return Ok(ChangesOutcome::Resync);
    }
    insert_versions(&transaction, added).await?;
    unlink(&transaction, agent_id, removed).await?;
    link(&transaction, agent_id, added).await?;
    finish(
        transaction,
        agent_id,
        os.id.as_str(),
        os.version_id.as_str(),
        running_kernel,
        expected,
        now,
    )
    .await?;
    Ok(ChangesOutcome::Stored)
}

/// The host's stored fingerprint, with its row locked until the end of the
/// transaction.
async fn locked_digest(
    transaction: &Transaction<'_>,
    agent_id: &str,
) -> Result<Option<Vec<u8>>, StoreError> {
    Ok(transaction
        .query_one(
            "SELECT inventory_sha256 FROM agents WHERE agent_id = $1 FOR UPDATE",
            &[&agent_id],
        )
        .await?
        .get(0))
}

/// The rows as the column arrays `unnest` takes.
struct Columns<'a> {
    managers: Vec<&'a str>,
    names: Vec<&'a str>,
    epochs: Vec<i32>,
    versions: Vec<&'a str>,
    releases: Vec<&'a str>,
    arches: Vec<&'a str>,
    sources: Vec<Option<&'a str>>,
    source_versions: Vec<Option<&'a str>>,
}

fn columns(rows: &[PackageRow]) -> Columns<'_> {
    let column = |f: fn(&PackageRow) -> &str| rows.iter().map(f).collect::<Vec<_>>();
    Columns {
        managers: column(|p| &p.manager),
        names: column(|p| &p.name),
        epochs: rows.iter().map(|p| p.epoch).collect(),
        versions: column(|p| &p.version),
        releases: column(|p| &p.release),
        arches: column(|p| &p.arch),
        sources: rows.iter().map(|p| p.source.as_deref()).collect(),
        source_versions: rows.iter().map(|p| p.source_version.as_deref()).collect(),
    }
}

/// Inserts versions the fleet has not reported before.
async fn insert_versions(
    transaction: &Transaction<'_>,
    rows: &[PackageRow],
) -> Result<(), StoreError> {
    let c = columns(rows);
    transaction
        .execute(
            "INSERT INTO package_versions (manager, name, epoch, version, release, arch,
                 source, source_version)
             SELECT * FROM unnest($1::text[], $2::text[], $3::int[], $4::text[], $5::text[],
                                  $6::text[], $7::text[], $8::text[])
             ON CONFLICT DO NOTHING",
            &[
                &c.managers,
                &c.names,
                &c.epochs,
                &c.versions,
                &c.releases,
                &c.arches,
                &c.sources,
                &c.source_versions,
            ],
        )
        .await?;
    Ok(())
}

/// Links the host to each listed version.
async fn link(
    transaction: &Transaction<'_>,
    agent_id: &str,
    rows: &[PackageRow],
) -> Result<(), StoreError> {
    let c = columns(rows);
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
                &c.managers,
                &c.names,
                &c.epochs,
                &c.versions,
                &c.releases,
                &c.arches,
                &c.sources,
                &c.source_versions,
            ],
        )
        .await?;
    Ok(())
}

/// Removes the host's links to each listed version.
async fn unlink(
    transaction: &Transaction<'_>,
    agent_id: &str,
    rows: &[PackageRow],
) -> Result<(), StoreError> {
    let c = columns(rows);
    transaction
        .execute(
            "DELETE FROM host_packages h
             USING package_versions v,
                   unnest($2::text[], $3::text[], $4::int[], $5::text[], $6::text[], $7::text[],
                          $8::text[], $9::text[])
                       AS r(manager, name, epoch, version, release, arch, source, source_version)
             WHERE h.agent_id = $1 AND h.package_version_id = v.id
               AND (v.manager, v.name, v.epoch, v.version, v.release, v.arch)
                 = (r.manager, r.name, r.epoch, r.version, r.release, r.arch)
               AND v.source IS NOT DISTINCT FROM r.source
               AND v.source_version IS NOT DISTINCT FROM r.source_version",
            &[
                &agent_id,
                &c.managers,
                &c.names,
                &c.epochs,
                &c.versions,
                &c.releases,
                &c.arches,
                &c.sources,
                &c.source_versions,
            ],
        )
        .await?;
    Ok(())
}

/// Records the host's OS, kernel and fingerprint, notifies
/// `inventory_changed`, and commits.
async fn finish(
    transaction: Transaction<'_>,
    agent_id: &str,
    os_id: &str,
    os_version: &str,
    running_kernel: Option<&str>,
    sha256: [u8; 32],
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
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
    Ok(())
}
