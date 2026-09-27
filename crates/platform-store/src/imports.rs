//! Hosts imported from agent export files (protocol P3b): `agents` rows with
//! status `imported` and id `import.<install_id>`. They never authenticate
//! (certificates only name `agent.<uuid>`), and an import never touches an
//! enrolled agent: a file's `agent_id` is kept only as `claimed_agent_id`.

use chrono::{DateTime, Utc};

use crate::{
    Client, StoreError,
    inventory::{self, InventoryOutcome, PackageRow},
};

/// What one export file says about its host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportedHost<'a> {
    /// The agent installation's random id.
    pub install_id: &'a str,
    /// The `agent_id` the file names, if any; a label only.
    pub claimed_agent_id: Option<&'a str>,
    /// OS host name, a label only.
    pub hostname: Option<&'a str>,
    /// Agent version that wrote the file.
    pub scanner_version: &'a str,
    /// The file's time (`exported_at` or `collected_at`).
    pub seen_at: DateTime<Utc>,
}

/// Outcome of [`replace_inventory`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InventoryImport {
    /// Stored, and the vulnerability service notified.
    Stored,
    /// The host already had exactly this inventory.
    Unchanged,
    /// The host already has a newer inventory; nothing was written.
    Older,
}

/// Creates or updates the imported host `import.<install_id>` and returns
/// its id. The first import time becomes `enrolled_at`; labels come from the
/// newest file.
pub async fn upsert_host(
    client: &Client,
    host: &ImportedHost<'_>,
    now: DateTime<Utc>,
) -> Result<String, StoreError> {
    let row = client
        .query_opt(
            "INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at, scanner_version,
                 hostname, claimed_agent_id)
             VALUES ('import.' || $1, 'imported', $6, $5, $4, $3, $2)
             ON CONFLICT (agent_id) DO UPDATE SET
                 last_seen_at = GREATEST(agents.last_seen_at, EXCLUDED.last_seen_at),
                 scanner_version = CASE WHEN EXCLUDED.last_seen_at >= agents.last_seen_at
                     THEN EXCLUDED.scanner_version ELSE agents.scanner_version END,
                 hostname = CASE WHEN EXCLUDED.last_seen_at >= agents.last_seen_at
                     THEN EXCLUDED.hostname ELSE agents.hostname END,
                 claimed_agent_id = CASE WHEN EXCLUDED.last_seen_at >= agents.last_seen_at
                     THEN EXCLUDED.claimed_agent_id ELSE agents.claimed_agent_id END
             WHERE agents.status = 'imported'
             RETURNING agent_id",
            &[
                &host.install_id,
                &host.claimed_agent_id,
                &host.hostname,
                &host.scanner_version,
                &host.seen_at,
                &now,
            ],
        )
        .await?;
    row.map(|row| row.get(0)).ok_or(StoreError::Query)
}

/// Replaces an imported host's inventory if `collected_at` is newer than the
/// stored one, through the same store function as online reports. For an
/// imported host `inventory_at` is the snapshot time, which is what this
/// compares.
#[allow(clippy::too_many_arguments)]
pub async fn replace_inventory(
    client: &mut Client,
    agent_id: &str,
    os_id: &str,
    os_version: &str,
    running_kernel: Option<&str>,
    packages: &[PackageRow],
    sha256: [u8; 32],
    collected_at: DateTime<Utc>,
) -> Result<InventoryImport, StoreError> {
    // ponytail: the check and the replace are two transactions; one
    // operator's CLI makes the race moot. One transaction if imports ever
    // run concurrently.
    let stored: Option<DateTime<Utc>> = client
        .query_opt(
            "SELECT inventory_at FROM agents WHERE agent_id = $1 AND status = 'imported'",
            &[&agent_id],
        )
        .await?
        .ok_or(StoreError::Query)?
        .get(0);
    if stored.is_some_and(|at| at > collected_at) {
        return Ok(InventoryImport::Older);
    }
    let outcome = inventory::replace(
        client,
        agent_id,
        os_id,
        os_version,
        running_kernel,
        packages,
        sha256,
        collected_at,
    )
    .await?;
    Ok(match outcome {
        InventoryOutcome::Stored => InventoryImport::Stored,
        InventoryOutcome::Unchanged => {
            // Same content, newer file (a package rolled back): the snapshot
            // time still moves, so an older file cannot win afterwards.
            client
                .execute(
                    "UPDATE agents SET inventory_at = $2 WHERE agent_id = $1 AND inventory_at < $2",
                    &[&agent_id, &collected_at],
                )
                .await?;
            InventoryImport::Unchanged
        }
    })
}
