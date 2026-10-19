//! Automatic host groups (spec §5.1): one per OS family and per distribution
//! the fleet reports, made by ingest when a host's inventory first shows them.

use chrono::{DateTime, Utc};
use deadpool_postgres::GenericClient;

use crate::StoreError;

/// Serialises group creation across concurrent ingests (they would otherwise
/// race on the unique name index). Constant is "OVHG" in ASCII.
const AUTO_GROUP_LOCK: i64 = 0x4F56_4847;

fn capitalised(word: &str) -> String {
    let mut chars = word.chars();
    chars
        .next()
        .map(|first| first.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

/// Display name of an OS family; migration 53's `console_os_family_name`
/// holds the same map.
#[must_use]
pub fn os_family_name(os_family: &str) -> String {
    match os_family {
        "linux" => "Linux".into(),
        "windows" => "Windows".into(),
        other => capitalised(other),
    }
}

/// Display name of a distribution such as `debian 12`; migration 53's
/// `console_distribution_name` holds the same map.
#[must_use]
pub fn distribution_name(distribution: &str) -> String {
    let (first, rest) = distribution
        .find(' ')
        .map_or((distribution, ""), |at| distribution.split_at(at));
    let name = match first {
        "debian" => "Debian".into(),
        "ubuntu" => "Ubuntu".into(),
        "fedora" => "Fedora".into(),
        "rocky" => "Rocky Linux".into(),
        "almalinux" => "AlmaLinux".into(),
        other => capitalised(other),
    };
    format!("{name}{rest}")
}

/// Makes the automatic groups for `os_family:<f>` and `distribution:<d>` when
/// missing and not dismissed. Idempotent. Call inside the inventory
/// transaction: the advisory lock is transaction-scoped, taken only when a
/// group is actually missing, and each group is inserted by its own statement
/// so the next name sees it.
pub async fn ensure_automatic_groups(
    client: &(impl GenericClient + Sync),
    os_family: &str,
    distribution: &str,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let wanted = [
        ("os_family", os_family, os_family_name(os_family)),
        (
            "distribution",
            distribution,
            distribution_name(distribution),
        ),
    ];
    let mut locked = false;
    for (field, value, display) in wanted {
        let key = format!("{field}:{value}");
        let missing = "SELECT NOT EXISTS (SELECT 1 FROM console_asset_groups WHERE auto_key = $1)
                       AND NOT EXISTS (SELECT 1 FROM console_host_group_dismissed WHERE auto_key = $1)";
        if !client.query_one(missing, &[&key]).await?.get::<_, bool>(0) {
            continue;
        }
        if !locked {
            client
                .execute("SELECT pg_advisory_xact_lock($1)", &[&AUTO_GROUP_LOCK])
                .await?;
            locked = true;
            // another ingest may have made it while we waited
            if !client.query_one(missing, &[&key]).await?.get::<_, bool>(0) {
                continue;
            }
        }
        let description = if field == "os_family" {
            format!("Every host that reports {display}. Kept up to date by OpenVIBES.")
        } else {
            format!("Hosts running {display}.")
        };
        let created = client
            .query_opt(
                "INSERT INTO console_asset_groups
                   (asset_group_id, name, created_at, created_by, kind, auto_key, description)
                 VALUES (gen_random_uuid(), console_free_group_name($1, 'automatic'), $2,
                         'openvibes', 'automatic', $3, left($4, 500))
                 ON CONFLICT (auto_key) DO NOTHING
                 RETURNING asset_group_id::text, name",
                &[&display, &now, &key, &description],
            )
            .await?;
        let Some(row) = created else { continue };
        let (id, name): (String, String) = (row.get(0), row.get(1));
        client
            .execute(
                "INSERT INTO console_host_group_conditions (asset_group_id, position, field, negate, vals)
                 VALUES ($1::text::uuid, 0, $2, false, ARRAY[$3::text])",
                &[&id, &field, &value],
            )
            .await?;
        client
            .execute(
                "INSERT INTO audit_log (actor, action, target, result, detail, actor_kind, actor_id, target_kind, target_id)
                 VALUES ('openvibes', 'host_group.created_automatically', $1, 'success',
                         jsonb_build_object('auto_key', $2::text), 'system', 'openvibes', 'host_group', $3::text)",
                &[&name, &key, &id],
            )
            .await?;
    }
    Ok(())
}
