//! Automatic host groups (spec §5.1): one per OS family and per distribution
//! the fleet reports, made by ingest when a host's inventory first shows them.

use chrono::{DateTime, Utc};
use deadpool_postgres::GenericClient;

use crate::StoreError;

/// Serialises group creation across concurrent ingests (they would otherwise
/// race on the unique name index). Constant is "OVHG" in ASCII.
const AUTO_GROUP_LOCK: i64 = 0x4F56_4847;

/// Most automatic groups there can be; an agent reports its own os-release,
/// so without a cap a hostile one could make groups without end.
const MAX_AUTOMATIC_GROUPS: i64 = 200;

/// `[a-z0-9._-]{1,32}`, the os-release identifier format.
fn is_token(word: &str) -> bool {
    (1..=32).contains(&word.len())
        && word.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

/// Only these os ids get an automatic group: an agent reports its own
/// os-release, so anything else would let a hostile one fill the cap or squat
/// names. Users make rule groups for other systems. Migration 53's backfill
/// lists the same ids.
const KNOWN_OS_IDS: [&str; 5] = ["debian", "ubuntu", "fedora", "rocky", "almalinux"];

/// `<known id> <release>`, the release a token: the only distributions that get a group.
fn is_distribution(distribution: &str) -> bool {
    distribution
        .split_once(' ')
        .is_some_and(|(id, release)| KNOWN_OS_IDS.contains(&id) && is_token(release))
}

/// Display name of an OS family; migration 53's `console_os_family_name`
/// holds the same map.
#[must_use]
pub fn os_family_name(os_family: &str) -> String {
    match os_family {
        "linux" => "Linux".into(),
        "windows" => "Windows".into(),
        // never dressed up: an unknown name must not read like an admin's group
        other => other.into(),
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
        "debian" => "Debian",
        "ubuntu" => "Ubuntu",
        "fedora" => "Fedora",
        "rocky" => "Rocky Linux",
        "almalinux" => "AlmaLinux",
        // unknown ids stay raw lowercase, e.g. "production 1"
        _ => return distribution.into(),
    };
    format!("{name}{rest}")
}

/// Makes the automatic groups for `os_family:<f>` and `distribution:<d>` when
/// missing and not dismissed. Idempotent. Call inside the inventory
/// transaction: the advisory lock is transaction-scoped, taken only when a
/// group is actually missing, and each group is inserted by its own statement
/// so the next name sees it.
pub async fn ensure_automatic_groups(
    client: &impl GenericClient,
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
        if (field == "distribution" && !is_distribution(value))
            || (field == "os_family" && !matches!(value, "linux" | "windows"))
        {
            continue;
        }
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
        let automatic: i64 = client
            .query_one(
                "SELECT count(*) FROM console_asset_groups WHERE kind = 'automatic'",
                &[],
            )
            .await?
            .get(0);
        if automatic >= MAX_AUTOMATIC_GROUPS {
            // ponytail: no logging crate in the store; stderr reaches the journal
            eprintln!(
                "openvibes: automatic host group cap ({MAX_AUTOMATIC_GROUPS}) reached; not creating {key}"
            );
            continue;
        }
        let description = if field == "os_family" {
            format!("Every host that reports {display}. Kept up to date by OpenVIBES.")
        } else {
            format!("Hosts running {display}.")
        };
        // A console user taking the same name between the name lookup and the
        // INSERT fails the inventory transaction on the unique name index; the
        // agent's next delivery retries it (self-healing), so no retry here.
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
