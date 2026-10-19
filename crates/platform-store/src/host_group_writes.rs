//! Host-group writes (create, update, delete) (spec §5.1); the preview
//! shown before saving lives in `host_group_preview` and is re-exported here. Writes run in one transaction under the access
//! lock roles use, so a role cannot start using a group being deleted.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use tokio_postgres::error::SqlState;

use crate::{
    Client, StoreError,
    console_auth::ACCESS_BINDING_LOCK,
    console_read::AgentScope,
    host_groups::{Condition, GroupKind, GroupSummary, summaries},
};

pub use crate::host_group_preview::{
    HostRef, PREVIEW_CAP, PersonRef, Preview, PreviewOutcome, preview,
};

/// Most conditions in a rule.
pub const MAX_CONDITIONS: usize = 16;
/// Most values in one condition.
pub const MAX_VALUES: usize = 64;

/// What a group holds: a rule or hand-picked agent ids.
#[derive(Clone, Copy, Debug)]
pub enum GroupContent<'a> {
    /// Rule.
    Rule(&'a [Condition]),
    /// Manual.
    Manual(&'a [String]),
}

/// A group as a person saves it; the kind follows the content.
#[derive(Clone, Copy, Debug)]
pub struct GroupInput<'a> {
    /// Name.
    pub name: &'a str,
    /// Description.
    pub description: &'a str,
    /// Content.
    pub content: GroupContent<'a>,
}

/// The outcome of a write.
#[derive(Debug)]
pub enum GroupWrite {
    /// Written (for a delete: the group as it was).
    Saved(GroupSummary),
    /// Another group has this name, regardless of case.
    NameTaken,
    /// The version given is not the current one.
    Stale,
    /// Not found.
    NotFound,
    /// Roles reach the group (display names); it cannot be deleted.
    InUse(Vec<String>),
    /// A picked agent id does not exist or is not active.
    UnknownHost(String),
    /// The named part is malformed: `name`, `description`, `conditions`,
    /// or a condition's field.
    Invalid(String),
}

fn is_cidr(value: &str) -> bool {
    let (address, prefix) = match value.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix)),
        None => (value, None),
    };
    let Ok(ip) = address.parse::<IpAddr>() else {
        return false;
    };
    let max = if ip.is_ipv4() { 32 } else { 128 };
    prefix.is_none_or(|p| {
        (1..=3).contains(&p.len())
            && p.bytes().all(|b| b.is_ascii_digit())
            && p.parse::<u8>().is_ok_and(|p| p <= max)
    })
}

fn value_ok(field: &str, value: &str) -> bool {
    match field {
        "os_family" => matches!(value, "linux" | "windows"),
        "ip" => is_cidr(value),
        "distribution" | "hostname" => {
            (1..=255).contains(&value.chars().count()) && !value.chars().any(char::is_control)
        }
        _ => false,
    }
}

/// The malformed part of `input`, if any (see [`GroupWrite::Invalid`]). The
/// console checks first; this keeps a bad value from reaching the database.
#[must_use]
pub fn invalid_part(input: &GroupInput<'_>) -> Option<String> {
    let name = input.name.trim();
    if name != input.name
        || !(1..=128).contains(&name.chars().count())
        || name.chars().any(char::is_control)
    {
        return Some("name".into());
    }
    if input.description.chars().count() > 500 {
        return Some("description".into());
    }
    invalid_content(&input.content)
}

/// The malformed part of a rule (`conditions`, or a condition's field), if
/// any; picked lists are checked against the database instead.
#[must_use]
pub fn invalid_content(content: &GroupContent<'_>) -> Option<String> {
    let GroupContent::Rule(conditions) = content else {
        return None;
    };
    if conditions.len() > MAX_CONDITIONS {
        return Some("conditions".into());
    }
    conditions
        .iter()
        .find(|c| {
            !(1..=MAX_VALUES).contains(&c.values.len())
                || !c.values.iter().all(|v| value_ok(&c.field, v))
        })
        .map(|c| c.field.clone())
}

/// Picked ids without repeats, in the order given.
fn distinct(picked: &[String]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    picked
        .iter()
        .filter(|id| seen.insert(*id))
        .cloned()
        .collect()
}

type Tx<'a> = deadpool_postgres::Transaction<'a>;

async fn lock(tx: &Tx<'_>) -> Result<(), StoreError> {
    tx.query_one("SELECT pg_advisory_xact_lock($1)", &[&ACCESS_BINDING_LOCK])
        .await?;
    Ok(())
}

async fn unknown_host(tx: &Tx<'_>, picked: &[String]) -> Result<Option<String>, StoreError> {
    Ok(tx
        .query_opt(
            "SELECT x FROM unnest($1::text[]) WITH ORDINALITY AS t(x, n)
             WHERE NOT EXISTS (SELECT 1 FROM agents WHERE agent_id = x AND status = 'active')
             ORDER BY n LIMIT 1",
            &[&picked],
        )
        .await?
        .map(|row| row.get(0)))
}

fn name_taken(error: &tokio_postgres::Error) -> bool {
    error.as_db_error().is_some_and(|db| {
        db.code() == &SqlState::UNIQUE_VIOLATION
            && db.constraint() == Some("console_asset_groups_name_unique")
    })
}

async fn audit(
    tx: &Tx<'_>,
    action: &str,
    actor: &str,
    now: DateTime<Utc>,
    id: &str,
    detail: &serde_json::Value,
) -> Result<(), StoreError> {
    tx.execute(
        "INSERT INTO audit_log (at, actor, action, target, result, detail, actor_kind, actor_id,
             actor_display, target_kind, target_id)
         VALUES ($1, $2, $3, $4::jsonb->>'name', 'success', $4, 'user', $2, $2, 'host_group', $5)",
        &[&now, &actor, &action, detail, &id],
    )
    .await?;
    Ok(())
}

/// Whether exactly the roles `expected` reach group `id` now (read under
/// the access lock, so no role can start or stop reaching it before commit).
async fn same_roles(tx: &Tx<'_>, id: &str, expected: &[String]) -> Result<bool, StoreError> {
    let mut now: Vec<String> = tx
        .query(
            "SELECT role_id FROM console_role_groups WHERE asset_group_id::text = $1",
            &[&id],
        )
        .await?
        .iter()
        .map(|row| row.get(0))
        .collect();
    let mut expected = expected.to_vec();
    now.sort();
    expected.sort();
    expected.dedup();
    Ok(now == expected)
}

/// Validates, locks, checks the version and picked hosts, inserts or
/// updates the group row, then replaces the content and audits.
async fn write(
    client: &mut Client,
    existing: Option<(&str, i32)>,
    expected_roles: Option<&[String]>,
    input: &GroupInput<'_>,
    actor: &str,
    now: DateTime<Utc>,
) -> Result<GroupWrite, StoreError> {
    if let Some(part) = invalid_part(input) {
        return Ok(GroupWrite::Invalid(part));
    }
    let (kind, picked) = match input.content {
        GroupContent::Rule(_) => (GroupKind::Rule, Vec::new()),
        GroupContent::Manual(picked) => (GroupKind::Manual, distinct(picked)),
    };
    let tx = client.transaction().await?;
    lock(&tx).await?;
    if let Some((id, version)) = existing {
        let current = tx
            .query_opt(
                "SELECT version FROM console_asset_groups WHERE asset_group_id::text = $1 FOR UPDATE",
                &[&id],
            )
            .await?;
        match current.map(|row| row.get::<_, i32>(0)) {
            None => return Ok(GroupWrite::NotFound),
            Some(current) if current != version => return Ok(GroupWrite::Stale),
            Some(_) => {}
        }
        if let Some(expected) = expected_roles
            && !same_roles(&tx, id, expected).await?
        {
            return Ok(GroupWrite::Stale);
        }
    }
    if let Some(unknown) = unknown_host(&tx, &picked).await? {
        return Ok(GroupWrite::UnknownHost(unknown));
    }
    if let Some((id, _)) = existing {
        // an automatic group edited becomes the person's rule group; its key is
        // dismissed so the next inventory does not make the group again
        tx.execute(
            "INSERT INTO console_host_group_dismissed (auto_key, dismissed_at, dismissed_by)
             SELECT auto_key, $2, $3 FROM console_asset_groups
             WHERE asset_group_id::text = $1 AND auto_key IS NOT NULL ON CONFLICT DO NOTHING",
            &[&id, &now, &actor],
        )
        .await?;
    }
    let head = match existing {
        Some((id, _)) => {
            tx.query_one(
                "UPDATE console_asset_groups SET name = $2, description = $3, kind = $4, auto_key = NULL,
                     version = version + 1, changed_at = $5, changed_by = $6
                 WHERE asset_group_id::text = $1 RETURNING asset_group_id::text",
                &[&id, &input.name, &input.description, &kind.as_str(), &now, &actor],
            )
            .await
        }
        None => {
            tx.query_one(
                "INSERT INTO console_asset_groups (asset_group_id, name, description, kind, created_at,
                     created_by, changed_at, changed_by)
                 VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $4, $5) RETURNING asset_group_id::text",
                &[&input.name, &input.description, &kind.as_str(), &now, &actor],
            )
            .await
        }
    };
    let id: String = match head {
        Ok(row) => row.get(0),
        Err(error) if name_taken(&error) => return Ok(GroupWrite::NameTaken),
        Err(error) => return Err(error.into()),
    };
    tx.execute(
        "DELETE FROM console_host_group_conditions WHERE asset_group_id::text = $1",
        &[&id],
    )
    .await?;
    tx.execute(
        "DELETE FROM console_host_group_members WHERE asset_group_id::text = $1 AND agent_id <> ALL($2)",
        &[&id, &picked],
    )
    .await?;
    tx.execute(
        "INSERT INTO console_host_group_members (asset_group_id, agent_id, added_at, added_by)
         SELECT $1::text::uuid, unnest($2::text[]), $3, $4 ON CONFLICT DO NOTHING",
        &[&id, &picked, &now, &actor],
    )
    .await?;
    let mut detail = serde_json::json!({ "name": input.name, "kind": kind.as_str() });
    if let GroupContent::Rule(conditions) = input.content {
        for (position, c) in (0_i16..).zip(conditions) {
            tx.execute(
                "INSERT INTO console_host_group_conditions (asset_group_id, position, field, negate, vals)
                 VALUES ($1::text::uuid, $2, $3, $4, $5)",
                &[&id, &position, &c.field, &c.negate, &c.values],
            )
            .await?;
        }
        detail["conditions"] = serde_json::json!(conditions);
    } else {
        detail["picked"] = serde_json::json!(picked);
    }
    let action = if existing.is_some() {
        "host_group.updated"
    } else {
        "host_group.created"
    };
    audit(&tx, action, actor, now, &id, &detail).await?;
    let saved = summaries(&tx, Some(&id), &AgentScope::Global)
        .await?
        .pop()
        .ok_or(StoreError::Query)?;
    tx.commit().await?;
    Ok(GroupWrite::Saved(saved))
}

/// Creates a rule or manual group.
pub async fn create(
    client: &mut Client,
    input: &GroupInput<'_>,
    actor: &str,
    now: DateTime<Utc>,
) -> Result<GroupWrite, StoreError> {
    write(client, None, None, input, actor, now).await
}

/// Replaces a group's name, description and content when `version` is
/// current; an automatic group becomes a rule (or manual) group. With
/// `expected_roles` (the role ids the caller checked a membership change
/// against), the write is `Stale` unless exactly those roles reach the
/// group inside the transaction.
pub async fn update(
    client: &mut Client,
    id: &str,
    version: i32,
    expected_roles: Option<&[String]>,
    input: &GroupInput<'_>,
    actor: &str,
    now: DateTime<Utc>,
) -> Result<GroupWrite, StoreError> {
    write(
        client,
        Some((id, version)),
        expected_roles,
        input,
        actor,
        now,
    )
    .await
}

/// Deletes a group no role reaches, with its rule-set switches; a deleted
/// automatic group's key is remembered so ingest does not make it again.
pub async fn delete(
    client: &mut Client,
    id: &str,
    version: i32,
    actor: &str,
    now: DateTime<Utc>,
) -> Result<GroupWrite, StoreError> {
    let tx = client.transaction().await?;
    lock(&tx).await?;
    let current = tx
        .query_opt(
            "SELECT version FROM console_asset_groups WHERE asset_group_id::text = $1 FOR UPDATE",
            &[&id],
        )
        .await?;
    match current.map(|row| row.get::<_, i32>(0)) {
        None => return Ok(GroupWrite::NotFound),
        Some(current) if current != version => return Ok(GroupWrite::Stale),
        Some(_) => {}
    }
    let roles: Vec<String> = tx
        .query(
            "SELECT r.display_name FROM console_role_groups rg JOIN console_roles r USING (role_id)
             WHERE rg.asset_group_id::text = $1 ORDER BY r.display_name, r.role_id",
            &[&id],
        )
        .await?
        .iter()
        .map(|row| row.get(0))
        .collect();
    if !roles.is_empty() {
        return Ok(GroupWrite::InUse(roles));
    }
    let group = summaries(&tx, Some(id), &AgentScope::Global)
        .await?
        .pop()
        .ok_or(StoreError::Query)?;
    let overrides = overrides(&tx, id).await?;
    tx.execute(
        "INSERT INTO console_host_group_dismissed (auto_key, dismissed_at, dismissed_by)
         SELECT auto_key, $2, $3 FROM console_asset_groups
         WHERE asset_group_id::text = $1 AND auto_key IS NOT NULL ON CONFLICT DO NOTHING",
        &[&id, &now, &actor],
    )
    .await?;
    tx.execute(
        "DELETE FROM console_asset_groups WHERE asset_group_id::text = $1",
        &[&id],
    )
    .await?;
    let detail = serde_json::json!({
        "name": group.name, "kind": group.kind.as_str(), "overrides_removed": overrides,
    });
    audit(&tx, "host_group.deleted", actor, now, id, &detail).await?;
    tx.commit().await?;
    Ok(GroupWrite::Saved(group))
}

pub(crate) async fn overrides(
    client: &impl deadpool_postgres::GenericClient,
    id: &str,
) -> Result<i64, StoreError> {
    Ok(client
        .query_one(
            "SELECT count(*) FROM rule_set_group_assignment WHERE asset_group_id::text = $1",
            &[&id],
        )
        .await?
        .get(0))
}
