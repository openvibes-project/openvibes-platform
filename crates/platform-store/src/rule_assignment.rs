//! Rule-set assignment (spec 2026-10-14-rule-set-assignment-design.md): which
//! of the project's assignable sets run on which hosts. A default per set and
//! on/off overrides per asset group; console writes are audited
//! (`rules.assignment.change`) with the old and new value.

use crate::{Client, StoreError};

/// One asset group's override for a set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupOverride {
    /// The group.
    pub asset_group_id: String,
    /// Its name.
    pub name: String,
    /// On or off for the group's hosts.
    pub enabled: bool,
}

/// An assignable set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Assignment {
    /// Rule set id.
    pub rule_set_id: String,
    /// On or off for hosts no override covers.
    pub default_enabled: bool,
    /// A live (not retired) bundle is published, so agents can get it.
    pub published: bool,
    /// Overrides, by group name.
    pub groups: Vec<GroupOverride>,
}

/// An asset group an override can name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupName {
    /// The group.
    pub asset_group_id: String,
    /// Its name.
    pub name: String,
}

/// Every assignable set, and every asset group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Overview {
    /// The sets, by id.
    pub sets: Vec<Assignment>,
    /// The groups, by name.
    pub groups: Vec<GroupName>,
}

/// Outcome of a change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Change {
    /// Applied (or already so); the set as it now is.
    Done(Assignment),
    /// Not an assignable set.
    UnknownSet,
    /// No such asset group.
    UnknownGroup,
}

/// Every assignable set with its overrides, and every asset group.
pub async fn overview(client: &Client) -> Result<Overview, StoreError> {
    let sets = client
        .query(
            "SELECT a.rule_set_id, a.default_enabled,
                    EXISTS (SELECT 1 FROM rule_bundles b JOIN rule_sets s USING (rule_set_id)
                            WHERE b.rule_set_id = a.rule_set_id AND s.retired_at IS NULL)
             FROM rule_set_assignment a ORDER BY a.rule_set_id",
            &[],
        )
        .await?;
    let overrides = client
        .query(
            "SELECT o.rule_set_id, o.asset_group_id::text, g.name, o.enabled
             FROM rule_set_group_assignment o JOIN console_asset_groups g USING (asset_group_id)
             ORDER BY g.name",
            &[],
        )
        .await?;
    let groups = client
        .query(
            "SELECT asset_group_id::text, name FROM console_asset_groups ORDER BY name",
            &[],
        )
        .await?;
    Ok(Overview {
        sets: sets
            .iter()
            .map(|row| {
                let rule_set_id: String = row.get(0);
                Assignment {
                    groups: overrides
                        .iter()
                        .filter(|o| o.get::<_, &str>(0) == rule_set_id)
                        .map(|o| GroupOverride {
                            asset_group_id: o.get(1),
                            name: o.get(2),
                            enabled: o.get(3),
                        })
                        .collect(),
                    rule_set_id,
                    default_enabled: row.get(1),
                    published: row.get(2),
                }
            })
            .collect(),
        groups: groups
            .iter()
            .map(|row| GroupName {
                asset_group_id: row.get(0),
                name: row.get(1),
            })
            .collect(),
    })
}

async fn current(client: &Client, set: &str) -> Result<Change, StoreError> {
    Ok(overview(client)
        .await?
        .sets
        .into_iter()
        .find(|a| a.rule_set_id == set)
        .map_or(Change::UnknownSet, Change::Done))
}

/// One `rules.assignment.change` row: `group` is (id, name), `None` for the
/// default; `None` as old or new means "no override".
async fn audit(
    transaction: &tokio_postgres::Transaction<'_>,
    actor: &str,
    set: &str,
    group: Option<(&str, &str)>,
    old: Option<bool>,
    new: Option<bool>,
) -> Result<(), StoreError> {
    transaction
        .execute(
            "INSERT INTO audit_log (actor, action, target, result, detail, actor_kind, actor_id,
                 actor_display, target_kind, target_id)
             VALUES ($1, 'rules.assignment.change', 'rule_set', 'success',
                 jsonb_build_object('rule_set_id', $2::text, 'asset_group_id', $3::text,
                     'asset_group_name', $4::text, 'old', $5::boolean, 'new', $6::boolean),
                 'user', $1, $1, 'rule_set', $2)",
            &[
                &actor,
                &set,
                &group.map(|g| g.0),
                &group.map(|g| g.1),
                &old,
                &new,
            ],
        )
        .await?;
    Ok(())
}

/// Switches a set's default. Setting the value it has is a no-op (no audit).
pub async fn set_default(
    client: &mut Client,
    actor: &str,
    set: &str,
    enabled: bool,
) -> Result<Change, StoreError> {
    let transaction = client.transaction().await?;
    let Some(row) = transaction
        .query_opt(
            "SELECT default_enabled FROM rule_set_assignment WHERE rule_set_id = $1 FOR UPDATE",
            &[&set],
        )
        .await?
    else {
        return Ok(Change::UnknownSet);
    };
    let old: bool = row.get(0);
    if old != enabled {
        transaction
            .execute(
                "UPDATE rule_set_assignment SET default_enabled = $2 WHERE rule_set_id = $1",
                &[&set, &enabled],
            )
            .await?;
        audit(&transaction, actor, set, None, Some(old), Some(enabled)).await?;
    }
    transaction.commit().await?;
    current(client, set).await
}

/// Sets (`Some`) or removes (`None`) a group's override. `group` is compared
/// as text, so a malformed id is simply unknown.
pub async fn set_group(
    client: &mut Client,
    actor: &str,
    set: &str,
    group: &str,
    enabled: Option<bool>,
) -> Result<Change, StoreError> {
    let transaction = client.transaction().await?;
    if transaction
        .query_opt(
            "SELECT 1 FROM rule_set_assignment WHERE rule_set_id = $1 FOR UPDATE",
            &[&set],
        )
        .await?
        .is_none()
    {
        return Ok(Change::UnknownSet);
    }
    let Some(row) = transaction
        .query_opt(
            "SELECT asset_group_id::text, name FROM console_asset_groups
             WHERE asset_group_id::text = $1",
            &[&group],
        )
        .await?
    else {
        return Ok(Change::UnknownGroup);
    };
    let (group_id, name): (String, String) = (row.get(0), row.get(1));
    let old: Option<bool> = transaction
        .query_opt(
            "SELECT enabled FROM rule_set_group_assignment
             WHERE rule_set_id = $1 AND asset_group_id::text = $2",
            &[&set, &group_id],
        )
        .await?
        .map(|row| row.get(0));
    if old != enabled {
        match enabled {
            Some(on) => {
                transaction
                    .execute(
                        "INSERT INTO rule_set_group_assignment (rule_set_id, asset_group_id, enabled)
                         VALUES ($1, $2::text::uuid, $3)
                         ON CONFLICT (rule_set_id, asset_group_id) DO UPDATE SET enabled = EXCLUDED.enabled",
                        &[&set, &group_id, &on],
                    )
                    .await?
            }
            None => {
                transaction
                    .execute(
                        "DELETE FROM rule_set_group_assignment
                         WHERE rule_set_id = $1 AND asset_group_id::text = $2",
                        &[&set, &group_id],
                    )
                    .await?
            }
        };
        audit(
            &transaction,
            actor,
            set,
            Some((&group_id, &name)),
            old,
            enabled,
        )
        .await?;
    }
    transaction.commit().await?;
    current(client, set).await
}
