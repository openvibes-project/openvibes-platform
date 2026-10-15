//! Rule-set assignment (spec 2026-10-14-rule-set-assignment-design.md): which
//! of the project's assignable sets run on which hosts. A default per set and
//! on/off overrides per asset group; console writes are audited
//! (`rules.assignment.change`) with the old and new value.

use crate::{Client, StoreError};
use chrono::{DateTime, Utc};

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
    /// Linux hosts that run it now.
    pub hosts_on: i64,
    /// Linux hosts that do not.
    pub hosts_off: i64,
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
    /// Its selectors, `key=value`, sorted.
    pub selectors: Vec<String>,
    /// Linux hosts it matches.
    pub hosts: i64,
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

/// Linux hosts and their group memberships, as a CTE prefix for the
/// console's counts. A Linux host is an active agent (stale included;
/// revoked and imported not) whose inventory reported os-release (`os_id`).
/// A host is a member of a group with selectors whose every tag it carries,
/// as for access.
// ponytail: agents x groups per overview call; precompute if a fleet of many thousand hosts makes the panel slow.
const FLEET: &str = "
    WITH linux AS (SELECT agent_id FROM agents WHERE status = 'active' AND os_id IS NOT NULL),
    member AS (
        SELECT l.agent_id, g.asset_group_id FROM linux l CROSS JOIN console_asset_groups g
        WHERE EXISTS (SELECT 1 FROM console_asset_group_selectors s
                      WHERE s.asset_group_id = g.asset_group_id)
          AND NOT EXISTS (
              SELECT 1 FROM console_asset_group_selectors r
              WHERE r.asset_group_id = g.asset_group_id
                AND NOT EXISTS (SELECT 1 FROM console_agent_tags t
                                WHERE t.agent_id = l.agent_id AND t.tag_key = r.tag_key
                                  AND t.tag_value = r.tag_value)))";

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
    let counts = client
        .query(
            &format!(
                "{FLEET}
                 SELECT a.rule_set_id,
                        count(*) FILTER (WHERE COALESCE(o.on_any, a.default_enabled)),
                        count(*) FILTER (WHERE NOT COALESCE(o.on_any, a.default_enabled))
                 FROM rule_set_assignment a CROSS JOIN linux l
                 LEFT JOIN LATERAL (
                     SELECT bool_or(x.enabled) AS on_any FROM rule_set_group_assignment x
                     JOIN member m ON m.asset_group_id = x.asset_group_id AND m.agent_id = l.agent_id
                     WHERE x.rule_set_id = a.rule_set_id) o ON true
                 GROUP BY a.rule_set_id"
            ),
            &[],
        )
        .await?;
    let group_hosts = client
        .query(
            &format!("{FLEET} SELECT asset_group_id::text, count(*) FROM member GROUP BY 1"),
            &[],
        )
        .await?;
    let selectors = client
        .query(
            "SELECT asset_group_id::text, tag_key || '=' || tag_value
             FROM console_asset_group_selectors ORDER BY 2",
            &[],
        )
        .await?;
    Ok(Overview {
        sets: sets
            .iter()
            .map(|row| {
                let rule_set_id: String = row.get(0);
                let (hosts_on, hosts_off) = counts
                    .iter()
                    .find(|c| c.get::<_, &str>(0) == rule_set_id)
                    .map_or((0, 0), |c| (c.get(1), c.get(2)));
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
                    hosts_on,
                    hosts_off,
                }
            })
            .collect(),
        groups: groups
            .iter()
            .map(|row| {
                let asset_group_id: String = row.get(0);
                GroupName {
                    selectors: selectors
                        .iter()
                        .filter(|s| s.get::<_, &str>(0) == asset_group_id)
                        .map(|s| s.get(1))
                        .collect(),
                    hosts: group_hosts
                        .iter()
                        .find(|h| h.get::<_, &str>(0) == asset_group_id)
                        .map_or(0, |h| h.get(1)),
                    asset_group_id,
                    name: row.get(1),
                }
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

/// One `rules.assignment.change` row by console user `user_id` (shown by
/// display name; an id with no console user is an error): `group` is (id, name), `None` for the default; `None` as
/// old or new means "no override".
async fn audit(
    transaction: &tokio_postgres::Transaction<'_>,
    user_id: &str,
    set: &str,
    group: Option<(&str, &str)>,
    old: Option<bool>,
    new: Option<bool>,
) -> Result<(), StoreError> {
    // Fail closed: no console user, no audit row, so the change rolls back.
    let rows = transaction
        .execute(
            "INSERT INTO audit_log (actor, action, target, result, detail, actor_kind, actor_id,
                 actor_display, target_kind, target_id)
             SELECT $1, 'rules.assignment.change', 'rule_set', 'success',
                 jsonb_build_object('rule_set_id', $2::text, 'asset_group_id', $3::text,
                     'asset_group_name', $4::text, 'old', $5::boolean, 'new', $6::boolean),
                 'user', $1, u.display_name, 'rule_set', $2
             FROM console_users u WHERE u.user_id = $1::text::uuid",
            &[
                &user_id,
                &set,
                &group.map(|g| g.0),
                &group.map(|g| g.1),
                &old,
                &new,
            ],
        )
        .await?;
    if rows == 1 {
        Ok(())
    } else {
        Err(StoreError::Query)
    }
}

/// Switches a set's default for console user `user_id`. Setting the value
/// it has is a no-op (no audit).
pub async fn set_default(
    client: &mut Client,
    user_id: &str,
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
        audit(&transaction, user_id, set, None, Some(old), Some(enabled)).await?;
    }
    transaction.commit().await?;
    current(client, set).await
}

/// Sets (`Some`) or removes (`None`) a group's override for console user
/// `user_id`. `group` is compared as text, so a malformed id is simply
/// unknown.
pub async fn set_group(
    client: &mut Client,
    user_id: &str,
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
            user_id,
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

/// Where a host's state for a set comes from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Source {
    /// No group of the host overrides the set.
    Default,
    /// A group of the host decided it.
    Group,
}

/// One assignable set's state on one host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostAssignment {
    /// Rule set id.
    pub rule_set_id: String,
    /// Whether the host runs it.
    pub enabled: bool,
    /// Default or a group.
    pub source: Source,
    /// The group that decided it (the first by name when several agree);
    /// `None` when the default did.
    pub group: Option<String>,
    /// A live bundle is published, so the agent can get it.
    pub published: bool,
}

/// Per assignable set for agent `$1`: (set, enabled, decided by a group, ids of
/// the host's groups saying on, saying off).
/// `bool_or` over the overrides of the host's groups is true when any says
/// on, false when all say off, NULL when none applies (then the default). A
/// group matches when it has selectors and the host carries every one, as
/// for access (`console_read::agent_visibility`).
const HOST_STATE: &str = "
    SELECT a.rule_set_id, COALESCE(bool_or(o.enabled), a.default_enabled),
           bool_or(o.enabled) IS NOT NULL,
           array_agg(o.asset_group_id::text) FILTER (WHERE o.enabled),
           array_agg(o.asset_group_id::text) FILTER (WHERE NOT o.enabled)
    FROM rule_set_assignment a
    LEFT JOIN rule_set_group_assignment o ON o.rule_set_id = a.rule_set_id
     AND EXISTS (SELECT 1 FROM console_asset_group_selectors s
                 WHERE s.asset_group_id = o.asset_group_id)
     AND NOT EXISTS (
         SELECT 1 FROM console_asset_group_selectors r
         WHERE r.asset_group_id = o.asset_group_id
           AND NOT EXISTS (SELECT 1 FROM console_agent_tags t
                           WHERE t.agent_id = $1 AND t.tag_key = r.tag_key
                             AND t.tag_value = r.tag_value))
    GROUP BY a.rule_set_id, a.default_enabled";

/// Whether `agent_id` runs `set`. A set that is not assignable is always
/// assigned, so distribution answers it exactly as before.
pub async fn assigned(client: &Client, agent_id: &str, set: &str) -> Result<bool, StoreError> {
    let row = client
        .query_opt(
            &format!(
                "SELECT enabled FROM ({HOST_STATE}) AS h (rule_set_id, enabled, from_group, on_groups, off_groups)
                 WHERE rule_set_id = $2"
            ),
            &[&agent_id, &set],
        )
        .await?;
    Ok(row.is_none_or(|row| row.get(0)))
}

/// Every assignable set's state on `agent_id`, or `None` when the agent is
/// unknown or outside `scope`.
pub async fn for_agent(
    client: &Client,
    scope: &crate::console_read::AgentScope,
    agent_id: &str,
) -> Result<Option<Vec<HostAssignment>>, StoreError> {
    let visible = crate::console_read::agent_visibility("a.agent_id", "$2", "$3");
    if client
        .query_opt(
            &format!("SELECT 1 FROM agents a WHERE a.agent_id = $1 AND {visible}"),
            &[&agent_id, &scope.is_global(), &scope.group_ids()],
        )
        .await?
        .is_none()
    {
        return Ok(None);
    }
    let rows = client
        .query(
            &format!(
                "SELECT h.rule_set_id, h.enabled, h.from_group,
                        (SELECT min(g.name) FROM console_asset_groups g
                         WHERE g.asset_group_id::text = ANY(
                             CASE WHEN h.enabled THEN h.on_groups ELSE h.off_groups END)),
                        EXISTS (SELECT 1 FROM rule_bundles b JOIN rule_sets s USING (rule_set_id)
                                WHERE b.rule_set_id = h.rule_set_id AND s.retired_at IS NULL)
                 FROM ({HOST_STATE}) AS h (rule_set_id, enabled, from_group, on_groups, off_groups)
                 ORDER BY h.rule_set_id"
            ),
            &[&agent_id],
        )
        .await?;
    Ok(Some(
        rows.iter()
            .map(|row| HostAssignment {
                rule_set_id: row.get(0),
                enabled: row.get(1),
                source: if row.get(2) {
                    Source::Group
                } else {
                    Source::Default
                },
                group: row.get(3),
                published: row.get(4),
            })
            .collect(),
    ))
}

/// The hardening collector's outcome (the root-facts helper, P19) in
/// `agent_id`'s latest stored health report (`ok`; `not_found`: the
/// helper's file is stale or malformed; `invalid_data`: its facts failed
/// validation; `None`: no report, or no helper file at all, which the agent
/// does not report), and when a stored report last had it `ok` (`None`:
/// never since enrollment, or since schema 50). Callers check visibility
/// first (`for_agent`); an unknown agent gives `(None, None)`.
pub async fn hardening_facts(
    client: &Client,
    agent_id: &str,
) -> Result<(Option<String>, Option<DateTime<Utc>>), StoreError> {
    Ok(client
        .query_opt(
            "SELECT health -> 'last_scan' -> 'collectors' ->> 'hardening', hardening_facts_ok_at
             FROM agents WHERE agent_id = $1",
            &[&agent_id],
        )
        .await?
        .map_or((None, None), |row| (row.get(0), row.get(1))))
}
