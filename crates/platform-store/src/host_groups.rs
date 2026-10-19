//! Host groups as the console reads them (spec §5, §6): the list, one
//! group, its hosts and its recent changes. Host counts, problems and host
//! lists count only agents inside the caller's scope. Writes and the
//! preview are in `host_group_writes`.

use chrono::{DateTime, Duration, Utc};
use deadpool_postgres::GenericClient;
use tokio_postgres::Row;

use crate::{
    Client, StoreError,
    console_read::{AgentScope, MAX_PAGE_SIZE, agent_visibility},
    status::OFFLINE_AFTER_MINUTES,
};

/// How a group gets its hosts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GroupKind {
    /// Made by OpenVIBES from one agent fact.
    Automatic,
    /// A person's rule over agent facts.
    Rule,
    /// Hosts picked by hand.
    Manual,
}

impl GroupKind {
    /// The stored `kind` value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Automatic => "automatic",
            Self::Rule => "rule",
            Self::Manual => "manual",
        }
    }

    fn parse(kind: &str) -> Self {
        match kind {
            "automatic" => Self::Automatic,
            "rule" => Self::Rule,
            _ => Self::Manual,
        }
    }
}

/// One rule condition: `field` holds when any value matches (none, negated).
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Condition {
    /// `os_family`, `distribution`, `hostname` or `ip`.
    pub field: String,
    /// "is not" / "does not match" / "is not in".
    pub negate: bool,
    /// 1–64 values.
    pub values: Vec<String>,
}

/// A group with its membership counted inside the caller's scope.
#[derive(Clone, Debug)]
pub struct GroupSummary {
    /// Asset group id.
    pub asset_group_id: String,
    /// Name.
    pub name: String,
    /// Kind.
    pub kind: GroupKind,
    /// Description.
    pub description: String,
    /// The rule, in order (empty for manual groups).
    pub conditions: Vec<Condition>,
    /// Hosts picked by hand, revoked ones included (manual groups).
    pub picked: i64,
    /// Member hosts in scope.
    pub hosts: i64,
    /// Of those, seen within the online window.
    pub online: i64,
    /// Open agent alarms on those hosts.
    pub open_alarms: i64,
    /// Critical vulnerabilities on those hosts.
    pub critical: i64,
    /// Roles reaching the group: (role id, display name), by name.
    pub roles: Vec<(String, String)>,
    /// Distinct enabled people holding one of those roles.
    pub people: i64,
    /// Upgraded from tags.
    pub upgraded_from_tags: bool,
    /// When a person (or the upgrade) last changed it.
    pub changed_at: Option<DateTime<Utc>>,
    /// Who did.
    pub changed_by: Option<String>,
    /// Bumped by every write; updates and deletes must name it.
    pub version: i32,
}

/// A member host as the group page lists it.
#[derive(Clone, Debug)]
pub struct GroupHost {
    /// Agent id.
    pub agent_id: String,
    /// Hostname.
    pub hostname: Option<String>,
    /// Display name, e.g. `Debian 12`.
    pub distribution: Option<String>,
    /// Source address of its last connection.
    pub last_address: Option<String>,
    /// Labels.
    pub labels: Vec<String>,
    /// Last seen at.
    pub last_seen_at: Option<DateTime<Utc>>,
    /// Seen within the online window.
    pub online: bool,
    /// Open agent alarms on the host.
    pub open_alarms: i64,
    /// Critical vulnerabilities on the host.
    pub critical: i64,
    /// "Matches the rule" or "Picked by hand".
    pub why: String,
}

/// One audit row about a group, newest first.
#[derive(Clone, Debug)]
pub struct AuditLine {
    /// At.
    pub at: DateTime<Utc>,
    /// Actor.
    pub actor: String,
    /// Action.
    pub action: String,
    /// Detail.
    pub detail: serde_json::Value,
}

/// Per-host open agent alarms and critical vulnerabilities, for an `agents a` row.
const PROBLEMS: &str = "(SELECT count(*) FROM alarms al
                         WHERE al.agent_id = a.agent_id AND al.state = 'open' AND al.source = 'agent')::bigint,
                        COALESCE((SELECT v.critical FROM host_vulnerability_counts v
                                  WHERE v.agent_id = a.agent_id), 0)::bigint";

/// Summaries; `$1` global, `$2` scope groups, `$3` online threshold, `$4`
/// one group id or NULL for all.
fn summary_sql() -> String {
    let visible = agent_visibility("a.agent_id", "$1", "$2");
    format!(
        "SELECT g.asset_group_id::text, g.name, g.kind, g.description,
                COALESCE((SELECT jsonb_agg(jsonb_build_object('field', c.field, 'negate', c.negate, 'values', c.vals)
                                           ORDER BY c.position)
                          FROM console_host_group_conditions c WHERE c.asset_group_id = g.asset_group_id), '[]'),
                (SELECT count(*) FROM console_host_group_members m WHERE m.asset_group_id = g.asset_group_id),
                h.hosts, h.online, h.open_alarms, h.critical,
                ARRAY(SELECT r.role_id FROM console_role_groups rg JOIN console_roles r USING (role_id)
                      WHERE rg.asset_group_id = g.asset_group_id ORDER BY r.display_name, r.role_id),
                ARRAY(SELECT r.display_name FROM console_role_groups rg JOIN console_roles r USING (role_id)
                      WHERE rg.asset_group_id = g.asset_group_id ORDER BY r.display_name, r.role_id),
                (SELECT count(DISTINCT u.user_id) FROM console_role_groups rg
                   JOIN console_role_bindings b USING (role_id) JOIN console_users u USING (user_id)
                 WHERE rg.asset_group_id = g.asset_group_id AND b.revoked_at IS NULL AND u.enabled),
                g.upgraded_from_tags, g.changed_at, g.changed_by, g.version
         FROM console_asset_groups g
         CROSS JOIN LATERAL (
           SELECT count(*) AS hosts,
                  count(*) FILTER (WHERE agent_seen_at(a.agent_id, a.last_seen_at) >= $3) AS online,
                  COALESCE(sum(p.alarms), 0)::bigint AS open_alarms,
                  COALESCE(sum(p.critical), 0)::bigint AS critical
           FROM agents a CROSS JOIN LATERAL (SELECT {PROBLEMS}) p(alarms, critical)
           WHERE a.status = 'active' AND console_host_in_group(a.agent_id, g.asset_group_id)
             AND {visible}) h
         WHERE $4::text IS NULL OR g.asset_group_id::text = $4
         ORDER BY lower(g.name)"
    )
}

fn summary(row: &Row) -> GroupSummary {
    let conditions: serde_json::Value = row.get(4);
    let ids: Vec<String> = row.get(10);
    let names: Vec<String> = row.get(11);
    GroupSummary {
        asset_group_id: row.get(0),
        name: row.get(1),
        kind: GroupKind::parse(row.get(2)),
        description: row.get(3),
        conditions: serde_json::from_value(conditions).unwrap_or_default(),
        picked: row.get(5),
        hosts: row.get(6),
        online: row.get(7),
        open_alarms: row.get(8),
        critical: row.get(9),
        roles: ids.into_iter().zip(names).collect(),
        people: row.get(12),
        upgraded_from_tags: row.get(13),
        changed_at: row.get(14),
        changed_by: row.get(15),
        version: row.get(16),
    }
}

fn online_since() -> DateTime<Utc> {
    Utc::now() - Duration::minutes(OFFLINE_AFTER_MINUTES)
}

pub(crate) async fn summaries(
    client: &impl GenericClient,
    id: Option<&str>,
    scope: &AgentScope,
) -> Result<Vec<GroupSummary>, StoreError> {
    let rows = client
        .query(
            &summary_sql(),
            &[&scope.is_global(), &scope.group_ids(), &online_since(), &id],
        )
        .await?;
    Ok(rows.iter().map(summary).collect())
}

/// Every group, by name, counted inside `scope`.
pub async fn list(client: &Client, scope: &AgentScope) -> Result<Vec<GroupSummary>, StoreError> {
    summaries(client, None, scope).await
}

/// One group counted inside `scope`; `None` when it does not exist.
pub async fn detail(
    client: &Client,
    id: &str,
    scope: &AgentScope,
) -> Result<Option<GroupSummary>, StoreError> {
    Ok(summaries(client, Some(id), scope).await?.into_iter().next())
}

/// A page of the group's member hosts inside `scope`, by hostname, after
/// the host `after` (an agent id from the previous page). `limit` is held to
/// 1–100.
pub async fn hosts(
    client: &Client,
    id: &str,
    scope: &AgentScope,
    after: Option<&str>,
    limit: i64,
) -> Result<Vec<GroupHost>, StoreError> {
    let visible = agent_visibility("a.agent_id", "$1", "$2");
    let sql = format!(
        "SELECT a.agent_id, a.hostname, console_distribution_name(a.distribution), host(a.last_address),
                ARRAY(SELECT l.label FROM console_host_labels l WHERE l.agent_id = a.agent_id
                      ORDER BY l.label COLLATE \"C\"),
                agent_seen_at(a.agent_id, a.last_seen_at),
                COALESCE(agent_seen_at(a.agent_id, a.last_seen_at) >= $4, false),
                {PROBLEMS}, g.kind
         FROM console_asset_groups g JOIN agents a
           ON a.status = 'active' AND console_host_in_group(a.agent_id, g.asset_group_id)
         WHERE g.asset_group_id::text = $3 AND {visible}
           AND ($5::text IS NULL OR (COALESCE(lower(a.hostname), ''), a.agent_id) >
                (SELECT COALESCE(lower(hostname), ''), agent_id FROM agents WHERE agent_id = $5))
         ORDER BY COALESCE(lower(a.hostname), ''), a.agent_id
         LIMIT $6"
    );
    let limit = limit.clamp(1, i64::from(MAX_PAGE_SIZE));
    let rows = client
        .query(
            &sql,
            &[
                &scope.is_global(),
                &scope.group_ids(),
                &id,
                &online_since(),
                &after,
                &limit,
            ],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|row| GroupHost {
            agent_id: row.get(0),
            hostname: row.get(1),
            distribution: row.get(2),
            last_address: row.get(3),
            labels: row.get(4),
            last_seen_at: row.get(5),
            online: row.get(6),
            open_alarms: row.get(7),
            critical: row.get(8),
            why: if row.get::<_, &str>(9) == "manual" {
                "Picked by hand"
            } else {
                "Matches the rule"
            }
            .into(),
        })
        .collect())
}

/// The newest `limit` (1–100) audit rows about the group.
pub async fn recent_changes(
    client: &Client,
    id: &str,
    limit: i64,
) -> Result<Vec<AuditLine>, StoreError> {
    let rows = client
        .query(
            "SELECT at, COALESCE(actor_display, actor), action, detail FROM audit_log
             WHERE target_kind = 'host_group' AND target_id = $1
             ORDER BY at DESC, id DESC LIMIT $2",
            &[&id, &limit.clamp(1, i64::from(MAX_PAGE_SIZE))],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|row| AuditLine {
            at: row.get(0),
            actor: row.get(1),
            action: row.get(2),
            detail: row.get(3),
        })
        .collect())
}
