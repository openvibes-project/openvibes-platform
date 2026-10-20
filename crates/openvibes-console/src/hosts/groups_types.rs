//! Request and response shapes of the host-group and label API (spec §5,
//! §13).

use platform_store::host_group_writes::{HostRef, PersonRef, Preview};
use platform_store::host_groups::{Condition, GroupHost, GroupKind, GroupSummary};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::group_words::membership_sentence;

/// How a group gets its hosts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum HostGroupKind {
    /// Made by OpenVIBES from one agent fact.
    Automatic,
    /// A person's rule over agent facts.
    Rule,
    /// Hosts picked by hand.
    Manual,
}

impl From<GroupKind> for HostGroupKind {
    fn from(kind: GroupKind) -> Self {
        match kind {
            GroupKind::Automatic => Self::Automatic,
            GroupKind::Rule => Self::Rule,
            GroupKind::Manual => Self::Manual,
        }
    }
}

/// One rule condition: `field` holds when any value matches (none, when
/// negated).
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct GroupCondition {
    /// `os_family`, `distribution`, `hostname` or `ip`.
    pub field: String,
    /// "is not", "does not match", "is not in".
    #[serde(default)]
    pub negate: bool,
    /// 1–64 values of 1–255 characters: `linux`/`windows`; `debian 12`; a
    /// hostname pattern (`*` matches any run); an address or CIDR range.
    pub values: Vec<String>,
}

impl From<GroupCondition> for Condition {
    fn from(c: GroupCondition) -> Self {
        Self {
            field: c.field,
            negate: c.negate,
            values: c.values,
        }
    }
}

impl From<Condition> for GroupCondition {
    fn from(c: Condition) -> Self {
        Self {
            field: c.field,
            negate: c.negate,
            values: c.values,
        }
    }
}

/// A role reaching a group.
#[derive(Serialize, ToSchema)]
pub struct GroupRoleRef {
    pub role_id: String,
    pub name: String,
}

/// A host group with its hosts counted inside the caller's `hosts.read`
/// reach.
#[derive(Serialize, ToSchema)]
pub struct HostGroupView {
    pub asset_group_id: String,
    pub name: String,
    pub kind: HostGroupKind,
    pub description: String,
    /// The rule, in order (empty for manual groups).
    pub conditions: Vec<GroupCondition>,
    /// The membership in one sentence, e.g. "Hosts where OS family is
    /// Windows", or "3 hosts picked by hand".
    pub membership: String,
    /// Active hosts picked by hand inside reach (manual groups).
    pub picked: i64,
    /// Member hosts inside reach.
    pub hosts: i64,
    /// Of those, seen within the online window.
    pub online: i64,
    /// Open agent alarms on those hosts.
    pub open_alarms: i64,
    /// Critical vulnerabilities on those hosts.
    pub critical: i64,
    /// Roles reaching the group, by name.
    pub roles: Vec<GroupRoleRef>,
    /// Enabled people holding one of those roles.
    pub people: i64,
    /// Made from tags by the upgrade (schema 53).
    pub upgraded_from_tags: bool,
    /// RFC 3339; when it was last changed.
    pub changed_at: Option<String>,
    pub changed_by: Option<String>,
    /// Send it back with an edit or delete.
    pub version: i32,
}

impl From<GroupSummary> for HostGroupView {
    fn from(g: GroupSummary) -> Self {
        Self {
            membership: membership_sentence(g.kind, &g.conditions, g.picked),
            asset_group_id: g.asset_group_id,
            name: g.name,
            kind: g.kind.into(),
            description: g.description,
            conditions: g.conditions.into_iter().map(Into::into).collect(),
            picked: g.picked,
            hosts: g.hosts,
            online: g.online,
            open_alarms: g.open_alarms,
            critical: g.critical,
            roles: g
                .roles
                .into_iter()
                .map(|(role_id, name)| GroupRoleRef { role_id, name })
                .collect(),
            people: g.people,
            upgraded_from_tags: g.upgraded_from_tags,
            changed_at: g.changed_at.map(|at| at.to_rfc3339()),
            changed_by: g.changed_by,
            version: g.version,
        }
    }
}

/// One audited change to a group, newest first.
#[derive(Serialize, ToSchema)]
pub struct GroupChangeView {
    pub action: String,
    pub actor: String,
    /// RFC 3339.
    pub at: String,
    /// The audited detail (name, kind, conditions; for a caller who does
    /// not reach every host, without host lists or counts).
    #[schema(value_type = Object)]
    pub detail: serde_json::Value,
}

/// A group's page: the group and its recent changes.
#[derive(Serialize, ToSchema)]
pub struct HostGroupDetail {
    #[serde(flatten)]
    pub group: HostGroupView,
    /// The newest 10 changes.
    pub recent: Vec<GroupChangeView>,
}

/// A member host on the group page.
#[derive(Serialize, ToSchema)]
pub struct GroupHostView {
    pub agent_id: String,
    pub hostname: Option<String>,
    /// Display name, e.g. `Debian 12`.
    pub distribution: Option<String>,
    /// Source address of its last connection.
    pub last_address: Option<String>,
    pub labels: Vec<String>,
    /// RFC 3339.
    pub last_seen_at: Option<String>,
    pub online: bool,
    pub open_alarms: i64,
    pub critical: i64,
    /// "Matches the rule" or "Picked by hand".
    pub why: String,
}

impl From<GroupHost> for GroupHostView {
    fn from(h: GroupHost) -> Self {
        Self {
            agent_id: h.agent_id,
            hostname: h.hostname,
            distribution: h.distribution,
            last_address: h.last_address,
            labels: h.labels,
            last_seen_at: h.last_seen_at.map(|at| at.to_rfc3339()),
            online: h.online,
            open_alarms: h.open_alarms,
            critical: h.critical,
            why: h.why,
        }
    }
}

/// A new group: a rule (`conditions`) or hosts picked by hand
/// (`agent_ids`).
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateHostGroup {
    /// 1–128 characters, unique regardless of case.
    pub name: String,
    /// At most 500 characters.
    #[serde(default)]
    pub description: String,
    /// `rule` or `manual`.
    pub kind: HostGroupKind,
    /// The rule: 1–16 conditions, all of which must hold.
    pub conditions: Option<Vec<GroupCondition>>,
    /// The hosts, for a manual group.
    pub agent_ids: Option<Vec<String>>,
}

/// New details; a field left out is unchanged. Sending `conditions` makes
/// the group a rule group, `agent_ids` a manual one.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateHostGroup {
    pub name: Option<String>,
    pub description: Option<String>,
    pub conditions: Option<Vec<GroupCondition>>,
    pub agent_ids: Option<Vec<String>>,
    /// The version you read.
    pub version: i32,
}

/// What to preview: a rule, a pick of hosts, or (`{}`, on an existing
/// group) deleting it.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PreviewHostGroup {
    pub conditions: Option<Vec<GroupCondition>>,
    pub agent_ids: Option<Vec<String>>,
}

/// A host in a preview.
#[derive(Serialize, ToSchema)]
pub struct PreviewHost {
    pub agent_id: String,
    pub hostname: Option<String>,
}

/// A person in a preview.
#[derive(Serialize, ToSchema)]
pub struct PreviewPerson {
    pub user_id: String,
    pub username: String,
    pub display_name: String,
}

/// What saving (or deleting) would change. Lists hold at most 50 entries;
/// the totals count them all.
#[derive(Serialize, ToSchema)]
pub struct HostGroupPreview {
    pub joins: Vec<PreviewHost>,
    pub leaves: Vec<PreviewHost>,
    /// People who would gain the joining hosts.
    pub gains: Vec<PreviewPerson>,
    /// People who would lose the leaving hosts.
    pub loses: Vec<PreviewPerson>,
    pub joins_total: i64,
    pub leaves_total: i64,
    pub people_total: i64,
    /// Rule-set switches a delete removes.
    pub overrides_removed: i64,
    /// Waiting and active alarm suppressions a delete ends.
    pub suppressions_ended: i64,
}

fn host(h: HostRef) -> PreviewHost {
    PreviewHost {
        agent_id: h.agent_id,
        hostname: h.hostname,
    }
}

fn person(p: PersonRef) -> PreviewPerson {
    PreviewPerson {
        user_id: p.user_id,
        username: p.username,
        display_name: p.display_name,
    }
}

impl From<Preview> for HostGroupPreview {
    fn from(p: Preview) -> Self {
        Self {
            joins: p.joins.into_iter().map(host).collect(),
            leaves: p.leaves.into_iter().map(host).collect(),
            gains: p.gains.into_iter().map(person).collect(),
            loses: p.loses.into_iter().map(person).collect(),
            joins_total: p.joins_total,
            leaves_total: p.leaves_total,
            people_total: p.people_total,
            overrides_removed: p.overrides_removed,
            suppressions_ended: p.suppressions_ended,
        }
    }
}

/// A group a host is in.
#[derive(Serialize, ToSchema)]
pub struct HostGroupRef {
    pub asset_group_id: String,
    pub name: String,
    pub kind: HostGroupKind,
}

/// A host's labels and the groups it is in.
#[derive(Serialize, ToSchema)]
pub struct HostLabelsView {
    /// In byte order.
    pub labels: Vec<String>,
    /// By name.
    pub groups: Vec<HostGroupRef>,
}
