//! The Hosts list answer (`GET /v1/hosts`).

use platform_store::host_list::{HostListPage, HostRow};
use serde::Serialize;
use utoipa::ToSchema;

use super::groups_types::HostGroupKind;

/// A host's operating system.
#[derive(Serialize, ToSchema)]
pub(crate) struct HostOsView {
    /// OS id, such as `debian`.
    pub id: Option<String>,
    /// OS version.
    pub version: Option<String>,
    /// Display name, such as `Debian 12`.
    pub distribution: Option<String>,
    /// `linux` or `windows`.
    pub family: Option<String>,
}

/// A group a host belongs to.
#[derive(Serialize, ToSchema)]
pub(crate) struct HostListGroupView {
    /// Group id.
    pub id: String,
    /// Group name.
    pub name: String,
    /// How the group gets its hosts.
    pub kind: HostGroupKind,
}

/// Problem counts; absent where the viewer may not read that kind for the host.
#[derive(Serialize, ToSchema)]
pub(crate) struct HostProblemsView {
    /// Open agent alarms.
    pub open_alarms: Option<i64>,
    /// Critical vulnerabilities.
    pub critical: Option<i64>,
    /// Failing compliance checks.
    pub failing: Option<i64>,
}

/// The host's agent.
#[derive(Serialize, ToSchema)]
pub(crate) struct HostAgentView {
    /// Agent version.
    pub version: Option<String>,
    /// Older than the latest release; absent when unknown.
    pub older: Option<bool>,
}

/// One row of the Hosts list.
#[derive(Serialize, ToSchema)]
pub(crate) struct HostRowView {
    /// Agent id.
    pub id: String,
    /// Host name.
    pub hostname: Option<String>,
    /// Address of the last connection.
    pub address: Option<String>,
    /// Operating system.
    pub os: HostOsView,
    /// `online`, `offline`, `revoked` or `imported`.
    pub status: String,
    /// Last heartbeat, RFC 3339.
    pub last_seen_at: Option<String>,
    /// The first two groups by name.
    pub groups: Vec<HostListGroupView>,
    /// All its groups.
    pub group_count: i64,
    /// Labels.
    pub labels: Vec<String>,
    /// Problem counts.
    pub problems: HostProblemsView,
    /// Agent.
    pub agent: HostAgentView,
}

/// A filter value and how many hosts have it.
#[derive(Serialize, ToSchema)]
pub(crate) struct CountView {
    /// The URL value.
    pub value: String,
    /// Hosts matching with the other filters applied.
    pub count: i64,
}

/// A group filter value.
#[derive(Serialize, ToSchema)]
pub(crate) struct GroupCountView {
    /// Group id.
    pub value: String,
    /// Group name.
    pub name: String,
    /// How the group gets its hosts.
    pub kind: HostGroupKind,
    /// Hosts in the group in the viewer's reach.
    pub count: i64,
}

/// Per-value counts for every filter.
#[derive(Serialize, ToSchema)]
pub(crate) struct HostCountsView {
    /// By status.
    pub status: Vec<CountView>,
    /// By OS family.
    pub os: Vec<CountView>,
    /// By group.
    pub group: Vec<GroupCountView>,
    /// By label.
    pub label: Vec<CountView>,
    /// By problems.
    pub problems: Vec<CountView>,
    /// By agent age.
    pub agent: Vec<CountView>,
}

/// The line above the list.
#[derive(Serialize, ToSchema)]
pub(crate) struct HostSummaryLineView {
    /// Online hosts.
    pub online: i64,
    /// Hosts with an older agent.
    pub older_agent: i64,
    /// Hosts with a critical vulnerability.
    pub critical: i64,
}

/// One page of the Hosts list.
#[derive(Serialize, ToSchema)]
pub(crate) struct HostListView {
    /// The page.
    pub items: Vec<HostRowView>,
    /// Hosts matching every filter.
    pub total: i64,
    /// Per-value counts.
    pub counts: HostCountsView,
    /// Summary over the matching hosts.
    pub summary: HostSummaryLineView,
    /// Latest agent release, when known.
    pub latest_agent_version: Option<String>,
    /// RFC 3339.
    pub generated_at: String,
}

impl From<HostRow> for HostRowView {
    fn from(r: HostRow) -> Self {
        Self {
            id: r.agent_id,
            hostname: r.hostname,
            address: r.address,
            os: HostOsView {
                id: r.os_id,
                version: r.os_version,
                distribution: r.distribution,
                family: r.os_family,
            },
            status: r.status.as_str().into(),
            last_seen_at: r.last_seen_at.map(|t| t.to_rfc3339()),
            groups: r
                .groups
                .into_iter()
                .map(|(id, name, kind)| HostListGroupView {
                    id,
                    name,
                    kind: kind.into(),
                })
                .collect(),
            group_count: r.group_count,
            labels: r.labels,
            problems: HostProblemsView {
                open_alarms: r.open_alarms,
                critical: r.critical,
                failing: r.failing,
            },
            agent: HostAgentView {
                version: r.scanner_version,
                older: r.agent_older,
            },
        }
    }
}

fn counts<T>(rows: Vec<(T, i64)>, name: impl Fn(T) -> String) -> Vec<CountView> {
    rows.into_iter()
        .map(|(v, count)| CountView {
            value: name(v),
            count,
        })
        .collect()
}

impl HostListView {
    pub(crate) fn new(
        page: HostListPage,
        latest: Option<String>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        let c = page.counts;
        Self {
            items: page.rows.into_iter().map(Into::into).collect(),
            total: page.total,
            counts: HostCountsView {
                status: counts(c.status, |v| v.as_str().into()),
                os: counts(c.os_family, |v| v),
                group: c
                    .groups
                    .into_iter()
                    .map(|(value, name, kind, count)| GroupCountView {
                        value,
                        name,
                        kind: kind.into(),
                        count,
                    })
                    .collect(),
                label: counts(c.labels, |v| v),
                problems: counts(c.problems, |v| v.as_str().into()),
                agent: counts(c.agent, |v| v.as_str().into()),
            },
            summary: HostSummaryLineView {
                online: page.summary.online,
                older_agent: page.summary.older_agent,
                critical: page.summary.critical,
            },
            latest_agent_version: latest,
            generated_at: now.to_rfc3339(),
        }
    }
}
