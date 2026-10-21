//! The host page's summary answer (`GET /v1/hosts/{agent_id}/summary`).

use serde::Serialize;
use utoipa::ToSchema;

use super::LastTest;
use super::list_types::{HostListGroupView, HostOsView};
use crate::{AgentAlarmsView, CertificateView};

/// The header and Details facts.
#[derive(Serialize, ToSchema)]
pub(crate) struct HostFactsView {
    /// Agent id.
    pub id: String,
    /// Host name.
    pub hostname: Option<String>,
    /// `online`, `offline`, `revoked` or `imported`.
    pub status: String,
    /// Address of the last connection.
    pub address: Option<String>,
    /// Operating system.
    pub os: HostOsView,
    /// Running kernel.
    pub running_kernel: Option<String>,
    /// Agent version.
    pub scanner_version: Option<String>,
    /// Older than the latest agent release; absent when unknown.
    pub agent_older: Option<bool>,
    /// RFC 3339.
    pub enrolled_at: String,
    /// RFC 3339.
    pub revoked_at: Option<String>,
    /// Last heartbeat, RFC 3339.
    pub last_seen_at: Option<String>,
    /// Last inventory, RFC 3339.
    pub inventory_at: Option<String>,
    /// Reported agent capabilities.
    pub capabilities: Vec<String>,
}

/// The four tiles; each absent without its permission on this host.
#[derive(Serialize, ToSchema)]
pub(crate) struct HostTilesView {
    /// Open agent alarms (`alarms.read`).
    pub open_alarms: Option<i64>,
    /// Failing compliance checks (`compliance.read`).
    pub compliance_failing: Option<i64>,
    /// Open vulnerabilities (`vulnerabilities.read`).
    pub vulnerabilities: Option<i64>,
    /// Installed packages (`hosts.read`).
    pub software: Option<i64>,
}

/// Protection: threat alarms and the latest test.
#[derive(Serialize, ToSchema)]
pub(crate) struct HostProtectionView {
    /// Threat alarms on or off; absent before the first health report.
    pub threat_alarms: Option<AgentAlarmsView>,
    /// The latest test alarm and finding.
    pub last_test: LastTest,
}

/// An open alarm in the top three.
#[derive(Serialize, ToSchema)]
pub(crate) struct TopAlarmView {
    /// Alarm id.
    pub id: i64,
    /// Rule.
    pub rule_id: String,
    /// Message.
    pub message: String,
    /// Severity.
    pub severity: String,
    /// Latest match, RFC 3339.
    pub last_seen: String,
}

/// An open vulnerability in the top three.
#[derive(Serialize, ToSchema)]
pub(crate) struct TopVulnerabilityView {
    /// Advisory id.
    pub advisory: String,
    /// Severity.
    pub severity: String,
    /// On the known-exploited list.
    pub kev: bool,
    /// Known to be exploited (KEV or EUVD), as the Vulnerabilities list flags it.
    pub exploited: bool,
    /// The advisory's title.
    pub title: String,
}

/// A failing check in the top three.
#[derive(Serialize, ToSchema)]
pub(crate) struct TopFailingView {
    /// Rule set.
    pub rule_set_id: String,
    /// Rule.
    pub rule_id: String,
    /// Severity.
    pub severity: String,
    /// Message.
    pub message: String,
}

/// Open alarms, most severe then newest first.
#[derive(Serialize, ToSchema)]
pub(crate) struct TopAlarmsView {
    /// Up to three.
    pub items: Vec<TopAlarmView>,
    /// All of them.
    pub total: i64,
}

/// Open vulnerabilities, in the Vulnerabilities list's priority order.
#[derive(Serialize, ToSchema)]
pub(crate) struct TopVulnerabilitiesView {
    /// Up to three.
    pub items: Vec<TopVulnerabilityView>,
    /// All of them.
    pub total: i64,
}

/// Failing checks, most severe then newest first.
#[derive(Serialize, ToSchema)]
pub(crate) struct TopFailingListView {
    /// Up to three.
    pub items: Vec<TopFailingView>,
    /// All of them.
    pub total: i64,
}

/// Software, ports and services counts.
#[derive(Serialize, ToSchema)]
pub(crate) struct HostInventoryView {
    /// Installed packages.
    pub packages: i64,
    /// Listening ports.
    pub listening_ports: i64,
    /// Listening ports reachable from outside the host.
    pub exposed_ports: i64,
    /// Running services.
    pub services: i64,
}

/// What the caller may do on this host.
#[derive(Serialize, ToSchema)]
pub(crate) struct HostActionsView {
    /// Add and remove labels (`hosts.label`, not on a revoked or imported host).
    pub label: bool,
    /// Revoke (`hosts.revoke`, not on a revoked or imported host).
    pub revoke: bool,
    /// Export (`hosts.export`).
    pub export: bool,
    /// Add to a case (`cases.write`).
    pub add_to_case: bool,
    /// Ask the assistant (`assistant.use`).
    pub ask: bool,
}

/// Everything above the fold on a host's page.
#[derive(Serialize, ToSchema)]
pub(crate) struct HostSummaryView {
    /// Header and Details facts.
    pub host: HostFactsView,
    /// Tiles.
    pub tiles: HostTilesView,
    /// Protection.
    pub protection: HostProtectionView,
    /// Groups holding the host, by name.
    pub groups: Vec<HostListGroupView>,
    /// Labels.
    pub labels: Vec<String>,
    /// The five newest certificates.
    pub certificates: Vec<CertificateView>,
    /// All its certificates.
    pub certificate_count: i64,
    /// Top three open alarms (`alarms.read`).
    pub top_alarms: Option<TopAlarmsView>,
    /// Top three open vulnerabilities (`vulnerabilities.read`).
    pub top_vulnerabilities: Option<TopVulnerabilitiesView>,
    /// Top three failing checks (`compliance.read`).
    pub top_failing: Option<TopFailingListView>,
    /// Counts behind the software, ports and services sub-pages.
    pub inventory: HostInventoryView,
    /// Allowed actions.
    pub can: HostActionsView,
}
