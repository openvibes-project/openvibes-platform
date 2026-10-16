//! The stable permission identifiers and the object scope attached to one.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Stable console permission identifiers, one per action (spec §3). Their
/// metadata (area, column, scope, needs) lives in `access/catalogue.rs`.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
pub enum Permission {
    /// View alarms.
    #[serde(rename = "alarms.read")]
    AlarmsRead,
    /// View suppressions.
    #[serde(rename = "alarms.suppressions.read")]
    AlarmsSuppressionsRead,
    /// Triage alarms.
    #[serde(rename = "alarms.triage")]
    AlarmsTriage,
    /// Suppress alarms (with a reason).
    #[serde(rename = "alarms.suppress")]
    AlarmsSuppress,
    /// Export alarms.
    #[serde(rename = "alarms.export")]
    AlarmsExport,
    /// Approve suppressions.
    #[serde(rename = "alarms.suppressions.approve")]
    AlarmsSuppressionsApprove,
    /// View findings.
    #[serde(rename = "compliance.read")]
    ComplianceRead,
    /// Triage findings.
    #[serde(rename = "compliance.triage")]
    ComplianceTriage,
    /// Export findings.
    #[serde(rename = "compliance.export")]
    ComplianceExport,
    /// View vulnerabilities.
    #[serde(rename = "vulnerabilities.read")]
    VulnerabilitiesRead,
    /// Triage vulnerabilities.
    #[serde(rename = "vulnerabilities.triage")]
    VulnerabilitiesTriage,
    /// Export vulnerabilities.
    #[serde(rename = "vulnerabilities.export")]
    VulnerabilitiesExport,
    /// View hosts.
    #[serde(rename = "hosts.read")]
    HostsRead,
    /// Label hosts.
    #[serde(rename = "hosts.label")]
    HostsLabel,
    /// Revoke a host.
    #[serde(rename = "hosts.revoke")]
    HostsRevoke,
    /// Export host data.
    #[serde(rename = "hosts.export")]
    HostsExport,
    /// View cases.
    #[serde(rename = "cases.read")]
    CasesRead,
    /// Create and edit cases.
    #[serde(rename = "cases.write")]
    CasesWrite,
    /// Assign cases.
    #[serde(rename = "cases.assign")]
    CasesAssign,
    /// View rule sets and versions.
    #[serde(rename = "rules.read")]
    RulesRead,
    /// View where sets run.
    #[serde(rename = "rules.assignment.read")]
    RulesAssignmentRead,
    /// View ATT&CK coverage.
    #[serde(rename = "rules.coverage.read")]
    RulesCoverageRead,
    /// View rule contents.
    #[serde(rename = "rules.contents.read")]
    RulesContentsRead,
    /// Change where sets run.
    #[serde(rename = "rules.assignment.write")]
    RulesAssignmentWrite,
    /// Publish a rule bundle.
    #[serde(rename = "rules.publish")]
    RulesPublish,
    /// View site rule drafts.
    #[serde(rename = "site_rules.read")]
    SiteRulesRead,
    /// Edit site rule drafts.
    #[serde(rename = "site_rules.write")]
    SiteRulesWrite,
    /// Test a draft on a host.
    #[serde(rename = "site_rules.test")]
    SiteRulesTest,
    /// Publish site rules.
    #[serde(rename = "site_rules.publish")]
    SiteRulesPublish,
    /// Share dashboards with your roles.
    #[serde(rename = "dashboards.share")]
    DashboardsShare,
    /// Publish dashboards to everyone.
    #[serde(rename = "dashboards.publish")]
    DashboardsPublish,
    /// Use the assistant.
    #[serde(rename = "assistant.use")]
    AssistantUse,
    /// Configure the assistant and internet lookups.
    #[serde(rename = "assistant.admin")]
    AssistantAdmin,
    /// View people and roles.
    #[serde(rename = "access.read")]
    AccessRead,
    /// Create, edit and disable users.
    #[serde(rename = "access.users")]
    AccessUsers,
    /// Create and edit roles.
    #[serde(rename = "access.roles")]
    AccessRoles,
    /// Give people roles.
    #[serde(rename = "access.grant")]
    AccessGrant,
    /// Manage host groups.
    #[serde(rename = "host_groups.manage")]
    HostGroupsManage,
    /// View service accounts.
    #[serde(rename = "service_accounts.read")]
    ServiceAccountsRead,
    /// Create and disable service accounts.
    #[serde(rename = "service_accounts.manage")]
    ServiceAccountsManage,
    /// Issue and revoke their tokens.
    #[serde(rename = "service_accounts.tokens")]
    ServiceAccountsTokens,
    /// View enrollment tokens.
    #[serde(rename = "tokens.read")]
    TokensRead,
    /// Create and revoke tokens.
    #[serde(rename = "tokens.manage")]
    TokensManage,
    /// Download the agent installer.
    #[serde(rename = "tokens.installer")]
    TokensInstaller,
    /// View the audit log.
    #[serde(rename = "audit.read")]
    AuditRead,
    /// Change retention.
    #[serde(rename = "audit.retention.manage")]
    AuditRetentionManage,
    /// Export the audit log.
    #[serde(rename = "audit.export")]
    AuditExport,
    /// Change general settings.
    #[serde(rename = "settings.manage")]
    SettingsManage,
}

impl Permission {
    /// Every permission, in catalogue order.
    pub const ALL: [Permission; 48] = [
        Self::AlarmsRead,
        Self::AlarmsSuppressionsRead,
        Self::AlarmsTriage,
        Self::AlarmsSuppress,
        Self::AlarmsExport,
        Self::AlarmsSuppressionsApprove,
        Self::ComplianceRead,
        Self::ComplianceTriage,
        Self::ComplianceExport,
        Self::VulnerabilitiesRead,
        Self::VulnerabilitiesTriage,
        Self::VulnerabilitiesExport,
        Self::HostsRead,
        Self::HostsLabel,
        Self::HostsRevoke,
        Self::HostsExport,
        Self::CasesRead,
        Self::CasesWrite,
        Self::CasesAssign,
        Self::RulesRead,
        Self::RulesAssignmentRead,
        Self::RulesCoverageRead,
        Self::RulesContentsRead,
        Self::RulesAssignmentWrite,
        Self::RulesPublish,
        Self::SiteRulesRead,
        Self::SiteRulesWrite,
        Self::SiteRulesTest,
        Self::SiteRulesPublish,
        Self::DashboardsShare,
        Self::DashboardsPublish,
        Self::AssistantUse,
        Self::AssistantAdmin,
        Self::AccessRead,
        Self::AccessUsers,
        Self::AccessRoles,
        Self::AccessGrant,
        Self::HostGroupsManage,
        Self::ServiceAccountsRead,
        Self::ServiceAccountsManage,
        Self::ServiceAccountsTokens,
        Self::TokensRead,
        Self::TokensManage,
        Self::TokensInstaller,
        Self::AuditRead,
        Self::AuditRetentionManage,
        Self::AuditExport,
        Self::SettingsManage,
    ];

    /// The wire and database identifier, e.g. `alarms.read`.
    #[must_use]
    pub fn id(self) -> &'static str {
        crate::access::catalogue::def(self).id
    }

    /// The permission with this identifier, if any.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.id() == id)
    }
}

/// Effective object scope attached to one permission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PermissionScope {
    /// The permission applies globally.
    Global,
    /// The permission applies only to the listed asset groups.
    AssetGroups {
        /// Stable asset-group identifiers selected by the binding resolver.
        asset_group_ids: Vec<String>,
    },
}
