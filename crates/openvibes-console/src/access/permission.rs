//! The stable permission identifiers and the object scope attached to one.

use serde::Serialize;
use utoipa::ToSchema;

/// Stable console permission identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub enum Permission {
    /// Read agents and their certificate/contact metadata.
    #[serde(rename = "agents.read")]
    AgentsRead,
    /// Revoke an enrolled agent.
    #[serde(rename = "agents.revoke")]
    AgentsRevoke,
    /// Read observed compliance findings.
    #[serde(rename = "compliance.read")]
    ComplianceRead,
    /// Read vulnerability exposure for hosts in the bound asset scope.
    #[serde(rename = "vulnerabilities.read")]
    VulnerabilitiesRead,
    /// Change human triage state for compliance findings.
    #[serde(rename = "compliance.triage")]
    ComplianceTriage,
    /// Change human triage state for vulnerabilities, per host (triage v2).
    #[serde(rename = "vulnerabilities.triage")]
    VulnerabilitiesTriage,
    /// Read threat alarms.
    #[serde(rename = "alarms.read")]
    AlarmsRead,
    /// Access to the cases view and its details.
    #[serde(rename = "cases.read")]
    CasesRead,
    /// Create and change cases: items, notes, assignment, closing.
    #[serde(rename = "cases.manage")]
    CasesManage,
    /// Change human triage state for alarms.
    #[serde(rename = "alarms.triage")]
    AlarmsTriage,
    /// Create and remove alarm suppressions.
    #[serde(rename = "alarms.suppress")]
    AlarmsSuppress,
    /// Read enrollment tokens.
    #[serde(rename = "tokens.read")]
    TokensRead,
    /// Create enrollment tokens.
    #[serde(rename = "tokens.create")]
    TokensCreate,
    /// Revoke enrollment tokens.
    #[serde(rename = "tokens.revoke")]
    TokensRevoke,
    /// Read rule bundles and versions.
    #[serde(rename = "rules.read")]
    RulesRead,
    /// Publish an already-signed rule bundle.
    #[serde(rename = "rules.upload")]
    RulesUpload,
    /// Write, check and delete draft rules in the site's own rule sets.
    #[serde(rename = "rules.write")]
    RulesWrite,
    /// Read audit events.
    #[serde(rename = "audit.read")]
    AuditRead,
    /// Export bounded audit results.
    #[serde(rename = "audit.export")]
    AuditExport,
    /// Change the assistant's internet-lookup setting.
    #[serde(rename = "assistant.admin")]
    AssistantAdmin,
    /// Change the audit-retention policy.
    #[serde(rename = "audit.retention.manage")]
    AuditRetentionManage,
    /// Read roles, bindings, and asset groups.
    #[serde(rename = "rbac.read")]
    RbacRead,
    /// Change roles and bindings.
    #[serde(rename = "rbac.manage")]
    RbacManage,
    /// Change manual asset-group selectors and tags.
    #[serde(rename = "asset_groups.manage")]
    AssetGroupsManage,
    /// Read service accounts and token metadata.
    #[serde(rename = "service_accounts.read")]
    ServiceAccountsRead,
    /// Change service accounts and their tokens.
    #[serde(rename = "service_accounts.manage")]
    ServiceAccountsManage,
    /// Ask the read-only local assistant questions about permitted data.
    #[serde(rename = "assistant.use")]
    AssistantUse,
    /// Share one's own dashboards with a role (global only).
    #[serde(rename = "dashboards.share")]
    DashboardsShare,
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
