//! The permission catalogue: one entry per action, declared once (spec §3).
//! The web console reads the same list from `web/src/api/permissions.json`,
//! which a test keeps equal to [`catalogue_json`].

use std::collections::BTreeSet;

use serde::Serialize;

use crate::Permission;

/// Where a permission applies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// On the hosts the granting role reaches.
    Host,
    /// Everywhere: the role's hosts do not limit it.
    Platform,
}

/// The matrix column a permission sits in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Column {
    /// Seeing something.
    View,
    /// Changing something.
    Change,
    /// Taking data out.
    Export,
    /// Approving or publishing what others prepared.
    #[serde(rename = "Approve and publish")]
    Approve,
}

/// One permission's metadata.
#[derive(Debug, Serialize)]
pub struct PermissionDef {
    /// The permission this row describes.
    #[serde(skip)]
    pub permission: Permission,
    /// The wire and database identifier.
    pub id: &'static str,
    /// The matrix row (area) it belongs to.
    pub area: &'static str,
    /// The console text.
    pub label: &'static str,
    /// The matrix column.
    pub column: Column,
    /// Host or platform scope.
    pub scope: Scope,
    /// What it needs to be usable; transitive.
    #[serde(serialize_with = "serialize_ids")]
    pub needs: &'static [Permission],
}

/// Serializes a permission list as its identifiers.
pub(crate) fn serialize_ids<S: serde::Serializer>(
    permissions: &&'static [Permission],
    s: S,
) -> Result<S::Ok, S::Error> {
    s.collect_seq(permissions.iter().map(|p| p.id()))
}

use Column::*;
use Permission as P;
use Scope::*;

const fn d(
    permission: Permission,
    id: &'static str,
    area: &'static str,
    label: &'static str,
    column: Column,
    scope: Scope,
    needs: &'static [Permission],
) -> PermissionDef {
    PermissionDef {
        permission,
        id,
        area,
        label,
        column,
        scope,
        needs,
    }
}

/// Spec §3, in order. Areas group the matrix rows.
#[rustfmt::skip]
pub static CATALOGUE: [PermissionDef; 48] = [
    d(P::AlarmsRead, "alarms.read", "Alarms", "View alarms", View, Host, &[]),
    d(P::AlarmsSuppressionsRead, "alarms.suppressions.read", "Alarms", "View suppressions", View, Host, &[P::AlarmsRead]),
    d(P::AlarmsTriage, "alarms.triage", "Alarms", "Triage alarms", Change, Host, &[P::AlarmsRead]),
    d(P::AlarmsSuppress, "alarms.suppress", "Alarms", "Suppress alarms (with a reason)", Change, Host, &[P::AlarmsRead, P::AlarmsSuppressionsRead]),
    d(P::AlarmsExport, "alarms.export", "Alarms", "Export alarms", Export, Host, &[P::AlarmsRead]),
    d(P::AlarmsSuppressionsApprove, "alarms.suppressions.approve", "Alarms", "Approve suppressions", Approve, Host, &[P::AlarmsSuppressionsRead]),
    d(P::ComplianceRead, "compliance.read", "Compliance", "View findings", View, Host, &[]),
    d(P::ComplianceTriage, "compliance.triage", "Compliance", "Triage findings", Change, Host, &[P::ComplianceRead]),
    d(P::ComplianceExport, "compliance.export", "Compliance", "Export findings", Export, Host, &[P::ComplianceRead]),
    d(P::VulnerabilitiesRead, "vulnerabilities.read", "Vulnerabilities", "View vulnerabilities", View, Host, &[]),
    d(P::VulnerabilitiesTriage, "vulnerabilities.triage", "Vulnerabilities", "Triage vulnerabilities", Change, Host, &[P::VulnerabilitiesRead]),
    d(P::VulnerabilitiesExport, "vulnerabilities.export", "Vulnerabilities", "Export vulnerabilities", Export, Host, &[P::VulnerabilitiesRead]),
    d(P::HostsRead, "hosts.read", "Hosts", "View hosts", View, Host, &[]),
    d(P::HostsLabel, "hosts.label", "Hosts", "Label hosts", Change, Host, &[P::HostsRead]),
    d(P::HostsRevoke, "hosts.revoke", "Hosts", "Revoke a host", Change, Host, &[P::HostsRead]),
    d(P::HostsExport, "hosts.export", "Hosts", "Export host data", Export, Host, &[P::HostsRead]),
    d(P::CasesRead, "cases.read", "Cases", "View cases", View, Host, &[]),
    d(P::CasesWrite, "cases.write", "Cases", "Create and edit cases", Change, Host, &[P::CasesRead]),
    d(P::CasesAssign, "cases.assign", "Cases", "Assign cases", Change, Host, &[P::CasesWrite]),
    d(P::RulesRead, "rules.read", "Rule sets", "View rule sets and versions", View, Platform, &[]),
    d(P::RulesAssignmentRead, "rules.assignment.read", "Rule sets", "View where sets run", View, Platform, &[P::RulesRead]),
    d(P::RulesCoverageRead, "rules.coverage.read", "Rule sets", "View ATT&CK coverage", View, Platform, &[]),
    d(P::RulesContentsRead, "rules.contents.read", "Rule sets", "View rule contents", View, Platform, &[P::RulesRead]),
    d(P::RulesAssignmentWrite, "rules.assignment.write", "Rule sets", "Change where sets run", Change, Platform, &[P::RulesAssignmentRead]),
    d(P::RulesPublish, "rules.publish", "Rule sets", "Publish a rule bundle", Approve, Platform, &[P::RulesRead]),
    d(P::SiteRulesRead, "site_rules.read", "Site rules", "View site rule drafts", View, Platform, &[]),
    d(P::SiteRulesWrite, "site_rules.write", "Site rules", "Edit site rule drafts", Change, Platform, &[P::SiteRulesRead]),
    d(P::SiteRulesTest, "site_rules.test", "Site rules", "Test a draft on a host", Change, Platform, &[P::SiteRulesWrite, P::HostsRead]),
    d(P::SiteRulesPublish, "site_rules.publish", "Site rules", "Publish site rules", Approve, Platform, &[P::SiteRulesWrite]),
    d(P::DashboardsShare, "dashboards.share", "Dashboards", "Share dashboards with your roles", Change, Platform, &[]),
    d(P::DashboardsPublish, "dashboards.publish", "Dashboards", "Publish dashboards to everyone", Approve, Platform, &[P::DashboardsShare]),
    d(P::AssistantUse, "assistant.use", "Assistant", "Use the assistant", View, Host, &[]),
    d(P::AssistantAdmin, "assistant.admin", "Assistant", "Configure the assistant and internet lookups", Change, Platform, &[]),
    d(P::AccessRead, "access.read", "Access", "View people and roles", View, Platform, &[]),
    d(P::AccessUsers, "access.users", "Access", "Create, edit and disable users", Change, Platform, &[P::AccessRead]),
    d(P::AccessRoles, "access.roles", "Access", "Create and edit roles", Change, Platform, &[P::AccessRead]),
    d(P::AccessGrant, "access.grant", "Access", "Give people roles", Change, Platform, &[P::AccessRead]),
    d(P::HostGroupsManage, "host_groups.manage", "Access", "Manage host groups", Change, Platform, &[P::AccessRead, P::HostsRead]),
    d(P::ServiceAccountsRead, "service_accounts.read", "Service accounts", "View service accounts", View, Platform, &[]),
    d(P::ServiceAccountsManage, "service_accounts.manage", "Service accounts", "Create and disable service accounts", Change, Platform, &[P::ServiceAccountsRead]),
    d(P::ServiceAccountsTokens, "service_accounts.tokens", "Service accounts", "Issue and revoke their tokens", Change, Platform, &[P::ServiceAccountsRead]),
    d(P::TokensRead, "tokens.read", "Enrollment", "View enrollment tokens", View, Platform, &[]),
    d(P::TokensManage, "tokens.manage", "Enrollment", "Create and revoke tokens", Change, Platform, &[P::TokensRead]),
    d(P::TokensInstaller, "tokens.installer", "Enrollment", "Download the agent installer", Export, Platform, &[P::TokensRead]),
    d(P::AuditRead, "audit.read", "Audit log", "View the audit log", View, Platform, &[]),
    d(P::AuditRetentionManage, "audit.retention.manage", "Audit log", "Change retention", Change, Platform, &[P::AuditRead]),
    d(P::AuditExport, "audit.export", "Audit log", "Export the audit log", Export, Platform, &[P::AuditRead]),
    d(P::SettingsManage, "settings.manage", "General", "Change general settings", Change, Platform, &[]),
];

/// The catalogue row of a permission.
#[must_use]
pub fn def(p: Permission) -> &'static PermissionDef {
    CATALOGUE
        .iter()
        .find(|d| d.permission == p)
        .expect("every permission is in the catalogue")
}

/// The set plus everything it needs, transitively.
#[must_use]
pub fn with_needs(set: &BTreeSet<Permission>) -> BTreeSet<Permission> {
    let mut out = set.clone();
    let mut stack: Vec<Permission> = set.iter().copied().collect();
    while let Some(p) = stack.pop() {
        for n in def(p).needs {
            if out.insert(*n) {
                stack.push(*n);
            }
        }
    }
    out
}

/// The catalogue as the pretty-printed JSON of `web/src/api/permissions.json`.
#[must_use]
pub fn catalogue_json() -> String {
    serde_json::to_string_pretty(&CATALOGUE[..]).expect("catalogue serializes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn there_are_48_permissions_with_unique_ids_that_round_trip() {
        let ids: BTreeSet<_> = Permission::ALL.iter().map(|p| p.id()).collect();
        assert_eq!(ids.len(), 48);
        for p in Permission::ALL {
            assert_eq!(Permission::from_id(p.id()), Some(p));
        }
        assert_eq!(Permission::from_id("agents.read"), None);
    }

    #[test]
    fn every_permission_has_a_definition_and_needs_are_acyclic() {
        for p in Permission::ALL {
            assert_eq!(def(p).permission, p);
            let mut seen = BTreeSet::new();
            let mut stack: Vec<Permission> = def(p).needs.to_vec();
            while let Some(n) = stack.pop() {
                assert_ne!(n, p, "{} needs itself through {}", p.id(), n.id());
                if seen.insert(n) {
                    stack.extend(def(n).needs.iter().copied());
                }
            }
        }
    }

    #[test]
    fn with_needs_closes_transitively() {
        let got = with_needs(&BTreeSet::from([Permission::CasesAssign]));
        assert_eq!(
            got,
            BTreeSet::from([
                Permission::CasesAssign,
                Permission::CasesWrite,
                Permission::CasesRead
            ])
        );
        let got = with_needs(&BTreeSet::from([Permission::SiteRulesTest]));
        assert!(
            got.contains(&Permission::SiteRulesWrite)
                && got.contains(&Permission::SiteRulesRead)
                && got.contains(&Permission::HostsRead)
        );
    }
}
