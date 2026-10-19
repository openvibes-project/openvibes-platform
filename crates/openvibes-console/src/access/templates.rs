//! Role templates: fixed starting points for a new role (spec §4.2).
//! Picking one only fills the form. The web console reads the same list
//! from `web/src/api/templates.json`, which a test keeps equal to
//! [`templates_json`].

use crate::Permission;
use Permission as P;

/// One template: a name, a one-line description and its permissions.
#[derive(Debug, serde::Serialize)]
pub struct Template {
    /// The template's name, also the suggested role name.
    pub name: &'static str,
    /// One line on who it is for.
    pub description: &'static str,
    /// Its permissions, closed under needs.
    #[serde(serialize_with = "crate::access::catalogue::serialize_ids")]
    pub permissions: &'static [Permission],
}

/// The templates, in the order the console offers them.
pub static TEMPLATES: [Template; 6] = [
    Template {
        name: "Viewer",
        description: "Sees alarms, findings, vulnerabilities, hosts and dashboards.",
        permissions: &[
            P::AlarmsRead,
            P::AlarmsSuppressionsRead,
            P::ComplianceRead,
            P::VulnerabilitiesRead,
            P::HostsRead,
            P::CasesRead,
            P::RulesRead,
            P::RulesCoverageRead,
        ],
    },
    Template {
        name: "Analyst",
        description: "Viewer, plus triage, cases, suppressing with a reason, and the assistant.",
        permissions: &[
            P::AlarmsRead,
            P::AlarmsSuppressionsRead,
            P::ComplianceRead,
            P::VulnerabilitiesRead,
            P::HostsRead,
            P::CasesRead,
            P::RulesRead,
            P::RulesCoverageRead,
            P::AlarmsTriage,
            P::AlarmsSuppress,
            P::ComplianceTriage,
            P::VulnerabilitiesTriage,
            P::CasesWrite,
            P::AssistantUse,
        ],
    },
    Template {
        name: "Operator",
        description: "Runs the fleet: enrollment, labels, revoking hosts, publishing rules and where they run.",
        permissions: &[
            P::AlarmsRead,
            P::ComplianceRead,
            P::VulnerabilitiesRead,
            P::HostsRead,
            P::HostsLabel,
            P::HostsRevoke,
            P::TokensRead,
            P::TokensManage,
            P::TokensInstaller,
            P::RulesRead,
            P::RulesAssignmentRead,
            P::RulesCoverageRead,
            P::RulesContentsRead,
            P::RulesPublish,
            P::RulesAssignmentWrite,
        ],
    },
    Template {
        name: "Team lead",
        description: "For a role limited to some groups: Analyst, plus approving suppressions, labels, sharing dashboards and giving roles within its share.",
        permissions: &[
            P::AlarmsRead,
            P::AlarmsSuppressionsRead,
            P::ComplianceRead,
            P::VulnerabilitiesRead,
            P::HostsRead,
            P::CasesRead,
            P::RulesRead,
            P::RulesCoverageRead,
            P::AlarmsTriage,
            P::AlarmsSuppress,
            P::ComplianceTriage,
            P::VulnerabilitiesTriage,
            P::CasesWrite,
            P::AssistantUse,
            P::AlarmsSuppressionsApprove,
            P::HostsLabel,
            P::DashboardsShare,
            P::AccessRead,
            P::AccessGrant,
        ],
    },
    Template {
        name: "Auditor",
        description: "Reads everything, plus the audit log and its export. Changes nothing.",
        permissions: &[
            P::AlarmsRead,
            P::AlarmsSuppressionsRead,
            P::AlarmsExport,
            P::ComplianceRead,
            P::ComplianceExport,
            P::VulnerabilitiesRead,
            P::VulnerabilitiesExport,
            P::HostsRead,
            P::HostsExport,
            P::CasesRead,
            P::RulesRead,
            P::RulesAssignmentRead,
            P::RulesCoverageRead,
            P::RulesContentsRead,
            P::SiteRulesRead,
            P::AccessRead,
            P::ServiceAccountsRead,
            P::TokensRead,
            P::AuditRead,
            P::AuditExport,
        ],
    },
    Template {
        name: "Rule author",
        description: "Site rule drafts, testing on a host, publishing, and coverage.",
        permissions: &[
            P::HostsRead,
            P::RulesRead,
            P::RulesAssignmentRead,
            P::RulesCoverageRead,
            P::RulesContentsRead,
            P::SiteRulesRead,
            P::SiteRulesWrite,
            P::SiteRulesTest,
            P::SiteRulesPublish,
        ],
    },
];

/// The templates as the pretty-printed JSON of `web/src/api/templates.json`.
#[must_use]
pub fn templates_json() -> String {
    serde_json::to_string_pretty(&TEMPLATES[..]).expect("templates serialize")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::TEMPLATES;
    use crate::access::catalogue::with_needs;

    #[test]
    fn templates_are_closed_under_needs_and_use_known_permissions() {
        for t in TEMPLATES.iter() {
            let set: BTreeSet<_> = t.permissions.iter().copied().collect();
            assert_eq!(with_needs(&set), set, "template {} misses a need", t.name);
        }
        assert_eq!(
            TEMPLATES.iter().map(|t| t.name).collect::<Vec<_>>(),
            [
                "Viewer",
                "Analyst",
                "Operator",
                "Team lead",
                "Auditor",
                "Rule author"
            ]
        );
    }
}
