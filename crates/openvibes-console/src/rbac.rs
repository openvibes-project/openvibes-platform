//! Built-in role permissions and asset-scope resolution.

use std::collections::BTreeSet;

use crate::{EffectiveCapability, Permission, PermissionScope};

/// First-release built-in console roles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuiltInRole {
    /// Read hosts, compliance, vulnerabilities and alarms.
    Viewer,
    /// Viewer access plus triage, cases and the assistant.
    Analyst,
    /// Viewer access plus agent revocation, token management, and rule upload.
    Operator,
    /// Every web-console permission, except CLI-only CA operations.
    Admin,
}

impl BuiltInRole {
    /// Every built-in role, least to most access.
    pub const ALL: [Self; 4] = [Self::Viewer, Self::Analyst, Self::Operator, Self::Admin];

    /// The role's id in bindings and the API, e.g. `viewer`.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Analyst => "analyst",
            Self::Operator => "operator",
            Self::Admin => "admin",
        }
    }

    /// The role's name as people read it, e.g. `Viewer`.
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Viewer => "Viewer",
            Self::Analyst => "Analyst",
            Self::Operator => "Operator",
            Self::Admin => "Admin",
        }
    }

    /// The built-in role with this id, if any.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|role| role.id() == id)
    }
}

/// The built-in roles as the access inventory lists them: id, name and
/// permissions. The web console's demo reads the same list from
/// `web/src/api/roles.json`, which a test keeps equal to this.
#[must_use]
pub fn builtin_roles() -> serde_json::Value {
    BuiltInRole::ALL
        .into_iter()
        .map(|role| {
            let permissions = resolve_capabilities(&[RoleBinding::global(role)])
                .into_iter()
                .map(|capability| serde_json::to_value(capability.permission).expect("permissions serialize"))
                .collect::<Vec<_>>();
            serde_json::json!({
                "role_id": role.id(), "display_name": role.display_name(), "builtin": true, "permissions": permissions
            })
        })
        .collect()
}

/// [`builtin_roles`] as the pretty-printed JSON of `web/src/api/roles.json`.
#[must_use]
pub fn builtin_roles_json() -> String {
    serde_json::to_string_pretty(&builtin_roles()).expect("roles serialize")
}

/// A role assignment together with its global or asset-group binding scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleBinding {
    role: BuiltInRole,
    scope: BindingScope,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum BindingScope {
    Global,
    AssetGroups(BTreeSet<String>),
}

/// Invalid asset-group identifiers supplied to a scoped binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoleBindingError {
    /// A scoped role needs at least one nonempty group identifier.
    EmptyAssetGroup,
}

impl RoleBinding {
    /// Creates a globally effective role binding.
    pub fn global(role: BuiltInRole) -> Self {
        Self {
            role,
            scope: BindingScope::Global,
        }
    }

    /// Creates an asset-group-scoped role binding.
    pub fn scoped(
        role: BuiltInRole,
        asset_group_ids: impl IntoIterator<Item = String>,
    ) -> Result<Self, RoleBindingError> {
        let groups: BTreeSet<_> = asset_group_ids.into_iter().collect();
        if groups.is_empty() || groups.iter().any(String::is_empty) {
            return Err(RoleBindingError::EmptyAssetGroup);
        }
        Ok(Self {
            role,
            scope: BindingScope::AssetGroups(groups),
        })
    }
}

/// Resolves role assignments into effective permissions and merged scopes.
///
/// Global bindings grant every permission in the role. Scoped bindings grant
/// only agent-bound permissions; their control-plane permissions are inert.
/// A global grant dominates scoped grants for the same permission.
pub fn resolve_capabilities(bindings: &[RoleBinding]) -> Vec<EffectiveCapability> {
    ALL_PERMISSIONS
        .iter()
        .filter_map(|permission| {
            let mut global = false;
            let mut asset_groups = BTreeSet::new();

            for binding in bindings {
                if !role_has_permission(binding.role, *permission) {
                    continue;
                }
                match &binding.scope {
                    BindingScope::Global => global = true,
                    BindingScope::AssetGroups(groups) if is_agent_bound(*permission) => {
                        asset_groups.extend(groups.iter().cloned());
                    }
                    BindingScope::AssetGroups(_) => {}
                }
            }

            if global {
                Some(EffectiveCapability {
                    permission: *permission,
                    scope: PermissionScope::Global,
                })
            } else if !asset_groups.is_empty() {
                Some(EffectiveCapability {
                    permission: *permission,
                    scope: PermissionScope::AssetGroups {
                        asset_group_ids: asset_groups.into_iter().collect(),
                    },
                })
            } else {
                None
            }
        })
        .collect()
}

fn role_has_permission(role: BuiltInRole, permission: Permission) -> bool {
    use Permission as P;
    match role {
        BuiltInRole::Viewer => matches!(
            permission,
            P::AgentsRead | P::ComplianceRead | P::VulnerabilitiesRead | P::AlarmsRead
        ),
        BuiltInRole::Analyst => {
            matches!(
                permission,
                P::AgentsRead
                    | P::ComplianceRead
                    | P::ComplianceTriage
                    | P::VulnerabilitiesRead
                    | P::VulnerabilitiesTriage
                    | P::AssistantUse
                    | P::AlarmsRead
                    | P::AlarmsTriage
                    | P::AlarmsSuppress
                    | P::CasesRead
                    | P::CasesManage
            )
        }
        BuiltInRole::Operator => matches!(
            permission,
            P::AgentsRead
                | P::AgentsRevoke
                | P::ComplianceRead
                | P::VulnerabilitiesRead
                | P::TokensRead
                | P::TokensCreate
                | P::TokensRevoke
                | P::RulesUpload
                | P::RulesWrite
                | P::AlarmsRead
        ),
        BuiltInRole::Admin => true,
    }
}

fn is_agent_bound(permission: Permission) -> bool {
    matches!(
        permission,
        Permission::AgentsRead
            | Permission::AgentsRevoke
            | Permission::ComplianceRead
            | Permission::VulnerabilitiesRead
            | Permission::ComplianceTriage
            | Permission::VulnerabilitiesTriage
            | Permission::AlarmsRead
            | Permission::AlarmsTriage
            | Permission::AlarmsSuppress
            | Permission::CasesRead
            | Permission::CasesManage
    )
}

const ALL_PERMISSIONS: &[Permission] = &[
    Permission::AgentsRead,
    Permission::AgentsRevoke,
    Permission::ComplianceRead,
    Permission::VulnerabilitiesRead,
    Permission::ComplianceTriage,
    Permission::VulnerabilitiesTriage,
    Permission::AlarmsRead,
    Permission::AlarmsTriage,
    Permission::AlarmsSuppress,
    Permission::TokensRead,
    Permission::TokensCreate,
    Permission::TokensRevoke,
    Permission::RulesRead,
    Permission::RulesUpload,
    Permission::RulesWrite,
    Permission::AuditRead,
    Permission::AuditExport,
    Permission::AuditRetentionManage,
    Permission::RbacRead,
    Permission::RbacManage,
    Permission::AssetGroupsManage,
    Permission::ServiceAccountsRead,
    Permission::ServiceAccountsManage,
    Permission::AssistantUse,
    Permission::AssistantAdmin,
    Permission::DashboardsShare,
    Permission::CasesRead,
    Permission::CasesManage,
];

#[cfg(test)]
mod tests {
    use crate::{Permission, PermissionScope};

    use super::{BuiltInRole, RoleBinding, RoleBindingError, resolve_capabilities};

    #[test]
    fn roles_merge_asset_scopes_and_keep_control_plane_permissions_global_only() {
        let scoped_operator = RoleBinding::scoped(
            BuiltInRole::Operator,
            [
                "group-b".to_owned(),
                "group-a".to_owned(),
                "group-a".to_owned(),
            ],
        )
        .unwrap();
        let capabilities = resolve_capabilities(&[scoped_operator]);
        assert_eq!(
            capabilities,
            [
                (Permission::AgentsRead, vec!["group-a", "group-b"]),
                (Permission::AgentsRevoke, vec!["group-a", "group-b"]),
                (Permission::ComplianceRead, vec!["group-a", "group-b"]),
                (Permission::VulnerabilitiesRead, vec!["group-a", "group-b"]),
                (Permission::AlarmsRead, vec!["group-a", "group-b"]),
            ]
            .map(|(permission, asset_group_ids)| crate::EffectiveCapability {
                permission,
                scope: PermissionScope::AssetGroups {
                    asset_group_ids: asset_group_ids.into_iter().map(str::to_owned).collect(),
                },
            })
        );

        let viewer_capabilities = resolve_capabilities(&[RoleBinding::global(BuiltInRole::Viewer)]);
        assert!(
            !viewer_capabilities
                .iter()
                .any(|item| item.permission == Permission::RulesRead)
        );
        assert!(viewer_capabilities.iter().any(|item| {
            item.permission == Permission::VulnerabilitiesRead
                && item.scope == PermissionScope::Global
        }));
        let operator_capabilities =
            resolve_capabilities(&[RoleBinding::global(BuiltInRole::Operator)]);
        assert!(
            !operator_capabilities
                .iter()
                .any(|item| item.permission == Permission::RulesRead)
        );

        let global_viewer = RoleBinding::global(BuiltInRole::Viewer);
        let scoped_admin = RoleBinding::scoped(BuiltInRole::Admin, ["group-a".to_owned()]).unwrap();
        let mixed = resolve_capabilities(&[global_viewer, scoped_admin]);
        assert_eq!(
            mixed
                .iter()
                .find(|item| item.permission == Permission::AgentsRead)
                .unwrap()
                .scope,
            PermissionScope::Global
        );
        assert!(
            !mixed
                .iter()
                .any(|item| item.permission == Permission::RbacManage)
        );
        let global_admin = resolve_capabilities(&[RoleBinding::global(BuiltInRole::Admin)]);
        assert!(
            global_admin
                .iter()
                .any(|item| item.permission == Permission::RbacManage)
        );
        assert!(
            global_admin
                .iter()
                .any(|item| item.permission == Permission::RulesRead)
        );
    }

    #[test]
    fn only_analysts_and_admins_manage_cases_and_the_permission_follows_the_scope() {
        let manages = |binding: RoleBinding| {
            resolve_capabilities(&[binding])
                .into_iter()
                .find(|item| item.permission == Permission::CasesManage)
                .map(|item| item.scope)
        };
        for role in [BuiltInRole::Viewer, BuiltInRole::Operator] {
            assert_eq!(manages(RoleBinding::global(role)), None, "{role:?}");
        }
        for role in [BuiltInRole::Analyst, BuiltInRole::Admin] {
            assert_eq!(
                manages(RoleBinding::global(role)),
                Some(PermissionScope::Global),
                "{role:?}"
            );
            assert_eq!(
                manages(RoleBinding::scoped(role, ["group-a".to_owned()]).unwrap()),
                Some(PermissionScope::AssetGroups {
                    asset_group_ids: vec!["group-a".to_owned()]
                }),
                "{role:?}: an agent-bound permission, so a scoped binding keeps it"
            );
        }
    }

    #[test]
    fn scoped_binding_rejects_missing_groups() {
        assert_eq!(
            RoleBinding::scoped(BuiltInRole::Analyst, std::iter::empty()),
            Err(RoleBindingError::EmptyAssetGroup)
        );
        assert_eq!(
            RoleBinding::scoped(BuiltInRole::Analyst, [String::new()]),
            Err(RoleBindingError::EmptyAssetGroup)
        );
    }
}
