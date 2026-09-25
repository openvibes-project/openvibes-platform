//! Built-in role permissions and asset-scope resolution.

use std::collections::BTreeSet;

use crate::{EffectiveCapability, Permission, PermissionScope};

/// First-release built-in console roles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuiltInRole {
    /// Read agents, findings, and rules.
    Viewer,
    /// Viewer access plus finding triage.
    Analyst,
    /// Viewer access plus agent revocation, token management, and rule upload.
    Operator,
    /// Every web-console permission, except CLI-only CA operations.
    Admin,
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
        BuiltInRole::Viewer => matches!(permission, P::AgentsRead | P::FindingsRead),
        BuiltInRole::Analyst => {
            matches!(
                permission,
                P::AgentsRead | P::FindingsRead | P::FindingsTriage
            )
        }
        BuiltInRole::Operator => matches!(
            permission,
            P::AgentsRead
                | P::AgentsRevoke
                | P::FindingsRead
                | P::TokensRead
                | P::TokensCreate
                | P::TokensRevoke
                | P::RulesUpload
        ),
        BuiltInRole::Admin => true,
    }
}

fn is_agent_bound(permission: Permission) -> bool {
    matches!(
        permission,
        Permission::AgentsRead
            | Permission::AgentsRevoke
            | Permission::FindingsRead
            | Permission::FindingsTriage
    )
}

const ALL_PERMISSIONS: &[Permission] = &[
    Permission::AgentsRead,
    Permission::AgentsRevoke,
    Permission::FindingsRead,
    Permission::FindingsTriage,
    Permission::TokensRead,
    Permission::TokensCreate,
    Permission::TokensRevoke,
    Permission::RulesRead,
    Permission::RulesUpload,
    Permission::AuditRead,
    Permission::AuditExport,
    Permission::AuditRetentionManage,
    Permission::RbacRead,
    Permission::RbacManage,
    Permission::AssetGroupsManage,
    Permission::ServiceAccountsRead,
    Permission::ServiceAccountsManage,
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
                (Permission::FindingsRead, vec!["group-a", "group-b"]),
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
