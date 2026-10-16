//! What a principal may do: the roles it holds, read from the database on
//! every request (spec §4.3, §6: no capability cache), resolved into
//! effective permissions and their host scope.

use std::collections::BTreeSet;

use platform_store::{
    Client, StoreError,
    console_roles::{self, Grant, Principal, Reach},
};

use crate::access::catalogue::{Scope, def};
use crate::{EffectiveCapability, Permission, PermissionScope};

/// The built-in Administrator role: it holds every permission on every
/// host, whatever its stored permissions say.
pub const ADMIN_ROLE: &str = "admin";

/// Resolves held roles into effective permissions and merged scopes.
///
/// A platform permission is global whatever the reach. A host permission
/// applies on the union of the reaches of the roles holding it; reach all
/// dominates, and reach none grants it nowhere. Stored ids the catalogue
/// does not know are ignored.
#[must_use]
pub fn resolve_capabilities(grants: &[Grant]) -> Vec<EffectiveCapability> {
    let admin = grants.iter().any(|grant| grant.role_id == ADMIN_ROLE);
    Permission::ALL
        .iter()
        .filter_map(|&permission| {
            let mut global = admin;
            let mut groups = BTreeSet::new();
            let holders = grants
                .iter()
                .filter(|grant| grant.permissions.iter().any(|id| id == permission.id()));
            for grant in holders {
                match (def(permission).scope, &grant.reach) {
                    (Scope::Platform, _) | (Scope::Host, Reach::All) => global = true,
                    (Scope::Host, Reach::Groups(ids)) => groups.extend(ids.iter().cloned()),
                    (Scope::Host, Reach::None) => {}
                }
            }
            let scope = if global {
                PermissionScope::Global
            } else if groups.is_empty() {
                return None;
            } else {
                PermissionScope::AssetGroups {
                    asset_group_ids: groups.into_iter().collect(),
                }
            };
            Some(EffectiveCapability { permission, scope })
        })
        .collect()
}

/// The one place bindings become capabilities: bearer tokens, sessions and
/// `GET /api/v1/session` all come through here.
pub(crate) async fn principal_capabilities(
    client: &Client,
    principal: Principal<'_>,
) -> Result<Vec<EffectiveCapability>, StoreError> {
    Ok(resolve_capabilities(
        &console_roles::grants(client, principal).await?,
    ))
}

#[cfg(test)]
mod tests {
    use platform_store::console_roles::{Grant, Reach};

    use super::resolve_capabilities;
    use crate::{EffectiveCapability, Permission, PermissionScope};

    fn g(role: &str, perms: &[&str], reach: Reach) -> Grant {
        Grant {
            role_id: role.into(),
            permissions: perms.iter().map(|s| s.to_string()).collect(),
            reach,
        }
    }
    fn scope_of(caps: &[EffectiveCapability], p: Permission) -> Option<PermissionScope> {
        caps.iter()
            .find(|c| c.permission == p)
            .map(|c| c.scope.clone())
    }

    #[test]
    fn host_permissions_follow_the_union_of_reaches_and_platform_ones_are_global() {
        let caps = resolve_capabilities(&[
            g(
                "a",
                &["hosts.read", "access.read"],
                Reach::Groups(vec!["lab".into()]),
            ),
            g("b", &["hosts.read"], Reach::Groups(vec!["prod".into()])),
        ]);
        assert_eq!(
            scope_of(&caps, Permission::HostsRead),
            Some(PermissionScope::AssetGroups {
                asset_group_ids: vec!["lab".into(), "prod".into()]
            })
        );
        assert_eq!(
            scope_of(&caps, Permission::AccessRead),
            Some(PermissionScope::Global)
        );
    }

    #[test]
    fn all_hosts_dominates_and_reach_none_grants_no_host_permission() {
        let caps = resolve_capabilities(&[
            g("a", &["alarms.read"], Reach::Groups(vec!["lab".into()])),
            g("b", &["alarms.read"], Reach::All),
            g("c", &["hosts.read", "audit.read"], Reach::None),
        ]);
        assert_eq!(
            scope_of(&caps, Permission::AlarmsRead),
            Some(PermissionScope::Global)
        );
        assert_eq!(scope_of(&caps, Permission::HostsRead), None);
        assert_eq!(
            scope_of(&caps, Permission::AuditRead),
            Some(PermissionScope::Global)
        );
    }

    #[test]
    fn administrator_has_everything_whatever_is_stored() {
        let caps = resolve_capabilities(&[g("admin", &[], Reach::None)]);
        assert_eq!(caps.len(), 48);
        assert!(caps.iter().all(|c| c.scope == PermissionScope::Global));
    }

    #[test]
    fn unknown_stored_ids_are_ignored() {
        let caps = resolve_capabilities(&[g("a", &["agents.read"], Reach::All)]);
        assert!(caps.is_empty());
    }
}
