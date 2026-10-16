//! The share check (spec §4.4): nobody grants a role, or edits one, beyond
//! what they hold themselves. Pure; the HTTP handlers call it.

use crate::access::catalogue::{Scope, def};
use crate::{EffectiveCapability, Permission, PermissionScope};

/// Which hosts a role reaches.
pub enum RoleReach<'a> {
    None,
    All,
    Groups(&'a [String]),
}

/// The first permission that does not fit inside the editor's own access.
pub struct ShareRefusal {
    pub permission: Permission,
    pub reason: &'static str,
}

/// Does a role with these permissions and this reach fit inside the editor's
/// capabilities? An editor may hold a permission through several roles, so
/// their reaches are combined.
pub fn fits(
    editor: &[EffectiveCapability],
    permissions: &[Permission],
    reach: RoleReach<'_>,
) -> Result<(), ShareRefusal> {
    let refuse = |permission, reason| Err(ShareRefusal { permission, reason });
    for &p in permissions {
        let held: Vec<_> = editor.iter().filter(|c| c.permission == p).collect();
        if held.is_empty() {
            return refuse(p, "you do not hold this permission");
        }
        if def(p).scope == Scope::Platform {
            continue;
        }
        if held
            .iter()
            .any(|c| matches!(c.scope, PermissionScope::Global))
        {
            continue;
        }
        let covers = |g: &String| {
            held.iter().any(|c| match &c.scope {
                PermissionScope::AssetGroups { asset_group_ids } => asset_group_ids.contains(g),
                PermissionScope::Global => true,
            })
        };
        match reach {
            RoleReach::None => {}
            RoleReach::All => return refuse(p, "you hold it only on some asset groups"),
            RoleReach::Groups(r) if r.iter().all(covers) => {}
            RoleReach::Groups(_) => return refuse(p, "the role reaches asset groups you do not"),
        }
    }
    Ok(())
}

/// Are all of these roles inside the editor's share (§4.4)? An empty set fits.
pub fn all_fit<'a>(
    editor: &[EffectiveCapability],
    roles: impl IntoIterator<Item = (&'a [Permission], RoleReach<'a>)>,
) -> bool {
    roles
        .into_iter()
        .all(|(perms, reach)| fits(editor, perms, reach).is_ok())
}

pub fn refusal_message(r: &ShareRefusal) -> String {
    format!(
        "You can only give roles that fit inside your own access ({} is outside it)",
        def(r.permission).label
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn cap(p: Permission, groups: Option<&[&str]>) -> EffectiveCapability {
        EffectiveCapability {
            permission: p,
            scope: match groups {
                None => PermissionScope::Global,
                Some(g) => PermissionScope::AssetGroups {
                    asset_group_ids: g.iter().map(|s| s.to_string()).collect(),
                },
            },
        }
    }
    #[test]
    fn a_permission_the_editor_lacks_is_refused() {
        let r = fits(
            &[cap(Permission::HostsRead, None)],
            &[Permission::HostsRevoke],
            RoleReach::All,
        )
        .unwrap_err();
        assert_eq!(r.permission, Permission::HostsRevoke);
    }
    #[test]
    fn host_permissions_must_cover_the_roles_reach() {
        let editor = [cap(Permission::AlarmsRead, Some(&["lab"]))];
        assert!(
            fits(
                &editor,
                &[Permission::AlarmsRead],
                RoleReach::Groups(&["lab".into()])
            )
            .is_ok()
        );
        assert!(
            fits(
                &editor,
                &[Permission::AlarmsRead],
                RoleReach::Groups(&["prod".into()])
            )
            .is_err()
        );
        assert!(fits(&editor, &[Permission::AlarmsRead], RoleReach::All).is_err());
        assert!(fits(&editor, &[Permission::AlarmsRead], RoleReach::None).is_ok());
    }
    #[test]
    fn platform_permissions_ignore_reach() {
        let editor = [cap(Permission::AuditRead, None)];
        assert!(
            fits(
                &editor,
                &[Permission::AuditRead],
                RoleReach::Groups(&["lab".into()])
            )
            .is_ok()
        );
    }
    #[test]
    fn editing_own_role_cannot_widen_reach() {
        let editor = [
            cap(Permission::HostsRead, Some(&["lab"])),
            cap(Permission::AccessRoles, None),
        ];
        let r = fits(&editor, &[Permission::HostsRead], RoleReach::All).unwrap_err();
        assert_eq!(r.permission, Permission::HostsRead);
    }
    #[test]
    fn reaches_from_several_roles_combine() {
        let editor = [
            cap(Permission::HostsRead, Some(&["lab"])),
            cap(Permission::HostsRead, Some(&["prod"])),
        ];
        let both = ["lab".to_string(), "prod".to_string()];
        assert!(fits(&editor, &[Permission::HostsRead], RoleReach::Groups(&both)).is_ok());
    }
    #[test]
    fn all_fit_needs_every_role_and_accepts_none() {
        let editor = [cap(Permission::HostsRead, None)];
        let ok: (&[Permission], RoleReach) = (&[Permission::HostsRead], RoleReach::All);
        let bad: (&[Permission], RoleReach) = (&[Permission::HostsRevoke], RoleReach::All);
        assert!(all_fit(&editor, []));
        assert!(!all_fit(&editor, [ok, bad]));
    }
    #[test]
    fn the_refusal_names_the_permission_in_console_words() {
        let msg = refusal_message(&ShareRefusal {
            permission: Permission::HostsRevoke,
            reason: "outside",
        });
        assert!(msg.contains("Revoke a host"));
    }
}
