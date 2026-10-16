//! Request and response shapes of the roles API (spec §4.1).

use platform_store::console_roles::{Reach, StoredRole};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::Permission;

/// A role to create, or a role's new contents.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SaveRole {
    /// 1–64 characters after trimming, no control characters; unique
    /// regardless of case.
    pub name: String,
    /// At most 500 characters.
    #[serde(default)]
    pub description: String,
    /// Closed under needs: each permission's needs are included too.
    pub permissions: Vec<Permission>,
    /// The hosts the role's host permissions apply on.
    pub reach: ReachInput,
    /// The version read; required when editing, ignored when creating.
    pub version: Option<i32>,
}

/// The hosts a role reaches, as sent.
#[derive(Deserialize, Serialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReachInput {
    /// No host: only platform permissions apply.
    None,
    /// Every host.
    All,
    /// The hosts of 1–64 existing host groups.
    Groups {
        /// Host group UUIDs, each once.
        asset_group_ids: Vec<String>,
    },
}

/// One role as the console shows it.
#[derive(Serialize, ToSchema)]
pub struct RoleView {
    pub role_id: String,
    pub name: String,
    pub description: String,
    /// Only Administrator is built in; it cannot be changed or deleted.
    pub builtin: bool,
    pub permissions: Vec<Permission>,
    pub reach: ReachView,
    /// Active bindings (people and service accounts) holding the role.
    pub members: i64,
    /// Send it back when editing.
    pub version: i32,
}

/// The hosts a role reaches, with group names.
#[derive(Serialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReachView {
    None,
    All,
    Groups { groups: Vec<GroupRef> },
}

/// A host group a role reaches.
#[derive(Serialize, ToSchema)]
pub struct GroupRef {
    pub asset_group_id: String,
    pub name: String,
}

impl From<StoredRole> for RoleView {
    fn from(role: StoredRole) -> Self {
        let reach = match role.reach {
            Reach::None => ReachView::None,
            Reach::All => ReachView::All,
            Reach::Groups(_) => ReachView::Groups {
                groups: role
                    .group_names
                    .into_iter()
                    .map(|(asset_group_id, name)| GroupRef {
                        asset_group_id,
                        name,
                    })
                    .collect(),
            },
        };
        Self {
            role_id: role.role_id,
            name: role.name,
            description: role.description,
            builtin: role.builtin,
            // Stored ids the catalogue does not know are left out, as in
            // the access check.
            permissions: role
                .permissions
                .iter()
                .map(String::as_str)
                .filter_map(Permission::from_id)
                .collect(),
            reach,
            members: role.members,
            version: role.version,
        }
    }
}
