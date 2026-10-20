//! Request and response shapes of the People API (spec §9.1, §13).

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::Permission;
use crate::access::roles_types::{GroupRef, RoleView};

/// One person in the People list.
#[derive(Serialize, ToSchema)]
pub struct PersonRow {
    pub user_id: String,
    pub username: String,
    pub display_name: String,
    pub email: Option<String>,
    pub enabled: bool,
    /// How they sign in: `password` or `sso`.
    pub auth_source: String,
    /// RFC 3339; null until their first sign-in.
    pub last_sign_in_at: Option<String>,
    /// The roles they hold, with their reach.
    pub roles: Vec<RoleView>,
}

/// A person's page.
#[derive(Serialize, ToSchema)]
pub struct PersonView {
    pub user_id: String,
    pub username: String,
    pub display_name: String,
    pub email: Option<String>,
    pub enabled: bool,
    pub auth_source: String,
    pub last_sign_in_at: Option<String>,
    pub created_at: String,
    pub roles: Vec<RoleView>,
    /// Each permission they hold, where it applies and the role giving it.
    pub access: Vec<AccessLine>,
    /// Their newest actions (at most 10).
    pub recent: Vec<ActivityLine>,
}

/// One permission a person holds through one role.
#[derive(Serialize, ToSchema)]
pub struct AccessLine {
    pub permission: Permission,
    /// The catalogue's label, e.g. "View hosts".
    pub label: String,
    /// The catalogue's area, e.g. "Hosts".
    pub area: String,
    pub applies: Applies,
    /// The groups, when it applies on groups.
    pub groups: Vec<GroupRef>,
    /// The role's name.
    pub from_role: String,
}

/// Where a permission applies.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Applies {
    /// On every host.
    All,
    /// On the hosts of some groups.
    Groups,
    /// Not tied to hosts.
    Platform,
}

/// One audited action.
#[derive(Serialize, ToSchema)]
pub struct ActivityLine {
    pub action: String,
    pub target: Option<String>,
    /// RFC 3339.
    pub at: String,
}

/// New details; a field left out is unchanged.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdatePerson {
    /// 1 to 160 printable characters.
    pub display_name: Option<String>,
    /// An address of at most 254 characters; empty clears it.
    pub email: Option<String>,
}

/// A reset password, shown only in this response.
#[derive(Serialize, ToSchema)]
pub struct OneTimePassword {
    #[schema(format = Password, read_only = true)]
    pub one_time_password: String,
}

impl Drop for OneTimePassword {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.one_time_password.zeroize();
    }
}
