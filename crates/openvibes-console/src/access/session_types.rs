//! Sign-in, session and password types of the console API.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{Permission, PermissionScope};

/// Authentication mechanism that established a browser session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationMethod {
    /// First-release local username and password authentication.
    LocalPassword,
    /// Later OpenID Connect authentication adapter.
    Oidc,
    /// Later SAML authentication adapter.
    Saml,
}

/// Authentication assurance reached by the current browser session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationLevel {
    /// One verified authentication factor.
    SingleFactor,
    /// A later adapter has verified multiple factors.
    MultiFactor,
}

/// One effective capability returned to the browser.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct EffectiveCapability {
    /// Permission granted to the current principal.
    pub permission: Permission,
    /// Effective global or asset-group scope for the permission.
    pub scope: PermissionScope,
}

/// Human principal represented by an authenticated browser session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct SessionPrincipal {
    /// Stable local or federated user identifier.
    pub id: String,
    /// Operator-facing display label.
    pub display_name: String,
    /// Local username when the identity has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Version of their picture, as `v` in `/api/v1/users/{id}/picture`;
    /// absent when they have none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
}

/// Successful response from `GET /api/v1/session` for an active session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct SessionResponse {
    /// Current human principal. Service-account tokens cannot call this route.
    pub principal: SessionPrincipal,
    /// Mechanism that established the session.
    pub authentication_method: AuthenticationMethod,
    /// Assurance reached by the current session.
    pub authentication_level: AuthenticationLevel,
    /// Effective permissions and their scopes, resolved for this request.
    pub capabilities: Vec<EffectiveCapability>,
    /// Per-session value required in `X-CSRF-Token` on unsafe browser requests.
    #[schema(min_length = 32, max_length = 256)]
    pub csrf_token: String,
    /// RFC 3339 instant when idle expiry occurs if the session is not used.
    #[schema(format = DateTime)]
    pub idle_expires_at: String,
    /// RFC 3339 absolute session expiry instant.
    #[schema(format = DateTime)]
    pub absolute_expires_at: String,
    /// The user signed in with a one-time password and must set their own
    /// before anything else: every other route answers 403
    /// `password_change_required`, and `capabilities` is empty.
    pub password_must_change: bool,
}

/// One-use local login request. The password is never echoed by the API.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct LoginRequest {
    /// Canonical local username (case is normalized by the server).
    #[schema(max_length = 64)]
    pub username: String,
    /// Password supplied over the configured secure transport.
    #[schema(format = Password, write_only = true, max_length = 4096)]
    pub password: String,
}

impl Drop for LoginRequest {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.password.zeroize();
        self.username.zeroize();
    }
}

/// Sets the signed-in user's own password (`POST /api/v1/session/password`).
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ChangePasswordRequest {
    /// The current password (the one-time password after New user).
    #[schema(format = Password, write_only = true, max_length = 4096)]
    pub current_password: String,
    /// The new password, at least 15 characters and different from the current.
    #[schema(format = Password, write_only = true, max_length = 4096)]
    pub new_password: String,
}

impl Drop for ChangePasswordRequest {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.current_password.zeroize();
        self.new_password.zeroize();
    }
}

/// Creates a local console user holding roles, with a one-time password
/// (`POST /api/v1/users`).
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateUserRequest {
    /// 1 to 64 ASCII letters, digits or `._@+-`; stored lowercase.
    #[schema(max_length = 64)]
    pub username: String,
    /// Operator-facing name, 1 to 160 printable characters.
    #[schema(max_length = 160)]
    pub display_name: String,
    /// Optional email address, at most 254 characters.
    #[schema(max_length = 254)]
    pub email: Option<String>,
    /// 1 to 64 roles, each inside the creator's own access.
    pub role_ids: Vec<String>,
}

/// A created user and their one-time password, shown only in this response.
#[derive(Serialize, ToSchema)]
pub struct CreatedUser {
    /// New user id.
    pub user_id: String,
    /// Canonical (lowercase) username.
    pub username: String,
    /// Display name as stored.
    pub display_name: String,
    /// The roles given.
    pub role_ids: Vec<String>,
    /// One-time password; the user must replace it at first sign-in.
    #[schema(format = Password, read_only = true)]
    pub one_time_password: String,
}

impl Drop for CreatedUser {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.one_time_password.zeroize();
    }
}

/// CSRF challenge returned before local password login.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct PreauthResponse {
    /// One-use value required in `X-CSRF-Token` on the login request.
    pub csrf_token: String,
}

impl Drop for PreauthResponse {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.csrf_token.zeroize();
    }
}

/// Acknowledgement returned after a local password login succeeds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct LoginResponse {
    /// Always true for the successful response; the session cookie is set separately.
    pub authenticated: bool,
}
