//! Who may do what: sign-in, the session and permission checks, roles,
//! people and their roles, and service accounts.

use axum::{
    Router,
    routing::{get, post, put},
};

use crate::http::AuthHttpState;

pub(crate) mod auth;
pub(crate) mod auth_first;
pub mod catalogue;
pub(crate) mod editor;
mod grant_types;
pub(crate) mod guard;
pub(crate) mod login;
pub(crate) mod people;
pub(crate) mod people_admin;
pub(crate) mod people_roles;
pub(crate) mod people_types;
mod permission;
pub(crate) mod rbac;
pub(crate) mod roles;
pub(crate) mod roles_types;
pub(crate) mod service_accounts;
pub(crate) mod service_tokens;
pub(crate) mod session;
mod session_types;
pub(crate) mod share;
pub mod templates;
pub(crate) mod throttle;
pub(crate) mod users;

pub use grant_types::{
    CreateServiceAccountRequest, CreateServiceTokenRequest, CreatedServiceToken, RoleName,
    ServiceAccountPage, ServiceAccountView, ServiceTokenPage, ServiceTokenView,
};
pub use permission::{Permission, PermissionScope};
pub use session_types::{
    AuthenticationLevel, AuthenticationMethod, ChangePasswordRequest, CreateUserRequest,
    CreatedUser, EffectiveCapability, LoginRequest, LoginResponse, PreauthResponse,
    SessionPrincipal, SessionResponse,
};

/// The signed-in session, its password change, and access control: roles,
/// people and their roles, and service accounts and their tokens.
pub(crate) fn routes() -> Router<AuthHttpState> {
    Router::new()
        .route("/v1/session", get(session::authenticated_session))
        .route("/v1/session/password", post(users::change_password))
        .route("/v1/permissions", get(roles::permissions))
        .route("/v1/role-templates", get(roles::role_templates))
        .route("/v1/roles", get(roles::list_roles).post(roles::create_role))
        .route(
            "/v1/roles/{role_id}",
            get(roles::get_role)
                .patch(roles::update_role)
                .delete(roles::delete_role),
        )
        .route(
            "/v1/users",
            get(people::list_people).post(people::create_person),
        )
        .route(
            "/v1/users/{user_id}",
            get(people::get_person).patch(people::update_person),
        )
        .route(
            "/v1/users/{user_id}/disable",
            post(people_admin::disable_person),
        )
        .route(
            "/v1/users/{user_id}/enable",
            post(people_admin::enable_person),
        )
        .route(
            "/v1/users/{user_id}/reset-password",
            post(people_admin::reset_password),
        )
        .route(
            "/v1/users/{user_id}/roles/{role_id}",
            put(people_roles::give_user_role).delete(people_roles::remove_user_role),
        )
        .route(
            "/v1/service-accounts/{service_account_id}/roles/{role_id}",
            put(people_roles::give_account_role).delete(people_roles::remove_account_role),
        )
        .route(
            "/v1/service-accounts",
            get(service_accounts::authenticated_service_accounts)
                .post(service_accounts::create_authenticated_service_account),
        )
        .route(
            "/v1/service-accounts/{service_account_id}/disable",
            post(service_accounts::disable_authenticated_service_account),
        )
        .route(
            "/v1/service-accounts/{service_account_id}/tokens",
            get(service_tokens::authenticated_service_tokens)
                .post(service_tokens::create_authenticated_service_token),
        )
        .route(
            "/v1/service-accounts/{service_account_id}/tokens/{token_id}/revoke",
            post(service_tokens::revoke_authenticated_service_token),
        )
}
