//! Who may do what: sign-in, the session and permission checks, roles,
//! users, service accounts, role bindings, asset groups and host tags.

use axum::{
    Router,
    routing::{delete, get, post, put},
};

use crate::http::AuthHttpState;

pub(crate) mod asset_groups;
pub(crate) mod auth;
pub(crate) mod auth_first;
pub(crate) mod bindings;
mod grant_types;
pub(crate) mod guard;
pub(crate) mod inventory;
pub(crate) mod login;
pub(crate) mod rbac;
pub(crate) mod service_accounts;
pub(crate) mod service_tokens;
pub(crate) mod session;
mod session_types;
pub(crate) mod tags;
pub(crate) mod throttle;
pub(crate) mod users;

pub use grant_types::{
    AccessAssetGroup, AccessBinding, AccessInventory, AccessRole, AccessUser,
    AgentTagBindingImpact, AgentTagChangeRequest, AgentTagGroupImpact, AgentTagInput,
    AgentTagPreviewResponse, ApplyAgentTagsRequest, AssetGroupSelectorInput,
    CreateAccessBindingRequest, CreateServiceAccountRequest, CreateServiceTokenRequest,
    CreatedServiceToken, SaveAssetGroupRequest, ServiceAccountPage, ServiceAccountView,
    ServiceTokenPage, ServiceTokenView,
};
pub use session_types::{
    AuthenticationLevel, AuthenticationMethod, ChangePasswordRequest, CreateUserRequest,
    CreatedUser, EffectiveCapability, LoginRequest, LoginResponse, PreauthResponse,
    SessionPrincipal, SessionResponse,
};

/// The signed-in session, its password change, and access control: roles,
/// users, service accounts and their tokens, bindings, asset groups and host
/// tags.
pub(crate) fn routes() -> Router<AuthHttpState> {
    Router::new()
        .route("/v1/session", get(session::authenticated_session))
        .route("/v1/session/password", post(users::change_password))
        .route(
            "/v1/agents/{agent_id}/tags/preview",
            post(tags::preview_authenticated_agent_tags),
        )
        .route(
            "/v1/agents/{agent_id}/tags",
            put(tags::apply_authenticated_agent_tags),
        )
        .route(
            "/v1/access-control",
            get(inventory::authenticated_access_inventory),
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
        .route(
            "/v1/access-control/asset-groups",
            post(asset_groups::create_authenticated_asset_group),
        )
        .route(
            "/v1/access-control/asset-groups/{group_id}",
            put(asset_groups::update_authenticated_asset_group),
        )
        .route(
            "/v1/access-control/bindings",
            post(bindings::create_authenticated_access_binding),
        )
        .route("/v1/access-control/users", post(users::create_user))
        .route(
            "/v1/access-control/bindings/{binding_id}",
            delete(bindings::revoke_authenticated_access_binding),
        )
}
