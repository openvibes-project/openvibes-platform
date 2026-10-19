//! The session and permission checks every area's handlers run: who is
//! calling, with which capabilities and scope, and the answers when they
//! may not.

use axum::{
    http::{HeaderMap, StatusCode},
    response::Response,
};
use chrono::{Duration, Utc};
use platform_store::{console_auth, console_roles::Principal};
use subtle::ConstantTimeEq;

use crate::http::{
    AuthHttpState,
    middleware::request_origin,
    problem::{ProblemDetails, problem_response},
};

pub(crate) async fn authenticated_agent_scope(
    state: &AuthHttpState,
    headers: &HeaderMap,
    permission: crate::Permission,
) -> Result<platform_store::console_read::AgentScope, Response> {
    authenticated_permission(state, headers, permission, false)
        .await
        .map(|(scope, _user_id)| scope)
}

pub(crate) async fn authenticated_permission(
    state: &AuthHttpState,
    headers: &HeaderMap,
    permission: crate::Permission,
    csrf_required: bool,
) -> Result<(platform_store::console_read::AgentScope, String), Response> {
    use crate::access::auth::{PresentedCredentials, presented_credentials, session_digest};

    let now = Utc::now();
    let secret = match presented_credentials(headers) {
        Ok(PresentedCredentials::Session(secret)) => secret,
        Ok(PresentedCredentials::Bearer(secret)) => {
            if csrf_required {
                // Browser mutations require a session-bound CSRF value; bearer
                // mutations are not enabled by this first API adapter.
                return Err(problem_response(ProblemDetails::new(
                    StatusCode::FORBIDDEN,
                    "permission_denied",
                    "Access is not available",
                )));
            }
            let digest = session_digest(secret.expose_secret());
            let client = state.pool.get().await.map_err(|_| unavailable_auth())?;
            let token = console_auth::active_service_token(&client, &digest, now)
                .await
                .map_err(|_| unavailable_auth())?
                .ok_or_else(authentication_required)?;
            let capabilities = crate::access::rbac::principal_capabilities(
                &client,
                Principal::ServiceAccount(&token.service_account_id),
            )
            .await
            .map_err(|_| unavailable_auth())?;
            return scope_of(&capabilities, permission)
                .map(|scope| (scope, token.service_account_id))
                .ok_or_else(permission_denied);
        }
        _ => return Err(authentication_required()),
    };
    let user = session_capabilities(state, headers, secret.expose_secret(), csrf_required).await?;
    scope_of(&user.capabilities, permission)
        .map(|scope| (scope, user.user_id))
        .ok_or_else(permission_denied)
}

/// The scope `capabilities` give `permission`, if they hold it.
fn scope_of(
    capabilities: &[crate::EffectiveCapability],
    permission: crate::Permission,
) -> Option<platform_store::console_read::AgentScope> {
    use platform_store::console_read::AgentScope;
    let capability = capabilities
        .iter()
        .find(|capability| capability.permission == permission)?;
    Some(match &capability.scope {
        crate::PermissionScope::Global => AgentScope::Global,
        crate::PermissionScope::AssetGroups { asset_group_ids } => {
            AgentScope::AssetGroups(asset_group_ids.clone())
        }
    })
}

fn permission_denied() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::FORBIDDEN,
        "permission_denied",
        "Access is not available",
    ))
}

/// A signed-in browser user and their effective capabilities. Bearer
/// tokens are refused: dashboards and preferences belong to people.
pub(crate) struct SessionUser {
    pub(crate) user_id: String,
    pub(crate) capabilities: Vec<crate::EffectiveCapability>,
}

pub(crate) async fn session_user(
    state: &AuthHttpState,
    headers: &HeaderMap,
    csrf_required: bool,
) -> Result<SessionUser, Response> {
    use crate::access::auth::{PresentedCredentials, presented_credentials};
    match presented_credentials(headers) {
        Ok(PresentedCredentials::Session(secret)) => {
            session_capabilities(state, headers, secret.expose_secret(), csrf_required).await
        }
        Ok(PresentedCredentials::Bearer(_)) => Err(problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "Access is not available",
        ))),
        _ => Err(authentication_required()),
    }
}

/// Verifies the session cookie and CSRF and touches the session, without
/// the `password_must_change` gate: the set-password route needs a session
/// while the flag is set. Returns the session and its digest.
pub(crate) async fn checked_session(
    state: &AuthHttpState,
    headers: &HeaderMap,
    secret: &str,
    csrf_required: bool,
) -> Result<(console_auth::Session, [u8; 32]), Response> {
    use crate::access::auth::{session_csrf, session_digest};
    let now = Utc::now();
    let digest = session_digest(secret);
    let csrf = session_csrf(secret).0;
    let client = state.pool.get().await.map_err(|_| unavailable_auth())?;
    let active = console_auth::session(&client, &digest, now)
        .await
        .map_err(|_| unavailable_auth())?
        .ok_or_else(authentication_required)?;
    let expected_csrf_hash = session_digest(&csrf);
    if active.csrf_sha256.len() != expected_csrf_hash.len()
        || !bool::from(
            active
                .csrf_sha256
                .as_slice()
                .ct_eq(expected_csrf_hash.as_slice()),
        )
    {
        return Err(authentication_required());
    }
    if csrf_required
        && (!state.public_origin_valid
            || !crate::browser_origin_allowed(headers, &request_origin(state, headers))
            || !crate::csrf_token_matches(headers, &csrf))
    {
        return Err(problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "request_rejected",
            "The request was rejected",
        )));
    }
    if !background_request(headers)
        && !console_auth::touch_session(&client, &digest, now, Duration::minutes(30))
            .await
            .unwrap_or(false)
    {
        return Err(authentication_required());
    }
    Ok((active, digest))
}

/// A request the web app makes on its own (the live-alarm poll), marked
/// with `X-OpenVIBES-Background: 1`. It is checked like any other, but it
/// does not extend the session's idle expiry: an unattended open console
/// still signs out after 30 idle minutes.
pub(crate) fn background_request(headers: &HeaderMap) -> bool {
    headers
        .get("x-openvibes-background")
        .is_some_and(|value| value.as_bytes() == b"1")
}

/// 403 for a user who must set their own password first.
pub(crate) fn password_change_required() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::FORBIDDEN,
        "password_change_required",
        "Set your own password first",
    ))
}

/// The session path shared by `authenticated_permission` and `session_user`:
/// verifies the session and CSRF, touches it, refuses a user who must still
/// set their own password, and resolves capabilities.
async fn session_capabilities(
    state: &AuthHttpState,
    headers: &HeaderMap,
    secret: &str,
    csrf_required: bool,
) -> Result<SessionUser, Response> {
    let (active, _digest) = checked_session(state, headers, secret, csrf_required).await?;
    // One gate for every session route (#85): until the user replaces a
    // one-time password, only the session read, setting the password and
    // sign-out work, and those do not come through here.
    if active.password_must_change {
        return Err(password_change_required());
    }
    let client = state.pool.get().await.map_err(|_| unavailable_auth())?;
    let capabilities =
        crate::access::rbac::principal_capabilities(&client, Principal::User(&active.user_id))
            .await
            .map_err(|_| unavailable_auth())?;
    Ok(SessionUser {
        user_id: active.user_id,
        capabilities,
    })
}

pub(crate) fn authentication_required() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::UNAUTHORIZED,
        "authentication_required",
        "Authentication required",
    ))
}

pub(crate) fn unavailable_auth() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "authentication_unavailable",
        "Authentication is temporarily unavailable",
    ))
}
