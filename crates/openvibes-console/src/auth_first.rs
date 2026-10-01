//! Authentication before anything else on the authenticated console API
//! (#97). Every `/api` route but the two below resolves the caller's
//! session or bearer token here, before its handler runs, so nothing about
//! a request (a malformed body, a field rule, an unknown id) is answered
//! to an unauthenticated caller, and a user who must still replace a
//! one-time password gets 403 `password_change_required` everywhere.
//! Handlers still check their own permission, scope and CSRF.

use axum::{
    extract::{Request, State},
    http::Method,
    middleware::Next,
    response::Response,
};
use chrono::Utc;
use platform_store::console_auth;

use crate::{
    auth::{PresentedCredentials, presented_credentials, session_digest},
    router::{
        AuthHttpState, authentication_required, checked_session, password_change_required,
        unavailable_auth,
    },
};

/// Routes that resolve the caller themselves: the session read (which
/// reports `password_must_change`) and setting the password.
fn open(method: &Method, path: &str) -> bool {
    matches!(
        (method, path),
        (&Method::GET, "/v1/session") | (&Method::POST, "/v1/session/password")
    )
}

pub(crate) async fn authenticate_first(
    State(state): State<AuthHttpState>,
    request: Request,
    next: Next,
) -> Response {
    // Inside `nest("/api", …)` the path arrives without the prefix.
    if open(request.method(), request.uri().path()) {
        return next.run(request).await;
    }
    match presented_credentials(request.headers()) {
        Ok(PresentedCredentials::Session(secret)) => {
            // CSRF is the handler's (it knows whether the route mutates).
            match checked_session(&state, request.headers(), secret.expose_secret(), false).await {
                Ok((session, _)) if session.password_must_change => {
                    return password_change_required();
                }
                Ok(_) => {}
                Err(response) => return response,
            }
        }
        Ok(PresentedCredentials::Bearer(secret)) => {
            let digest = session_digest(secret.expose_secret());
            let Ok(client) = state.pool.get().await else {
                return unavailable_auth();
            };
            match console_auth::active_service_token(&client, &digest, Utc::now()).await {
                Ok(Some(_)) => {}
                Ok(None) => return authentication_required(),
                Err(_) => return unavailable_auth(),
            }
        }
        _ => return authentication_required(),
    }
    // ponytail: the handler resolves the caller again (one more session or
    // token read per request); pass it on in an extension if that shows up.
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use axum::http::Method;

    #[test]
    fn only_the_session_read_and_set_password_skip_it() {
        assert!(super::open(&Method::GET, "/v1/session"));
        assert!(super::open(&Method::POST, "/v1/session/password"));
        assert!(!super::open(&Method::POST, "/v1/session"));
        assert!(!super::open(&Method::GET, "/v1/session/password"));
        assert!(!super::open(&Method::POST, "/v1/access-control/users"));
    }
}
