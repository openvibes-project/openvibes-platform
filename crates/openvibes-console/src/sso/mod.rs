//! Single sign-on: the settings checks, the pasted identity provider
//! certificates, our side for the identity provider (the service provider
//! metadata) and the sign-in itself.

use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{get, post},
};

use crate::http::AuthHttpState;

mod certificates;
mod change;
mod provider;
pub(crate) mod service_provider;
pub(crate) mod signin;
#[cfg(test)]
mod tests;

pub(crate) use certificates::{IdpCertificateView, summaries};
pub(crate) use change::check_change;
pub(crate) use service_provider::ServiceProviderView;

/// The answer to editing the name, email or roles of someone who signs in
/// through the identity provider: the next sign-in would overwrite them.
pub(crate) fn managed_by_sso() -> axum::response::Response {
    use crate::http::problem::{ProblemDetails, problem_response};
    problem_response(ProblemDetails::new(
        axum::http::StatusCode::CONFLICT,
        "managed_by_sso",
        "Their name, email and roles come from single sign-on and are set again at each sign-in",
    ))
}

/// The console's API paths.
pub(crate) fn api_routes() -> Router<AuthHttpState> {
    Router::new().route(
        "/v1/sso/service-provider",
        get(service_provider::service_provider),
    )
}

/// The paths under `/auth` that need no session: the identity provider
/// and its administrator fetch the metadata.
pub(crate) fn auth_routes() -> Router<AuthHttpState> {
    Router::new()
        .route("/saml/metadata", get(service_provider::metadata))
        .route("/saml/start", get(signin::start))
        .route(
            "/saml/acs",
            post(signin::acs).layer(DefaultBodyLimit::max(1024 * 1024)),
        )
        .route("/v1/sso", get(signin::status))
}
