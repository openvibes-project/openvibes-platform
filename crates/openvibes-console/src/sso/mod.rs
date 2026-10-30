//! Single sign-on, first slice: the settings checks, the pasted identity
//! provider certificates, and our side for the identity provider (the
//! service provider metadata). Signing in comes with the next slice.

use axum::{Router, routing::get};

use crate::http::AuthHttpState;

mod certificates;
mod change;
pub(crate) mod service_provider;
#[cfg(test)]
mod tests;

pub(crate) use certificates::{IdpCertificateView, summaries};
pub(crate) use change::check_change;
pub(crate) use service_provider::ServiceProviderView;

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
    Router::new().route("/saml/metadata", get(service_provider::metadata))
}
