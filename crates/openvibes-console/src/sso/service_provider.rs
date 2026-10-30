//! Our side, for the identity provider's administrator.

use axum::{
    extract::{Json, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use utoipa::ToSchema;

use crate::Permission;
use crate::access::editor::caller;
use crate::http::{
    AuthHttpState,
    problem::{ProblemDetails, problem_response},
};

/// What to enter in the identity provider.
#[derive(Serialize, ToSchema)]
pub(crate) struct ServiceProviderView {
    /// Our entity ID (the audience of the response).
    pub entity_id: String,
    /// Where the identity provider posts the response.
    pub acs_url: String,
    /// The metadata document with both, for importing.
    pub metadata_url: String,
}

pub(super) fn addresses(origin: &str) -> ServiceProviderView {
    let origin = origin.trim_end_matches('/');
    ServiceProviderView {
        entity_id: format!("{origin}/auth/saml/metadata"),
        acs_url: format!("{origin}/auth/saml/acs"),
        metadata_url: format!("{origin}/auth/saml/metadata"),
    }
}

/// Our entity ID, response address and metadata address.
#[utoipa::path(get, path = "/api/v1/sso/service-provider", tag = "settings",
    responses((status = 200, description = "Our side", body = ServiceProviderView),
        (status = 403, description = "Needs settings.manage", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "public_origin_invalid", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn service_provider(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    let editor = match caller(&state, &headers, false).await {
        Ok(editor) => editor,
        Err(response) => return response,
    };
    if let Some(response) = editor.denied(Permission::SettingsManage) {
        return response;
    }
    if !state.public_origin_valid {
        return origin_unusable();
    }
    Json(addresses(&state.public_origin)).into_response()
}

/// The service provider metadata (SAML 2.0), for the identity provider.
#[utoipa::path(get, path = "/auth/saml/metadata", tag = "authentication",
    responses((status = 200, description = "SAML metadata", content_type = "application/samlmetadata+xml"),
        (status = 503, description = "public_origin_invalid", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn metadata(State(state): State<AuthHttpState>) -> Response {
    if !state.public_origin_valid {
        return origin_unusable();
    }
    let ours = addresses(&state.public_origin);
    let body = format!(
        concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"{entity}\">\n",
            "  <md:SPSSODescriptor AuthnRequestsSigned=\"false\" WantAssertionsSigned=\"true\" ",
            "protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n",
            "    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>\n",
            "    <md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" ",
            "Location=\"{acs}\" index=\"0\" isDefault=\"true\"/>\n",
            "  </md:SPSSODescriptor>\n",
            "</md:EntityDescriptor>\n"
        ),
        entity = xml_attribute(&ours.entity_id),
        acs = xml_attribute(&ours.acs_url),
    );
    (
        [
            (header::CONTENT_TYPE, "application/samlmetadata+xml"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response()
}

fn origin_unusable() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "public_origin_invalid",
        "The console's public address is not set up",
    ))
}

pub(super) fn xml_attribute(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
