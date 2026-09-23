//! Deterministic OpenAPI document generated from the Rust console contract.

use utoipa::OpenApi;

use crate::{
    api::{
        AuthenticationLevel, AuthenticationMethod, CursorPagination, EffectiveCapability,
        Permission, PermissionScope, SessionPrincipal, SessionResponse,
    },
    problem::{FieldError, ProblemDetails},
};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "OpenVIBES Console API",
        version = "1.0.0",
        description = "Versioned human and service-account API for the OpenVIBES console.",
        license(name = "MIT")
    ),
    paths(crate::router::session),
    components(schemas(
        AuthenticationLevel,
        AuthenticationMethod,
        CursorPagination,
        EffectiveCapability,
        FieldError,
        Permission,
        PermissionScope,
        ProblemDetails,
        SessionPrincipal,
        SessionResponse
    )),
    tags((name = "session", description = "Current browser session"))
)]
struct ConsoleApi;

/// Returns the generated OpenAPI 3 document.
pub fn document() -> utoipa::openapi::OpenApi {
    ConsoleApi::openapi()
}

/// Serializes the generated document deterministically as pretty JSON.
pub fn json() -> Result<String, serde_json::Error> {
    let mut output = serde_json::to_string_pretty(&document())?;
    output.push('\n');
    Ok(output)
}
