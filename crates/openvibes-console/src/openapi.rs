//! Deterministic OpenAPI document generated from the Rust console contract.

use utoipa::OpenApi;

use crate::{
    api::{
        AgentDetail, AgentPage, AgentStatus, AgentSummary, AgentView, AuthenticationLevel,
        AuthenticationMethod, CertificatePage, CertificateView, CursorPagination,
        EffectiveCapability, FindingHistoryEntry, FindingHistoryPage, FindingOrigin, FindingPage,
        FindingSummary, FindingView, LoginRequest, LoginResponse, Permission, PermissionScope,
        PreauthResponse, SessionPrincipal, SessionResponse, Severity,
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
    paths(
        crate::router::session,
        crate::router::preauth,
        crate::router::login,
        crate::router::logout,
        crate::router::authenticated_agent_summary,
        crate::router::authenticated_agents,
        crate::router::authenticated_agent_detail,
        crate::router::authenticated_agent_certificates
    ),
    components(schemas(
        AuthenticationLevel,
        AuthenticationMethod,
        AgentDetail,
        AgentPage,
        AgentStatus,
        AgentSummary,
        AgentView,
        LoginRequest,
        LoginResponse,
        CertificatePage,
        CertificateView,
        CursorPagination,
        EffectiveCapability,
        FieldError,
        FindingHistoryEntry,
        FindingHistoryPage,
        FindingOrigin,
        FindingPage,
        FindingSummary,
        FindingView,
        Permission,
        PermissionScope,
        PreauthResponse,
        ProblemDetails,
        SessionPrincipal,
        SessionResponse,
        Severity
    )),
    tags(
        (name = "session", description = "Current browser session"),
        (name = "authentication", description = "Local browser authentication"),
        (name = "agents", description = "Scope-filtered agent reads")
    )
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
