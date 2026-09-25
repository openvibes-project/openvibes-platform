//! Deterministic OpenAPI document generated from the Rust console contract.

use utoipa::OpenApi;

use crate::{
    api::{
        AccessAssetGroup, AccessBinding, AccessInventory, AccessRole, AccessUser, AgentDetail,
        AgentPage, AgentStatus, AgentSummary, AgentTagBindingImpact, AgentTagChangeRequest,
        AgentTagGroupImpact, AgentTagInput, AgentTagPreviewResponse, AgentView,
        ApplyAgentTagsRequest, AssetGroupSelectorInput, AuditEventPage, AuditEventView,
        AuditRetentionPolicy, AuthenticationLevel, AuthenticationMethod, CertificatePage,
        CertificateView, CreateAccessBindingRequest, CreateEnrollmentTokenRequest,
        CreatedEnrollmentToken, CursorPagination, EffectiveCapability, EnrollmentTokenPage,
        EnrollmentTokenView, FindingHistoryEntry, FindingHistoryPage, FindingOrigin, FindingPage,
        FindingSummary, FindingView, LoginRequest, LoginResponse, Permission, PermissionScope,
        PreauthResponse, RevokeAgentRequest, SaveAssetGroupRequest, SessionPrincipal,
        SessionResponse, Severity, UpdateAuditRetentionRequest,
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
        crate::router::create_authenticated_asset_group,
        crate::router::update_authenticated_asset_group,
        crate::router::revoke_authenticated_agent,
        crate::router::authenticated_enrollment_tokens,
        crate::router::authenticated_enrollment_token,
        crate::router::create_authenticated_enrollment_token,
        crate::router::revoke_authenticated_enrollment_token,
        crate::router::authenticated_service_accounts,
        crate::router::create_authenticated_service_account,
        crate::router::disable_authenticated_service_account,
        crate::router::authenticated_service_tokens,
        crate::router::create_authenticated_service_token,
        crate::router::revoke_authenticated_service_token,
        crate::router::preview_authenticated_agent_tags,
        crate::router::apply_authenticated_agent_tags,
        crate::router::authenticated_access_inventory,
        crate::router::create_authenticated_access_binding,
        crate::router::revoke_authenticated_access_binding,
        crate::router::session,
        crate::router::preauth,
        crate::router::login,
        crate::router::logout,
        crate::router::authenticated_agent_summary,
        crate::router::authenticated_agents,
        crate::router::authenticated_agent_detail,
        crate::router::authenticated_agent_certificates,
        crate::router::authenticated_finding_summary,
        crate::router::authenticated_latest_findings,
        crate::router::authenticated_latest_finding,
        crate::router::authenticated_finding_history,
        crate::router::authenticated_finding_event,
        crate::router::authenticated_audit_retention,
        crate::router::authenticated_audit_events,
        crate::router::authenticated_audit_export,
        crate::router::update_authenticated_audit_retention
    ),
    components(schemas(
        AssetGroupSelectorInput,
        SaveAssetGroupRequest,
        RevokeAgentRequest,
        CreateEnrollmentTokenRequest,
        CreatedEnrollmentToken,
        EnrollmentTokenPage,
        EnrollmentTokenView,
        AgentTagBindingImpact,
        AgentTagChangeRequest,
        AgentTagGroupImpact,
        AgentTagInput,
        AgentTagPreviewResponse,
        ApplyAgentTagsRequest,
        AccessAssetGroup,
        AccessBinding,
        AccessInventory,
        AccessRole,
        AccessUser,
        CreateAccessBindingRequest,
        AuthenticationLevel,
        AuthenticationMethod,
        AuditRetentionPolicy,
        AuditEventPage,
        AuditEventView,
        AuditRetentionPolicy,
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
        UpdateAuditRetentionRequest,
        UpdateAuditRetentionRequest,
        Severity
    )),
    tags(
        (name = "session", description = "Current browser session"),
        (name = "authentication", description = "Local browser authentication"),
        (name = "agents", description = "Scope-filtered agent reads"),
        (name = "findings", description = "Scope-filtered observation reads"),
        (name = "audit", description = "Audit policy and event access")
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
