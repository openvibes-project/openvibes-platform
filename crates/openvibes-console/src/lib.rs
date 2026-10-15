#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Human-facing OpenVIBES console HTTP skeleton.
//!
//! C0 provides strict route separation and loopback-only development and
//! health listeners. Optional C3 local authentication uses database-backed
//! sessions on the same loopback listener. TLS and authenticated data access
//! remain unavailable until their implementation milestones. Production frontend assets are included only
//! by the `embedded-ui` feature after their Vite output has been validated.

mod about;
mod access;
mod agent_package;
mod alarm_suppressions;
mod alarms;
mod api;
mod assistant;
mod assistant_internet;
mod bulk;
mod cases;
mod config;
mod coverage;
mod dashboards;
mod detection;
mod fetch_client;
mod http;
mod metrics;
mod ports;
mod presence;
mod router;
mod rule_assignment;
mod rule_drafts;
mod rule_test;
#[cfg(feature = "dev-seed")]
mod seeded;
mod server;
mod site_fleet;
mod software;
mod triage_detail;

pub use access::auth::{
    CredentialParseError, NormalizedPassword, PasswordError, PasswordHash, PasswordHashError,
    PasswordVerification, PresentedCredentials, PresentedSecret, SessionLifetime, SessionSecret,
    browser_origin_allowed, csrf_token_matches, hash_password, presented_credentials,
    session_cookie, verify_password,
};
pub use access::rbac::{
    BuiltInRole, RoleBinding, RoleBindingError, builtin_roles, builtin_roles_json,
    resolve_capabilities,
};
pub use access::{
    AccessAssetGroup, AccessBinding, AccessInventory, AccessRole, AccessUser,
    AgentTagBindingImpact, AgentTagChangeRequest, AgentTagGroupImpact, AgentTagInput,
    AgentTagPreviewResponse, ApplyAgentTagsRequest, AssetGroupSelectorInput, AuthenticationLevel,
    AuthenticationMethod, ChangePasswordRequest, CreateAccessBindingRequest,
    CreateServiceAccountRequest, CreateServiceTokenRequest, CreateUserRequest, CreatedServiceToken,
    CreatedUser, EffectiveCapability, LoginRequest, LoginResponse, PreauthResponse,
    SaveAssetGroupRequest, ServiceAccountPage, ServiceAccountView, ServiceTokenPage,
    ServiceTokenView, SessionPrincipal, SessionResponse,
};
pub use api::{
    AgentAlarmsView, AgentCommandView, AgentDetail, AgentPage, AgentRuleSetView, AgentStatus,
    AgentSummary, AgentView, AssistantInternet, AssistantInternetTest, AuditEventPage,
    AuditEventView, AuditRetentionPolicy, BulkFindingTriageChange, BulkFindingTriageRequest,
    BulkFindingTriageResponse, CertificatePage, CertificateView, CreateEnrollmentTokenRequest,
    CreatedEnrollmentToken, CursorPage, CursorPagination, CveDetailView, DEFAULT_PAGE_SIZE,
    DashboardPage, DashboardView, EnrollmentTokenPage, EnrollmentTokenView,
    FindingGroupEndpointPage, FindingGroupEndpointView, FindingGroupPage, FindingGroupView,
    FindingHistoryEntry, FindingHistoryPage, FindingOrigin, FindingPage, FindingSummary,
    FindingTriageCounts, FindingTriageView, FindingView, HomeDashboard, MAX_CURSOR_LENGTH,
    MAX_PAGE_SIZE, PaginationError, Permission, PermissionScope, RevokeAgentRequest,
    RuleBundlePage, RuleBundlePreview, RuleBundleView, RuleSetPage, RuleSetView,
    SaveDashboardRequest, Severity, ShareDashboardRequest, SignedRuleEnvelopeRequest,
    UpdateAssistantInternetRequest, UpdateAuditRetentionRequest, UpdateFindingTriageRequest,
    VulnerabilityAdvisoryDetail, VulnerabilityPage, VulnerabilitySeverity,
    VulnerabilitySeverityCount, VulnerabilitySummary, VulnerabilityTopHost, VulnerabilityView,
};
pub use config::{AgentInstallConfig, ConsoleConfig, ConsoleTransportMode, load_config};
pub use http::error::ConsoleError;
pub use http::openapi::{document as console_openapi, json as openapi_json};
pub use http::problem::{FieldError, ProblemDetails};
pub use http::{
    Readiness, authenticated_router, authenticated_router_for_hosts,
    authenticated_router_with_agent_install, authenticated_router_with_fetch,
    authenticated_router_with_signer, development_router, health_router, public_router,
};
pub use server::{TrustedPeer, run, serve};
