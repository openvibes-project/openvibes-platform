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
mod alarms;
mod assistant;
mod audit;
mod cases;
mod compliance;
mod config;
mod dashboards;
mod host_pages;
mod hosts;
mod http;
mod lists;
mod ports;
mod rules;
#[cfg(feature = "dev-seed")]
mod seeded;
mod server;
mod services;
mod settings;
mod software_pages;
mod vulnerabilities;

pub use access::auth::{
    CredentialParseError, NormalizedPassword, PasswordError, PasswordHash, PasswordHashError,
    PasswordVerification, PresentedCredentials, PresentedSecret, SessionLifetime, SessionSecret,
    browser_origin_allowed, csrf_token_matches, hash_password, presented_credentials,
    session_cookie, verify_password,
};
pub use access::catalogue::catalogue_json;
pub use access::rbac::{ADMIN_ROLE, resolve_capabilities};
pub use access::templates::templates_json;
pub use access::{
    AuthenticationLevel, AuthenticationMethod, ChangePasswordRequest, CreateServiceAccountRequest,
    CreateServiceTokenRequest, CreateUserRequest, CreatedServiceToken, CreatedUser,
    EffectiveCapability, LoginRequest, LoginResponse, Permission, PermissionScope, PreauthResponse,
    RoleName, ServiceAccountPage, ServiceAccountView, ServiceTokenPage, ServiceTokenView,
    SessionPrincipal, SessionResponse,
};
pub use assistant::{AssistantInternet, AssistantInternetTest, UpdateAssistantInternetRequest};
pub use audit::{
    AuditEventPage, AuditEventView, AuditRetentionPolicy, UpdateAuditRetentionRequest,
};
pub use compliance::{
    BulkFindingTriageChange, BulkFindingTriageRequest, BulkFindingTriageResponse,
    FindingGroupEndpointPage, FindingGroupEndpointView, FindingGroupPage, FindingGroupView,
    FindingHistoryEntry, FindingHistoryPage, FindingOrigin, FindingPage, FindingSummary,
    FindingTriageCounts, FindingTriageView, FindingView, Severity, UpdateFindingTriageRequest,
};
pub use config::{AgentInstallConfig, ConsoleConfig, ConsoleTransportMode, load_config};
pub use dashboards::{
    DashboardPage, DashboardRole, DashboardView, HomeDashboard, SaveDashboardRequest,
    ShareDashboardRequest,
};
pub use hosts::{
    AgentAlarmsView, AgentCommandView, AgentDetail, AgentPage, AgentRuleSetView, AgentStatus,
    AgentSummary, AgentView, CertificatePage, CertificateView, CreateEnrollmentTokenRequest,
    CreatedEnrollmentToken, EnrollmentTokenPage, EnrollmentTokenView, RevokeAgentRequest,
};
pub use http::error::ConsoleError;
pub use http::openapi::{document as console_openapi, json as openapi_json};
pub use http::pagination::{
    CursorPage, CursorPagination, DEFAULT_PAGE_SIZE, MAX_CURSOR_LENGTH, MAX_PAGE_SIZE,
    PaginationError,
};
pub use http::problem::{FieldError, ProblemDetails};
pub use http::{
    Readiness, authenticated_router, authenticated_router_for_hosts,
    authenticated_router_with_agent_install, authenticated_router_with_fetch,
    authenticated_router_with_signer, development_router, health_router, public_router,
};
pub use rules::meta::{
    Backfill as RuleMetaBackfill, backfill as backfill_rule_meta, index_bundle as index_rule_bundle,
};
pub use rules::{
    RuleBundlePage, RuleBundlePreview, RuleBundleView, RuleSetPage, RuleSetView,
    SignedRuleEnvelopeRequest,
};
pub use server::{TrustedPeer, run, serve};
pub use vulnerabilities::{
    CveDetailView, VulnerabilityAdvisoryDetail, VulnerabilityPage, VulnerabilitySeverity,
    VulnerabilitySeverityCount, VulnerabilitySummary, VulnerabilityTopHost, VulnerabilityView,
};
