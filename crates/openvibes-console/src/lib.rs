#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Human-facing OpenVIBES console HTTP skeleton.
//!
//! C0 provides strict route separation and loopback-only development and
//! health listeners. Optional C3 local authentication uses database-backed
//! sessions on the same loopback listener. TLS and authenticated data access
//! remain unavailable until their implementation milestones. Production frontend assets are included only
//! by the `embedded-ui` feature after their Vite output has been validated.

mod api;
#[cfg(feature = "embedded-ui")]
mod assets;
mod auth;
mod config;
mod error;
#[cfg(feature = "embedded-ui")]
mod frontend_contract;
mod openapi;
mod problem;
mod rbac;
mod router;
#[cfg(feature = "dev-seed")]
mod seeded;
mod server;

pub use api::{
    AccessAssetGroup, AccessBinding, AccessInventory, AccessRole, AccessUser, AgentDetail,
    AgentPage, AgentStatus, AgentSummary, AgentTagBindingImpact, AgentTagChangeRequest,
    AgentTagGroupImpact, AgentTagInput, AgentTagPreviewResponse, AgentView, ApplyAgentTagsRequest,
    AssetGroupSelectorInput, AuditEventPage, AuditEventView, AuditRetentionPolicy,
    AuthenticationLevel, AuthenticationMethod, CertificatePage, CertificateView,
    CreateAccessBindingRequest, CreateEnrollmentTokenRequest, CreateServiceAccountRequest,
    CreateServiceTokenRequest, CreatedEnrollmentToken, CreatedServiceToken, CursorPage,
    CursorPagination, DEFAULT_PAGE_SIZE, EffectiveCapability, EnrollmentTokenPage,
    EnrollmentTokenView, FindingHistoryEntry, FindingHistoryPage, FindingOrigin, FindingPage,
    FindingSummary, FindingView, LoginRequest, LoginResponse, MAX_CURSOR_LENGTH, MAX_PAGE_SIZE,
    PaginationError, Permission, PermissionScope, PreauthResponse, RevokeAgentRequest,
    SaveAssetGroupRequest, ServiceAccountPage, ServiceAccountView, ServiceTokenPage,
    ServiceTokenView, SessionPrincipal, SessionResponse, Severity, UpdateAuditRetentionRequest,
};
pub use auth::{
    CredentialParseError, NormalizedPassword, PasswordError, PasswordHash, PasswordHashError,
    PasswordVerification, PresentedCredentials, PresentedSecret, SessionLifetime, SessionSecret,
    browser_origin_allowed, csrf_token_matches, hash_password, presented_credentials,
    session_cookie, verify_password,
};
pub use config::{ConsoleConfig, load_config};
pub use error::ConsoleError;
pub use openapi::{document as console_openapi, json as openapi_json};
pub use problem::{FieldError, ProblemDetails};
pub use rbac::{BuiltInRole, RoleBinding, RoleBindingError, resolve_capabilities};
pub use router::{
    Readiness, authenticated_router, development_router, health_router, public_router,
};
pub use server::{TrustedPeer, run, serve};
