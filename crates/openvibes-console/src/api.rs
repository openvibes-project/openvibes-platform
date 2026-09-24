//! Stable, versioned console API data-transfer objects.

use std::{error::Error, fmt};

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Default number of records requested by a cursor-paginated collection.
pub const DEFAULT_PAGE_SIZE: u16 = 50;
/// Maximum number of records returned by one collection request.
pub const MAX_PAGE_SIZE: u16 = 100;
/// Maximum accepted encoded cursor length.
pub const MAX_CURSOR_LENGTH: usize = 2_048;

/// Authentication mechanism that established a browser session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationMethod {
    /// First-release local username and password authentication.
    LocalPassword,
    /// Later OpenID Connect authentication adapter.
    Oidc,
    /// Later SAML authentication adapter.
    Saml,
}

/// Authentication assurance reached by the current browser session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationLevel {
    /// One verified authentication factor.
    SingleFactor,
    /// A later adapter has verified multiple factors.
    MultiFactor,
}

/// Stable console permission identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub enum Permission {
    /// Read agents and their certificate/contact metadata.
    #[serde(rename = "agents.read")]
    AgentsRead,
    /// Revoke an enrolled agent.
    #[serde(rename = "agents.revoke")]
    AgentsRevoke,
    /// Read observed findings.
    #[serde(rename = "findings.read")]
    FindingsRead,
    /// Change human triage state for findings.
    #[serde(rename = "findings.triage")]
    FindingsTriage,
    /// Read enrollment tokens.
    #[serde(rename = "tokens.read")]
    TokensRead,
    /// Create enrollment tokens.
    #[serde(rename = "tokens.create")]
    TokensCreate,
    /// Revoke enrollment tokens.
    #[serde(rename = "tokens.revoke")]
    TokensRevoke,
    /// Read rule bundles and versions.
    #[serde(rename = "rules.read")]
    RulesRead,
    /// Publish an already-signed rule bundle.
    #[serde(rename = "rules.upload")]
    RulesUpload,
    /// Read audit events.
    #[serde(rename = "audit.read")]
    AuditRead,
    /// Export bounded audit results.
    #[serde(rename = "audit.export")]
    AuditExport,
    /// Change the audit-retention policy.
    #[serde(rename = "audit.retention.manage")]
    AuditRetentionManage,
    /// Read roles, bindings, and asset groups.
    #[serde(rename = "rbac.read")]
    RbacRead,
    /// Change roles and bindings.
    #[serde(rename = "rbac.manage")]
    RbacManage,
    /// Change manual asset-group selectors and tags.
    #[serde(rename = "asset_groups.manage")]
    AssetGroupsManage,
    /// Read service accounts and token metadata.
    #[serde(rename = "service_accounts.read")]
    ServiceAccountsRead,
    /// Change service accounts and their tokens.
    #[serde(rename = "service_accounts.manage")]
    ServiceAccountsManage,
}

/// Effective object scope attached to one permission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PermissionScope {
    /// The permission applies globally.
    Global,
    /// The permission applies only to the listed asset groups.
    AssetGroups {
        /// Stable asset-group identifiers selected by the binding resolver.
        asset_group_ids: Vec<String>,
    },
}

/// One effective capability returned to the browser.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct EffectiveCapability {
    /// Permission granted to the current principal.
    pub permission: Permission,
    /// Effective global or asset-group scope for the permission.
    pub scope: PermissionScope,
}

/// Human principal represented by an authenticated browser session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct SessionPrincipal {
    /// Stable local or federated user identifier.
    pub id: String,
    /// Operator-facing display label.
    pub display_name: String,
    /// Local username when the identity has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

/// Successful response from `GET /api/v1/session` for an active session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct SessionResponse {
    /// Current human principal. Service-account tokens cannot call this route.
    pub principal: SessionPrincipal,
    /// Mechanism that established the session.
    pub authentication_method: AuthenticationMethod,
    /// Assurance reached by the current session.
    pub authentication_level: AuthenticationLevel,
    /// Effective permissions and their scopes, resolved for this request.
    pub capabilities: Vec<EffectiveCapability>,
    /// Per-session value required in `X-CSRF-Token` on unsafe browser requests.
    #[schema(min_length = 32, max_length = 256)]
    pub csrf_token: String,
    /// RFC 3339 instant when idle expiry occurs if the session is not used.
    #[schema(format = DateTime)]
    pub idle_expires_at: String,
    /// RFC 3339 absolute session expiry instant.
    #[schema(format = DateTime)]
    pub absolute_expires_at: String,
}

/// One-use local login request. The password is never echoed by the API.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct LoginRequest {
    /// Canonical local username (case is normalized by the server).
    #[schema(max_length = 64)]
    pub username: String,
    /// Password supplied over the configured secure transport.
    #[schema(format = Password, write_only = true, max_length = 4096)]
    pub password: String,
}

impl Drop for LoginRequest {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.password.zeroize();
        self.username.zeroize();
    }
}

/// CSRF challenge returned before local password login.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct PreauthResponse {
    /// One-use value required in `X-CSRF-Token` on the login request.
    pub csrf_token: String,
}

impl Drop for PreauthResponse {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.csrf_token.zeroize();
    }
}

/// Acknowledgement returned after a local password login succeeds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct LoginResponse {
    /// Always true for the successful response; the session cookie is set separately.
    pub authenticated: bool,
}

/// Validated cursor and limit accepted by cursor-paginated collection routes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct CursorPagination {
    #[schema(max_length = 2048)]
    cursor: Option<String>,
    #[schema(minimum = 1, maximum = 100, default = 50)]
    limit: u16,
}

impl CursorPagination {
    /// Creates a validated pagination request.
    pub fn new(cursor: Option<String>, limit: u16) -> Result<Self, PaginationError> {
        if !(1..=MAX_PAGE_SIZE).contains(&limit) {
            return Err(PaginationError::InvalidLimit);
        }
        if cursor
            .as_ref()
            .is_some_and(|cursor| cursor.is_empty() || cursor.len() > MAX_CURSOR_LENGTH)
        {
            return Err(PaginationError::InvalidCursor);
        }
        Ok(Self { cursor, limit })
    }

    /// Returns the opaque cursor, if this is not the first page.
    pub fn cursor(&self) -> Option<&str> {
        self.cursor.as_deref()
    }

    /// Returns the validated page-size limit.
    pub fn limit(&self) -> u16 {
        self.limit
    }
}

impl<'de> Deserialize<'de> for CursorPagination {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawPagination {
            #[serde(default)]
            cursor: Option<String>,
            #[serde(default = "default_page_size")]
            limit: u16,
        }

        let raw = RawPagination::deserialize(deserializer)?;
        Self::new(raw.cursor, raw.limit).map_err(serde::de::Error::custom)
    }
}

fn default_page_size() -> u16 {
    DEFAULT_PAGE_SIZE
}

/// A bounded page of typed results using an opaque continuation cursor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct CursorPage<T> {
    /// Records in stable server-defined order.
    pub items: Vec<T>,
    /// Opaque cursor for the next page, or `null` at the end.
    pub next_cursor: Option<String>,
    /// RFC 3339 instant when this page was generated.
    pub generated_at: String,
}

/// Lifecycle state reported for an enrolled agent.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    /// The agent is enrolled and reporting within the expected interval.
    Active,
    /// The agent has not reported within the configured stale interval.
    Stale,
    /// The agent was revoked by an operator.
    Revoked,
}

/// Severity attached to the latest observation for a rule.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Highest severity.
    Critical,
    /// High severity.
    High,
    /// Medium severity.
    Medium,
    /// Low severity.
    Low,
}

/// Provenance of a stored observation.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FindingOrigin {
    /// Received from an enrolled agent.
    Online,
    /// Loaded from an operator-provided import.
    Import,
}

/// Operator-facing agent fields shared by the read API and seeded server.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct AgentView {
    /// Stable platform agent identifier.
    pub id: String,
    /// Latest hostname reported by an authenticated heartbeat; this is an operator label.
    pub hostname: Option<String>,
    /// Current lifecycle state.
    pub status: AgentStatus,
    /// RFC 3339 enrollment time.
    pub enrolled_at: String,
    /// RFC 3339 revocation time, if revoked.
    pub revoked_at: Option<String>,
    /// RFC 3339 time of the latest heartbeat, if present.
    pub last_seen_at: Option<String>,
    /// Reported scanner version, if present.
    pub scanner_version: Option<String>,
    /// Reported agent capabilities.
    pub capabilities: Vec<String>,
}

/// Certificate metadata exposed in an agent detail response.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct CertificateView {
    /// Certificate serial rendered as hexadecimal.
    pub serial: String,
    /// RFC 3339 certificate validity start.
    pub not_before: String,
    /// RFC 3339 certificate expiry time.
    pub not_after: String,
    /// RFC 3339 certificate issuance time.
    pub issued_at: String,
}

/// A page of certificate metadata using the shared cursor response shape.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct CertificatePage {
    /// Records in stable server-defined order.
    pub items: Vec<CertificateView>,
    /// Opaque cursor for the next page, or `null` at the end.
    pub next_cursor: Option<String>,
    /// RFC 3339 instant when this page was generated.
    pub generated_at: String,
}

/// Agent and current certificate metadata.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct AgentDetail {
    /// Operator-facing agent fields.
    #[serde(flatten)]
    pub agent: AgentView,
    /// Certificate metadata for the agent.
    pub certificates: Vec<CertificateView>,
}

/// Fleet counts visible to the current principal.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct AgentSummary {
    /// Number of visible enrolled agents.
    pub total: u64,
    /// Number of visible active agents.
    pub active: u64,
    /// Number of visible stale agents.
    pub stale: u64,
    /// Number of visible revoked agents.
    pub revoked: u64,
}

/// Latest observation state for one agent, rule set, and rule.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct FindingView {
    /// Stable latest-finding identifier.
    pub id: String,
    /// Agent associated with this observation.
    pub agent_id: String,
    /// Latest hostname reported by the agent; this is an operator label.
    pub hostname: Option<String>,
    /// Rule set that produced the finding, or `~unknown` for legacy data.
    pub rule_set_id: String,
    /// Rule identifier within the rule set.
    pub rule_id: String,
    /// Signed rule version.
    pub rule_version: u64,
    /// Latest observed severity.
    pub severity: Severity,
    /// Confidence as a percentage from 0 through 100.
    #[schema(minimum = 0, maximum = 100)]
    pub confidence: u8,
    /// Latest observation message.
    pub message: String,
    /// Evidence key/value strings from the observation.
    pub evidence: Vec<String>,
    /// Scan that produced the observation.
    pub scan_id: String,
    /// Whether the observation was received through an authenticated agent.
    pub authenticated: bool,
    /// Observation provenance.
    pub origin: FindingOrigin,
    /// RFC 3339 time of the first observation.
    pub first_observed_at: String,
    /// RFC 3339 time of the latest observation.
    pub last_observed_at: String,
    /// RFC 3339 time the platform received this observation.
    pub received_at: String,
}

/// Counts for the latest observation rows visible to the current principal.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct FindingSummary {
    /// Number of visible latest observation rows.
    pub total: u64,
    /// Number of visible agents with at least one latest observation.
    pub impacted_agents: u64,
    /// Visible critical latest observations.
    pub critical: u64,
    /// Visible high latest observations.
    pub high: u64,
    /// Visible medium latest observations.
    pub medium: u64,
    /// Visible low latest observations.
    pub low: u64,
}

/// A page of agents using the shared cursor response shape.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct AgentPage {
    /// Records in stable server-defined order.
    pub items: Vec<AgentView>,
    /// Opaque cursor for the next page, or `null` at the end.
    pub next_cursor: Option<String>,
    /// RFC 3339 instant when this page was generated.
    pub generated_at: String,
}

/// A page of latest observations using the shared cursor response shape.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct FindingPage {
    /// Records in stable server-defined order.
    pub items: Vec<FindingView>,
    /// Opaque cursor for the next page, or `null` at the end.
    pub next_cursor: Option<String>,
    /// RFC 3339 instant when this page was generated.
    pub generated_at: String,
}

/// One historical observation event.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct FindingHistoryEntry {
    /// Finding identifier from the partitioned event table.
    pub id: String,
    /// Agent associated with this event.
    pub agent_id: String,
    /// Rule set that produced the event, or `~unknown` for legacy data.
    pub rule_set_id: String,
    /// Rule identifier within the rule set.
    pub rule_id: String,
    /// Signed rule version.
    pub rule_version: u64,
    /// Severity recorded for this observation.
    pub severity: Severity,
    /// Confidence as a percentage from 0 through 100.
    #[schema(minimum = 0, maximum = 100)]
    pub confidence: u8,
    /// Message recorded for this observation.
    pub message: String,
    /// Evidence key/value strings from the observation.
    pub evidence: Vec<String>,
    /// Scan that produced the observation.
    pub scan_id: String,
    /// Whether the observation was received through an authenticated agent.
    pub authenticated: bool,
    /// Observation provenance.
    pub origin: FindingOrigin,
    /// RFC 3339 time the agent or importer observed this finding.
    pub observed_at: String,
    /// RFC 3339 time the platform received this observation.
    pub received_at: String,
}

/// A page of historical observation events using the shared cursor response shape.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct FindingHistoryPage {
    /// Records in stable server-defined order.
    pub items: Vec<FindingHistoryEntry>,
    /// Opaque cursor for the next page, or `null` at the end.
    pub next_cursor: Option<String>,
    /// RFC 3339 instant when this page was generated.
    pub generated_at: String,
}

/// Why a pagination request is outside its documented bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaginationError {
    /// Limit is zero or above [`MAX_PAGE_SIZE`].
    InvalidLimit,
    /// Cursor is empty or above [`MAX_CURSOR_LENGTH`].
    InvalidCursor,
}

impl fmt::Display for PaginationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit => write!(formatter, "limit must be between 1 and {MAX_PAGE_SIZE}"),
            Self::InvalidCursor => write!(
                formatter,
                "cursor must be non-empty and at most {MAX_CURSOR_LENGTH} bytes"
            ),
        }
    }
}

impl Error for PaginationError {}

#[cfg(test)]
mod tests {
    use super::{CursorPagination, DEFAULT_PAGE_SIZE, MAX_CURSOR_LENGTH};

    #[test]
    fn pagination_defaults_and_rejects_unknown_fields() {
        let pagination: CursorPagination = serde_json::from_str("{}").unwrap();
        assert_eq!(pagination.limit(), DEFAULT_PAGE_SIZE);
        assert!(pagination.cursor().is_none());

        assert!(serde_json::from_str::<CursorPagination>(r#"{"offset": 1}"#).is_err());
    }

    #[test]
    fn pagination_rejects_unbounded_values() {
        assert!(serde_json::from_str::<CursorPagination>(r#"{"limit": 0}"#).is_err());
        assert!(serde_json::from_str::<CursorPagination>(r#"{"limit": 101}"#).is_err());
        assert!(serde_json::from_str::<CursorPagination>(r#"{"cursor": ""}"#).is_err());
        assert!(CursorPagination::new(Some("x".repeat(MAX_CURSOR_LENGTH + 1)), 50).is_err());
    }
}
