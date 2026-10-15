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

/// Stable console permission identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub enum Permission {
    /// Read agents and their certificate/contact metadata.
    #[serde(rename = "agents.read")]
    AgentsRead,
    /// Revoke an enrolled agent.
    #[serde(rename = "agents.revoke")]
    AgentsRevoke,
    /// Read observed compliance findings.
    #[serde(rename = "compliance.read")]
    ComplianceRead,
    /// Read vulnerability exposure for hosts in the bound asset scope.
    #[serde(rename = "vulnerabilities.read")]
    VulnerabilitiesRead,
    /// Change human triage state for compliance findings.
    #[serde(rename = "compliance.triage")]
    ComplianceTriage,
    /// Change human triage state for vulnerabilities, per host (triage v2).
    #[serde(rename = "vulnerabilities.triage")]
    VulnerabilitiesTriage,
    /// Read threat alarms.
    #[serde(rename = "alarms.read")]
    AlarmsRead,
    /// Access to the cases view and its details.
    #[serde(rename = "cases.read")]
    CasesRead,
    /// Create and change cases: items, notes, assignment, closing.
    #[serde(rename = "cases.manage")]
    CasesManage,
    /// Change human triage state for alarms.
    #[serde(rename = "alarms.triage")]
    AlarmsTriage,
    /// Create and remove alarm suppressions.
    #[serde(rename = "alarms.suppress")]
    AlarmsSuppress,
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
    /// Write, check and delete draft rules in the site's own rule sets.
    #[serde(rename = "rules.write")]
    RulesWrite,
    /// Read audit events.
    #[serde(rename = "audit.read")]
    AuditRead,
    /// Export bounded audit results.
    #[serde(rename = "audit.export")]
    AuditExport,
    /// Change the assistant's internet-lookup setting.
    #[serde(rename = "assistant.admin")]
    AssistantAdmin,
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
    /// Ask the read-only local assistant questions about permitted data.
    #[serde(rename = "assistant.use")]
    AssistantUse,
    /// Share one's own dashboards with a role (global only).
    #[serde(rename = "dashboards.share")]
    DashboardsShare,
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

/// The assistant's internet-lookup setting.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct AssistantInternet {
    /// 0 off, 1 security references (OSV, Bodhi), 2 those and web search through SearXNG.
    pub level: u8,
    /// SearXNG base URL, required at level 2.
    pub searxng_url: Option<String>,
    /// Extra internal domain names the outbound filter refuses.
    pub internal_domains: Vec<String>,
    /// Host of the console's public origin; always filtered.
    pub platform_domain: String,
    /// Version for conditional updates.
    pub version: u64,
    /// RFC 3339 update instant.
    pub updated_at: String,
    /// Local user id that last changed the setting.
    pub updated_by: String,
}

/// The outcome of a Test connection against the stored SearXNG.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct AssistantInternetTest {
    /// True when the search ran and answered.
    pub ok: bool,
    /// `N results`, or why not (off, blocked, unreachable).
    pub detail: String,
}

/// Request body for changing the assistant internet setting.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateAssistantInternetRequest {
    /// 0 off, 1 security references (OSV, Bodhi), 2 those and web search.
    #[schema(minimum = 0, maximum = 2)]
    pub level: u8,
    /// SearXNG base URL: `https://`, or `http://` on a local or private address.
    pub searxng_url: Option<String>,
    /// Lowercase internal domain names, at most 50.
    pub internal_domains: Vec<String>,
}

/// Published rule-set summary for the console.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct RuleSetView {
    /// Rule-set identifier.
    pub rule_set_id: String,
    /// Highest published version, when present.
    pub current_version: Option<i64>,
    /// Current signed expiry, in Unix milliseconds.
    pub current_expires_at_ms: Option<i64>,
    /// Issuer of the current bundle.
    pub current_issuer_key_id: Option<String>,
    /// True when the current bundle's signer has been removed from trust.
    pub current_signer_removed: bool,
    /// Number of currently trusted public keys.
    pub trusted_keys: i64,
    /// Whether operators retired this set.
    pub retired: bool,
}

/// A published signed-bundle metadata row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct RuleBundleView {
    /// Monotonically increasing version.
    pub version: i64,
    /// SHA-256 of exact signed bytes, lower-case hexadecimal.
    pub envelope_sha256: String,
    /// Trusted issuer key id at publish time.
    pub issuer_key_id: String,
    /// Signed creation and expiry instants, in Unix milliseconds.
    pub created_at_ms: i64,
    /// Signed expiry instant, in Unix milliseconds.
    pub expires_at_ms: i64,
    /// Server-side publish instant.
    pub published_at: String,
    /// Operator who published it.
    pub published_by: String,
    /// Stored envelope bytes.
    pub bytes: i32,
}

/// Published rule-set inventory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct RuleSetPage {
    /// Rule sets sorted by identifier.
    pub items: Vec<RuleSetView>,
}

/// Published bundle history for one set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct RuleBundlePage {
    /// Bundles newest first.
    pub items: Vec<RuleBundleView>,
}

/// Signature and version details returned by upload preview.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct RuleBundlePreview {
    /// Rule-set identifier.
    pub rule_set_id: String,
    /// Signed version.
    pub version: i64,
    /// Trusted issuer key id.
    pub issuer_key_id: String,
    /// Signed expiry instant, in Unix milliseconds.
    pub expires_at_ms: i64,
    /// SHA-256 of exact envelope bytes.
    pub envelope_sha256: String,
    /// Token to send with the exact same bytes to publish.
    pub preview_token: String,
    /// Current version at preview time.
    pub current_version: Option<i64>,
}

/// Accepted signed-envelope JSON shape for preview and publish requests.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedRuleEnvelopeRequest {
    /// Envelope schema version (currently 1).
    pub schema_version: u16,
    /// Stable rule-set identifier.
    pub rule_set_id: String,
    /// Monotonically increasing version.
    pub rule_set_version: u64,
    /// Trusted Ed25519 issuer identifier.
    pub issuer_key_id: String,
    /// Creation time in Unix milliseconds.
    pub created_at_unix_ms: i64,
    /// Expiry time in Unix milliseconds.
    pub expires_at_unix_ms: i64,
    /// Payload encoding (`json` or `yaml`).
    pub payload_encoding: String,
    /// Exact UTF-8 signed payload.
    pub payload: String,
    /// Lowercase SHA-256 digest of the payload.
    pub payload_sha256_hex: String,
    /// Base64url Ed25519 signature.
    pub signature_base64url: String,
}

/// One dashboard as the viewer sees it.
#[derive(Clone, Debug, PartialEq, Serialize, ToSchema)]
pub struct DashboardView {
    /// Stable UUID.
    pub dashboard_id: String,
    /// 1–80 characters.
    pub name: String,
    /// Display name of the owner.
    pub owner_display_name: String,
    /// Whether the viewer owns it (only owners may change it).
    pub mine: bool,
    /// Role it is shared with, if any.
    pub shared_role_id: Option<String>,
    /// Version for `If-Match`.
    pub version: u64,
    /// Layout: `{ "schema": 1, "widgets": [...] }`.
    #[schema(value_type = Object)]
    pub layout: serde_json::Value,
    /// RFC 3339 creation time.
    pub created_at: String,
    /// RFC 3339 last change.
    pub updated_at: String,
}

/// Dashboards visible to the viewer: own first, then shared.
#[derive(Clone, Debug, PartialEq, Serialize, ToSchema)]
pub struct DashboardPage {
    /// At most 100 own dashboards plus those shared with the viewer's roles.
    pub items: Vec<DashboardView>,
}

/// Create or replace a dashboard's name and layout.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SaveDashboardRequest {
    /// 1–80 characters.
    pub name: String,
    /// Layout document (validated; at most 64 KiB and 40 widgets).
    #[schema(value_type = Object)]
    pub layout: serde_json::Value,
}

/// Share with a role, or stop sharing with `null`.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ShareDashboardRequest {
    /// Built-in role id, or `null`.
    pub role_id: Option<String>,
}

/// The dashboard that opens first; `null` is the built-in Overview.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct HomeDashboard {
    /// Visible dashboard id, or `null`.
    pub dashboard_id: Option<String>,
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
