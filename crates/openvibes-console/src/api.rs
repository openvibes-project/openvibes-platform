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
