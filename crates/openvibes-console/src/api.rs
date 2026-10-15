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

/// Latest observation state for one agent, rule set, and rule.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct FindingView {
    /// Original evaluation evidence; absent for legacy observations.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<crate::detection::DetectionView>)]
    pub detection: Option<serde_json::Value>,
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

/// Human workflow state attached to the latest finding.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct FindingTriageView {
    /// Workflow state.
    pub state: String,
    /// Rule version this state covers.
    pub rule_version: i64,
    /// Assigned analyst username.
    pub assigned_to: Option<String>,
    /// Operator note.
    pub note: Option<String>,
    /// Accepted risk expiry, if applicable.
    pub accepted_until: Option<String>,
    /// Monotonic update version used with ETag and If-Match.
    pub version: i64,
}

/// Requested human workflow update for a latest finding.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateFindingTriageRequest {
    /// Workflow state.
    pub state: String,
    /// Analyst username; omit or null to unassign.
    pub assigned_to: Option<String>,
    /// Required when moving to a completed state.
    pub note: Option<String>,
    /// Required only for accepted risk.
    pub accepted_until: Option<String>,
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

/// Advisory severity used by the vulnerability matcher.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum VulnerabilitySeverity {
    /// Critical.
    Critical,
    /// Important.
    Important,
    /// Moderate.
    Moderate,
    /// Low.
    Low,
    /// No severity rating was supplied.
    Unrated,
}

/// One severity total in the visible vulnerability scope.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct VulnerabilitySeverityCount {
    /// Advisory severity.
    pub severity: VulnerabilitySeverity,
    /// Open host-advisory pairs.
    pub count: u64,
}

/// Operator-facing top vulnerable host.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct VulnerabilityTopHost {
    /// Agent or imported installation identifier.
    pub agent_id: String,
    /// Hostname label, when reported.
    pub hostname: Option<String>,
    /// Number of open advisories.
    pub open: u64,
    /// Critical and important advisories.
    pub serious: u64,
}

/// Scope-filtered fleet vulnerability summary.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct VulnerabilitySummary {
    /// Open host-advisory pairs by severity.
    pub by_severity: Vec<VulnerabilitySeverityCount>,
    /// Hosts with at least one open advisory.
    pub hosts: u64,
    /// Ten most affected hosts in scope.
    pub top_hosts: Vec<VulnerabilityTopHost>,
    /// Hosts only needing a reboot to activate the installed fix.
    pub reboot_hosts: u64,
    /// Host-advisory pairs without a known fixed package version.
    pub no_fix: u64,
    /// Open, non-reboot findings with KEV/EUVD exploitation evidence.
    pub exploited: u64,
    /// When an advisory feed last imported new content (RFC 3339); null
    /// until one has, so zero counts mean "nothing found" only when set.
    pub feed_last_imported_at: Option<String>,
}

/// One host-advisory match with package and exploitation details.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct VulnerabilityView {
    /// Agent or imported installation identifier.
    pub agent_id: String,
    /// Hostname label, when reported.
    pub hostname: Option<String>,
    /// Advisory identifier.
    pub advisory_id: String,
    /// Advisory severity.
    pub severity: VulnerabilitySeverity,
    /// Advisory title.
    pub title: String,
    /// Advisory URL.
    pub url: String,
    /// CVE identifiers named by the advisory.
    pub cves: Vec<String>,
    /// Affected package names and installed/fixed versions.
    pub packages: serde_json::Value,
    /// First time this host matched the advisory.
    pub first_seen_at: String,
    /// When the vulnerability was fixed; absent while still open.
    pub fixed_at: Option<String>,
    /// A kernel fix is installed but not running.
    pub reboot_needed: bool,
    /// At least one CVE is on KEV or EUVD exploited lists.
    pub exploited: bool,
    /// At least one CVE is on CISA KEV.
    pub kev: bool,
    /// At least one CVE is on EUVD's exploited list.
    pub euvd: bool,
    /// Earliest KEV due date.
    pub kev_due: Option<String>,
    /// One CVE is known to be used by ransomware.
    pub ransomware: bool,
    /// Highest EPSS score among advisory CVEs.
    pub epss: Option<f32>,
    /// Highest EPSS percentile among advisory CVEs.
    pub epss_percentile: Option<f32>,
    /// Highest NVD CVSS base score among advisory CVEs.
    pub cvss: Option<f32>,
    /// Feed the advisory came from, e.g. `fedora-44-x86_64`.
    pub source: String,
    /// How the host was matched to the advisory, e.g. `distribution-advisory`.
    pub match_method: String,
    /// Mapping confidence, 0 to 100.
    pub confidence: u8,
    /// A sentence saying how the host was matched.
    pub match_basis: String,
    /// This host's triage: `open`, `mitigated`, `accepted_risk` or
    /// `false_positive` (triage v2).
    pub triage_state: String,
    /// Triage write version (0 = never triaged), for If-Match.
    pub triage_version: i64,
    /// Assigned analyst's username.
    pub assigned_to: Option<String>,
}

/// Bounded prioritised vulnerability list for the current scope.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct VulnerabilityPage {
    /// Highest-priority rows returned by the query.
    pub items: Vec<VulnerabilityView>,
    /// True when more rows exist beyond this response's fixed page bound.
    pub more_available: bool,
    /// RFC 3339 instant when this page was generated.
    pub generated_at: String,
}

/// CVE enrichment visible through one advisory present in the caller's scope.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct CveDetailView {
    /// CVE identifier.
    pub cve_id: String,
    /// NVD CVSS base score.
    pub cvss_score: Option<f32>,
    /// CVSS version.
    pub cvss_version: Option<String>,
    /// CWE identifiers.
    pub cwe: Vec<String>,
    /// NVD description.
    pub description: Option<String>,
    /// On CISA KEV.
    pub kev: bool,
    /// EUVD identifier, if listed as exploited.
    pub euvd_exploited: Option<String>,
    /// EPSS score.
    pub epss: Option<f32>,
}

/// Advisory view and in-scope affected hosts.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct VulnerabilityAdvisoryDetail {
    /// Affected host-advisory matches in the current scope.
    pub hosts: VulnerabilityPage,
    /// CVE metadata for this visible advisory.
    pub cves: Vec<CveDetailView>,
}

/// One grouped current finding across visible endpoints.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct FindingGroupView {
    /// Rule-set identifier; `~unknown` represents legacy findings without one.
    pub rule_set_id: String,
    /// Rule identifier within the rule set.
    pub rule_id: String,
    /// Visible endpoints whose latest observation is inside the requested window.
    pub endpoint_count: u64,
    /// Highest severity among the current in-window endpoints.
    pub severity: Severity,
    /// Message from the most recently observed endpoint.
    pub latest_message: String,
    /// Distinct signed rule versions represented in the group.
    pub rule_versions: Vec<u64>,
    /// Earliest first-observed timestamp in the group.
    pub first_observed_at: String,
    /// Latest-observed timestamp in the group.
    pub last_observed_at: String,
    /// Visible endpoints whose latest observation is older than the window.
    pub older_endpoint_count: u64,
    /// Counts by endpoint triage state, for current in-window observations.
    pub triage_counts: FindingTriageCounts,
}

/// Number of endpoints in each current finding triage state.
#[derive(Clone, Debug, Default, Serialize, ToSchema)]
pub struct FindingTriageCounts {
    /// Open endpoints.
    pub open: u64,
    /// Mitigated endpoints.
    pub mitigated: u64,
    /// Endpoints accepted as risk.
    pub accepted_risk: u64,
    /// Findings marked as false positives.
    pub false_positive: u64,
}

/// Page of unique rule groups.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct FindingGroupPage {
    /// Current page of unique rule groups.
    pub items: Vec<FindingGroupView>,
    /// Opaque continuation cursor, or `null` after the final page.
    pub next_cursor: Option<String>,
    /// RFC 3339 time when this page was generated.
    pub generated_at: String,
    /// RFC 3339 start of the grouping window.
    pub since: String,
}

/// One endpoint reporting a grouped finding.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct FindingGroupEndpointView {
    /// Enrolled-agent or imported-installation identifier.
    pub agent_id: String,
    /// Hostname label, when reported.
    pub hostname: Option<String>,
    /// RFC 3339 time when this endpoint first reported the finding.
    pub first_observed_at: String,
    /// RFC 3339 time of the latest observation.
    pub last_observed_at: String,
    /// Signed rule version reported by this endpoint.
    pub rule_version: u64,
    /// Current workflow state; missing triage records are `open`.
    pub triage_state: String,
    /// Monotonic triage version used to reject stale writes.
    pub triage_version: i64,
    /// Assigned analyst username, or `null` when unassigned.
    pub assigned_to: Option<String>,
    /// RFC 3339 accepted-risk expiry, or `null`.
    pub accepted_until: Option<String>,
    /// RFC 3339 time the match ended (protocol P13), or `null` while open.
    pub ended_at: Option<String>,
    /// The end time is approximate (known only to be before a resync).
    pub end_approximate: bool,
    /// Whether this endpoint is older than the requested window.
    pub outside_window: bool,
    /// Online or imported observation provenance.
    pub origin: FindingOrigin,
    /// Whether the finding arrived over authenticated agent transport.
    pub authenticated: bool,
}

/// Page of endpoints reporting one rule.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct FindingGroupEndpointPage {
    /// Current page of visible endpoints reporting the rule.
    pub items: Vec<FindingGroupEndpointView>,
    /// Opaque continuation cursor, or `null` after the final page.
    pub next_cursor: Option<String>,
    /// RFC 3339 time when this page was generated.
    pub generated_at: String,
    /// RFC 3339 start of the endpoint query window.
    pub since: String,
}

/// One endpoint and its expected triage version for a bulk transition.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BulkFindingTriageChange {
    /// Enrolled-agent or imported-installation identifier.
    pub agent_id: String,
    /// Expected triage version for this endpoint.
    pub version: i64,
}

/// Atomic workflow transition for selected endpoints in one rule group.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BulkFindingTriageRequest {
    /// One through 100 unique endpoints to update atomically.
    pub changes: Vec<BulkFindingTriageChange>,
    /// Requested workflow state.
    pub state: String,
    /// Analyst username, or `null` to unassign.
    pub assigned_to: Option<String>,
    /// Required when moving to a completed state.
    pub note: Option<String>,
    /// Required only for accepted risk; RFC 3339 timestamp.
    pub accepted_until: Option<String>,
}

/// Successful endpoint-level triage results.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct BulkFindingTriageResponse {
    /// New triage state and version for every updated endpoint.
    pub updated: Vec<(String, FindingTriageView)>,
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
    /// UTC partition day used for stable event lookup.
    pub observed_day: String,
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
