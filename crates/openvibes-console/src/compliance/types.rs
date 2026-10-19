//! Request and response types of findings, finding groups, history and triage.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

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
    #[schema(value_type = Option<crate::alarms::DetectionView>)]
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
