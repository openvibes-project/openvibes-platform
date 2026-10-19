//! Request and response types of hosts, certificates and enrollment tokens.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

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
    /// Host represented by a file import, with no online identity.
    Imported,
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
    /// OS id from the last inventory (os-release `ID`, e.g. `fedora`).
    pub os_id: Option<String>,
    /// OS version from the last inventory (os-release `VERSION_ID`).
    pub os_version: Option<String>,
    /// Running kernel from the last inventory (`uname -r`).
    pub running_kernel: Option<String>,
    /// RFC 3339 time the last inventory was received: software "as of".
    pub inventory_at: Option<String>,
    /// Rule sets the agent reported holding in its latest health report;
    /// empty for an agent that never reported one.
    pub rule_sets: Vec<AgentRuleSetView>,
    /// RFC 3339 time that report was written.
    pub rule_sets_at: Option<String>,
    /// Threat alarms on this host, from the same report; absent before one.
    pub alarms: Option<AgentAlarmsView>,
}

/// The one-line agent install command for the Enrollment page.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct AgentCommandView {
    /// Run as root on a new host; it carries the standing enrollment token.
    pub command: String,
}

/// Threat alarms on one host: on and from which source, or off, why, and the
/// command that turns them on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct AgentAlarmsView {
    /// `on` or `off`.
    pub state: String,
    /// `ebpf` or `audit` when on.
    pub source: Option<String>,
    /// Why off: `not_enabled`, `audit_not_set_up` or `no_source`.
    pub reason: Option<String>,
    /// Why off, in words.
    pub text: Option<String>,
    /// What turns them on, in words.
    pub fix: Option<String>,
    /// The command to run on the host for that, when there is one (copyable).
    pub command: Option<String>,
    /// Off by a fault, not by the admin's choice: the Hosts list badges these.
    pub fault: bool,
}

/// One rule set an agent reports holding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct AgentRuleSetView {
    /// Rule-set identifier.
    pub id: String,
    /// Bundle version in use; absent before the agent accepted one.
    pub version: Option<i64>,
    /// Signed expiry of that bundle, in Unix milliseconds.
    pub expires_at_ms: Option<i64>,
    /// Why the agent refused the last bundle it was given, when it did.
    pub refused: Option<String>,
    /// The agent's state for the set: `not_assigned` when the platform
    /// switched it off for this host (P20); absent otherwise.
    pub state: Option<String>,
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
    /// When the host last raised the harmless test triggers
    /// (`openvibes-test alarm|finding`).
    pub last_test: LastTest,
}

/// The host's latest test alarm and test finding (spec
/// `2026-10-09-test-triggers-design.md`); absent when never seen.
#[derive(Clone, Debug, Default, Serialize, ToSchema)]
pub struct LastTest {
    /// Latest test alarm (RFC 3339).
    pub alarm_at: Option<String>,
    /// Latest test finding observation (RFC 3339).
    pub finding_at: Option<String>,
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
    /// Number of visible imported hosts.
    pub imported: u64,
    /// This platform's version: agents older than it are shown as outdated.
    /// Readable by every signed-in role (it is in the packages anyway).
    pub platform_version: String,
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

/// Reason supplied by an operator when revoking an agent.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RevokeAgentRequest {
    /// Short operator reason recorded in the audit event.
    pub reason: String,
}

/// Bounded one-time enrollment-token creation request.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateEnrollmentTokenRequest {
    /// Validity in hours, from one through 8760.
    pub expires_in_hours: u32,
    /// Number of enrollments, from one through 100000.
    pub max_uses: u32,
    /// Optional operator label.
    pub label: Option<String>,
}

/// Enrollment token secret, returned only at creation time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct CreatedEnrollmentToken {
    /// Stable token identifier.
    pub token_id: String,
    /// Secret token. Never returned by list or revoke operations.
    pub token: Option<String>,
    /// True when this response replays creation metadata for the same key.
    pub replayed: bool,
    /// Whether the plaintext is present in this response.
    pub secret_available: bool,
    /// RFC3339 expiry instant.
    pub expires_at: String,
}

/// Safe enrollment-token listing row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct EnrollmentTokenView {
    /// Stable token identifier.
    pub token_id: String,
    /// Operator label.
    pub label: Option<String>,
    /// Creation instant.
    pub created_at: String,
    /// Expiry instant.
    pub expires_at: String,
    /// Maximum enrollments.
    pub max_uses: i32,
    /// Completed enrollments.
    pub uses: i64,
    /// Whether the token was revoked.
    pub revoked: bool,
    /// The standing token: never expires and has no use limit; its expiry
    /// and maximum are placeholders.
    pub standing: bool,
}

/// Full bounded enrollment-token inventory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct EnrollmentTokenPage {
    /// Tokens newest first, without secret material.
    pub items: Vec<EnrollmentTokenView>,
}
