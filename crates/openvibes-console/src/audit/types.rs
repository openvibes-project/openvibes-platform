//! Request and response types of the audit events and retention.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Current administrator-controlled audit retention policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct AuditRetentionPolicy {
    /// Number of days kept after the next maintenance run.
    pub retention_days: u32,
    /// Version for conditional updates.
    pub version: u64,
    /// RFC 3339 update instant.
    pub updated_at: String,
    /// Local user id that last changed the policy.
    pub updated_by: String,
}

/// One safe audit event in a bounded audit search.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct AuditEventView {
    /// Stable database event identifier.
    pub id: String,
    /// RFC 3339 event timestamp.
    pub at: String,
    /// Operator-facing actor label.
    pub actor: String,
    /// Stable action code.
    pub action: String,
    /// Safe target label, when present.
    pub target: Option<String>,
    /// Event result code.
    pub result: String,
    /// Request correlation id, when present.
    pub request_id: Option<String>,
    /// Actor kind and stable id.
    pub actor_kind: Option<String>,
    /// Stable actor id.
    pub actor_id: Option<String>,
    /// Authentication method, when present.
    pub authentication_method: Option<String>,
    /// Target kind and stable id.
    pub target_kind: Option<String>,
    /// Stable target id.
    pub target_id: Option<String>,
    /// Safe reason code.
    pub reason_code: Option<String>,
}

/// Bounded audit-event page with an opaque continuation cursor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct AuditEventPage {
    /// Events in descending timestamp order.
    pub items: Vec<AuditEventView>,
    /// Opaque cursor for the next page, if present.
    pub next_cursor: Option<String>,
}

/// Request body for changing audit retention.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateAuditRetentionRequest {
    /// Retention window in days, from 1 through 36500.
    #[schema(minimum = 1, maximum = 36500)]
    pub retention_days: u32,
}
