//! Query parameters and cursor tokens of the audit event list and export.

use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuditEventListParams {
    pub(super) since: String,
    pub(super) until: Option<String>,
    pub(super) actor: Option<String>,
    pub(super) action: Option<String>,
    pub(super) result: Option<String>,
    pub(super) action_prefix: Option<String>,
    pub(super) cursor: Option<String>,
    pub(super) limit: Option<u16>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuditEventExportParams {
    pub(super) since: String,
    pub(super) until: Option<String>,
    pub(super) actor: Option<String>,
    pub(super) action: Option<String>,
    pub(super) result: Option<String>,
}

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AuditEventCursorToken {
    pub(super) since: String,
    pub(super) until: Option<String>,
    pub(super) actor: Option<String>,
    pub(super) action: Option<String>,
    pub(super) result: Option<String>,
    #[serde(default)]
    pub(super) action_prefix: Option<String>,
    pub(super) at: String,
    pub(super) id: i64,
}
